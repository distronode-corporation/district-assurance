// Gate (entry): the outcome after verification. A verified call gets a signed, time-limited access
// grant (ES256 over canonical JSON, `access.ts`), delivered to a door controller. It refuses without
// a valid verification grant covering `entry.open`, an access scope whose floor is level 2, and
// every grant and its outcome go to the ledger.
//
// Gate is a built-in module, like Paylink: its runtime runs inside the engine, on the engine's own
// writes, and no module code can reach its part of a call (`updateModule` refuses built-in
// modules). The door controllers (`access`) and the grant signer (`accessSigner`) are engine
// adapters. So the engine itself reserves each grant, signs it, computes its digest from the frozen
// grant, calls the controller once, and records the controller's actual answer: nothing else can
// write a grant's outcome (ADR-25).
//
// An unlock is never retried. It is reserved in one write (one in flight per call), signed, sent
// once, and its answer committed. A lost answer is "unknown", and opening again needs a fresh
// request: a new grant, within the per-call limit. Ending the call is refused while a signed grant
// may still be acted on (at its door, or answered unknown and not yet expired); a grant reserved
// but not yet signed, or past its expiry, is settled unknown in the write that ends the call,
// before the receipt's ledger head is taken, so no outcome ever follows the receipt.
import type { AccessController, AccessGrantBody, SignedAccessGrant, UnlockResult } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, ModuleManifest, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { AssuranceLevel } from "../core/policy.ts";
import type { CallDraft, EngineRuntime } from "../core/runtime.ts";
import { isDenseArray, isIntegerIn, isObject, isStringArray, unknownKeys } from "../core/shape.ts";
import { signDocument } from "../prove/receipt.ts";
import { accessGrantDigest, MAX_ACCESS_GRANT_SECONDS } from "./access.ts";

export const GATE = "gate";

/** The scope a `gate.grant` step needs. An access scope: never below level 2. */
export const ENTRY_SCOPE = "entry.open";

export const DEFAULT_ACCESS_SECONDS = 60;
export const MIN_ACCESS_SECONDS = 10;
export const DEFAULT_GRANTS_PER_CALL = 3;
export const MAX_GRANTS_PER_CALL = 5;

const TARGET_ID = /^[a-z][a-z0-9-]{0,63}$/;

/** A door, as config names it: Gate's id for it, the controller that works it, and that controller's ref. */
export interface GateTarget {
  id: string;
  controller: string;
  ref: string;
}

export interface GateSettings {
  targets: GateTarget[];
  /** Access grants a call may get, delivered or not. 1 to 5, default 3. */
  maxGrantsPerCall?: number;
}

export interface GateGrantStep extends FlowStep {
  type: "gate.grant";
  target: string;
  /** How long the access grant lives, 10 to 900 seconds. Default 60. Never past the verification grant. */
  lifetimeSeconds?: number;
}

export type AccessStatus = "reserved" | "delivered" | "refused" | "unknown" | "failed";

/** One access grant on a call, as the engine keeps it. Never the signature itself. */
export interface AccessRecord {
  grantId: string;
  target: string;
  controller: string;
  ref: string;
  level: AssuranceLevel;
  issuedAt: string;
  expiresAt: string;
  status: AccessStatus;
  confirmed: boolean;
  providerRef: string | null;
  /** The digest of the signed grant (computed by the engine) and its key id, written just before it is sent. */
  digest: string | null;
  kid: string | null;
}

export interface GateSlice {
  /** The targets in force when the call started: a config change never moves a call. */
  targets: GateTarget[];
  maxGrantsPerCall: number;
  grants: AccessRecord[];
}

export interface AccessResult {
  grantId: string;
  /** `delivered`: the controller took it. `refused`: it certainly did not act. `unknown`: the answer was lost, or the call ended first; do not assume either. */
  status: "delivered" | "refused" | "unknown";
  /** The controller reported that the door moved. */
  confirmed: boolean;
}

/** What the access adapter declares to the validator: the names of its controllers. */
export interface AccessCapabilities {
  controllers: string[];
}

export const gateModule: AssuranceModule = {
  manifest: {
    name: GATE,
    version: "2",
    summary: "Turn a verified call into a signed, time-limited access grant for a door controller.",
    provides: { factors: [], steps: ["gate.grant"], outcomes: ["access_grant"] },
    scopes: { grants: [], needs: { "gate.grant": ENTRY_SCOPE }, classes: { [ENTRY_SCOPE]: "access" } },
    adapters: ["access", "accessSigner"],
  } satisfies ModuleManifest,

  validateSettings(settings: unknown): string[] {
    if (!isObject(settings)) return ["must be an object with the targets"];
    const errors = unknownKeys(settings, ["targets", "maxGrantsPerCall"]).map((k) => `${k} is not a gate setting`);
    if (settings.maxGrantsPerCall !== undefined && !isIntegerIn(settings.maxGrantsPerCall, 1, MAX_GRANTS_PER_CALL)) {
      errors.push(`maxGrantsPerCall must be an integer from 1 to ${MAX_GRANTS_PER_CALL}`);
    }
    const targets = settings.targets;
    if (!isDenseArray(targets) || targets.length === 0) return [...errors, "targets must list at least one target"];
    const ids: unknown[] = [];
    targets.forEach((target: unknown, i: number) => {
      const at = `targets[${i}]`;
      if (!isObject(target)) {
        errors.push(`${at} must be { id, controller, ref }`);
        return;
      }
      ids.push(target.id);
      errors.push(...unknownKeys(target, ["id", "controller", "ref"]).map((k) => `${at}.${k} is not a target field`));
      if (typeof target.id !== "string" || !TARGET_ID.test(target.id)) errors.push(`${at}.id must be lower-case letters, digits and hyphens, at most 64`);
      if (typeof target.controller !== "string" || target.controller === "") errors.push(`${at}.controller must name a controller`);
      if (typeof target.ref !== "string" || target.ref.trim() === "" || target.ref.length > 200) errors.push(`${at}.ref must be 1 to 200 characters`);
    });
    if (new Set(ids).size !== ids.length) errors.push("two targets have the same id");
    return errors;
  },

  requiredAdapters(): string[] {
    return ["access", "accessSigner"];
  },

  checkAdapters(settings: unknown, capabilities: Readonly<Record<string, unknown>>): string[] {
    const declared = capabilities.access as AccessCapabilities | undefined;
    if (declared === undefined) return [];
    if (!isObject(declared) || !isStringArray(declared.controllers)) return ["the access adapter must declare its controllers as a list of names"];
    return (settings as GateSettings).targets
      .filter((t) => !declared.controllers.includes(t.controller))
      .map((t) => `target ${t.id} names the controller ${t.controller}, which the access adapter does not have (it has: ${declared.controllers.join(", ") || "none"})`);
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "target", "lifetimeSeconds"]).map((k) => `${k} is not a field of this step`);
    if (step.lifetimeSeconds !== undefined && !isIntegerIn(step.lifetimeSeconds, MIN_ACCESS_SECONDS, MAX_ACCESS_GRANT_SECONDS)) {
      errors.push(`lifetimeSeconds must be an integer from ${MIN_ACCESS_SECONDS} to ${MAX_ACCESS_GRANT_SECONDS}`);
    }
    if (typeof step.target !== "string") return [...errors, "target must name a target in the gate settings"];
    const settings = ctx.settings as GateSettings | null;
    if (settings !== null && !settings.targets.some((t) => t.id === step.target)) errors.push(`no target ${step.target} in the gate settings`);
    return errors;
  },

  validateFlow(steps: readonly FlowStep[], ctx: StepContext): string[] {
    // Each gate.grant step completes only on a grant of its own, and every grant counts against the
    // call's limit, so a flow with more such steps than the limit could never finish (and would fail
    // at the door after earlier grants were delivered).
    const max = (ctx.settings as GateSettings).maxGrantsPerCall ?? DEFAULT_GRANTS_PER_CALL;
    const grants = steps.filter((step) => isObject(step) && step.type === "gate.grant").length;
    return grants > max ? [`${grants} gate.grant steps, but a call may have at most ${max} access grant${max === 1 ? "" : "s"} (maxGrantsPerCall)`] : [];
  },

  initCall(settings: unknown): JsonValue {
    const s = settings as GateSettings;
    const slice: GateSlice = { targets: structuredClone(s.targets), maxGrantsPerCall: s.maxGrantsPerCall ?? DEFAULT_GRANTS_PER_CALL, grants: [] };
    return slice as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as GateSlice).grants.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue): string | null {
    return (s as unknown as GateSlice).targets.some((t) => t.id === step.target) ? null : `the call has no target ${String(step.target)}`;
  },

  stepStatus(_step: FlowStep, view: StepView): StepStatus {
    const slice = view.slice as unknown as GateSlice;
    const mine = slice.grants.slice(view.mark as number);
    if (mine.some((g) => g.status === "delivered")) return "complete";
    // Every grant the call may have is used, none delivered in this step and none in flight: the step
    // fails. A last grant whose answer was lost may still have opened the door; the ledger says unknown.
    const inFlight = mine.some((g) => g.status === "reserved");
    return !inFlight && slice.grants.length >= slice.maxGrantsPerCall ? "failed" : "pending";
  },
};

// ---- runtime -------------------------------------------------------------------------------

function gateSlice(draft: CallDraft): GateSlice {
  return draft.slice<GateSlice>(GATE);
}

/**
 * Settles, inside a write of the engine's, every grant still reserved past its expiry as unknown
 * (the process that sent it stopped before recording the answer). With `call_ended`, it first
 * refuses (`precondition_failed`) while a signed grant may still be acted on, then settles every
 * grant still reserved (not yet signed, or past its expiry) as unknown: the call is ending.
 */
export function settleInFlight(rt: EngineRuntime, draft: CallDraft, reason: "no_answer_recorded" | "call_ended"): void {
  const slice = draft.record.modules[GATE] as unknown as GateSlice | undefined;
  if (slice === undefined) return;
  const now = Date.parse(rt.now());
  for (const g of slice.grants) {
    const expired = Date.parse(g.expiresAt) <= now;
    // A grant that was signed and may still be acted on: at its door now (reserved), or sent with
    // its answer lost (unknown, which the controller may still be working on). The call ends once
    // its answer is recorded or it expires (after which a relay refuses it), never while it can
    // still open a door: so no door acts on a grant after the receipt. Stale grants are expired.
    const live = (g.status === "reserved" || g.status === "unknown") && g.digest !== null && !expired;
    if (reason === "call_ended" && live) {
      throw new EngineError("precondition_failed", "an access grant may still be acted on at its door; end the call once it answers or expires");
    }
    if (g.status !== "reserved") continue;
    if (reason === "call_ended" || expired) {
      g.status = "unknown";
      draft.emit("access.unknown", "system", { grantId: g.grantId, ...(g.digest === null ? {} : { digest: g.digest, kid: g.kid! }), reason: expired ? "no_answer_recorded" : reason });
    }
  }
}

/**
 * Issues an access grant for a target and sends it to its controller, once. In a flow the step
 * names the target and its lifetime (pass no input); outside one the host's code passes them.
 * Returns the outcome the call holds; an `unknown` one is never retried here.
 */
export async function grantAccess(rt: EngineRuntime, callId: string, input?: { target: string; lifetimeSeconds?: number }, only?: { controller: AccessController }): Promise<AccessResult> {
  rt.settings(GATE);
  // A stale reservation is settled in a write of its own, so the settlement holds even when the
  // request that follows is refused (at the grant limit, the step then fails instead of waiting).
  const before = (await rt.read(callId)).modules[GATE] as unknown as GateSlice | undefined;
  const now = Date.parse(rt.now());
  if (before?.grants.some((g) => g.status === "reserved" && Date.parse(g.expiresAt) <= now) === true) {
    await rt.update(callId, (draft) => settleInFlight(rt, draft, "no_answer_recorded"));
  }
  const record = await rt.update(callId, (draft) => reserve(rt, draft, input, only));
  const body = grantBody(rt, record);
  let grant: SignedAccessGrant;
  try {
    grant = await signDocument(rt.adapter("accessSigner"), body);
  } catch (error) {
    // Nothing was sent: the grant failed, and a new request may follow.
    await failUnsent(rt, callId, record.grantId, { reason: "not_signed" });
    throw error;
  }
  // The engine computes the digest from the frozen grant it signed; it is never taken from elsewhere.
  const digest = accessGrantDigest(body);
  // Signing can take a while (a KMS): checked again, in a write, right before the door is asked,
  // and the controller looked up in it: a grant that cannot be sent is failed, never unknown.
  const checked = await rt.update(callId, (draft): AccessController | EngineError => {
    const g = find(draft, record.grantId);
    if (g.status !== "reserved") return new EngineError("scope_denied", "the access grant was not sent: it was settled meanwhile");
    const controller = controllerOf(rt, g.controller);
    const why = !rt.authorized(draft.record, ENTRY_SCOPE) ? "not_authorized" : Date.parse(g.expiresAt) <= Date.parse(rt.now()) ? "expired" : controller === null ? "not_sent" : null;
    g.digest = digest;
    g.kid = grant.kid;
    if (why === null) return controller!;
    g.status = "failed";
    draft.emit("access.failed", "code", { grantId: g.grantId, digest, kid: grant.kid, reason: why });
    return why === "not_sent"
      ? new EngineError("precondition_failed", `the access grant was not sent: the engine has no access controller named ${g.controller}`)
      : new EngineError("scope_denied", `the access grant was not sent: ${why === "expired" ? "it expired" : "the call is no longer authorized"}`);
  });
  if (checked instanceof EngineError) throw checked;
  const controller = checked;
  // The call can change between that write and here (a taint, written by its own update), and so
  // can the config (a stricter floor for entry.open): the call is read again, as it is now, and
  // checked against the config in force, with nothing in between this check and the send. A taint
  // that commits after this read lands while the grant is already on its way to the door.
  if (!rt.authorized(await rt.read(callId), ENTRY_SCOPE)) {
    await failUnsent(rt, callId, record.grantId, { digest, kid: grant.kid, reason: "not_authorized" });
    throw new EngineError("scope_denied", "the access grant was not sent: the call is no longer authorized");
  }
  let answer: UnlockResult | "lost" | "malformed";
  try {
    answer = readAnswer(await controller.unlock({ grant, target: record.ref, idempotencyKey: rt.idempotencyKey(callId, record.grantId, "unlock") }));
  } catch {
    // The answer was lost (a timeout, a dropped connection, a controller error). The door may or
    // may not have moved: record that, and never send this grant again.
    answer = "lost";
  }
  return rt.update(callId, (draft) => {
    const g = find(draft, record.grantId);
    // Settled meanwhile (the call ended, or another process found it stale): it stays as it is.
    if (g.status === "reserved") {
      if (answer === "lost" || answer === "malformed") {
        g.status = "unknown";
        draft.emit("access.unknown", "code", { grantId: g.grantId, digest, kid: grant.kid, reason: answer === "lost" ? "answer_lost" : "malformed_answer" });
      } else if (answer.outcome === "delivered") {
        Object.assign(g, { status: "delivered", confirmed: answer.confirmed, providerRef: answer.providerRef });
        draft.emit("access.delivered", "code", { grantId: g.grantId, digest, kid: grant.kid, confirmed: answer.confirmed });
      } else {
        g.status = "refused";
        draft.emit("access.refused", "code", { grantId: g.grantId, digest, kid: grant.kid, reason: reasonCode(answer.reason) });
      }
    }
    return { grantId: g.grantId, status: g.status as AccessResult["status"], confirmed: g.confirmed };
  });
}

/** The body of a grant as the engine signs it, from its record. */
function grantBody(rt: EngineRuntime, record: AccessRecord): AccessGrantBody {
  return {
    v: 1,
    kind: "access",
    grantId: record.grantId,
    workspaceId: rt.workspaceId,
    audience: record.controller,
    target: record.ref,
    action: "unlock",
    scope: ENTRY_SCOPE,
    level: record.level,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
  };
}

/**
 * In the taint's own write: every grant of the call that may still be acted on (signed and not
 * expired: at its door, delivered, or answered unknown) is written down with the taint, and
 * returned, for `revokeTainted`. A taint never pulls back a door that already opened.
 */
export function noteTaintedGrants(rt: EngineRuntime, draft: CallDraft): AccessRecord[] {
  const slice = draft.record.modules[GATE] as unknown as GateSlice | undefined;
  if (slice === undefined) return [];
  const now = Date.parse(rt.now());
  const live = slice.grants.filter((g) => g.digest !== null && g.status !== "failed" && g.status !== "refused" && Date.parse(g.expiresAt) > now);
  for (const g of live) {
    const controller = controllerOf(rt, g.controller);
    draft.emit("access.tainted", "system", { grantId: g.grantId, digest: g.digest!, status: g.status, revocable: controller !== null && typeof controller.revoke === "function" });
  }
  return structuredClone(live);
}

/**
 * After the taint: asks each tainted grant's controller to withdraw it, once, where it can
 * (`AccessController.revoke`), and records each answer. One that cannot is left to expire; a
 * revoke that throws is recorded as failed, and the taint stands either way.
 */
export async function revokeTainted(rt: EngineRuntime, callId: string, grants: readonly AccessRecord[]): Promise<void> {
  const outcomes: Array<{ grantId: string; outcome: "revoked" | "failed" }> = [];
  for (const g of grants) {
    const controller = controllerOf(rt, g.controller);
    if (controller === null || typeof controller.revoke !== "function") continue;
    try {
      await controller.revoke({ grant: grantBody(rt, g), target: g.ref, callId, idempotencyKey: rt.idempotencyKey(callId, g.grantId, "revoke") });
      outcomes.push({ grantId: g.grantId, outcome: "revoked" });
    } catch {
      outcomes.push({ grantId: g.grantId, outcome: "failed" });
    }
  }
  if (outcomes.length === 0) return;
  await rt.update(callId, (draft) => {
    for (const o of outcomes) draft.emit("access.revoked", "system", o);
  });
}

/** The one write that reserves a grant: checked against the call, the step, the scope and the limits. */
function reserve(rt: EngineRuntime, draft: CallDraft, input: { target: string; lifetimeSeconds?: number } | undefined, only: { controller: AccessController } | undefined): AccessRecord {
  const step = stepOfType<GateGrantStep>(draft.record, "gate.grant");
  // The scope is checked on every request, in a flow and outside one.
  if (!rt.authorized(draft.record, ENTRY_SCOPE)) throw new EngineError("scope_denied", `the grant does not cover ${ENTRY_SCOPE}`);
  if (step !== null && input !== undefined) throw new EngineError("invalid_input", "the flow step names the target; pass no input");
  if (input !== undefined && (!isObject(input) || typeof input.target !== "string")) throw new EngineError("invalid_input", "the input is { target, lifetimeSeconds? }");
  const wanted = step ?? input;
  if (wanted === undefined) throw new EngineError("invalid_input", "outside a flow, the target is required");
  const slice = gateSlice(draft);
  const target = slice.targets.find((t) => t.id === wanted.target);
  if (target === undefined) throw new EngineError("invalid_input", `no target ${wanted.target} on this call`);
  const controller = controllerOf(rt, target.controller);
  if (controller === null) throw new EngineError("precondition_failed", `the engine has no access controller named ${target.controller}`);
  // A caller that works only one controller (access codes) never sets off another: a target that
  // names a live door is refused here, before anything is reserved or sent.
  if (only !== undefined && controller !== only.controller) throw new EngineError("invalid_input", `target ${target.id} is not worked by that controller`);
  const lifetime = wanted.lifetimeSeconds ?? DEFAULT_ACCESS_SECONDS;
  if (!isIntegerIn(lifetime, MIN_ACCESS_SECONDS, MAX_ACCESS_GRANT_SECONDS)) {
    throw new EngineError("invalid_input", `lifetimeSeconds must be an integer from ${MIN_ACCESS_SECONDS} to ${MAX_ACCESS_GRANT_SECONDS}`);
  }
  if (slice.grants.some((g) => g.status === "reserved")) throw new EngineError("precondition_failed", "an access grant is being delivered on this call");
  if (slice.grants.length >= slice.maxGrantsPerCall) throw new EngineError("precondition_failed", "this call has used every access grant it may have");
  // `entry.open` is an access scope, never below level 2, so an authorized call holds a grant.
  const verification = draft.record.state.grant!;
  const now = rt.now();
  // Grant ids come from the host's id generator; one that repeats an id on this call (a second
  // process with its own sequence) would send a grant the relay takes for a replay, and leave this
  // reservation unanswerable (every write finds the first grant of that id). Refused: try again.
  const grantId = rt.ids.next("acc");
  if (slice.grants.some((g) => g.grantId === grantId)) throw new EngineError("conflict", "the id generator gave an access grant id this call already used; try again");
  const record: AccessRecord = {
    grantId,
    target: target.id,
    controller: target.controller,
    ref: target.ref,
    level: verification.level,
    issuedAt: now,
    expiresAt: new Date(Math.min(Date.parse(now) + lifetime * 1000, Date.parse(verification.expiresAt))).toISOString(),
    status: "reserved",
    confirmed: false,
    providerRef: null,
    digest: null,
    kid: null,
  };
  slice.grants.push(record);
  draft.emit("access.issued", "code", {
    grantId: record.grantId,
    target: record.target,
    controller: record.controller,
    scope: ENTRY_SCOPE,
    level: record.level,
    verificationGrantId: verification.grantId,
    expiresAt: record.expiresAt,
  });
  return structuredClone(record);
}

/** The access controller by name: own properties only, and only an object with an unlock function. */
function controllerOf(rt: EngineRuntime, name: string): AccessController | null {
  const all = rt.adapter("access");
  const found = Object.hasOwn(all, name) ? all[name] : undefined;
  return typeof found?.unlock === "function" ? found : null;
}

/** Settles a grant that was never sent as failed, unless something settled it first. */
async function failUnsent(rt: EngineRuntime, callId: string, grantId: string, detail: { [key: string]: JsonValue }): Promise<void> {
  await rt.update(callId, (draft) => {
    const g = find(draft, grantId);
    if (g.status !== "reserved") return;
    g.status = "failed";
    draft.emit("access.failed", "code", { grantId, ...detail });
  });
}

function find(draft: CallDraft, grantId: string): AccessRecord {
  return gateSlice(draft).grants.find((g) => g.grantId === grantId)!;
}

/**
 * A controller's answer, read once and checked: a delivery with its provider ref and a boolean
 * `confirmed`, or a refusal with a string reason. Anything else (nothing, an outcome it does not
 * name, a field of the wrong type) does not establish what the door did: "malformed", recorded as
 * unknown, never as a refusal.
 */
function readAnswer(raw: unknown): UnlockResult | "malformed" {
  if (!isObject(raw)) return "malformed";
  const { outcome, providerRef, confirmed, reason } = raw;
  if (outcome === "delivered" && typeof providerRef === "string" && typeof confirmed === "boolean") return { outcome, providerRef, confirmed };
  if (outcome === "refused" && typeof reason === "string") return { outcome, reason };
  return "malformed";
}

/** A controller's refusal reason as a short code for the ledger; anything else becomes "refused". */
function reasonCode(reason: string): string {
  return /^[a-z][a-z0-9_]{0,31}$/.test(reason) ? reason : "refused";
}
