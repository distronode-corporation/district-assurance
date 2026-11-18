// Gate (entry): the outcome after verification. A verified call gets a signed, time-limited access
// grant (ES256 over canonical JSON, `access.ts`), delivered to a door controller through an
// `AccessController` adapter. It refuses without a valid verification grant covering `entry.open`,
// an access scope whose floor is level 2, and every grant and its outcome go to the ledger.
//
// Gate ships in this package but is installed like an outside module (`engine.use(gate)`) and
// runs through `Engine.updateModule`, so the engine itself holds its step to `entry.open`: Gate
// asks too, and a mistake in either still fails closed. The controller's answer is recorded with
// `Engine.recordModuleOutcome`, which still writes if the grant expired while the door answered.
//
// An unlock is never retried. It is reserved in one write (one in flight per call), signed, sent
// once, and its answer committed. A lost answer is recorded as "unknown", and opening again needs
// a fresh request: a new grant, within the per-call limit.
import type { JsonWebKey } from "node:crypto";

import type { ReceiptSigner } from "../core/adapters.ts";
import type { JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import type { AssuranceModule, FlowStep, ModuleManifest, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { AssuranceLevel } from "../core/policy.ts";
import { isDenseArray, isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import type { Engine, ModuleCallView } from "../engine.ts";
import { signDocument } from "../prove/receipt.ts";
import { accessGrantDigest, MAX_ACCESS_GRANT_SECONDS, type AccessController, type AccessGrantBody, type SignedAccessGrant, type UnlockResult } from "./access.ts";

export const GATE = "gate";

/** The scope a `gate.grant` step needs. An access scope: never below level 2. */
export const ENTRY_SCOPE = "entry.open";

export const DEFAULT_ACCESS_SECONDS = 60;
export const MIN_ACCESS_SECONDS = 10;
export const DEFAULT_GRANTS_PER_CALL = 3;
export const MAX_GRANTS_PER_CALL = 5;

const TARGET_ID = /^[a-z][a-z0-9-]{0,63}$/;
const CONTROLLER_NAME = /^[a-z][a-z0-9-]{0,63}$/;

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

/** One access grant on a call, as Gate keeps it. Never the signature itself. */
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
  /** The grant's digest and key id, written just before it is sent. */
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
  /** `delivered`: the controller took it. `refused`: it certainly did not act. `unknown`: the answer was lost; do not assume either. */
  status: "delivered" | "refused" | "unknown";
  /** The controller reported that the door moved. */
  confirmed: boolean;
}

export interface GateOptions {
  /** Signs access grants. Use its own key (its own `kid`), not the receipt key. */
  signer: ReceiptSigner;
  /** Controller name to adapter. Targets in the settings name one of these. */
  controllers: Readonly<Record<string, AccessController>>;
}

/** What Gate needs of an engine. */
export type GateHost = Pick<Engine, "updateModule" | "recordModuleOutcome" | "moduleState" | "workspaceId">;

/** Gate: install with `engine.use(gate)` (or `modules: [gate]`), then turn it on in the config. */
export function gateModule(options: GateOptions): GateModule {
  return new GateModule(options);
}

export class GateModule implements AssuranceModule {
  readonly manifest: ModuleManifest = {
    name: GATE,
    version: "1",
    summary: "Turn a verified call into a signed, time-limited access grant for a door controller.",
    provides: { factors: [], steps: ["gate.grant"], outcomes: ["access_grant"] },
    scopes: { grants: [], needs: { "gate.grant": ENTRY_SCOPE }, classes: { [ENTRY_SCOPE]: "access" } },
    adapters: [],
  };
  readonly #signer: ReceiptSigner;
  readonly #controllers: ReadonlyMap<string, AccessController>;

  constructor(options: GateOptions) {
    const names = Object.keys(options.controllers);
    const bad = names.filter((n) => !CONTROLLER_NAME.test(n));
    if (bad.length > 0) throw new EngineError("invalid_input", `controller names are lower-case letters, digits and hyphens: ${bad.join(", ")}`);
    if (names.length === 0) throw new EngineError("invalid_input", "gate needs at least one controller");
    this.#signer = options.signer;
    this.#controllers = new Map(Object.entries(options.controllers));
  }

  /** The public key set access sides verify grants with. */
  keys(): JsonWebKey[] {
    return [this.#signer.publicJwk()];
  }

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
      if (typeof target.controller !== "string" || !this.#controllers.has(target.controller)) {
        errors.push(`${at}.controller must name a controller this gate was given (${[...this.#controllers.keys()].join(", ")})`);
      }
      if (typeof target.ref !== "string" || target.ref.trim() === "" || target.ref.length > 200) errors.push(`${at}.ref must be 1 to 200 characters`);
    });
    if (new Set(ids).size !== ids.length) errors.push("two targets have the same id");
    return errors;
  }

  requiredAdapters(): string[] {
    return [];
  }

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "target", "lifetimeSeconds"]).map((k) => `${k} is not a field of this step`);
    if (step.lifetimeSeconds !== undefined && !isIntegerIn(step.lifetimeSeconds, MIN_ACCESS_SECONDS, MAX_ACCESS_GRANT_SECONDS)) {
      errors.push(`lifetimeSeconds must be an integer from ${MIN_ACCESS_SECONDS} to ${MAX_ACCESS_GRANT_SECONDS}`);
    }
    if (typeof step.target !== "string") return [...errors, "target must name a target in the gate settings"];
    const settings = ctx.settings as GateSettings | null;
    if (settings !== null && !settings.targets.some((t) => t.id === step.target)) errors.push(`no target ${step.target} in the gate settings`);
    return errors;
  }

  initCall(settings: unknown): JsonValue {
    const s = settings as GateSettings;
    const slice: GateSlice = { targets: structuredClone(s.targets), maxGrantsPerCall: s.maxGrantsPerCall ?? DEFAULT_GRANTS_PER_CALL, grants: [] };
    return slice as unknown as JsonValue;
  }

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as GateSlice).grants.length;
  }

  cannotRunStep(step: FlowStep, s: JsonValue): string | null {
    return (s as unknown as GateSlice).targets.some((t) => t.id === step.target) ? null : `the call has no target ${String(step.target)}`;
  }

  stepStatus(_step: FlowStep, view: StepView): StepStatus {
    const slice = view.slice as unknown as GateSlice;
    const mine = slice.grants.slice(view.mark as number);
    if (mine.some((g) => g.status === "delivered")) return "complete";
    // Every grant the call may have is used and none is in flight: the door was never opened by this step.
    const inFlight = mine.some((g) => g.status === "reserved");
    return !inFlight && slice.grants.length >= slice.maxGrantsPerCall ? "failed" : "pending";
  }

  /**
   * Issues an access grant for a target and sends it to its controller, once. In a flow the step
   * names the target and its lifetime (pass no input); outside one the host's code passes them.
   * Returns the outcome; an `unknown` one is never retried here.
   */
  async grantAccess(engine: GateHost, callId: string, input?: { target: string; lifetimeSeconds?: number }): Promise<AccessResult> {
    await settleStale(engine, callId);
    const reserved = (await engine.updateModule(callId, GATE, (s, call) => reserve(s as unknown as GateSlice, call, input) as unknown as JsonValue)) as unknown as GateSlice;
    const record = reserved.grants.at(-1)!;
    const body: AccessGrantBody = {
      v: 1,
      kind: "access",
      grantId: record.grantId,
      workspaceId: engine.workspaceId,
      audience: record.controller,
      target: record.ref,
      action: "unlock",
      scope: ENTRY_SCOPE,
      level: record.level,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
    };
    let grant: SignedAccessGrant;
    try {
      grant = await signDocument(this.#signer, body);
    } catch (error) {
      // Nothing was sent: the grant failed, and a new request may follow.
      await commit(engine, callId, record.grantId, { status: "failed", confirmed: false, providerRef: null }, "access.failed", {});
      throw error;
    }
    const digest = accessGrantDigest(body);
    // Signing can take a while (a KMS): the call may have been tainted, or the grant expired, since
    // the reservation. Checked once more right before the door is asked; nothing is sent if not.
    const lapsed = await this.#stillAuthorized(engine, callId, record.grantId, digest, grant.kid);
    if (lapsed !== null) throw new EngineError("scope_denied", `the access grant was not sent: ${lapsed}`);
    let answer: UnlockResult | null;
    try {
      answer = await this.#controllers.get(record.controller)!.unlock({
        grant,
        target: record.ref,
        idempotencyKey: JSON.stringify([engine.workspaceId, callId, record.grantId, "unlock"]),
      });
    } catch {
      // The answer was lost (a timeout, a dropped connection, a controller error). The door may or
      // may not have moved: record that, and never send this grant again.
      answer = null;
    }
    // Only the controller's call decides the outcome. A failure to write it afterwards is thrown
    // as it is; the reservation then settles as unknown once its grant expires.
    const stored =
      answer === null
        ? await commit(engine, callId, record.grantId, { status: "unknown", confirmed: false, providerRef: null }, "access.unknown", { digest, kid: grant.kid })
        : answer.outcome === "delivered"
          ? await commit(engine, callId, record.grantId, { status: "delivered", confirmed: answer.confirmed, providerRef: answer.providerRef }, "access.delivered", {
              digest,
              confirmed: answer.confirmed,
              kid: grant.kid,
            })
          : await commit(engine, callId, record.grantId, { status: "refused", confirmed: false, providerRef: null }, "access.refused", {
              digest,
              reason: reasonCode(answer.reason),
              kid: grant.kid,
            });
    // What the call holds, which another process may have settled first (as unknown), not only what the door said.
    return { grantId: record.grantId, status: stored.status as AccessResult["status"], confirmed: stored.confirmed };
  }

  /** Settles the reservation as failed and returns why, when the grant may no longer be sent; null when it may. */
  async #stillAuthorized(engine: GateHost, callId: string, grantId: string, digest: string, kid: string): Promise<string | null> {
    // Set by each attempt of the write; the attempt that was saved is the last one to run.
    let lapsed: string | null = null;
    await engine.recordModuleOutcome(callId, GATE, (s, call) => {
      const slice = s as unknown as GateSlice;
      const record = slice.grants.find((g) => g.grantId === grantId)!;
      lapsed =
        record.status !== "reserved"
          ? "it was settled meanwhile"
          : !call.authorized(ENTRY_SCOPE)
            ? "the call is no longer authorized"
            : Date.parse(record.expiresAt) <= Date.parse(call.now)
              ? "it expired"
              : null;
      if (record.status === "reserved") {
        // Written before the send, so a reservation that never gets its answer still names its grant.
        record.digest = digest;
        record.kid = kid;
        if (lapsed !== null) {
          record.status = "failed";
          call.emit("access.failed", { grantId, digest, kid, reason: lapsed === "it expired" ? "expired" : "not_authorized" });
        }
      }
      return slice as unknown as JsonValue;
    });
    return lapsed;
  }
}

/** The one write that reserves a grant: checked against the call, the step and the limits. */
function reserve(slice: GateSlice, call: ModuleCallView, input: { target: string; lifetimeSeconds?: number } | undefined): GateSlice {
  if (!call.authorized(ENTRY_SCOPE)) throw new EngineError("scope_denied", `the grant does not cover ${ENTRY_SCOPE}`);
  const step = call.step as GateGrantStep | null;
  if (step !== null && input !== undefined) throw new EngineError("invalid_input", "the flow step names the target; pass no input");
  const wanted = step ?? input;
  if (wanted === undefined) throw new EngineError("invalid_input", "outside a flow, the target is required");
  const target = slice.targets.find((t) => t.id === wanted.target);
  if (target === undefined) throw new EngineError("invalid_input", `no target ${wanted.target} on this call`);
  const lifetime = wanted.lifetimeSeconds ?? DEFAULT_ACCESS_SECONDS;
  if (!isIntegerIn(lifetime, MIN_ACCESS_SECONDS, MAX_ACCESS_GRANT_SECONDS)) {
    throw new EngineError("invalid_input", `lifetimeSeconds must be an integer from ${MIN_ACCESS_SECONDS} to ${MAX_ACCESS_GRANT_SECONDS}`);
  }
  const now = Date.parse(call.now);
  if (slice.grants.some((g) => g.status === "reserved")) throw new EngineError("precondition_failed", "an access grant is being delivered on this call");
  if (slice.grants.length >= slice.maxGrantsPerCall) throw new EngineError("precondition_failed", "this call has used every access grant it may have");
  // `entry.open` is an access scope, never below level 2, so an authorized call holds a grant.
  const verification = call.state.grant!;
  const record: AccessRecord = {
    grantId: call.newId("acc"),
    target: target.id,
    controller: target.controller,
    ref: target.ref,
    level: verification.level,
    issuedAt: call.now,
    expiresAt: new Date(Math.min(now + lifetime * 1000, Date.parse(verification.expiresAt))).toISOString(),
    status: "reserved",
    confirmed: false,
    providerRef: null,
    digest: null,
    kid: null,
  };
  slice.grants.push(record);
  call.emit("access.issued", {
    grantId: record.grantId,
    target: record.target,
    controller: record.controller,
    scope: ENTRY_SCOPE,
    level: record.level,
    verificationGrantId: verification.grantId,
    expiresAt: record.expiresAt,
  });
  return slice;
}

/**
 * Settles, in its own write, every reservation whose grant expired with no answer recorded (the
 * process stopped while the door answered) as unknown. Its own write, so it holds even when the
 * request that follows is refused: at the grant limit, the step then fails instead of waiting.
 */
async function settleStale(engine: GateHost, callId: string): Promise<void> {
  const before = (await engine.moduleState(callId, GATE)) as unknown as GateSlice;
  if (!before.grants.some((g) => g.status === "reserved")) return;
  await engine.recordModuleOutcome(callId, GATE, (s, call) => {
    const slice = s as unknown as GateSlice;
    const now = Date.parse(call.now);
    for (const g of slice.grants) {
      if (g.status === "reserved" && Date.parse(g.expiresAt) <= now) {
        g.status = "unknown";
        call.emit("access.unknown", {
          grantId: g.grantId,
          ...(g.digest === null ? {} : { digest: g.digest }),
          ...(g.kid === null ? {} : { kid: g.kid }),
          reason: "no_answer_recorded",
        });
      }
    }
    return slice as unknown as JsonValue;
  });
}

async function commit(
  engine: GateHost,
  callId: string,
  grantId: string,
  outcome: Pick<AccessRecord, "status" | "confirmed" | "providerRef">,
  event: string,
  detail: { [key: string]: JsonValue },
): Promise<AccessRecord> {
  const after = (await engine.recordModuleOutcome(callId, GATE, (s, call) => {
    const slice = s as unknown as GateSlice;
    const record = slice.grants.find((g) => g.grantId === grantId)!;
    // Only a reservation takes an outcome: one settled as unknown meanwhile stays unknown.
    if (record.status === "reserved") {
      Object.assign(record, outcome);
      call.emit(event, { grantId, ...detail });
    }
    return slice as unknown as JsonValue;
  })) as unknown as GateSlice;
  return after.grants.find((g) => g.grantId === grantId)!;
}

/** A controller's refusal reason as a short code for the ledger; anything else becomes "refused". */
function reasonCode(reason: string): string {
  return /^[a-z][a-z0-9_]{0,31}$/.test(reason) ? reason : "refused";
}
