// Web sign-in step-up (GAT-4): digital entry. A person signing in on the host's site is shown a
// nonce, calls, is verified, and keys the nonce; the call then gets a step-up token, a compact JWS
// (ES256, a JWT) bound to that nonce, the verified subject and the call's verification grant. The
// host's web sign-in exchanges it once, through the engine, and raises the session's
// authentication level (an OpenID Connect `acr`). See SPEC.md, section 18, and ADR-24.
//
// Step-up is a built-in module, like Gate (ADR-25): its runtime runs inside the engine, on the
// engine's own writes, and no module code can reach its part of a call (`updateModule` refuses
// built-in modules). Its signer (`stepUpSigner`) is an engine adapter, its own key. So the engine
// itself reserves each token, signs it, checks the call once more and makes it valid, and records
// its one exchange: nothing else can write a token's outcome. The engine holds the step to
// `entry.sign_in`, an access scope whose floor is level 2, and a tainted call refuses an exchange.
import { canonicalJson, type JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { hexDigestsEqual, sha256Hex } from "../core/hash.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, ModuleManifest, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { AssuranceLevel } from "../core/policy.ts";
import { isDenseArray, isIntegerIn, isObject, unknownKeys } from "../core/shape.ts";
import type { CallDraft, CallRecord, EngineRuntime } from "../core/runtime.ts";
import { BADGE, type BadgeSlice } from "../verify/badge.ts";

export const STEP_UP = "step-up";

/** The scope a `step-up.issue` step needs. An access scope: never below level 2. */
export const SIGN_IN_SCOPE = "entry.sign_in";

/** A token lives 2 to 5 minutes, 2 by default, and never past the verification grant. */
export const MIN_STEP_UP_SECONDS = 120;
export const MAX_STEP_UP_SECONDS = 300;
export const DEFAULT_STEP_UP_SECONDS = 120;
export const DEFAULT_TOKENS_PER_CALL = 3;
export const MAX_TOKENS_PER_CALL = 5;

const SITE_ID = /^[a-z][a-z0-9-]{0,63}$/;
/** The nonce the site showed, as the caller keys it. */
const NONCE = /^[0-9]{6,12}$/;
const ISSUER = /^https:\/\/[^\s?#@]+$/;

/** A site that may ask for a step-up: Gate's id for it, and the `aud` its tokens carry (its client id or origin). */
export interface StepUpSite {
  id: string;
  audience: string;
}

export interface StepUpSettings {
  /** The tokens' `iss`: the https URL whose `/.well-known/jwks.json` serves `engine.stepUpKeys()`. */
  issuer: string;
  sites: StepUpSite[];
  /** Tokens a call may get, exchanged or not. 1 to 5, default 3. */
  maxTokensPerCall?: number;
}

export interface StepUpIssueStep extends FlowStep {
  type: "step-up.issue";
  site: string;
  /** How long the token lives, 120 to 300 seconds. Default 120. Never past the verification grant. */
  lifetimeSeconds?: number;
}

/** `reserved` while signing; `issued` once valid; then `exchanged` or `refused`, once. `failed`: never valid. */
export type StepUpStatus = "reserved" | "issued" | "exchanged" | "refused" | "failed";

/** One step-up token on a call, as the engine keeps it. Never the token, never the nonce. */
export interface StepUpRecord {
  /** The token's `jti`. */
  tokenId: string;
  site: string;
  audience: string;
  /** The token's `sub`: `stepUpSubject(subjectKey, audience)`. */
  subject: string;
  level: AssuranceLevel;
  verificationGrantId: string;
  /** When the verification grant was issued: the token's `auth_time`. */
  authTime: string;
  issuedAt: string;
  expiresAt: string;
  status: StepUpStatus;
  /** SHA-256 of the compact token and the key id, written once it is signed. */
  digest: string | null;
  kid: string | null;
}

export interface StepUpSlice {
  /** The issuer and the sites in force when the call started: a config change never moves a call. */
  issuer: string;
  sites: StepUpSite[];
  maxTokensPerCall: number;
  tokens: StepUpRecord[];
}

/** The JWT claims of a step-up token. Times are seconds since the epoch. */
export interface StepUpClaims {
  iss: string;
  /** The site's audience. */
  aud: string;
  /** An opaque handle for the verified subject, per site: `stepUpSubject(subjectKey, aud)`. */
  sub: string;
  iat: number;
  exp: number;
  /** When the call's verification grant was issued. */
  auth_time: number;
  jti: string;
  /** The level the caller was verified to: `stepUpAcr(level)`. */
  acr: string;
  /** The site's nonce, as the caller keyed it. */
  nonce: string;
  /** The call. */
  sid: string;
  /** The call's verification grant the token is bound to. */
  grant: string;
}

export interface StepUpToken {
  /** The compact JWS: `header.payload.signature`, base64url. Hand it to the web sign-in, nowhere else. */
  token: string;
  tokenId: string;
  expiresAt: string;
}

export type StepUpExchange =
  | { ok: true; claims: StepUpClaims }
  /**
   * `malformed`: not a step-up token. `unknown`: not one this engine has waiting (never issued,
   * already exchanged or refused, another workspace's). The rest are refusals, and each uses the token up:
   * `tainted`, `not_authorized` (the call's grant changed), `expired`, `mismatch` (another site,
   * subject or nonce).
   */
  | { ok: false; reason: "malformed" | "unknown" | "tainted" | "not_authorized" | "expired" | "mismatch" };

/** The `acr` value for a level. */
export function stepUpAcr(level: AssuranceLevel): string {
  return `urn:district-assurance:level:${level}`;
}

/** The `sub` of a site's tokens for a subject: a handle per site, so two sites cannot link a person. */
export function stepUpSubject(subjectKey: string, audience: string): string {
  return sha256Hex(canonicalJson(["step-up", audience, subjectKey]));
}

export const stepUpModule: AssuranceModule = {
  manifest: {
    name: STEP_UP,
    version: "2",
    summary: "Turn a verified call into a short-lived token a web sign-in exchanges once to step up.",
    provides: { factors: [], steps: ["step-up.issue"], outcomes: ["step_up_token"] },
    scopes: { grants: [], needs: { "step-up.issue": SIGN_IN_SCOPE }, classes: { [SIGN_IN_SCOPE]: "access" } },
    adapters: ["stepUpSigner"],
  } satisfies ModuleManifest,

  validateSettings(settings: unknown): string[] {
    if (!isObject(settings)) return ["must be an object with the issuer and the sites"];
    const errors = unknownKeys(settings, ["issuer", "sites", "maxTokensPerCall"]).map((k) => `${k} is not a step-up setting`);
    if (typeof settings.issuer !== "string" || !ISSUER.test(settings.issuer)) errors.push("issuer must be an https URL without a query, a fragment or credentials");
    if (settings.maxTokensPerCall !== undefined && !isIntegerIn(settings.maxTokensPerCall, 1, MAX_TOKENS_PER_CALL)) {
      errors.push(`maxTokensPerCall must be an integer from 1 to ${MAX_TOKENS_PER_CALL}`);
    }
    const sites = settings.sites;
    if (!isDenseArray(sites) || sites.length === 0) return [...errors, "sites must list at least one site"];
    const ids: unknown[] = [];
    sites.forEach((site: unknown, i: number) => {
      const at = `sites[${i}]`;
      if (!isObject(site)) {
        errors.push(`${at} must be { id, audience }`);
        return;
      }
      ids.push(site.id);
      errors.push(...unknownKeys(site, ["id", "audience"]).map((k) => `${at}.${k} is not a site field`));
      if (typeof site.id !== "string" || !SITE_ID.test(site.id)) errors.push(`${at}.id must be lower-case letters, digits and hyphens, at most 64`);
      if (typeof site.audience !== "string" || !/^\S{1,200}$/.test(site.audience)) errors.push(`${at}.audience must be 1 to 200 characters, no spaces`);
    });
    if (new Set(ids).size !== ids.length) errors.push("two sites have the same id");
    return errors;
  },

  requiredAdapters(): string[] {
    return ["stepUpSigner"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "site", "lifetimeSeconds"]).map((k) => `${k} is not a field of this step`);
    if (step.lifetimeSeconds !== undefined && !isIntegerIn(step.lifetimeSeconds, MIN_STEP_UP_SECONDS, MAX_STEP_UP_SECONDS)) {
      errors.push(`lifetimeSeconds must be an integer from ${MIN_STEP_UP_SECONDS} to ${MAX_STEP_UP_SECONDS}`);
    }
    if (typeof step.site !== "string") return [...errors, "site must name a site in the step-up settings"];
    const settings = ctx.settings as StepUpSettings | null;
    if (settings !== null && !settings.sites.some((s) => s.id === step.site)) errors.push(`no site ${step.site} in the step-up settings`);
    return errors;
  },

  initCall(settings: unknown): JsonValue {
    const s = settings as StepUpSettings;
    const slice: StepUpSlice = { issuer: s.issuer, sites: structuredClone(s.sites), maxTokensPerCall: s.maxTokensPerCall ?? DEFAULT_TOKENS_PER_CALL, tokens: [] };
    return slice as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as StepUpSlice).tokens.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue): string | null {
    return (s as unknown as StepUpSlice).sites.some((site) => site.id === step.site) ? null : `the call has no site ${String(step.site)}`;
  },

  stepStatus(_step: FlowStep, view: StepView): StepStatus {
    const slice = view.slice as unknown as StepUpSlice;
    const mine = slice.tokens.slice(view.mark as number);
    // The step's work is done once a token is valid: what the site does with it comes later.
    if (mine.some((t) => t.status !== "reserved" && t.status !== "failed")) return "complete";
    const inFlight = mine.some((t) => t.status === "reserved");
    return !inFlight && slice.tokens.length >= slice.maxTokensPerCall ? "failed" : "pending";
  },
};

// ---- runtime -------------------------------------------------------------------------------

/**
 * The subject key the call's verification grant was issued for, or null: no grant, or a
 * verification is running (it may be for another subject). Only Badge issues grants, so a call with
 * a grant has Badge's part.
 */
function grantSubject(record: CallRecord): string | null {
  if (record.state.grant === null || record.state.phase === "verifying") return null;
  return (record.modules[BADGE] as unknown as BadgeSlice).subjectKey;
}

/**
 * Settles, inside the write that ends a call, a token still being signed: it is failed, so it is
 * never handed out after the call ended. A token already issued stays exchangeable until it
 * expires (the web sign-in may finish just after the caller hangs up).
 */
export function settleStepUpInFlight(draft: CallDraft): void {
  const slice = draft.record.modules[STEP_UP] as unknown as StepUpSlice | undefined;
  for (const t of slice?.tokens ?? []) {
    if (t.status !== "reserved") continue;
    t.status = "failed";
    draft.emit("stepup.failed", "system", { tokenId: t.tokenId, reason: "call_ended" });
  }
}

/**
 * Issues a step-up token for the nonce the caller keyed. In a flow the step names the site and
 * the lifetime (pass only the nonce); outside one the host's code passes them too. The token is
 * returned to the host's code, which hands it to the waiting web sign-in; it is never texted,
 * spoken or logged.
 */
export async function issueStepUpToken(rt: EngineRuntime, callId: string, input: { nonce: string; site?: string; lifetimeSeconds?: number }): Promise<StepUpToken> {
  rt.settings(STEP_UP);
  // A token left reserved past its expiry (the process signing it stopped before its last write)
  // is failed in a write of its own, so it never blocks the call's next request. One still within
  // its life is a live signing, and keeps blocking.
  const before = (await rt.read(callId)).modules[STEP_UP] as unknown as StepUpSlice | undefined;
  const stale = (t: StepUpRecord) => t.status === "reserved" && Date.parse(t.expiresAt) <= Date.parse(rt.now());
  if (before?.tokens.some(stale) === true) {
    await rt.update(callId, (draft) => {
      for (const t of draft.slice<StepUpSlice>(STEP_UP).tokens.filter(stale)) {
        t.status = "failed";
        draft.emit("stepup.failed", "system", { tokenId: t.tokenId, reason: "not_issued_in_time" });
      }
    });
  }
  const { record, issuer } = await rt.update(callId, (draft) => reserve(rt, draft, input));
  const claims: StepUpClaims = {
    iss: issuer,
    aud: record.audience,
    sub: record.subject,
    iat: seconds(record.issuedAt),
    exp: seconds(record.expiresAt),
    auth_time: seconds(record.authTime),
    jti: record.tokenId,
    acr: stepUpAcr(record.level),
    nonce: input.nonce,
    sid: callId,
    grant: record.verificationGrantId,
  };
  const signer = rt.adapter("stepUpSigner");
  let token: string;
  try {
    const signingInput = `${base64url({ alg: "ES256", typ: "JWT", kid: signer.keyId })}.${base64url(claims)}`;
    const signature = await signer.sign(new TextEncoder().encode(signingInput));
    token = `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
  } catch (error) {
    // Nothing was handed out: the token failed, and a new request may follow.
    await rt.update(callId, (draft) => {
      const t = find(draft, record.tokenId);
      if (t.status !== "reserved") return;
      t.status = "failed";
      draft.emit("stepup.failed", "code", { tokenId: t.tokenId, reason: "signing" });
    });
    throw error;
  }
  const digest = sha256Hex(token);
  const kid = signer.keyId;
  // Signing can take a while (a KMS): the call may have been tainted, verified again or ended, or
  // the token expired, since the reservation. Checked once more, in a write, before the token
  // becomes valid; it is never handed out if not.
  const lapsed = await rt.update(callId, (draft): string | null => {
    const t = find(draft, record.tokenId);
    // Settled meanwhile (the call ended): never valid.
    if (t.status !== "reserved") return "not_authorized";
    const why =
      !rt.authorized(draft.record, SIGN_IN_SCOPE) || grantSubject(draft.record) !== record.subjectKey || draft.record.state.grant?.grantId !== record.verificationGrantId
        ? "not_authorized"
        : Date.parse(t.expiresAt) <= Date.parse(rt.now())
          ? "expired"
          : null;
    if (why !== null) {
      t.status = "failed";
      draft.emit("stepup.failed", "code", { tokenId: t.tokenId, digest, kid, reason: why });
      return why;
    }
    Object.assign(t, { status: "issued", digest, kid });
    return null;
  });
  if (lapsed !== null) throw new EngineError("scope_denied", `the step-up token was not issued: ${lapsed === "expired" ? "it expired" : "the call is no longer authorized"}`);
  return { token, tokenId: record.tokenId, expiresAt: record.expiresAt };
}

/**
 * The host's web sign-in exchanges a token, once: it must have been issued by this engine for
 * this `audience`, this subject (`subjectKey`, the person signing in) and the `nonce` the site
 * showed, still be live, and its call must not be tainted nor verified again since. Any of those
 * refusals uses the token up. Runs after the call ended too. Never throws for a bad token; a write
 * that fails is thrown as it is.
 */
export async function exchangeStepUpToken(rt: EngineRuntime, token: unknown, expect: { audience: string; subjectKey: string; nonce: string }): Promise<StepUpExchange> {
  const claims = readClaims(token);
  if (claims === null) return { ok: false, reason: "malformed" };
  const digest = sha256Hex(token as string);
  try {
    return await rt.update(claims.sid, (draft): StepUpExchange => {
      const slice = draft.record.modules[STEP_UP] as unknown as StepUpSlice | undefined;
      const record = slice?.tokens.find((t) => t.tokenId === claims.jti);
      // Only the exact bytes this call issued, still waiting: anything else is refused without using the token up.
      if (record === undefined || record.status !== "issued" || !hexDigestsEqual(record.digest!, digest)) return { ok: false, reason: "unknown" };
      const state = draft.record.state;
      const reason = state.tainted
        ? "tainted"
        : // A new verification running (maybe for another account), or a grant that changed: no longer the token's.
          state.phase === "verifying" || (state.phase !== "ended" && state.grant?.grantId !== record.verificationGrantId)
          ? "not_authorized"
          : Date.parse(record.expiresAt) <= Date.parse(rt.now())
            ? "expired"
            : expect.audience !== record.audience ||
                !hexDigestsEqual(stepUpSubject(String(expect.subjectKey), record.audience), record.subject) ||
                !hexDigestsEqual(sha256Hex(String(expect.nonce)), sha256Hex(claims.nonce))
              ? "mismatch"
              : null;
      if (reason === null) {
        record.status = "exchanged";
        draft.emit("stepup.exchanged", "code", { tokenId: record.tokenId, digest, kid: record.kid! });
        return { ok: true, claims: claims as unknown as StepUpClaims };
      }
      record.status = "refused";
      draft.emit("stepup.refused", "code", { tokenId: record.tokenId, digest, reason });
      return { ok: false, reason };
    });
  } catch (error) {
    // Another workspace's call, or none: not a token this engine has waiting.
    if (error instanceof EngineError && error.code === "unknown_call") return { ok: false, reason: "unknown" };
    throw error;
  }
}

/** The one write that reserves a token: checked against the call, the step and the limits. */
function reserve(rt: EngineRuntime, draft: CallDraft, input: { nonce: string; site?: string; lifetimeSeconds?: number }): { record: StepUpRecord & { subjectKey: string }; issuer: string } {
  const step = stepOfType<StepUpIssueStep>(draft.record, "step-up.issue");
  if (!rt.authorized(draft.record, SIGN_IN_SCOPE)) throw new EngineError("scope_denied", `the grant does not cover ${SIGN_IN_SCOPE}`);
  // A grant covering an access scope is level 2 or more; while a new verification runs, its subject is not yet the grant's.
  const subjectKey = grantSubject(draft.record);
  if (subjectKey === null) throw new EngineError("precondition_failed", "a verification is running; finish it first");
  if (!isObject(input) || typeof input.nonce !== "string" || !NONCE.test(input.nonce)) throw new EngineError("invalid_input", "the nonce must be 6 to 12 digits");
  if (step !== null && (input.site !== undefined || input.lifetimeSeconds !== undefined)) throw new EngineError("invalid_input", "the flow step names the site; pass only the nonce");
  const wanted = step ?? input;
  if (wanted.site === undefined) throw new EngineError("invalid_input", "outside a flow, the site is required");
  const slice = draft.slice<StepUpSlice>(STEP_UP);
  const site = slice.sites.find((s) => s.id === wanted.site);
  if (site === undefined) throw new EngineError("invalid_input", `no site ${String(wanted.site)} on this call`);
  const lifetime = wanted.lifetimeSeconds ?? DEFAULT_STEP_UP_SECONDS;
  if (!isIntegerIn(lifetime, MIN_STEP_UP_SECONDS, MAX_STEP_UP_SECONDS)) {
    throw new EngineError("invalid_input", `lifetimeSeconds must be an integer from ${MIN_STEP_UP_SECONDS} to ${MAX_STEP_UP_SECONDS}`);
  }
  if (slice.tokens.some((t) => t.status === "reserved")) throw new EngineError("precondition_failed", "a step-up token is being issued on this call");
  if (slice.tokens.length >= slice.maxTokensPerCall) throw new EngineError("precondition_failed", "this call has used every step-up token it may have");
  const verification = draft.record.state.grant!;
  // Whole seconds, as the token carries them, so the record and the claims never disagree.
  const now = Math.floor(Date.parse(rt.now()) / 1000) * 1000;
  const record: StepUpRecord = {
    tokenId: rt.ids.next("stu"),
    site: site.id,
    audience: site.audience,
    subject: stepUpSubject(subjectKey, site.audience),
    level: verification.level,
    verificationGrantId: verification.grantId,
    authTime: verification.issuedAt,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(Math.floor(Math.min(now + lifetime * 1000, Date.parse(verification.expiresAt)) / 1000) * 1000).toISOString(),
    status: "reserved",
    digest: null,
    kid: null,
  };
  slice.tokens.push(record);
  draft.emit("stepup.issued", "code", {
    tokenId: record.tokenId,
    site: site.id,
    scope: SIGN_IN_SCOPE,
    level: record.level,
    verificationGrantId: verification.grantId,
    expiresAt: record.expiresAt,
  });
  return { record: { ...structuredClone(record), subjectKey }, issuer: slice.issuer };
}

function find(draft: CallDraft, tokenId: string): StepUpRecord {
  return draft.slice<StepUpSlice>(STEP_UP).tokens.find((t) => t.tokenId === tokenId)!;
}

/** The claims a compact token carries, read without trusting them: only to find its call and its id. */
function readClaims(token: unknown): Pick<StepUpClaims, "sid" | "jti" | "nonce"> | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!isObject(claims) || typeof claims.sid !== "string" || typeof claims.jti !== "string" || typeof claims.nonce !== "string") return null;
  return claims as unknown as Pick<StepUpClaims, "sid" | "jti" | "nonce">;
}

function base64url(value: unknown): string {
  return Buffer.from(canonicalJson(value)).toString("base64url");
}

function seconds(iso: string): number {
  return Math.floor(Date.parse(iso) / 1000);
}
