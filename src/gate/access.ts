// Access grants: what Gate hands a door controller after a call is verified. A grant is a short
// JSON body signed with ES256 over its canonical JSON (the code receipts use), so the access side
// checks it with the public key only and cannot mint one. The controller adapter (AccessController)
// delivers it; a relay on the site network verifies it with `verifyAccessGrant`, refuses a grant id
// it has seen (`SeenGrants`), and only then works the door.
import type { JsonWebKey } from "node:crypto";

import { canonicalPayload, verifyDocument, type SignedDocument } from "../prove/receipt.ts";
import { sha256Hex } from "../core/hash.ts";
import type { AssuranceLevel } from "../core/policy.ts";

export interface AccessGrantBody {
  v: 1;
  kind: "access";
  /** Unique per grant. A relay refuses an id it has seen until the grant expires. */
  grantId: string;
  /** The workspace that issued it. */
  workspaceId: string;
  /** The controller it is for: its name in `gateModule({ controllers })`. A relay checks it is its own. */
  audience: string;
  /** The door, lock or access point, as the controller names it. Set in config, never by the model. */
  target: string;
  action: "unlock";
  /** The scope the call's verification grant covered. */
  scope: string;
  /** The level the caller was verified to. */
  level: AssuranceLevel;
  /** ISO 8601. */
  issuedAt: string;
  /** ISO 8601. Never later than the call's verification grant. */
  expiresAt: string;
}

export type SignedAccessGrant = SignedDocument<AccessGrantBody>;

/** SHA-256 hex of a grant's signed bytes: what the ledger keeps instead of the grant. */
export function accessGrantDigest(body: AccessGrantBody): string {
  return sha256Hex(canonicalPayload(body));
}

/** What a controller answered. A lost answer is a thrown error, never a value. */
export type UnlockResult =
  /** The controller took the request. `confirmed` only when it reports that the door actually moved. */
  | { outcome: "delivered"; providerRef: string; confirmed: boolean }
  /** The controller certainly did not act (it refused the grant, the door is offline). */
  | { outcome: "refused"; reason: string };

/**
 * A door controller, lock or access system, reached by the host's adapter. Gate calls `unlock`
 * once per grant and never retries: if the call throws or times out, the outcome is recorded as
 * "unknown", and opening again needs a fresh request (a new grant). An adapter therefore must not
 * retry on its own either.
 */
export interface AccessController {
  unlock(input: { grant: SignedAccessGrant; target: string; idempotencyKey: string }): Promise<UnlockResult>;
}

export type AccessGrantCheck =
  | { ok: true; body: AccessGrantBody }
  | { ok: false; reason: "malformed" | "signature" | "audience" | "not_yet_valid" | "expired" | "lifetime" };

/** The longest an access grant may live, in seconds: 15 minutes. */
export const MAX_ACCESS_GRANT_SECONDS = 900;

const LEVELS: readonly unknown[] = [0, 1, 2, 3];

function isAccessGrantBody(value: unknown): value is AccessGrantBody {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const b = value as Record<string, unknown>;
  const strings = ["grantId", "workspaceId", "audience", "target", "scope", "issuedAt", "expiresAt"];
  return (
    b.v === 1 &&
    b.kind === "access" &&
    b.action === "unlock" &&
    LEVELS.includes(b.level) &&
    strings.every((k) => typeof b[k] === "string" && b[k] !== "") &&
    Number.isFinite(Date.parse(b.issuedAt as string)) &&
    Number.isFinite(Date.parse(b.expiresAt as string))
  );
}

/**
 * Checks an access grant for one controller: its shape, the ES256 signature against the key set,
 * that it is addressed to `audience`, that `now` is inside its validity (with `clockSkewSeconds`,
 * default 30, either way) and that it lives no longer than 15 minutes. Never throws. Replay is the
 * caller's to refuse, with `SeenGrants`.
 */
export function verifyAccessGrant(
  grant: unknown,
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>,
  expect: { audience: string; now: Date; clockSkewSeconds?: number },
): AccessGrantCheck {
  if (typeof grant !== "object" || grant === null) return { ok: false, reason: "malformed" };
  const g = grant as Record<string, unknown>;
  if (typeof g.kid !== "string" || typeof g.signature !== "string" || !isAccessGrantBody(g.body)) return { ok: false, reason: "malformed" };
  if (!verifyDocument(grant as SignedAccessGrant, keys)) return { ok: false, reason: "signature" };
  const body = g.body;
  if (body.audience !== expect.audience) return { ok: false, reason: "audience" };
  const skew = (expect.clockSkewSeconds ?? 30) * 1000;
  const now = expect.now.getTime();
  const issued = Date.parse(body.issuedAt);
  const expires = Date.parse(body.expiresAt);
  if (expires - issued > MAX_ACCESS_GRANT_SECONDS * 1000 || expires < issued) return { ok: false, reason: "lifetime" };
  if (issued - skew > now) return { ok: false, reason: "not_yet_valid" };
  if (expires + skew <= now) return { ok: false, reason: "expired" };
  return { ok: true, body };
}

/**
 * The grant ids a relay has accepted, each kept until the verifier would refuse its grant as
 * expired (expiry plus the clock skew), so a replayed grant is refused. In memory: a relay that restarts must keep refusing for 15 minutes (or keep them on disk).
 */
export class SeenGrants {
  readonly #until = new Map<string, number>();
  readonly #skewMs: number;

  /** `clockSkewSeconds` must be at least the verifier's (default 30, the verifier's default too). */
  constructor(options: { clockSkewSeconds?: number } = {}) {
    this.#skewMs = (options.clockSkewSeconds ?? 30) * 1000;
  }

  /** True the first time a grant id is offered while it is valid; false for a replay. */
  accept(body: AccessGrantBody, now: Date): boolean {
    const at = now.getTime();
    for (const [id, until] of this.#until) if (until <= at) this.#until.delete(id);
    if (this.#until.has(body.grantId)) return false;
    // Kept until the verifier refuses the grant as expired: its expiry plus the same skew.
    this.#until.set(body.grantId, Date.parse(body.expiresAt) + this.#skewMs);
    return true;
  }
}
