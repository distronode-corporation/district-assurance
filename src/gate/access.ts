// Access grants: what Gate hands a door controller after a call is verified. A grant is a short
// JSON body signed with ES256 over its canonical JSON (the code receipts use), so the access side
// checks it with the public key only and cannot mint one. The controller adapter (AccessController)
// delivers it; a relay on the site network verifies it with `verifyAccessGrant`, refuses a grant id
// it has seen (`SeenGrants`), and only then works the door.
import type { JsonWebKey } from "node:crypto";

import { canonicalPayload, verifyDocument } from "../prove/receipt.ts";
import { sha256Hex } from "../core/hash.ts";

export type { AccessGrantBody, SignedAccessGrant } from "../core/adapters.ts";
import type { AccessGrantBody, SignedAccessGrant } from "../core/adapters.ts";

/** SHA-256 hex of a grant's signed bytes: what the ledger keeps instead of the grant. */
export function accessGrantDigest(body: AccessGrantBody): string {
  return sha256Hex(canonicalPayload(body));
}

export type { AccessController, UnlockResult } from "../core/adapters.ts";

export type AccessGrantCheck =
  | { ok: true; body: AccessGrantBody }
  | { ok: false; reason: "invalid_options" | "malformed" | "signature" | "workspace" | "audience" | "not_yet_valid" | "expired" | "lifetime" };

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
 * that it was issued by `workspaceId` (required: workspaces that share a signing key and a
 * controller name must never open each other's doors), that it is addressed to `audience`, that it
 * lives no longer than 15 minutes, and that `now` is inside its validity. The clock skew
 * (`clockSkewSeconds`, default 30) applies to the start only: a grant issued a little ahead of this
 * clock is accepted. The expiry is strict, never extended, because the engine ends a call only once
 * every grant at a door has answered or expired: a relay must refuse it from that moment on. Never
 * throws. Replay is the caller's to refuse, with `SeenGrants`.
 */
export function verifyAccessGrant(
  grant: unknown,
  keys: ReadonlyArray<JsonWebKey & { kid?: string }>,
  expect: { workspaceId: string; audience: string; now: Date; clockSkewSeconds?: number },
): AccessGrantCheck {
  if (typeof grant !== "object" || grant === null) return { ok: false, reason: "malformed" };
  const g = grant as Record<string, unknown>;
  if (typeof g.kid !== "string" || typeof g.signature !== "string" || !isAccessGrantBody(g.body)) return { ok: false, reason: "malformed" };
  if (!verifyDocument(grant as SignedAccessGrant, keys)) return { ok: false, reason: "signature" };
  const body = g.body;
  if (typeof expect.workspaceId !== "string" || expect.workspaceId === "" || body.workspaceId !== expect.workspaceId) return { ok: false, reason: "workspace" };
  if (body.audience !== expect.audience) return { ok: false, reason: "audience" };
  const seconds: unknown = expect.clockSkewSeconds === undefined ? 30 : expect.clockSkewSeconds;
  // A skew that is not a finite, non-negative number would turn the not-before check off (NaN) or
  // accept anything (Infinity): refused, so the check fails closed.
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return { ok: false, reason: "invalid_options" };
  const skew = seconds * 1000;
  // An unusable clock reading would make both time checks false and let an expired grant through.
  const now = expect.now instanceof Date ? expect.now.getTime() : Number.NaN;
  if (!Number.isFinite(now)) return { ok: false, reason: "invalid_options" };
  const issued = Date.parse(body.issuedAt);
  const expires = Date.parse(body.expiresAt);
  if (expires - issued > MAX_ACCESS_GRANT_SECONDS * 1000 || expires < issued) return { ok: false, reason: "lifetime" };
  if (issued - skew > now) return { ok: false, reason: "not_yet_valid" };
  if (expires <= now) return { ok: false, reason: "expired" };
  return { ok: true, body };
}

/**
 * The grant ids a relay has accepted, each kept until its grant expires (the verifier refuses it
 * from then on), so a replayed grant is refused. In memory only: a relay that restarts must keep
 * the ids on disk, or refuse every grant for the longest a grant can be accepted, 15 minutes plus
 * the verifier's clock skew, after it starts.
 */
export class SeenGrants {
  readonly #until = new Map<string, number>();
  /**
   * The point up to which ids were forgotten: every forgotten id expired at or before it, and any
   * grant expiring at or before it is refused, so a clock that moves back never revives one.
   */
  #forgotUpTo = Number.NEGATIVE_INFINITY;
  /** The latest expiry of any grant accepted: the forget point never passes it. */
  #latestExpiry = Number.NEGATIVE_INFINITY;

  /** True the first time a grant id is offered while it is valid; false for a replay. */
  accept(body: AccessGrantBody, now: Date): boolean {
    // Forgetting goes no further than the latest expiry accepted, so a clock that jumped forward
    // cannot move the forget point past the grants a relay has really seen (which would refuse
    // every fresh grant until real time caught up): at most one grant lifetime ahead of them.
    const point = Math.min(now.getTime(), this.#latestExpiry);
    if (point > this.#forgotUpTo) {
      for (const [id, until] of this.#until) if (until <= point) this.#until.delete(id);
      this.#forgotUpTo = point;
    }
    // A grant that expired by the time ids were last forgotten may have been accepted and then
    // forgotten: refused, even if the clock has since moved back to inside its validity.
    if (Date.parse(body.expiresAt) <= this.#forgotUpTo) return false;
    if (this.#until.has(body.grantId)) return false;
    this.#until.set(body.grantId, Date.parse(body.expiresAt));
    this.#latestExpiry = Math.max(this.#latestExpiry, Date.parse(body.expiresAt));
    return true;
  }
}
