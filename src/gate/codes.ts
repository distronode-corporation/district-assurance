// One-time access codes (GAT-3): entry where no controller can be called live. Instead of sending
// the signed access grant to a door, Gate texts a short code to the number on file, and a keypad at
// the door later hands the code to the host, which redeems it here, once, for that same grant.
//
// A code rides on Gate's own grant path: `accessCodes(...).controller` is an `AccessController`,
// named in `gateModule({ controllers })` like any other, and `issue` runs `gate.grantAccess` for
// it. So a code gets everything a grant gets: the reservation, the `entry.open` checks before and
// right before sending, one in flight per call, `maxGrantsPerCall`, the ledger entries with the
// grant's digest, and a lifetime that never passes the verification grant. "Delivered" means the
// code was texted.
//
// The engine keeps only a keyed hash of each code (HMAC under the codes' own key, bound to the
// workspace, the controller and the door) with the grant's body, never the code and never a
// signature: a stolen code store opens nothing. Redeeming takes the entry out in one step (single
// use), refuses it after the grant's expiry, and signs the grant body again for the door's relay,
// which checks it with `verifyAccessGrant` and `SeenGrants` as usual. The code is in the text and
// nowhere else: not in the ledger, an event, an error or the store.
//
// Texts count against send limits shared with texted codes (VER-2), per subject: `TextSendLimits`
// below is a stand-in until VER-2 lands, and the same limiter must be given to both.
import { randomInt } from "node:crypto";

import type { MessagePurpose, MessageSender, ReceiptSigner } from "../core/adapters.ts";
import { systemClock, type Clock } from "../core/clock.ts";
import { EngineError } from "../core/errors.ts";
import { hmacSha256Hex } from "../core/hash.ts";
import type { Engine } from "../engine.ts";
import { signDocument } from "../prove/receipt.ts";
import type { AccessController, AccessGrantBody, SignedAccessGrant, UnlockResult } from "./access.ts";
import { GATE, type AccessResult, type GateHost, type GateModule, type GateSlice } from "./gate.ts";

/** Digits in a code: a guess at the door is one in 100 million per live code. */
export const ACCESS_CODE_DIGITS = 8;

/** New codes tried when one is already live for the same door, before the request is refused. */
const CODE_TRIES = 3;

/** One live code, as the engine stores it: its keyed hash and the grant it stands for. */
export interface AccessCodeEntry {
  workspaceId: string;
  /** HMAC of the code, bound to the workspace, the controller and the door (`accessCodeDigest`). */
  digest: string;
  grantId: string;
  callId: string;
  /** The access grant's body, unsigned. Its `expiresAt` ends the code. */
  body: AccessGrantBody;
}

/**
 * Where live codes are kept until they are used, revoked or expired. A durable store must keep
 * `take` atomic across processes: two keypads offering one code get it once between them.
 */
export interface AccessCodeStore {
  /** Stores an entry. False, and nothing written, when an entry with this digest is live. */
  put(entry: AccessCodeEntry, now: Date): Promise<boolean>;
  /** Removes and returns the entry with this digest, or null. Never returns one entry twice. */
  take(workspaceId: string, digest: string): Promise<AccessCodeEntry | null>;
  /** Removes the code for a grant. Success when it is already gone. */
  revoke(workspaceId: string, grantId: string): Promise<void>;
}

/** The reference `AccessCodeStore`, in memory: one process only. */
export class MemoryAccessCodeStore implements AccessCodeStore {
  readonly #entries = new Map<string, AccessCodeEntry>();

  async put(entry: AccessCodeEntry, now: Date): Promise<boolean> {
    for (const [key, e] of this.#entries) if (Date.parse(e.body.expiresAt) <= now.getTime()) this.#entries.delete(key);
    const key = JSON.stringify([entry.workspaceId, entry.digest]);
    if (this.#entries.has(key)) return false;
    this.#entries.set(key, structuredClone(entry));
    return true;
  }

  async take(workspaceId: string, digest: string): Promise<AccessCodeEntry | null> {
    const key = JSON.stringify([workspaceId, digest]);
    const entry = this.#entries.get(key) ?? null;
    this.#entries.delete(key);
    return entry;
  }

  async revoke(workspaceId: string, grantId: string): Promise<void> {
    for (const [key, e] of this.#entries) if (e.workspaceId === workspaceId && e.grantId === grantId) this.#entries.delete(key);
  }

  /** How many entries are held, live or not yet pruned. */
  get size(): number {
    return this.#entries.size;
  }
}

/**
 * Send limits on texts to a subject's number on file, shared by every kind of texted code. A
 * stand-in for VER-2's limits: give the same limiter to texted codes once they are built.
 */
export interface TextSendLimits {
  /** Counts one text to the subject and returns true, or returns false and counts nothing when a limit is reached. */
  acquire(input: { workspaceId: string; subjectKey: string; purpose: MessagePurpose; at: Date }): Promise<boolean>;
}

/** VER-2's per-subject limits, in memory: 5 texts per subject per 24 hours, 60 seconds apart. */
export class MemoryTextSendLimits implements TextSendLimits {
  readonly #sent = new Map<string, number[]>();
  readonly #perDay: number;
  readonly #gapMs: number;

  constructor(options: { perSubjectPerDay?: number; minGapSeconds?: number } = {}) {
    this.#perDay = options.perSubjectPerDay ?? 5;
    this.#gapMs = (options.minGapSeconds ?? 60) * 1000;
  }

  async acquire(input: { workspaceId: string; subjectKey: string; purpose: MessagePurpose; at: Date }): Promise<boolean> {
    const key = JSON.stringify([input.workspaceId, input.subjectKey]);
    const at = input.at.getTime();
    const recent = (this.#sent.get(key) ?? []).filter((t) => t > at - 86_400_000);
    if (recent.length >= this.#perDay || recent.some((t) => t > at - this.#gapMs)) {
      this.#sent.set(key, recent);
      return false;
    }
    this.#sent.set(key, [...recent, at]);
    return true;
  }
}

export interface AccessCodeOptions {
  /** The HMAC key for codes, at least 16 bytes. Its own key, not the knowledge key. */
  key: string | Uint8Array;
  /** Signs a redeemed grant for the door's relay: Gate's own signer. */
  signer: ReceiptSigner;
  store: AccessCodeStore;
  /** Texts the code. The destination is always the number on file, from the engine. */
  messages: MessageSender;
  /** Shared with texted codes (VER-2). */
  limits: TextSendLimits;
  /** Default: the system clock. */
  clock?: Clock;
  /** Default: `ACCESS_CODE_DIGITS` random digits from node:crypto. */
  newCode?: () => string;
}

/** What `issue` needs of an engine. */
export type AccessCodeHost = GateHost & Pick<Engine, "numberOnFile">;

export type RedeemResult = { ok: true; grant: SignedAccessGrant } | { ok: false };

/** The keyed hash a code is stored and looked up under. */
export function accessCodeDigest(key: string | Uint8Array, door: { workspaceId: string; audience: string; target: string }, code: string): string {
  return hmacSha256Hex(key, JSON.stringify(["access-code", door.workspaceId, door.audience, door.target, code]));
}

/** One-time access codes: name `codes.controller` in `gateModule({ controllers })`, then `codes.issue(...)`. */
export function accessCodes(options: AccessCodeOptions): AccessCodes {
  return new AccessCodes(options);
}

interface Pending {
  engine: AccessCodeHost;
  callId: string;
}

export class AccessCodes {
  /** The `AccessController` that texts a code instead of working a door. */
  readonly controller: AccessController;
  readonly #options: AccessCodeOptions;
  readonly #clock: Clock;
  readonly #newCode: () => string;
  /** The `issue` calls running in this process: the only ones the controller texts for. */
  readonly #pending = new Set<Pending>();

  constructor(options: AccessCodeOptions) {
    const keyLength = typeof options.key === "string" ? Buffer.byteLength(options.key) : options.key.byteLength;
    if (keyLength < 16) throw new EngineError("invalid_input", "the access code key must be at least 16 bytes");
    this.#options = options;
    this.#clock = options.clock ?? systemClock;
    this.#newCode = options.newCode ?? (() => String(randomInt(0, 10 ** ACCESS_CODE_DIGITS)).padStart(ACCESS_CODE_DIGITS, "0"));
    this.controller = { unlock: (input) => this.#text(input.grant) };
  }

  /**
   * Issues an access grant through Gate for a target whose controller is `controller`, and texts
   * its code to the number on file. Takes what `gate.grantAccess` takes and answers the same:
   * `delivered` once the code was texted, `refused` at a send limit or when the text failed (the
   * code is then revoked), `unknown` when that is not known.
   */
  async issue(gate: GateModule, engine: AccessCodeHost, callId: string, input?: { target: string; lifetimeSeconds?: number }): Promise<AccessResult> {
    const pending: Pending = { engine, callId };
    this.#pending.add(pending);
    try {
      return await gate.grantAccess(engine, callId, input);
    } finally {
      this.#pending.delete(pending);
    }
  }

  /**
   * Redeems a code a keypad took, once: the grant it stands for, signed for the door's relay, or
   * `{ ok: false }`, the same for a wrong, used, revoked or expired code. `audience` and `target`
   * are the door's controller name and ref, as in the grant. Never throws for a bad code.
   */
  async redeem(input: { workspaceId: string; audience: string; target: string; code: string }): Promise<RedeemResult> {
    const code = typeof input.code === "string" && input.code.length <= 32 ? input.code : "";
    const entry = await this.#options.store.take(input.workspaceId, accessCodeDigest(this.#options.key, input, code));
    if (entry === null || Date.parse(entry.body.expiresAt) <= this.#clock.now().getTime()) return { ok: false };
    return { ok: true, grant: await signDocument(this.#options.signer, entry.body) };
  }

  /** Removes a grant's code before its end. Success when it is already gone. */
  async revoke(workspaceId: string, grantId: string): Promise<void> {
    await this.#options.store.revoke(workspaceId, grantId);
  }

  /** The controller's `unlock`: Gate reserved and signed the grant; text a code for it instead. */
  async #text(grant: SignedAccessGrant): Promise<UnlockResult> {
    const body = grant.body;
    const pending = await this.#callOf(body.grantId);
    if (pending === null) return { outcome: "refused", reason: "not_requested" };
    const to = await pending.engine.numberOnFile(pending.callId);
    const now = this.#clock.now();
    if (!(await this.#options.limits.acquire({ workspaceId: body.workspaceId, subjectKey: to.subjectKey, purpose: "one_time_code", at: now }))) {
      return { outcome: "refused", reason: "send_limit" };
    }
    let code: string | null = null;
    for (let i = 0; i < CODE_TRIES && code === null; i++) {
      const candidate = this.#newCode();
      const entry: AccessCodeEntry = { workspaceId: body.workspaceId, digest: accessCodeDigest(this.#options.key, body, candidate), grantId: body.grantId, callId: pending.callId, body };
      if (await this.#options.store.put(entry, now)) code = candidate;
    }
    if (code === null) return { outcome: "refused", reason: "no_free_code" };
    const minutes = Math.max(1, Math.ceil((Date.parse(body.expiresAt) - now.getTime()) / 60_000));
    const text =
      to.locale === "fr"
        ? `Votre code de porte, à usage unique : ${code}. Valable une fois, dans les ${minutes} min.`
        : `Your one-time door code: ${code}. It works once, within ${minutes} min.`;
    try {
      const { messageId } = await this.#options.messages.sendText({
        to: to.phoneOnFile,
        body: text,
        purpose: "one_time_code",
        idempotencyKey: JSON.stringify([body.workspaceId, pending.callId, body.grantId, "access_code"]),
      });
      return { outcome: "delivered", providerRef: messageId, confirmed: false };
    } catch {
      // The text may or may not have gone out: the code is revoked, so the door certainly will not
      // open with it. A revoke that fails is thrown, and Gate records the grant as unknown.
      await this.#options.store.revoke(body.workspaceId, body.grantId);
      return { outcome: "refused", reason: "text_failed" };
    }
  }

  /** The running `issue` whose call holds this grant's reservation, or null. */
  async #callOf(grantId: string): Promise<Pending | null> {
    for (const pending of this.#pending) {
      const slice = (await pending.engine.moduleState(pending.callId, GATE)) as unknown as GateSlice;
      if (slice.grants.some((g) => g.grantId === grantId && g.status === "reserved")) return pending;
    }
    return null;
  }
}
