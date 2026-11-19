// One-time access codes (GAT-3): entry where no controller can be called live. Instead of sending
// the signed access grant to a door, Gate texts a short code to the number on file, and a keypad at
// the door later hands the code to the host, which redeems it here, once, for that same grant.
//
// A code rides on Gate's own grant path: `accessCodes(...).controller` is an `AccessController`,
// named in the engine's `access` adapter like any other, and `issue` runs `engine.grantAccess` for
// it. So a code gets everything a grant gets: the engine's reservation, the `entry.open` checks
// before and right before sending, one in flight per call, `maxGrantsPerCall`, the engine's own
// ledger entries with the grant's digest, and a lifetime that never passes the verification grant.
// The engine records the controller's answer itself (ADR-25): nothing here writes an outcome.
// "Delivered" means the code was texted: the door acts later, when the code is redeemed, which may
// be after the call ended and its receipt was issued, until the grant expires (SPEC.md, section 17).
//
// The engine keeps only a keyed hash of each code (HMAC under the codes' own key, bound to the
// workspace, the controller and the door) with the grant's body, never the code and never a
// signature: a stolen code store opens nothing. Redeeming takes the entry out in one step (single
// use), refuses it after the grant's expiry, and signs the grant body again for the door's relay,
// which checks it with `verifyAccessGrant` and `SeenGrants` as usual. The code is in the text and
// nowhere else: not in the ledger, an event, an error or the store.
//
// Texts count against the send limits of texted codes (VER-2), per subject, in VER-2's `CodeStore`
// (the engine's `codes` adapter once VER-2 lands): give both the same store, so they share a budget.
import { randomInt } from "node:crypto";

import type { AuditLedger, CodeStore, MessageSender, ReceiptSigner } from "../core/adapters.ts";
import { systemClock, type Clock } from "../core/clock.ts";
import type { Locale } from "../core/runtime.ts";
import { EngineError } from "../core/errors.ts";
import { hmacSha256Hex } from "../core/hash.ts";
import type { Engine } from "../engine.ts";
import { signDocument } from "../prove/receipt.ts";
import { accessGrantDigest, type AccessController, type AccessGrantBody, type SignedAccessGrant, type UnlockResult } from "./access.ts";
import type { AccessResult } from "./gate.ts";
import { TEXT_CODE_LIMITS } from "../verify/text-code.ts";

/** Digits in a code: a guess at the door is one in 100 million per live code. */
export const ACCESS_CODE_DIGITS = 8;

/** New codes tried when one is already live for the same door, before the request is refused. */
const CODE_TRIES = 3;

/** Wrong guesses at a door that spend each code live there: 5 by default, 1 to 10. */
export const ACCESS_CODE_WRONG_GUESSES = 5;
export const MAX_ACCESS_CODE_WRONG_GUESSES = 10;

/** What `newCode` must answer: exactly `ACCESS_CODE_DIGITS` digits. */
const CODE_SHAPE = new RegExp(`^[0-9]{${ACCESS_CODE_DIGITS}}$`);

/** One live code, as the engine stores it: its keyed hash and the grant it stands for. */
export interface AccessCodeEntry {
  workspaceId: string;
  /** HMAC of the code, bound to the workspace, the controller and the door (`accessCodeDigest`). */
  digest: string;
  grantId: string;
  callId: string;
  /** The access grant's body, unsigned. Its `expiresAt` ends the code. */
  body: AccessGrantBody;
  /** Wrong guesses at this code's door since it was stored. At the limit the code is spent. */
  misses: number;
  /**
   * Set once the code is spent by wrong guesses: it opens nothing from then on, and the entry is
   * kept, as the pending record of its `access.code_spent` entry, until that entry is in the
   * ledger (then `revoke` removes it).
   */
  spent?: true;
}

/**
 * Where live codes are kept until they are used, revoked or expired. A durable store must keep
 * `take` atomic across processes: two keypads offering one code get it once between them.
 */
export interface AccessCodeStore {
  /** Stores an entry. False, and nothing written, when an entry with this digest is live or spent. */
  put(entry: AccessCodeEntry, now: Date): Promise<boolean>;
  /** The entry with this digest, or null, leaving it in place. Null for a spent entry. */
  get(workspaceId: string, digest: string): Promise<AccessCodeEntry | null>;
  /**
   * Removes and returns the entry with this digest, or null, atomically: never one entry twice.
   * With `grantId`, only an entry for that grant: an entry another grant holds under the same
   * digest (the same code, drawn again once the first was used) is left in place, and null returned.
   * A spent entry is never taken: it is left in place, and null returned.
   */
  take(workspaceId: string, digest: string, grantId?: string): Promise<AccessCodeEntry | null>;
  /** Removes the code for a grant, a spent one too. Success when it is already gone. */
  revoke(workspaceId: string, grantId: string): Promise<void>;
  /**
   * Counts one wrong guess against every live entry for this door (the grant body's `audience`
   * and `target`), and marks those that reached `limit` spent, atomically: two wrong guesses at
   * once count twice. Returns every spent entry of the workspace still held: those spent now, and
   * those whose ledger entry is still to be written (kept until `revoke`), so a ledger append that
   * failed is made again on the next wrong guess, without the code ever opening a door again.
   */
  miss(workspaceId: string, door: { audience: string; target: string }, limit: number, now: Date): Promise<AccessCodeEntry[]>;
}

/** The reference `AccessCodeStore`, in memory: one process only. */
export class MemoryAccessCodeStore implements AccessCodeStore {
  readonly #entries = new Map<string, AccessCodeEntry>();

  async put(entry: AccessCodeEntry, now: Date): Promise<boolean> {
    // Expired codes are pruned; a spent one stays until its ledger entry is written.
    for (const [key, e] of this.#entries) if (e.spent !== true && Date.parse(e.body.expiresAt) <= now.getTime()) this.#entries.delete(key);
    const key = JSON.stringify([entry.workspaceId, entry.digest]);
    if (this.#entries.has(key)) return false;
    this.#entries.set(key, structuredClone(entry));
    return true;
  }

  async get(workspaceId: string, digest: string): Promise<AccessCodeEntry | null> {
    const entry = this.#entries.get(JSON.stringify([workspaceId, digest]));
    return entry === undefined || entry.spent === true ? null : structuredClone(entry);
  }

  async take(workspaceId: string, digest: string, grantId?: string): Promise<AccessCodeEntry | null> {
    const key = JSON.stringify([workspaceId, digest]);
    const entry = this.#entries.get(key);
    if (entry === undefined || entry.spent === true || (grantId !== undefined && entry.grantId !== grantId)) return null;
    this.#entries.delete(key);
    return entry;
  }

  async revoke(workspaceId: string, grantId: string): Promise<void> {
    for (const [key, e] of this.#entries) if (e.workspaceId === workspaceId && e.grantId === grantId) this.#entries.delete(key);
  }

  async miss(workspaceId: string, door: { audience: string; target: string }, limit: number, now: Date): Promise<AccessCodeEntry[]> {
    const spent: AccessCodeEntry[] = [];
    for (const e of this.#entries.values()) {
      if (e.workspaceId !== workspaceId) continue;
      const live = e.spent !== true && e.body.audience === door.audience && e.body.target === door.target && Date.parse(e.body.expiresAt) > now.getTime();
      if (live && ++e.misses >= limit) e.spent = true;
      if (e.spent === true) spent.push(structuredClone(e));
    }
    return spent;
  }

  /** How many entries are held, live, spent and not yet recorded, or not yet pruned. */
  get size(): number {
    return this.#entries.size;
  }
}

/** The access code text, by the call's locale: the code and the minutes it stays valid. */
export const ACCESS_CODE_TEXT: Record<Locale, (code: string, minutes: number) => string> = {
  en: (code, minutes) => `Your one-time door code: ${code}. It works once, within ${minutes} min.`,
  fr: (code, minutes) => `Votre code de porte, à usage unique : ${code}. Valable une fois, dans les ${minutes} min.`,
  es: (code, minutes) => `Su código de puerta de un solo uso: ${code}. Sirve una vez, dentro de ${minutes} min.`,
};

/**
 * The send limits an access code counts against, per subject: VER-2's subject limits for texted
 * codes, so the two kinds of code share one budget in one `CodeStore`.
 */
export const ACCESS_CODE_SEND_LIMITS = TEXT_CODE_LIMITS.subject;

export interface AccessCodeOptions {
  /** The HMAC key for codes, at least 16 bytes. Its own key, not the knowledge key. */
  key: string | Uint8Array;
  /** Signs a redeemed grant for the door's relay: the engine's `accessSigner`, so relays check it with `engine.accessKeys()`. */
  signer: ReceiptSigner;
  store: AccessCodeStore;
  /** Where a code spent by wrong guesses is recorded (`access.code_spent`): the engine's ledger. */
  ledger: AuditLedger;
  /** Wrong guesses at a door that spend the codes live there. 1 to 10, default 5. */
  maxWrongGuesses?: number;
  /** Texts the code. The destination is always the number on file, from the engine. */
  messages: MessageSender;
  /** VER-2's send limits store, the same instance the engine's texted codes count against. */
  limits: CodeStore;
  /** Default: the system clock. */
  clock?: Clock;
  /** Default: `ACCESS_CODE_DIGITS` random digits from node:crypto. Anything but exactly that many digits fails the issue. */
  newCode?: () => string;
}

/** What `issue` needs of an engine. */
export type AccessCodeHost = Pick<Engine, "workspaceId" | "grantAccess" | "accessGrants" | "numberOnFile">;

export type RedeemResult = { ok: true; grant: SignedAccessGrant } | { ok: false };

/** The keyed hash a code is stored and looked up under. */
export function accessCodeDigest(key: string | Uint8Array, door: { workspaceId: string; audience: string; target: string }, code: string): string {
  return hmacSha256Hex(key, JSON.stringify(["access-code", door.workspaceId, door.audience, door.target, code]));
}

/** One-time access codes: name `codes.controller` in the engine's `access` adapter, then `codes.issue(...)`. */
export function accessCodes(options: AccessCodeOptions): AccessCodes {
  return new AccessCodes(options);
}

interface Pending {
  engine: AccessCodeHost;
  callId: string;
  /** The codes this issue may store, drawn and checked before the engine reserved anything. */
  candidates: string[];
}

export class AccessCodes {
  /** The `AccessController` that texts a code instead of working a door. */
  readonly controller: AccessController;
  readonly #options: AccessCodeOptions;
  readonly #clock: Clock;
  readonly #newCode: () => string;
  readonly #maxWrongGuesses: number;
  /** The `issue` calls running in this process: the only ones the controller texts for. */
  readonly #pending = new Set<Pending>();

  constructor(options: AccessCodeOptions) {
    const keyLength = typeof options.key === "string" ? Buffer.byteLength(options.key) : options.key.byteLength;
    if (keyLength < 16) throw new EngineError("invalid_input", "the access code key must be at least 16 bytes");
    const guesses = options.maxWrongGuesses ?? ACCESS_CODE_WRONG_GUESSES;
    if (!Number.isSafeInteger(guesses) || guesses < 1 || guesses > MAX_ACCESS_CODE_WRONG_GUESSES) {
      throw new EngineError("invalid_input", `maxWrongGuesses must be an integer from 1 to ${MAX_ACCESS_CODE_WRONG_GUESSES}`);
    }
    this.#maxWrongGuesses = guesses;
    this.#options = options;
    this.#clock = options.clock ?? systemClock;
    this.#newCode = options.newCode ?? (() => String(randomInt(0, 10 ** ACCESS_CODE_DIGITS)).padStart(ACCESS_CODE_DIGITS, "0"));
    this.controller = { unlock: (input) => this.#text(input.grant) };
  }

  /**
   * Issues an access grant through Gate for a target whose controller is `controller`, and texts
   * its code to the number on file. Takes what `engine.grantAccess` takes and answers the same:
   * `delivered` once the code was texted, `refused` at a send limit or when the text failed (the
   * code is then revoked), `unknown` when that is not known.
   */
  async issue(engine: AccessCodeHost, callId: string, input?: { target: string; lifetimeSeconds?: number }): Promise<AccessResult> {
    // The host's generator is checked before anything is reserved, counted or stored: a code that
    // is not exactly its digits would shrink the guess space, or match a malformed guess.
    const candidates: string[] = [];
    for (let i = 0; i < CODE_TRIES; i++) {
      const code: unknown = this.#newCode();
      if (typeof code !== "string" || !CODE_SHAPE.test(code)) throw new EngineError("invalid_input", `newCode must answer exactly ${ACCESS_CODE_DIGITS} digits`);
      candidates.push(code);
    }
    const pending: Pending = { engine, callId, candidates };
    this.#pending.add(pending);
    try {
      return await engine.grantAccess(callId, input);
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
    // Read once: the door and code hashed are the ones looked up and taken, and a code passes its
    // length check with the value it is hashed with.
    const { workspaceId, audience, target, code: given } = input;
    const code = typeof given === "string" && given.length <= 32 ? given : "";
    const digest = accessCodeDigest(this.#options.key, { workspaceId, audience, target }, code);
    const store = this.#options.store;
    const live = (e: AccessCodeEntry | null): e is AccessCodeEntry => e !== null && Date.parse(e.body.expiresAt) > this.#clock.now().getTime();
    // Signed before the code is taken: a signer that fails throws and leaves the code to try again.
    const seen = await store.get(workspaceId, digest);
    if (!live(seen)) {
      await this.#wrongGuess(workspaceId, audience, target);
      return { ok: false };
    }
    const grant = await signDocument(this.#options.signer, seen.body);
    // Then taken, atomically, once: a code used or revoked meanwhile is refused and its signature dropped.
    // Only the entry that was signed: one another grant holds under this digest meanwhile stays.
    const taken = await store.take(workspaceId, digest, seen.grantId);
    if (!live(taken)) return { ok: false };
    return { ok: true, grant };
  }

  /**
   * A guess that matched no live code at this door counts against every code live there; those at
   * the limit are spent, each recorded in the ledger by its grant, never with the guess. Each spent
   * code's entry is appended (idempotent by its event id), and only then is the code removed: an
   * append that fails leaves it held, spent, and the next wrong guess appends it again. Every spent
   * code is tried; the first failure is thrown once all were.
   */
  async #wrongGuess(workspaceId: string, audience: string, target: string): Promise<void> {
    const now = this.#clock.now();
    const spent = await this.#options.store.miss(workspaceId, { audience, target }, this.#maxWrongGuesses, now);
    const failures: unknown[] = [];
    for (const entry of spent) {
      await this.#recordSpent(entry, now).catch((error: unknown) => failures.push(error));
    }
    if (failures.length > 0) throw failures[0];
  }

  /** One spent code's ledger entry, then its removal from the store. */
  async #recordSpent(entry: AccessCodeEntry, now: Date): Promise<void> {
    await this.#options.ledger.append({
      // The workspace first, as every engine event id has it, so reports attribute the entry (PRV-8).
      eventId: JSON.stringify([entry.workspaceId, "access.code_spent", entry.grantId]),
      callId: entry.callId,
      actor: "system",
      event: "access.code_spent",
      at: now.toISOString(),
      detail: { grantId: entry.grantId, reason: "wrong_guesses", guesses: this.#maxWrongGuesses },
    });
    await this.#options.store.revoke(entry.workspaceId, entry.grantId);
  }

  /** Removes a grant's code before its end. Success when it is already gone. */
  async revoke(workspaceId: string, grantId: string): Promise<void> {
    await this.#options.store.revoke(workspaceId, grantId);
  }

  /** The controller's `unlock`: Gate reserved and signed the grant; text a code for it instead. */
  async #text(grant: SignedAccessGrant): Promise<UnlockResult> {
    const body = grant.body;
    const pending = await this.#callOf(body);
    if (pending === null) return { outcome: "refused", reason: "not_requested" };
    const to = await pending.engine.numberOnFile(pending.callId);
    const now = this.#clock.now();
    const counted = await this.#options.limits.take({ workspaceId: body.workspaceId, key: { scope: "subject", key: to.subjectKey }, at: now.toISOString(), ...ACCESS_CODE_SEND_LIMITS });
    if (!counted) {
      return { outcome: "refused", reason: "send_limit" };
    }
    let code: string | null = null;
    let digest = "";
    for (const candidate of pending.candidates) {
      if (code !== null) break;
      const entry: AccessCodeEntry = { workspaceId: body.workspaceId, digest: accessCodeDigest(this.#options.key, body, candidate), grantId: body.grantId, callId: pending.callId, body, misses: 0 };
      if (await this.#options.store.put(entry, now)) [code, digest] = [candidate, entry.digest];
    }
    if (code === null) return { outcome: "refused", reason: "no_free_code" };
    // The limiter and the store can be slow: a grant that expired meanwhile is never texted, and
    // the minutes in the text count from now.
    const sendAt = this.#clock.now().getTime();
    if (Date.parse(body.expiresAt) <= sendAt) {
      await this.#options.store.take(body.workspaceId, digest, body.grantId);
      return { outcome: "refused", reason: "expired" };
    }
    const minutes = Math.max(1, Math.ceil((Date.parse(body.expiresAt) - sendAt) / 60_000));
    const text = ACCESS_CODE_TEXT[to.locale](code, minutes);
    try {
      const { messageId } = await this.#options.messages.sendText({
        to: to.phoneOnFile,
        body: text,
        purpose: "one_time_code",
        idempotencyKey: JSON.stringify([body.workspaceId, pending.callId, body.grantId, "access_code"]),
      });
      return { outcome: "delivered", providerRef: messageId, confirmed: false };
    } catch {
      // The text may or may not have gone out. Taking the code back proves it was not redeemed, and
      // the door certainly will not open with it: refused. Gone already (redeemed from a text that
      // did arrive, or expired), or a store that fails: thrown, and Gate records the grant as unknown.
      if ((await this.#options.store.take(body.workspaceId, digest, body.grantId)) !== null) return { outcome: "refused", reason: "text_failed" };
      throw new EngineError("precondition_failed", "the access code text failed and its code was already gone");
    }
  }

  /**
   * The running `issue` whose call holds this very grant in flight, or null: matched on the
   * engine's workspace and the digest the engine recorded for the grant it signed, never on the
   * grant id alone (two engines, or two workspaces, may hand out the same id), so a code is never
   * texted to another call's number.
   */
  async #callOf(body: AccessGrantBody): Promise<Pending | null> {
    const digest = accessGrantDigest(body);
    for (const pending of this.#pending) {
      if (pending.engine.workspaceId !== body.workspaceId) continue;
      const grants = await pending.engine.accessGrants(pending.callId);
      if (grants.some((g) => g.grantId === body.grantId && g.status === "reserved" && g.digest === digest)) return pending;
    }
    return null;
  }
}
