// The owner PIN (ADR-20, ADR-31): the PIN a business's owner keys on the business's own phone line
// for the `owner-command` flow, kept as an ordinary PIN subject of the engine.
//
// The owner is the subject: `subjectKey = HMAC(knowledgeKey, "subject:owner:" + workspaceId)`, so
// the owner's PIN subject never collides with an account number keyed on the line. The business
// sets the PIN from its own signed-in tools (SPEC.md section 6: only the business changes a PIN on
// file), never a caller: the new record is computed first, then any PIN on file is reset through
// `Engine.resetPin` (which also clears the PIN counters), then the record is stored. Judging a keyed
// PIN stays the engine's (`submitPin`, a constant-time comparison of the Argon2id tag): nothing here
// compares a PIN, and the digits are never stored, logged or put in an error message.
//
// The host keeps everything that is its own: who may call these (its sign-in), the owner's verified
// number, binding a phone call to an engine call, the key store behind `hmac`, and lock notices.
import type { AttemptCounterKey, AttemptCounters, RecordStore, SubjectRecord } from "../core/adapters.ts";
import { EngineError } from "../core/errors.ts";
import type { Engine } from "../engine.ts";
import { counterKeys, isCallingNumber, lockState, lockoutOf, type Lockout, type LockoutSettings } from "./counters.ts";
import type { BadgeSettings, PinSettings } from "./factors.ts";
import { knowledgeHmac, pinDigest, subjectKeyFor, type KnowledgeHmac } from "./knowledge.ts";
import { isWeakPin } from "./pin.ts";

/**
 * Writes the host's own fields of a subject record (`phoneOnFile`, `knowledge`), creating the
 * record when there is none: the one write `RecordStore` lacks, since the engine never creates a
 * subject. A store may replace the whole record; `setPin` calls it only after any PIN on file was
 * reset and stores the new PIN after it. `MemoryRecordStore` has it.
 */
export interface SubjectWriter {
  putSubject(workspaceId: string, subject: SubjectRecord): Promise<void> | void;
}

export interface OwnerPinOptions {
  /** The workspace's engine. Its config must have Badge on, the `pin` factor on, in `keyed_hash` mode. */
  engine: Engine;
  /** The engine's own knowledge key, as an HMAC function (the key stays in the key store). */
  hmac: KnowledgeHmac;
  /** The engine's own record store, with `putSubject`. */
  records: RecordStore & SubjectWriter;
  /** The engine's own counters store. */
  counters: AttemptCounters;
  /**
   * The lockout the facts are read with. Optional: the engine's Badge `lockout` (defaults filled
   * in) is the one that locks, so when given it must equal it, or every call is refused
   * (`precondition_failed`): facts read under another lockout would misstate the tries left.
   */
  lockout?: LockoutSettings;
  /** Reads the time for `status`. Default: the system clock. */
  now?: () => Date;
}

/** The owner's line: their verified number on file, E.164, or null when there is none. */
export interface OwnerLine {
  phone: string | null;
}

/** What the business's tools may show. Never the PIN, its record or a number. */
export interface OwnerPinStatus {
  /** A PIN is on file. */
  pinSet: boolean;
  /** Hard-locked: only `liftLock` or time clears it. */
  locked: boolean;
  /** Seconds until the wait after the latest failure ends; 0 when there is none. */
  waitSeconds: number;
  /** Wrong PINs in the window, on the counter that holds the most. */
  failures: number;
  /** Wrong PINs left before the hard lock. */
  remaining: number;
}

/** A PIN the business chose: stored, or refused. `weak` does not say which rule it broke. */
export type OwnerPinSetResult = { ok: true } | { ok: false; reason: "malformed" | "weak" };

export interface OwnerPin {
  /** The owner's PIN subject key, for `beginVerification` on the host's phone call. */
  subjectKey(): Promise<string>;
  /** Whether a PIN is on file, and the lock facts of the owner's counters, read without writing. */
  status(line: OwnerLine): Promise<OwnerPinStatus>;
  /** Stores a new PIN, replacing any (reset first, so its counters go too). */
  setPin(line: OwnerLine, pin: string): Promise<OwnerPinSetResult>;
  /** Removes the PIN on file, if any, and clears its counters. Idempotent; each call is a `pin.reset` in the ledger. */
  clearPin(): Promise<void>;
  /** Lifts the owner's locks early: the subject's counter and the line's. `memberId` as `Engine.unlock` takes it. */
  liftLock(line: OwnerLine, memberId: string): Promise<void>;
}

const HOUR_MS = 3_600_000;
const DIGITS = /^[0-9]+$/;

/** The owner's subject key in a workspace: the subject key of the account number `owner:<workspaceId>`. */
export function ownerSubjectKey(hmac: KnowledgeHmac, workspaceId: string): Promise<string> {
  return subjectKeyFor(knowledgeHmac(hmac), `owner:${workspaceId}`);
}

/** The owner PIN of the engine's workspace, over the engine's own stores and knowledge key. */
export function createOwnerPin(options: OwnerPinOptions): OwnerPin {
  const { engine, records, counters, lockout: given, now = () => new Date() } = options;
  if (typeof options.hmac !== "function") throw new EngineError("invalid_input", "hmac must be the knowledge HMAC function");
  // The answer is checked to be 64 lower-case hex, so a misbehaving key store fails loudly.
  const hmac = knowledgeHmac(options.hmac);
  const workspaceId = engine.workspaceId;
  const givenLockout = given === undefined ? undefined : lockoutOf(given);

  /** Badge's PIN settings and lockout now (a `configure` may change them), or a refusal. */
  function settings(): { pin: PinSettings; lockout: Lockout } {
    // An enabled module always has its entry, and the config check made its settings Badge's.
    const badge = engine.isEnabled("badge") ? (engine.config.modules.badge!.settings as unknown as BadgeSettings) : null;
    const pin = badge?.factors.includes("pin") === true ? badge.pin : undefined;
    if (pin?.mode !== "keyed_hash") throw new EngineError("precondition_failed", "the owner PIN needs Badge's pin factor on, in keyed_hash mode");
    const lockout = lockoutOf(badge!.lockout);
    if (givenLockout !== undefined && JSON.stringify(givenLockout) !== JSON.stringify(lockout)) {
      throw new EngineError("precondition_failed", "lockout must equal the engine's Badge lockout");
    }
    return { pin, lockout };
  }

  function phoneOf(line: OwnerLine): string | null {
    const phone: unknown = typeof line === "object" && line !== null ? line.phone : undefined;
    if (phone === null) return null;
    if (typeof phone !== "string" || !isCallingNumber(phone)) throw new EngineError("invalid_input", "phone must be an E.164 number or null");
    return phone;
  }

  const subjectKey = (): Promise<string> => ownerSubjectKey(hmac, workspaceId);

  /** The counters a PIN keyed on the owner's line is counted on: the owner's, and the line's. */
  async function pinCounters(phone: string | null, key: string): Promise<AttemptCounterKey[]> {
    return counterKeys(workspaceId, "pin", { subjectKey: key, numberKey: phone === null ? null : await hmac(`number:${phone}`) });
  }

  async function pinOnFile(key: string): Promise<boolean> {
    return typeof (await records.getSubject(workspaceId, key))?.pinDigest === "string";
  }

  return {
    subjectKey,

    async status(line) {
      const phone = phoneOf(line);
      const { lockout } = settings();
      const key = await subjectKey();
      const at = now();
      const since = new Date(at.getTime() - lockout.windowHours * HOUR_MS + 1).toISOString();
      let locked = false;
      let until = at.getTime();
      let failures = 0;
      for (const counter of await pinCounters(phone, key)) {
        const times = await counters.get(counter, since);
        failures = Math.max(failures, times.length);
        const lock = lockState(lockout, times, at);
        if (lock?.hard === true) locked = true;
        else if (lock !== null) until = Math.max(until, Date.parse(lock.until));
      }
      return {
        pinSet: await pinOnFile(key),
        locked,
        waitSeconds: Math.ceil((until - at.getTime()) / 1000),
        failures,
        remaining: Math.max(0, lockout.lockAfterFailures - failures),
      };
    },

    async setPin(line, pin) {
      const phone = phoneOf(line);
      const { pin: rules } = settings();
      // A string of digits only, never coerced; the length is the engine's, so the PIN can be keyed.
      if (typeof pin !== "string" || !DIGITS.test(pin) || pin.length < rules.minDigits || pin.length > rules.maxDigits) return { ok: false, reason: "malformed" };
      if (isWeakPin(pin)) return { ok: false, reason: "weak" };
      const key = await subjectKey();
      // The new record first (the key store and Argon2id), so a failure there leaves the PIN on file as it was.
      const record = await pinDigest(hmac, key, pin);
      // A change: the old PIN and its counters go first. A failure between this and the write below
      // leaves no PIN on file, so the owner command is refused until the business sets one again:
      // never an unguarded line (RecordStore has no atomic reset-and-replace).
      if (await pinOnFile(key)) await engine.resetPin(key);
      await records.putSubject(workspaceId, { subjectKey: key, phoneOnFile: phone ?? "", knowledge: {} });
      if (!(await records.putPinDigest(workspaceId, key, record))) {
        throw new EngineError("conflict", "another PIN was stored for the owner at the same time");
      }
      return { ok: true };
    },

    async clearPin() {
      settings();
      await engine.resetPin(await subjectKey());
    },

    async liftLock(line, memberId) {
      const phone = phoneOf(line);
      settings();
      for (const counter of await pinCounters(phone, await subjectKey())) await engine.unlock({ ...counter, memberId });
    },
  };
}
