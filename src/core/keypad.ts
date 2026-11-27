// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// INT-1: the keypad collector. A host gets keypad tones one at a time from its carrier bridge and
// must buffer them, outside the model and outside its logs, until the caller presses `#`. This is
// that buffer, written once: pure (no timers, no I/O; time comes from the injected clock), with a
// maximum length and an idle timeout, and with nothing in it that prints a digit. The digits leave
// only through the one callback given at construction, once per entry, after the buffer is wiped.
//
// VER-11 adds two things on top: request keys (`*` or `A` to `D`) that hand the host a `repeat` or
// `slower` request instead of digits, and an idle timeout a call may lengthen up to a limit
// (`Engine.keypadTiming` gives both from Badge's `accessibility` settings).
import { type Clock, systemClock } from "./clock.ts";
import { EngineError } from "./errors.ts";
import { isIntegerIn, isObject, unknownKeys } from "./shape.ts";

/** Longest entry a collector may be set to: the longest the engine judges (SPEC.md, section 5). */
export const MAX_KEYPAD_DIGITS = 32;
/** Longest idle timeout a collector may be set to, ten minutes. */
export const MAX_KEYPAD_IDLE_MS = 600_000;

/** What a caller can ask for on the keypad instead of entering digits (VER-11). Never an attempt. */
export type KeypadRequest = "repeat" | "slower";

/** The keys that can carry a request: `#` ends an entry and digits are digits. */
export const KEYPAD_REQUEST_KEYS: readonly string[] = ["*", "A", "B", "C", "D"];

export interface KeypadCollectorOptions<R> {
  /** Most digits an entry may have, 1 to 32. One more discards the entry. */
  maxDigits: number;
  /** Milliseconds, 1 to 600,000, after the last tone at which an unfinished entry is discarded. */
  idleTimeoutMs: number;
  /** The longest `lengthenIdleTimeout` may make it, `idleTimeoutMs` to 600,000. Default: `idleTimeoutMs`, so it cannot grow. */
  maxIdleTimeoutMs?: number;
  /**
   * Keys that hand the host a request instead of digits, for example `{ "*": "repeat" }` (VER-11):
   * `*` or `A` to `D`. A request drops the unfinished entry; the host replays or slows its line.
   * A `*` listed here is a request, no longer "start over".
   */
  requestKeys?: Readonly<Record<string, KeypadRequest>>;
  /** Given the digits of each entry ended by `#`, once. Its return value is handed back by `press`. */
  onDigits: (digits: string) => R;
  clock?: Clock;
}

/**
 * What a tone did. `timedOut` says an unfinished entry had gone idle and was discarded before the
 * tone was taken. None of these carries a digit; `submitted` carries what the callback returned
 * (await it when the callback is asynchronous, for example `engine.submitPin`).
 */
export type KeypadPress<R> =
  | { status: "submitted"; result: R; timedOut: boolean }
  /** A digit was buffered. */
  | { status: "buffering"; timedOut: boolean }
  /** `#` with nothing buffered: no entry, no callback. */
  | { status: "empty"; timedOut: boolean }
  /** `*`: the caller started over. */
  | { status: "cleared"; timedOut: boolean }
  /** A request key (`requestKeys`): the entry is dropped and the host replays or slows its line. */
  | { status: "request"; request: KeypadRequest; timedOut: boolean }
  /** A digit past `maxDigits`: the entry is discarded and never reaches the callback. */
  | { status: "overflow"; timedOut: boolean }
  /** Not `0` to `9`, `*` or `#` (for example `A` to `D`): the entry is discarded. */
  | { status: "rejected"; timedOut: boolean }
  /** A tone after an overflow or a rejection, before `#` or `*`: ignored, the entry stays discarded. */
  | { status: "discarding"; timedOut: boolean };

const DIGIT = /^[0-9]$/;
const OPTION_KEYS: readonly string[] = ["maxDigits", "idleTimeoutMs", "maxIdleTimeoutMs", "requestKeys", "onDigits", "clock"];

/**
 * Buffers keypad tones until `#`. Feed it every tone of the sensitive window (`press`), call
 * `expire` from the host's own timer if it wants an idle entry dropped before the next tone, and
 * `clear` when the window closes or the call ends. The digits live in a private field: `toString`,
 * `JSON.stringify` and `util.inspect` show none of them, nor how many there are. A JavaScript
 * string cannot be wiped in place, so the buffer is dropped, not overwritten; the host should not
 * keep the string its callback receives either.
 */
export class KeypadCollector<R = void> {
  readonly #maxDigits: number;
  readonly #maxIdleTimeoutMs: number;
  readonly #requests: ReadonlyMap<string, KeypadRequest>;
  #idleTimeoutMs: number;
  readonly #onDigits: (digits: string) => R;
  readonly #clock: Clock;
  #digits = "";
  /** True from an overflow or a rejection until `#`, `*`, `clear` or the idle timeout ends the entry. */
  #discarding = false;
  #lastAt = 0;

  constructor(options: KeypadCollectorOptions<R>) {
    if (!isObject(options)) throw new EngineError("invalid_input", "options must be an object");
    const unknown = unknownKeys(options as unknown as Record<string, unknown>, OPTION_KEYS);
    if (unknown.length > 0) throw new EngineError("invalid_input", `${unknown.join(", ")} is not a keypad collector option`);
    if (!isIntegerIn(options.maxDigits, 1, MAX_KEYPAD_DIGITS)) {
      throw new EngineError("invalid_input", `maxDigits must be an integer from 1 to ${MAX_KEYPAD_DIGITS}`);
    }
    if (!isIntegerIn(options.idleTimeoutMs, 1, MAX_KEYPAD_IDLE_MS)) {
      throw new EngineError("invalid_input", `idleTimeoutMs must be an integer from 1 to ${MAX_KEYPAD_IDLE_MS}`);
    }
    const max = options.maxIdleTimeoutMs ?? options.idleTimeoutMs;
    if (!isIntegerIn(max, options.idleTimeoutMs, MAX_KEYPAD_IDLE_MS)) {
      throw new EngineError("invalid_input", `maxIdleTimeoutMs must be an integer from idleTimeoutMs to ${MAX_KEYPAD_IDLE_MS}`);
    }
    const requests = new Map<string, KeypadRequest>();
    if (options.requestKeys !== undefined) {
      if (!isObject(options.requestKeys)) throw new EngineError("invalid_input", "requestKeys must map keys to repeat or slower");
      for (const [key, request] of Object.entries(options.requestKeys)) {
        if (!KEYPAD_REQUEST_KEYS.includes(key)) throw new EngineError("invalid_input", `request key ${JSON.stringify(key)} must be one of ${KEYPAD_REQUEST_KEYS.join(", ")}`);
        if (request !== "repeat" && request !== "slower") throw new EngineError("invalid_input", `the request on ${key} must be repeat or slower`);
        requests.set(key, request);
      }
    }
    if (typeof options.onDigits !== "function") throw new EngineError("invalid_input", "onDigits must be a function");
    if (options.clock !== undefined && !(isObject(options.clock) && typeof options.clock.now === "function")) {
      throw new EngineError("invalid_input", "clock must be an object with a now function");
    }
    this.#maxDigits = options.maxDigits;
    this.#idleTimeoutMs = options.idleTimeoutMs;
    this.#maxIdleTimeoutMs = max;
    this.#requests = requests;
    this.#onDigits = options.onDigits;
    this.#clock = options.clock ?? systemClock;
  }

  /** The idle timeout in force now. */
  get idleTimeoutMs(): number {
    return this.#idleTimeoutMs;
  }

  /**
   * Lengthens the idle timeout by `ms`, up to `maxIdleTimeoutMs`, for the rest of the call, and
   * returns the new timeout (VER-11: a caller who asked to slow down). It never touches the buffer
   * or any attempt.
   */
  lengthenIdleTimeout(ms: number): number {
    if (!isIntegerIn(ms, 1, MAX_KEYPAD_IDLE_MS)) throw new EngineError("invalid_input", `the timeout is lengthened by a whole number of milliseconds from 1 to ${MAX_KEYPAD_IDLE_MS}`);
    this.#idleTimeoutMs = Math.min(this.#idleTimeoutMs + ms, this.#maxIdleTimeoutMs);
    return this.#idleTimeoutMs;
  }

  /** Takes one tone. An unfinished entry that went idle is discarded first. */
  press(tone: string): KeypadPress<R> {
    const timedOut = this.expire();
    // A Map, so a tone such as "constructor" is never a request.
    const request = this.#requests.get(tone);
    if (request !== undefined) {
      this.clear();
      return { status: "request", request, timedOut };
    }
    if (tone === "#") {
      this.#discarding = false;
      if (this.#digits === "") return { status: "empty", timedOut };
      const digits = this.#digits;
      this.#digits = "";
      return { status: "submitted", result: this.#onDigits(digits), timedOut };
    }
    if (tone === "*") {
      this.clear();
      return { status: "cleared", timedOut };
    }
    this.#lastAt = this.#clock.now().getTime();
    if (this.#discarding) return { status: "discarding", timedOut };
    if (typeof tone !== "string" || !DIGIT.test(tone)) return this.#discard("rejected", timedOut);
    if (this.#digits.length === this.#maxDigits) return this.#discard("overflow", timedOut);
    this.#digits += tone;
    return { status: "buffering", timedOut };
  }

  /** Drops the buffer and ignores the rest of the entry until `#`, `*`, `clear` or the idle timeout. */
  #discard(status: "rejected" | "overflow", timedOut: boolean): KeypadPress<R> {
    this.#digits = "";
    this.#discarding = true;
    return { status, timedOut };
  }

  /**
   * Discards an unfinished entry (or ends a discarded one) whose last tone is `idleTimeoutMs` old
   * or older, or newer than now (a clock set back), so an entry never outlives its timeout. True
   * when it did.
   */
  expire(): boolean {
    if (this.#digits === "" && !this.#discarding) return false;
    const idle = this.#clock.now().getTime() - this.#lastAt;
    if (idle >= 0 && idle < this.#idleTimeoutMs) return false;
    this.clear();
    return true;
  }

  /** Discards any unfinished entry, for example when the sensitive window closes or the call ends. */
  clear(): void {
    this.#digits = "";
    this.#discarding = false;
  }

  toString(): string {
    return "KeypadCollector {}";
  }

  toJSON(): Record<string, never> {
    return {};
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}
