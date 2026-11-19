// INT-1: the keypad collector. A host gets keypad tones one at a time from its carrier bridge and
// must buffer them, outside the model and outside its logs, until the caller presses `#`. This is
// that buffer, written once: pure (no timers, no I/O; time comes from the injected clock), with a
// maximum length and an idle timeout, and with nothing in it that prints a digit. The digits leave
// only through the one callback given at construction, once per entry, after the buffer is wiped.
import { type Clock, systemClock } from "./clock.ts";
import { EngineError } from "./errors.ts";
import { isIntegerIn } from "./shape.ts";

/** Longest entry a collector may be set to: the longest the engine judges (SPEC.md, section 5). */
export const MAX_KEYPAD_DIGITS = 32;
/** Longest idle timeout a collector may be set to, ten minutes. */
export const MAX_KEYPAD_IDLE_MS = 600_000;

export interface KeypadCollectorOptions<R> {
  /** Most digits an entry may have, 1 to 32. One more discards the entry. */
  maxDigits: number;
  /** Milliseconds, 1 to 600,000, after the last tone at which an unfinished entry is discarded. */
  idleTimeoutMs: number;
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
  /** A digit past `maxDigits`: the entry is discarded and never reaches the callback. */
  | { status: "overflow"; timedOut: boolean }
  /** Not `0` to `9`, `*` or `#` (for example `A` to `D`): the entry is discarded. */
  | { status: "rejected"; timedOut: boolean };

const DIGIT = /^[0-9]$/;

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
  readonly #idleTimeoutMs: number;
  readonly #onDigits: (digits: string) => R;
  readonly #clock: Clock;
  #digits = "";
  #lastAt = 0;

  constructor(options: KeypadCollectorOptions<R>) {
    if (!isIntegerIn(options.maxDigits, 1, MAX_KEYPAD_DIGITS)) {
      throw new EngineError("invalid_input", `maxDigits must be an integer from 1 to ${MAX_KEYPAD_DIGITS}`);
    }
    if (!isIntegerIn(options.idleTimeoutMs, 1, MAX_KEYPAD_IDLE_MS)) {
      throw new EngineError("invalid_input", `idleTimeoutMs must be an integer from 1 to ${MAX_KEYPAD_IDLE_MS}`);
    }
    if (typeof options.onDigits !== "function") throw new EngineError("invalid_input", "onDigits must be a function");
    this.#maxDigits = options.maxDigits;
    this.#idleTimeoutMs = options.idleTimeoutMs;
    this.#onDigits = options.onDigits;
    this.#clock = options.clock ?? systemClock;
  }

  /** Takes one tone. An unfinished entry that went idle is discarded first. */
  press(tone: string): KeypadPress<R> {
    const timedOut = this.expire();
    if (tone === "#") {
      if (this.#digits === "") return { status: "empty", timedOut };
      const digits = this.#digits;
      this.#digits = "";
      return { status: "submitted", result: this.#onDigits(digits), timedOut };
    }
    if (tone === "*") {
      this.#digits = "";
      return { status: "cleared", timedOut };
    }
    if (typeof tone !== "string" || !DIGIT.test(tone)) {
      this.#digits = "";
      return { status: "rejected", timedOut };
    }
    if (this.#digits.length === this.#maxDigits) {
      this.#digits = "";
      return { status: "overflow", timedOut };
    }
    this.#digits += tone;
    this.#lastAt = this.#clock.now().getTime();
    return { status: "buffering", timedOut };
  }

  /** Discards an unfinished entry whose last tone is `idleTimeoutMs` old or older. True when it did. */
  expire(): boolean {
    if (this.#digits === "" || this.#clock.now().getTime() - this.#lastAt < this.#idleTimeoutMs) return false;
    this.#digits = "";
    return true;
  }

  /** Discards any unfinished entry, for example when the sensitive window closes or the call ends. */
  clear(): void {
    this.#digits = "";
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
