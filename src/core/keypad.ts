// The keypad collector: the digit buffer every host needs between its carrier's tone events and
// the engine. It is pure: no timers and no I/O; the host passes the time with each tone and calls
// `tick` from its own timer. The digits are handed to one callback and are never readable from the
// collector, its `toString` or its JSON.
//
// This is a minimal stand-in for INT-1 (keypad collector helper), with the parts VER-11 adds: a
// `repeat` or `slower` request on a key such as `*`, handed to the host instead of digits, and an
// idle timeout a call can lengthen up to a limit (Badge's `accessibility` settings).
import { EngineError } from "./errors.ts";
import { isIntegerIn } from "./shape.ts";

/** What a caller can ask for on the keypad instead of entering digits. Never an attempt. */
export type KeypadRequest = "repeat" | "slower";

/** How long a caller may pause between tones before the buffer is dropped, by default. */
export const DEFAULT_KEYPAD_IDLE_SECONDS = 10;

/** The keys that can carry a request: `#` ends an entry and digits are digits. */
const REQUEST_KEYS = ["*", "A", "B", "C", "D"];

export interface KeypadCollectorOptions {
  /** The longest entry, 1 to 32 digits. A tone past it discards the whole entry, up to `#`, a request or the idle timeout. */
  maxLength: number;
  /** Idle timeout in milliseconds, 1000 or more. */
  idleTimeoutMs: number;
  /** The longest the idle timeout may be lengthened to. Default: `idleTimeoutMs`, so it cannot be. */
  maxIdleTimeoutMs?: number;
  /** Keys that hand the host a request instead of digits, for example `{ "*": "repeat" }`. Keys: `*`, `A` to `D`. */
  requestKeys?: Readonly<Record<string, KeypadRequest>>;
  /** Gets the digits once `#` ends an entry. The only way digits leave the collector. */
  onDigits(digits: string): void;
  /** Gets a request. Required when `requestKeys` lists any key. */
  onRequest?(request: KeypadRequest): void;
  /** Told when a partial entry was dropped after the idle timeout. */
  onTimeout?(): void;
}

export class KeypadCollector {
  readonly #options: KeypadCollectorOptions;
  readonly #maxIdleTimeoutMs: number;
  #idleTimeoutMs: number;
  #digits = "";
  /** An entry ran past `maxLength`: the rest of it is discarded until `#`, a request or the idle timeout. */
  #overflow = false;
  #lastAt = 0;

  constructor(options: KeypadCollectorOptions) {
    const errors: string[] = [];
    if (!isIntegerIn(options.maxLength, 1, 32)) errors.push("maxLength must be 1 to 32");
    if (!isIntegerIn(options.idleTimeoutMs, 1000, Number.MAX_SAFE_INTEGER)) errors.push("idleTimeoutMs must be an integer of 1000 or more");
    const max = options.maxIdleTimeoutMs ?? options.idleTimeoutMs;
    if (!isIntegerIn(max, options.idleTimeoutMs, Number.MAX_SAFE_INTEGER)) errors.push("maxIdleTimeoutMs must be an integer of idleTimeoutMs or more");
    const requests = Object.entries(options.requestKeys ?? {});
    for (const [key, request] of requests) {
      if (!REQUEST_KEYS.includes(key)) errors.push(`request key ${JSON.stringify(key)} must be one of ${REQUEST_KEYS.join(", ")}`);
      if (request !== "repeat" && request !== "slower") errors.push(`request on ${key} must be repeat or slower`);
    }
    if (requests.length > 0 && options.onRequest === undefined) errors.push("onRequest is required with requestKeys");
    if (errors.length > 0) throw new EngineError("invalid_input", errors.join("; "));
    this.#options = options;
    this.#idleTimeoutMs = options.idleTimeoutMs;
    this.#maxIdleTimeoutMs = max;
  }

  /** The idle timeout in force now. */
  get idleTimeoutMs(): number {
    return this.#idleTimeoutMs;
  }

  /**
   * Lengthens the idle timeout by `ms`, up to the limit, for the rest of the call, and returns the
   * new timeout. It never touches the buffer or any attempt.
   */
  lengthenIdleTimeout(ms: number): number {
    if (!isIntegerIn(ms, 1, Number.MAX_SAFE_INTEGER)) throw new EngineError("invalid_input", "the timeout is lengthened by a positive whole number of milliseconds");
    this.#idleTimeoutMs = Math.min(this.#idleTimeoutMs + ms, this.#maxIdleTimeoutMs);
    return this.#idleTimeoutMs;
  }

  /**
   * One tone at `nowMs`. Digits are buffered and `#` hands them to `onDigits`. A request key drops
   * the buffer and hands its request to `onRequest`: the host replays its line, and no attempt is
   * used or given back. Any other key is ignored.
   */
  press(key: string, nowMs: number): void {
    this.tick(nowMs);
    // tick checked nowMs: a NaN here would stop every later timeout, keeping a partial entry forever.
    this.#lastAt = nowMs;
    if (/^[0-9]$/.test(key)) {
      if (this.#overflow) return;
      if (this.#digits.length < this.#options.maxLength) {
        this.#digits += key;
      } else {
        // An overlong entry is discarded whole: the digits after it never start a new entry.
        this.#digits = "";
        this.#overflow = true;
      }
      return;
    }
    if (key === "#") {
      const digits = this.#digits;
      this.#clear();
      if (digits !== "") this.#options.onDigits(digits);
      return;
    }
    const request = Object.hasOwn(this.#options.requestKeys ?? {}, key) ? this.#options.requestKeys![key] : undefined;
    if (request !== undefined) {
      this.#clear();
      this.#options.onRequest!(request);
    }
  }

  /** Drops a partial or overlong entry once the caller has been idle for the timeout. The host calls it from its own timer. */
  tick(nowMs: number): void {
    if (!Number.isFinite(nowMs)) throw new EngineError("invalid_input", "the time is a finite number of milliseconds");
    if (this.collecting && nowMs - this.#lastAt >= this.#idleTimeoutMs) {
      this.#clear();
      this.#options.onTimeout?.();
    }
  }

  /** Whether an entry is under way (an overlong one included). Never how long it is or what it holds. */
  get collecting(): boolean {
    return this.#digits !== "" || this.#overflow;
  }

  #clear(): void {
    this.#digits = "";
    this.#overflow = false;
  }

  toString(): string {
    return "[KeypadCollector]";
  }

  toJSON(): string {
    return "[KeypadCollector]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[KeypadCollector]";
  }
}
