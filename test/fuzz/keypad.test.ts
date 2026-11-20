// SRV-7: the keypad collector (INT-1) on hostile tones, clocks and options. Every run of tones is
// checked against a small model of the rules, and nothing the collector shows ever has a digit.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { inspect } from "node:util";

import fc from "fast-check";

import { EngineError } from "../../src/core/errors.ts";
import { KeypadCollector, MAX_KEYPAD_DIGITS, MAX_KEYPAD_IDLE_MS } from "../../src/core/keypad.ts";
import { FixedClock } from "../../src/testing/fakes.ts";
import { DIGITS, fuzz, jsonValue, nastyString } from "./harness.ts";

type Step = { tone: unknown; advanceMs: number } | { expire: true; advanceMs: number } | { clear: true; advanceMs: number };

interface Plan {
  maxDigits: number;
  idleTimeoutMs: number;
  steps: Step[];
}

/** Mostly digits, `*` and `#`, with keypad letters, junk strings and values that are not strings. */
const tone: fc.Arbitrary<unknown> = fc.oneof(
  { weight: 65, arbitrary: fc.constantFrom(...DIGITS) },
  { weight: 10, arbitrary: fc.constant("#") },
  { weight: 5, arbitrary: fc.constant("*") },
  { weight: 10, arbitrary: fc.constantFrom("A", "B", "C", "D", "", "##", "12", " 1", "1 ", "٣", "１", "0\n") },
  { weight: 5, arbitrary: nastyString(3) },
  { weight: 5, arbitrary: jsonValue(1) },
);

function step(idleTimeoutMs: number): fc.Arbitrary<Step> {
  const advanceMs = fc.oneof(
    { weight: 7, arbitrary: fc.constant(0) },
    { weight: 3, arbitrary: fc.oneof(fc.constantFrom(1, idleTimeoutMs - 1, idleTimeoutMs, idleTimeoutMs + 1), fc.integer({ min: 0, max: 2 * idleTimeoutMs })) },
  );
  return fc.oneof(
    { weight: 5, arbitrary: advanceMs.map((ms): Step => ({ expire: true, advanceMs: ms })) },
    { weight: 3, arbitrary: advanceMs.map((ms): Step => ({ clear: true, advanceMs: ms })) },
    { weight: 92, arbitrary: fc.tuple(tone, advanceMs).map(([t, ms]): Step => ({ tone: t, advanceMs: ms })) },
  );
}

const plan: fc.Arbitrary<Plan> = fc
  .tuple(fc.integer({ min: 1, max: MAX_KEYPAD_DIGITS }), fc.oneof(fc.constantFrom(1, 2, MAX_KEYPAD_IDLE_MS), fc.integer({ min: 1, max: 5000 })))
  .chain(([maxDigits, idleTimeoutMs]) => fc.array(step(idleTimeoutMs), { maxLength: 80 }).map((steps) => ({ maxDigits, idleTimeoutMs, steps })));

describe("fuzz: KeypadCollector", () => {
  it("follows the rules on any run of tones, clock moves, expiries and clears", async () => {
    await fuzz(fc.property(plan, (p) => {
      const clock = new FixedClock();
      const received: string[] = [];
      const keypad = new KeypadCollector({ maxDigits: p.maxDigits, idleTimeoutMs: p.idleTimeoutMs, clock, onDigits: (digits) => received.push(digits) });
      // The model: the digits buffered, whether the entry is being discarded (after an overflow or
      // a rejection, until `#`, `*`, a clear or the idle timeout), and the time of the last tone.
      let buffer = "";
      let discarding = false;
      let lastAt = 0;
      const expected: string[] = [];
      const modelExpire = () => {
        if ((buffer === "" && !discarding) || clock.now().getTime() - lastAt < p.idleTimeoutMs) return false;
        buffer = "";
        discarding = false;
        return true;
      };
      for (const step of p.steps) {
        clock.advance(step.advanceMs);
        if ("expire" in step) {
          assert.equal(keypad.expire(), modelExpire());
          continue;
        }
        if ("clear" in step) {
          keypad.clear();
          buffer = "";
          discarding = false;
          continue;
        }
        const timedOut = modelExpire();
        let status: string;
        if (step.tone === "#") {
          status = buffer === "" ? "empty" : "submitted";
          if (buffer !== "") expected.push(buffer);
          buffer = "";
          discarding = false;
        } else if (step.tone === "*") {
          status = "cleared";
          buffer = "";
          discarding = false;
        } else {
          lastAt = clock.now().getTime();
          if (discarding) status = "discarding";
          else if (typeof step.tone !== "string" || !/^[0-9]$/.test(step.tone) || buffer.length === p.maxDigits) {
            status = typeof step.tone !== "string" || !/^[0-9]$/.test(step.tone) ? "rejected" : "overflow";
            buffer = "";
            discarding = true;
          } else {
            status = "buffering";
            buffer += step.tone;
          }
        }
        const pressed = keypad.press(step.tone as string);
        assert.equal(pressed.status, status, `tone ${inspect(step.tone)}`);
        assert.equal(pressed.timedOut, timedOut);
        // The callback returns a count, so a result never carries a digit the caller keyed.
        const shown = { ...pressed, result: undefined };
        assert.doesNotMatch(JSON.stringify(shown), /[0-9]/);
      }
      assert.deepEqual(received, expected);
      for (const digits of received) {
        assert.match(digits, /^[0-9]+$/);
        assert.ok(digits.length <= p.maxDigits);
      }
      // Whatever is buffered, nothing shows it.
      for (const text of [String(keypad), JSON.stringify(keypad), inspect(keypad, { showHidden: true, depth: null })]) assert.doesNotMatch(text, /[0-9]/);
    }));
  });

  it("refuses bad options with invalid_input, and nothing else", async () => {
    const value: fc.Arbitrary<unknown> = fc.oneof(
      fc.integer({ min: -2, max: MAX_KEYPAD_IDLE_MS + 2 }),
      fc.constantFrom(0, 1, MAX_KEYPAD_DIGITS, MAX_KEYPAD_DIGITS + 1, MAX_KEYPAD_IDLE_MS, MAX_KEYPAD_IDLE_MS + 1, 1.5, -0, Number.NaN, Infinity, 2 ** 53),
      fc.integer({ min: 1, max: 10 }).map(String),
      jsonValue(1),
      fc.constant(undefined),
    );
    const onDigits = fc.oneof({ weight: 4, arbitrary: fc.constant((): undefined => undefined) }, { weight: 1, arbitrary: jsonValue(1) });
    await fuzz(
      fc.property(fc.record({ maxDigits: value, idleTimeoutMs: value, onDigits }), (options) => {
        const good =
          Number.isInteger(options.maxDigits) &&
          (options.maxDigits as number) >= 1 &&
          (options.maxDigits as number) <= MAX_KEYPAD_DIGITS &&
          Number.isInteger(options.idleTimeoutMs) &&
          (options.idleTimeoutMs as number) >= 1 &&
          (options.idleTimeoutMs as number) <= MAX_KEYPAD_IDLE_MS &&
          typeof options.onDigits === "function";
        const make = () => new KeypadCollector(options as unknown as ConstructorParameters<typeof KeypadCollector>[0]);
        if (good) assert.doesNotThrow(make);
        else assert.throws(make, (e: unknown) => e instanceof EngineError && e.code === "invalid_input");
      }),
    );
  });
});
