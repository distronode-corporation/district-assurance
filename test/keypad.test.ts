// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// INT-1: the keypad collector buffers tones until `#`, within a length and an idle timeout, and
// never shows a digit.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { inspect } from "node:util";

import { KeypadCollector, MAX_KEYPAD_DIGITS, MAX_KEYPAD_IDLE_MS, type KeypadCollectorOptions } from "../src/core/keypad.ts";
import { EngineError } from "../src/core/errors.ts";
import { FixedClock } from "../src/testing/fakes.ts";

function collector(options: Partial<KeypadCollectorOptions<string>> = {}) {
  const clock = new FixedClock();
  const received: string[] = [];
  const keypad = new KeypadCollector<string>({
    maxDigits: 6,
    idleTimeoutMs: 5000,
    clock,
    onDigits: (digits) => {
      received.push(digits);
      return `handled ${received.length}`;
    },
    ...options,
  });
  const keyAll = (tones: string) => [...tones].map((tone) => keypad.press(tone).status);
  return { clock, received, keypad, keyAll };
}

describe("KeypadCollector", () => {
  it("buffers digits until # and hands them to the callback once, returning its result", () => {
    const { keypad, received, keyAll } = collector();
    assert.deepEqual(keyAll("2468"), ["buffering", "buffering", "buffering", "buffering"]);
    assert.deepEqual(received, []);
    assert.deepEqual(keypad.press("#"), { status: "submitted", result: "handled 1", timedOut: false });
    assert.deepEqual(received, ["2468"]);
    assert.deepEqual(keypad.press("#"), { status: "empty", timedOut: false }, "the buffer was wiped");
    keyAll("13");
    assert.equal(keypad.press("#").status, "submitted");
    assert.deepEqual(received, ["2468", "13"]);
  });

  it("hands back an asynchronous callback's promise", async () => {
    const keypad = new KeypadCollector({ maxDigits: 4, idleTimeoutMs: 1000, clock: new FixedClock(), onDigits: async (digits) => ({ matched: digits === "1234" }) });
    for (const tone of "1234") keypad.press(tone);
    const pressed = keypad.press("#");
    assert.equal(pressed.status, "submitted");
    assert.deepEqual(await (pressed as { result: Promise<{ matched: boolean }> }).result, { matched: true });
  });

  it("starts over on *", () => {
    const { keypad, received, keyAll } = collector();
    assert.deepEqual(keyAll("99*12"), ["buffering", "buffering", "cleared", "buffering", "buffering"]);
    keypad.press("#");
    assert.deepEqual(received, ["12"]);
  });

  it("takes up to maxDigits, and discards the whole entry on one more", () => {
    const { keypad, received, keyAll } = collector({ maxDigits: 4 });
    assert.deepEqual(keyAll("12345"), ["buffering", "buffering", "buffering", "buffering", "overflow"]);
    assert.equal(keypad.press("#").status, "empty", "nothing of the long entry is submitted");
    keyAll("1234");
    keypad.press("#");
    assert.deepEqual(received, ["1234"]);
  });

  it("discards the entry on anything that is not a digit, * or #", () => {
    const { keypad, received } = collector();
    for (const tone of ["A", "D", "", "12", " ", "٣", 5 as unknown as string]) {
      keypad.press("7");
      assert.equal(keypad.press(tone).status, "rejected", JSON.stringify(tone));
      assert.equal(keypad.press("#").status, "empty");
    }
    assert.deepEqual(received, []);
  });

  it("ignores the rest of an overflowed entry until # ends it", () => {
    const { keypad, received, keyAll } = collector({ maxDigits: 4 });
    assert.deepEqual(keyAll("123456"), ["buffering", "buffering", "buffering", "buffering", "overflow", "discarding"]);
    assert.equal(keypad.press("#").status, "empty", "no tail of the long entry is submitted");
    keyAll("12");
    keypad.press("#");
    assert.deepEqual(received, ["12"], "the next entry is taken whole");
  });

  it("ignores the rest of a rejected entry until # ends it", () => {
    const { keypad, received, keyAll } = collector();
    assert.deepEqual(keyAll("12A3B4"), ["buffering", "buffering", "rejected", "discarding", "discarding", "discarding"]);
    assert.equal(keypad.press("#").status, "empty");
    assert.deepEqual(keyAll("A5"), ["rejected", "discarding"], "a rejected first tone discards the entry too");
    assert.equal(keypad.press("#").status, "empty");
    assert.deepEqual(received, []);
  });

  it("starts over on * or clear after a discarded entry", () => {
    const { keypad, received, keyAll } = collector({ maxDigits: 2 });
    assert.deepEqual(keyAll("123*45"), ["buffering", "buffering", "overflow", "cleared", "buffering", "buffering"]);
    keypad.press("#");
    keyAll("1A");
    keypad.clear();
    keyAll("67");
    keypad.press("#");
    assert.deepEqual(received, ["45", "67"]);
  });

  it("ends a discarded entry after idleTimeoutMs, each ignored tone restarting it", () => {
    const { keypad, clock, received, keyAll } = collector({ idleTimeoutMs: 5000 });
    keyAll("1A");
    clock.advance(4999);
    assert.deepEqual(keypad.press("2"), { status: "discarding", timedOut: false });
    clock.advance(4999);
    assert.equal(keypad.expire(), false);
    clock.advance(1);
    assert.equal(keypad.expire(), true);
    assert.equal(keypad.expire(), false);
    keyAll("1A");
    clock.advance(5000);
    assert.deepEqual(keypad.press("3"), { status: "buffering", timedOut: true }, "the tone starts a new entry");
    keypad.press("#");
    assert.deepEqual(received, ["3"]);
  });

  it("discards an entry left idle for idleTimeoutMs, on the next tone or on expire", () => {
    const { keypad, clock, received, keyAll } = collector({ idleTimeoutMs: 5000 });
    keyAll("12");
    clock.advance(4999);
    keyAll("3");
    clock.advance(4999);
    assert.deepEqual(keypad.press("#"), { status: "submitted", result: "handled 1", timedOut: false }, "each tone restarts the timeout");

    keyAll("45");
    clock.advance(5000);
    assert.deepEqual(keypad.press("#"), { status: "empty", timedOut: true });
    keyAll("67");
    clock.advance(5000);
    assert.deepEqual(keypad.press("8"), { status: "buffering", timedOut: true }, "the tone starts a new entry");
    keypad.press("#");
    assert.deepEqual(received, ["123", "8"]);

    keyAll("9");
    clock.advance(4999);
    assert.equal(keypad.expire(), false);
    clock.advance(1);
    assert.equal(keypad.expire(), true);
    assert.equal(keypad.expire(), false, "nothing left to discard");
    assert.equal(keypad.press("#").status, "empty");
  });

  it("discards an entry when the clock was set back, so it never outlives its timeout", () => {
    const { keypad, clock, received, keyAll } = collector({ idleTimeoutMs: 5000 });
    keyAll("12");
    clock.advance(-60_000);
    assert.deepEqual(keypad.press("#"), { status: "empty", timedOut: true });
    keyAll("34");
    clock.advance(-1);
    assert.equal(keypad.expire(), true);
    assert.deepEqual(received, []);
  });

  it("an empty collector never times out", () => {
    const { keypad, clock } = collector();
    clock.advance(10 * 60_000);
    assert.equal(keypad.expire(), false);
    assert.deepEqual(keypad.press("1"), { status: "buffering", timedOut: false });
  });

  it("clear discards an unfinished entry", () => {
    const { keypad, received, keyAll } = collector();
    keyAll("555");
    keypad.clear();
    assert.equal(keypad.press("#").status, "empty");
    assert.deepEqual(received, []);
  });

  it("wipes the buffer before the callback runs, even when it throws", () => {
    const keypad = new KeypadCollector({
      maxDigits: 4,
      idleTimeoutMs: 1000,
      clock: new FixedClock(),
      onDigits: () => {
        throw new Error("host failure");
      },
    });
    keypad.press("1");
    assert.throws(() => keypad.press("#"), /host failure/);
    assert.equal(keypad.press("#").status, "empty");
  });

  it("shows no digit, nor how many, through toString, JSON or inspect", () => {
    const { keypad, keyAll } = collector();
    const empty = [String(keypad), JSON.stringify(keypad), inspect(keypad, { showHidden: true, depth: null }), `${keypad}`];
    keyAll("314159");
    const shown = [String(keypad), JSON.stringify(keypad), inspect(keypad, { showHidden: true, depth: null }), `${keypad}`, JSON.stringify({ keypad })];
    assert.deepEqual(shown.slice(0, 4), empty, "a full buffer looks like an empty one");
    for (const text of shown) assert.doesNotMatch(text, /[0-9]/, text);
    assert.deepEqual(Object.keys(keypad), []);
  });

  it("puts no digit in a press result", () => {
    const { keypad, keyAll } = collector({ onDigits: () => "ok" });
    keyAll("4242");
    for (const tone of ["4", "*", "4", "A", "4", "#"]) assert.doesNotMatch(JSON.stringify(keypad.press(tone)), /4/);
  });

  it("refuses bad options", () => {
    const onDigits = () => {};
    for (const options of [
      { maxDigits: 0, idleTimeoutMs: 1000, onDigits },
      { maxDigits: MAX_KEYPAD_DIGITS + 1, idleTimeoutMs: 1000, onDigits },
      { maxDigits: 4.5, idleTimeoutMs: 1000, onDigits },
      { maxDigits: 4, idleTimeoutMs: 0, onDigits },
      { maxDigits: 4, idleTimeoutMs: MAX_KEYPAD_IDLE_MS + 1, onDigits },
      { maxDigits: 4, idleTimeoutMs: Number.NaN, onDigits },
      { maxDigits: 4, idleTimeoutMs: 1000, onDigits: "not a function" as unknown as () => void },
      { maxDigits: 4, idleTimeoutMs: 1000, onDigits, maxDigit: 8 },
      { maxDigits: 4, idleTimeoutMs: 1000, onDigits, clock: new FixedClock(), logDigits: true },
      { maxDigits: 4, idleTimeoutMs: 1000, onDigits, clock: { now: "2026-01-01" } },
      { maxDigits: 4, idleTimeoutMs: 1000, onDigits, clock: null },
      null,
      [],
    ]) {
      assert.throws(() => new KeypadCollector(options as KeypadCollectorOptions<void>),(e: unknown) => e instanceof EngineError && e.code === "invalid_input", JSON.stringify(options));
    }
    assert.doesNotThrow(() => new KeypadCollector({ maxDigits: MAX_KEYPAD_DIGITS, idleTimeoutMs: MAX_KEYPAD_IDLE_MS, onDigits }));
    assert.doesNotThrow(() => new KeypadCollector({ maxDigits: 1, idleTimeoutMs: 1, onDigits }));
    assert.doesNotThrow(() => new KeypadCollector({ maxDigits: 4, idleTimeoutMs: 1000, onDigits, clock: new FixedClock() }));
  });

  it("uses the system clock when none is given", () => {
    const keypad = new KeypadCollector({ maxDigits: 4, idleTimeoutMs: MAX_KEYPAD_IDLE_MS, onDigits: (digits) => digits.length });
    keypad.press("1");
    assert.equal(keypad.expire(), false);
    assert.deepEqual(keypad.press("#"), { status: "submitted", result: 1, timedOut: false });
  });
});
