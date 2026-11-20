// SRV-7: canonicalJson on any JSON value and on values JSON cannot carry. Every JSON value has one
// canonical form that parses back to it; anything else is refused with a TypeError, never dropped.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import { canonicalJson } from "../../src/core/canonical.ts";
import { fuzz, int, jsonValue, nastyString, pick, setOwn } from "./harness.ts";

/** A copy with every object's keys in an order drawn by `g`. */
function reorder(g: fc.GeneratorValue, value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => reorder(g, item));
  const keys = Object.keys(value);
  const out: Record<string, unknown> = {};
  for (const key of g(fc.shuffledSubarray, keys, { minLength: keys.length })) setOwn(out, key, reorder(g, (value as Record<string, unknown>)[key]));
  return out;
}

/** Orders two keys by UTF-16 code units, written out rather than left to `sort()`. */
function byCodeUnits(a: string, b: string): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** A second, independent writer of RFC 8785 for JSON values, to compare against. */
function reference(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(reference).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(byCodeUnits);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${reference(record[key])}`).join(",")}}`;
}

class Point {
  x = 1;
}

/** Values JSON cannot carry faithfully, each made fresh. */
const UNSUPPORTED: ReadonlyArray<() => unknown> = [
  () => undefined,
  () => () => 1,
  () => Symbol("s"),
  () => 1n,
  () => Number.NaN,
  () => Infinity,
  () => -Infinity,
  () => new Date(0),
  () => new Map([["a", 1]]),
  () => new Set([1]),
  () => new Point(),
  () => Object.create({ inherited: 1 }),
  () => new Number(1),
  () => new String("s"),
  () => new Uint8Array(2),
  () => /re/,
];

/** Whether a draw of `g` falls under `percent` out of 100. */
const chance = (g: fc.GeneratorValue, percent: number): boolean => int(g, 0, 99) < percent;

/** Puts one unsupported value (or a sparse array's hole) somewhere inside a JSON value. */
function plant(g: fc.GeneratorValue, value: unknown): unknown {
  const bad = () => (chance(g, 10) ? Object.assign([], { length: 1 }) : pick(g, UNSUPPORTED)());
  if (value === null || typeof value !== "object" || chance(g, 25)) {
    return chance(g, 50) ? bad() : chance(g, 50) ? [value, bad()] : Object.fromEntries([["k", bad()]]);
  }
  if (Array.isArray(value)) {
    const copy = [...value];
    if (copy.length === 0 || chance(g, 30)) {
      if (chance(g, 20)) copy.length += 1;
      else copy.splice(int(g, 0, copy.length), 0, bad());
    } else {
      const at = int(g, 0, copy.length - 1);
      copy[at] = plant(g, copy[at]);
    }
    return copy;
  }
  const copy: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) setOwn(copy, key, item);
  const keys = Object.keys(copy);
  if (keys.length === 0 || chance(g, 30)) setOwn(copy, g(nastyString, 4), bad());
  else {
    const key = pick(g, keys);
    setOwn(copy, key, plant(g, copy[key]));
  }
  return copy;
}

describe("fuzz: canonicalJson", () => {
  it("writes any JSON value in a form that parses back to it, and is its own canonical form", async () => {
    await fuzz(
      fc.property(jsonValue(4), (value) => {
        const text = canonicalJson(value);
        const parsed: unknown = JSON.parse(text);
        assert.deepEqual(parsed, value);
        assert.equal(canonicalJson(parsed), text);
        assert.equal(text, reference(value), "RFC 8785: keys by UTF-16 code units, no whitespace");
      }),
    );
  });

  it("gives the same text whatever the order of the keys", async () => {
    await fuzz(fc.property(jsonValue(4), fc.gen(), (value, g) => assert.equal(canonicalJson(reorder(g, value)), canonicalJson(value))));
  });

  it("refuses anything JSON cannot carry, wherever it is, with a TypeError naming the path", async () => {
    await fuzz(
      fc.property(jsonValue(3), fc.gen(), (json, g) => {
        const value = plant(g, json);
        assert.throws(
          () => canonicalJson(value),
          (e: unknown) => e instanceof TypeError && /^canonicalJson: (non-finite number|unsupported \w+|not a plain object) at \$/.test(e.message),
        );
      }),
    );
  });
});
