// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// SRV-7: the shared settings and value generators of the property and fuzz suites under
// test/property and test/fuzz, on fast-check (a development dependency only, ADR-3). Each property
// runs at least a fixed number of cases, then more until its time budget is spent, and a failure
// prints fast-check's seed and path, which replay that one case.
//
// Environment, all optional:
// - DA_FUZZ_MS: the time budget of each property in milliseconds, after its first cases (default
//   200, CI's bar). The scheduled fuzz workflow sets it much higher. The first cases and the order
//   of the later ones are fixed by the seed; how many later batches fit in the budget depends on
//   the machine, so a failure found only on a faster runner needs the seed and path it printed.
// - DA_FUZZ_SEED: the run's seed (default fixed, so CI is repeatable). fast-check uses its low 32
//   bits, and a failure prints the seed it used.
// - DA_FUZZ_PATH: with DA_FUZZ_SEED, replays the one case a failure printed (`path: "..."`). Run
//   it with `--test-name-pattern` on the failing property, since a path belongs to one property.
//
// Inputs that found bugs are kept as `examples` of their property, so they run first, always.
import fc from "fast-check";

function envInteger(name: string, fallback: number, min: number): number {
  const text = process.env[name];
  if (text === undefined || text === "") return fallback;
  const value = Number(text);
  if (!/^-?\d+$/.test(text) || !Number.isSafeInteger(value) || value < min) throw new Error(`${name} must be an integer of at least ${min}`);
  return value;
}

export const FUZZ_MS = envInteger("DA_FUZZ_MS", 200, 0);
export const FUZZ_SEED = envInteger("DA_FUZZ_SEED", 0xda5eed, Number.MIN_SAFE_INTEGER) | 0;
const FUZZ_PATH = process.env.DA_FUZZ_PATH === undefined || process.env.DA_FUZZ_PATH === "" ? undefined : process.env.DA_FUZZ_PATH;

export interface FuzzOptions<Ts> {
  /** Inputs that found bugs: run first on every run, whatever the budget. */
  examples?: Ts[];
  /** Cases to run even when the budget is spent. Default 20. */
  minRuns?: number;
  /** Most cases to run, whatever the budget: for a property that uses up something finite (ports). */
  maxRuns?: number;
}

/** Cases per batch in the timed phase: each batch runs to its end, so no case is left running. */
const BATCH = 10;

/**
 * Runs a fast-check property: its examples and `minRuns` cases on the run's seed, then batches of
 * more cases on the next seeds until DA_FUZZ_MS is spent (or `maxRuns` cases ran). Every run of
 * fast-check carries the examples first, and fast-check counts them inside `numRuns`, so each run
 * asks for its cases plus the examples. A batch is awaited in full: a case still running when the
 * budget is spent finishes and its failure is reported, and the budget only stops new batches.
 * With DA_FUZZ_PATH set, it replays that one case on the stream of the run that printed it (the
 * printed seed, its examples first).
 */
export async function fuzz<Ts>(property: fc.IProperty<Ts> | fc.IAsyncProperty<Ts>, options: FuzzOptions<Ts> = {}): Promise<void> {
  const raw = property as fc.IRawProperty<Ts>;
  const examples = options.examples ?? [];
  if (FUZZ_PATH !== undefined) {
    await fc.assert(raw, { seed: FUZZ_SEED, path: FUZZ_PATH, endOnFailure: true, examples });
    return;
  }
  const minRuns = options.minRuns ?? 20;
  const maxRuns = options.maxRuns ?? Number.MAX_SAFE_INTEGER;
  await fc.assert(raw, { seed: FUZZ_SEED, numRuns: minRuns + examples.length, examples });
  const deadline = Date.now() + FUZZ_MS;
  for (let ran = minRuns, batch = 1; FUZZ_MS > 0 && ran < maxRuns && Date.now() < deadline; batch++) {
    const runs = Math.min(BATCH, maxRuns - ran);
    await fc.assert(raw, { seed: (FUZZ_SEED + batch) | 0, numRuns: runs + examples.length, examples });
    ran += runs;
  }
}

export const DIGITS = [..."0123456789"];
export const PRINTABLE = [..." !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"];
/** Characters and runs that have broken parsers before: controls, quotes, escapes, separators, non-ASCII, lone surrogates. */
export const NASTY = [
  ...PRINTABLE,
  "\u0000",
  "\t",
  "\n",
  "\r",
  "\u001f",
  "\u007f",
  "é",
  " ",
  " ",
  " ",
  "﻿",
  "😀",
  "\ud800",
  "\udfff",
  "٣",
  "０",
  "__proto__",
  "constructor",
  "=",
  ",",
  "%00",
  "../",
];

/** One unit of a hostile string: mostly from NASTY, sometimes any code point fast-check draws. */
const nastyUnit: fc.Arbitrary<string> = fc.oneof(
  { weight: 4, arbitrary: fc.constantFrom(...NASTY) },
  { weight: 1, arbitrary: fc.string({ unit: "binary", minLength: 1, maxLength: 1 }) },
);

/** A string of up to `maxLength` hostile units. */
export function nastyString(maxLength = 12): fc.Arbitrary<string> {
  return fc.string({ unit: nastyUnit, maxLength });
}

/**
 * A string of up to `maxLength` hostile units with each lone surrogate made U+FFFD: text canonical
 * JSON (RFC 8785) can carry, for values that must be valid.
 */
export function nastyText(maxLength = 12): fc.Arbitrary<string> {
  return nastyString(maxLength).map((s) => s.toWellFormed());
}

/** A string of up to `maxLength` printable ASCII characters. */
export function printableString(maxLength: number): fc.Arbitrary<string> {
  return fc.string({ unit: fc.constantFrom(...PRINTABLE), maxLength });
}

/** Sets an own, enumerable property, so a key named `__proto__` is data, not the prototype. */
export function setOwn(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

/** A JSON number: integers, fractions, exponents, extremes. Never -0, which JSON writes as 0. */
export const jsonNumber: fc.Arbitrary<number> = fc
  .oneof(
    fc.integer({ min: -1000, max: 1000 }),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    fc.constantFrom(Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Number.MAX_VALUE, Number.MIN_VALUE, -Number.MAX_VALUE, 1e21, 1e-7, 0.1, 2 ** 53 + 2),
  )
  .map((value) => (Object.is(value, -0) ? 0 : value));

/** An object of up to `maxKeys` own properties with hostile keys (`__proto__` among them, as data). */
export function ownObject<T>(value: fc.Arbitrary<T>, maxKeys = 5, key: fc.Arbitrary<string> = nastyString(6)): fc.Arbitrary<Record<string, T>> {
  return fc.array(fc.tuple(key, value), { maxLength: maxKeys }).map((entries) => {
    const object: Record<string, T> = {};
    for (const [key, item] of entries) setOwn(object, key, item);
    return object;
  });
}

/**
 * Any JSON value, nested up to `depth`. Its strings and keys may hold lone surrogates, which
 * `JSON.stringify` writes but canonical JSON refuses; `wellFormed` leaves them out.
 */
export function jsonValue(depth = 3, wellFormed = false): fc.Arbitrary<unknown> {
  const text = wellFormed ? nastyText : nastyString;
  const leaf = fc.oneof(fc.constant(null), fc.boolean(), jsonNumber, text(12));
  if (depth <= 0) return leaf;
  const child = jsonValue(depth - 1, wellFormed);
  return fc.oneof({ weight: 4, arbitrary: leaf }, { weight: 1, arbitrary: fc.array(child, { maxLength: 4 }) }, { weight: 2, arbitrary: ownObject(child, 5, text(6)) });
}

/** A JSON object (the shape a ledger detail must have). */
export function jsonObject(depth = 3): fc.Arbitrary<Record<string, unknown>> {
  return ownObject(jsonValue(depth - 1));
}

/** An integer from min to max, both included, drawn inside a property through `fc.gen()`. */
export function int(g: fc.GeneratorValue, min: number, max: number): number {
  return g(fc.integer, { min, max });
}

/** One of the items, drawn inside a property through `fc.gen()`. */
export function pick<T>(g: fc.GeneratorValue, items: readonly T[]): T {
  return items[int(g, 0, items.length - 1)]!;
}

/**
 * Changes a JSON-like value in one place: a replaced, removed or added member somewhere inside,
 * or a wholly different value. Returns a new value; the input is not touched.
 */
export function mutate(g: fc.GeneratorValue, value: unknown, depth = 0): unknown {
  if (depth > 6 || value === null || typeof value !== "object" || int(g, 0, 99) < 15) {
    return pick<() => unknown>(g, [
      () => g(jsonValue, 2),
      () => undefined,
      () => pick(g, [Number.NaN, Infinity, -1, 0, 1.5, 2 ** 53, "", " ", "\u0000", [], {}, true, null]),
      () => (typeof value === "string" ? value + pick(g, NASTY) : g(nastyString)),
      () => (typeof value === "number" ? value + pick(g, [-1, 1, 0.5]) : g(() => jsonNumber)),
    ])();
  }
  if (Array.isArray(value)) {
    const copy = [...value];
    const action = copy.length === 0 ? 2 : int(g, 0, 3);
    const at = int(g, 0, Math.max(0, copy.length - 1));
    if (action === 0) copy[at] = mutate(g, copy[at], depth + 1);
    else if (action === 1) copy.splice(at, 1);
    else if (action === 2) copy.splice(at, 0, g(jsonValue, 2));
    else copy.length += 1;
    return copy;
  }
  const copy: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) setOwn(copy, key, item);
  const keys = Object.keys(copy);
  const action = keys.length === 0 ? 2 : int(g, 0, 2);
  const key = keys.length === 0 ? "" : pick(g, keys);
  if (action === 0) setOwn(copy, key, mutate(g, copy[key], depth + 1));
  else if (action === 1) delete copy[key];
  else setOwn(copy, int(g, 0, 9) < 3 ? pick(g, ["__proto__", "constructor", "toString", "hasOwnProperty"]) : g(nastyString, 8), g(jsonValue, 2));
  return copy;
}

/** A copy of the bytes with one byte changed to a different value. */
export const flipByte = (bytes: Buffer): fc.Arbitrary<Buffer> =>
  fc.tuple(fc.integer({ min: 0, max: Math.max(0, bytes.length - 1) }), fc.integer({ min: 1, max: 255 })).map(([at, delta]) => {
    const out = Buffer.from(bytes);
    out[at] = (out[at]! + delta) % 256;
    return out;
  });
