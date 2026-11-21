// `isWeakPin` from the package root, as a host imports it: the digits-only rule `enrolPin` and
// `enrolDuressPin` refuse as `weak`, so a host taking PINs itself refuses the same ones. It fails
// closed: anything that is not a well-formed PIN is weak.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import { isWeakPin } from "../src/index.ts";
import { DIGITS, fuzz, jsonValue, nastyString } from "./fuzz/harness.ts";

/**
 * The rule written out the long way: anything but one to 32 ASCII digits is weak; one digit is not;
 * otherwise one digit repeated, or each digit one up or one down (mod 10) from the last.
 */
function modelWeak(value: unknown): boolean {
  if (typeof value !== "string" || !/^[0-9]{1,32}$/.test(value)) return true;
  if (value.length === 1) return false;
  const digits = [...value].map(Number);
  const step = (i: number) => (digits[i]! - digits[i - 1]! + 10) % 10;
  const first = step(1);
  return [0, 1, 9].includes(first) && digits.every((_, i) => i === 0 || step(i) === first);
}

describe("isWeakPin from the package root", () => {
  it("is weak for one digit repeated and for runs up or down, through 0", () => {
    for (const pin of ["0000", "1111", "999999", "1234", "4321", "7890", "0987", "9012", "8901", "0123456789", "12", "00", "1".repeat(32)]) {
      assert.equal(isWeakPin(pin), true, pin);
    }
  });

  it("is not weak for any other digits", () => {
    for (const pin of ["5831", "1235", "1212", "1357", "2468", "1243", "0001", "9990", "12345670", "1122", "0918"]) {
      assert.equal(isWeakPin(pin), false, pin);
    }
  });

  it("judges one digit on its pattern only: length is the host's rule", () => {
    for (const pin of ["0", "7"]) assert.equal(isWeakPin(pin), false, pin);
  });

  it("is true, so refused, for anything that is not one to 32 ASCII digits, never coercing it", () => {
    const hostile: unknown[] = [
      "",
      undefined,
      null,
      1111,
      1234n,
      true,
      ["1111"],
      { toString: () => "1111" },
      { length: 4, 0: "1", 1: "1", 2: "1", 3: "1" },
      new String("1111"),
      Symbol("1111"),
      () => "1111",
      " 1111",
      "1111 ",
      "1111\n",
      "1 1 1 1",
      "    ",
      "\t\t\t\t",
      "11a1",
      "aaaa",
      "1.11",
      "-111",
      "+1234",
      "1e10",
      "0x11",
      "１１１１", // full-width digits
      "١٢٣٤", // Arabic-Indic digits
      "1111\u0000",
      "1".repeat(33),
      "1234567890".repeat(4),
      "5831".repeat(9), // a strong pattern, but 36 digits
      "5831 ",
      "５８３１", // full-width digits of a strong pattern
      { toString: () => "5831" },
      5831,
    ];
    for (const value of hostile) assert.equal(isWeakPin(value as string), true, typeof value === "symbol" ? value.toString() : JSON.stringify(String(value)));
  });

  it("agrees with the rule written out, on digits and on anything else", async () => {
    const digits = fc.array(fc.constantFrom(...DIGITS), { minLength: 0, maxLength: 34 }).map((d) => d.join(""));
    // Runs and repeats from a random start, so the weak side is reached as often as the other.
    const patterned = fc
      .tuple(fc.integer({ min: 0, max: 9 }), fc.constantFrom(0, 1, 9, 2, 5), fc.integer({ min: 1, max: 34 }))
      .map(([start, step, length]) => Array.from({ length }, (_, i) => String((start + i * step) % 10)).join(""));
    await fuzz(
      fc.property(fc.oneof(digits, patterned, nastyString(), jsonValue()), (value) => {
        assert.equal(isWeakPin(value as string), modelWeak(value));
      }),
    );
  });
});
