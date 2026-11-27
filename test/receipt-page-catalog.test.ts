// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The receipt page's words (PAGE_TEXT in the reference server): the same keys in English and
// French, and a word for every payment status, so a status another change adds fails here, loudly,
// instead of showing its raw name on the page.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { PAGE_TEXT } from "../examples/reference-server/src/app.ts";
import type { PaymentStatus } from "../src/pay/payment.ts";

/** Lists every member of a union: the compiler refuses a list that misses one. */
type Missing<All, Listed> = [Exclude<All, Listed>] extends [never] ? unknown : { missing: Exclude<All, Listed> };
const membersOf =
  <T extends string>() =>
  <const L extends readonly T[]>(list: L & Missing<T, L[number]>): readonly T[] =>
    list;

/** Every payment status this branch knows. A new one fails typecheck here until it is listed. */
const STATUSES = membersOf<PaymentStatus>()(["open", "paid", "failed", "expired"]);

/** Every key path of a catalog, functions as leaves. */
function paths(value: unknown, at = ""): string[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return [at];
  return Object.entries(value).flatMap(([key, inner]) => paths(inner, at === "" ? key : `${at}.${key}`));
}

describe("the receipt page's words", () => {
  it("have the same keys in English and French", () => {
    assert.deepEqual(paths(PAGE_TEXT.fr).sort(), paths(PAGE_TEXT.en).sort());
  });

  it("have a word for every payment status, in both locales, of its own", () => {
    for (const locale of ["en", "fr"] as const) {
      for (const status of STATUSES) {
        assert.ok(Object.hasOwn(PAGE_TEXT[locale].status, status), `${locale}: no word for the payment status ${status}`);
        assert.notEqual(PAGE_TEXT[locale].status[status], "", `${locale}: ${status}`);
      }
    }
    assert.notDeepEqual(PAGE_TEXT.fr.status, PAGE_TEXT.en.status, "French has its own words");
  });
});
