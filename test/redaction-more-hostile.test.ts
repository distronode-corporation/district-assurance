// Hostile-pass regressions for #91 (PRV-6): SIN, health card and bank number redactors.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  REDACTION_MARKERS,
  applyFindings,
  bankAccountRedactor,
  cardNumberRedactor,
  composeRedactors,
  healthCardRedactor,
  luhnValid,
  sinRedactor,
} from "../src/core/redaction.ts";

const SIN = "046454286";
/** A 10-digit Ontario-style number that passes Luhn. */
const ONTARIO = (() => {
  for (let d = 0; d < 10; d++) if (luhnValid(`123456789${d}`)) return `123456789${d}`;
  throw new Error("none");
})();
const all = composeRedactors(cardNumberRedactor, healthCardRedactor, sinRedactor, bankAccountRedactor);

describe("hostile #91: separators", () => {
  const separators: Record<string, string> = {
    "en dash": "–",
    "em dash": "—",
    "minus sign": "−",
    "zero-width space": "​",
    "soft hyphen": "­",
    "right-to-left override": "‮",
    "combining mark": "́",
  };
  for (const [name, sep] of Object.entries(separators)) {
    it(`redacts a SIN, a health card and a bank number grouped with a ${name}`, () => {
      assert.equal(sinRedactor.redact([SIN.slice(0, 3), SIN.slice(3, 6), SIN.slice(6)].join(sep)).text, REDACTION_MARKERS.sin, name);
      assert.equal(healthCardRedactor.redact([ONTARIO.slice(0, 4), ONTARIO.slice(4, 7), ONTARIO.slice(7)].join(sep)).text, REDACTION_MARKERS.health_card, name);
      assert.equal(healthCardRedactor.redact(`TREM${sep}7501${sep}0112`).text, REDACTION_MARKERS.health_card, `${name} in a Quebec number`);
      assert.equal(bankAccountRedactor.redact(`account 1234${sep}5678`).text, `account ${REDACTION_MARKERS.bank_account}`, name);
    });
  }
});

describe("hostile #91: what holds", () => {
  it("composed findings point at the original input: applied there in position order, they give the composed text", () => {
    const text = `card 4111 1111 1111 1111, health ${ONTARIO}, sin ${SIN}, account 12345678, card again 4111111111111111`;
    const result = all.redact(text);
    // Reported in redactor order, as composeRedactors documents; sorted here before they are applied.
    assert.deepEqual(result.findings.map((f) => f.kind), ["card_number", "card_number", "health_card", "sin", "bank_account"]);
    let rebuilt = "";
    let at = 0;
    for (const f of [...result.findings].sort((x, y) => x.start - y.start)) {
      rebuilt += text.slice(at, f.start) + REDACTION_MARKERS[f.kind];
      at = f.end;
    }
    rebuilt += text.slice(at);
    assert.equal(rebuilt, result.text);
    assert.equal(/\d{3}/.test(result.text), false, result.text);
  });

  it("never throws on hostile text, and prototype keys are not bank words", () => {
    for (const text of ["constructor 12345678", "__proto__ 12345678", "\ud800 046 454 286", "x".repeat(200_000) + " account 1234"]) {
      assert.doesNotThrow(() => all.redact(text));
    }
    assert.equal(bankAccountRedactor.redact("constructor 12345678").findings.length, 0);
  });
});

describe("hostile #91: more separators, decimal digits in any script, and words", () => {
  const script = (zero: number) => (digits: string) => Array.from(digits, (d) => String.fromCodePoint(zero + Number(d))).join("");
  for (const [name, sep] of Object.entries({ slash: "/", underscore: "_", "middle dot": "\u00b7" })) {
    it(`redacts a SIN, a health card and a bank number grouped with a ${name}`, () => {
      assert.equal(sinRedactor.redact([SIN.slice(0, 3), SIN.slice(3, 6), SIN.slice(6)].join(sep)).text, REDACTION_MARKERS.sin);
      assert.equal(healthCardRedactor.redact(`TREM${sep}7501${sep}0112`).text, REDACTION_MARKERS.health_card);
      assert.equal(bankAccountRedactor.redact(`account 1234${sep}5678`).text, `account ${REDACTION_MARKERS.bank_account}`);
    });
  }

  for (const [name, write] of Object.entries({ fullwidth: script(0xff10), "Arabic-Indic": script(0x0660), Devanagari: script(0x0966), "mathematical bold (astral)": script(0x1d7ce) })) {
    it(`reads ${name} digits by their values for every check, and removes the original span`, () => {
      assert.equal(sinRedactor.redact(`sin ${write(SIN)} ok`).text, `sin ${REDACTION_MARKERS.sin} ok`);
      assert.equal(healthCardRedactor.redact(`health ${write(ONTARIO)} ok`).text, `health ${REDACTION_MARKERS.health_card} ok`);
      assert.equal(healthCardRedactor.redact(`TREM ${write("75010112")}`).text, REDACTION_MARKERS.health_card);
      assert.equal(bankAccountRedactor.redact(`account ${write("12345678")}`).text, `account ${REDACTION_MARKERS.bank_account}`);
      const bad = `${SIN.slice(0, 8)}${(Number(SIN[8]) + 1) % 10}`;
      assert.equal(sinRedactor.redact(write(bad)).text, write(bad), "the Luhn check runs on the values");
    });
  }

  it("reads prototype keys as words, never as inherited functions", () => {
    for (const word of ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"]) {
      assert.equal(bankAccountRedactor.redact(`account ${word} 12345678`).text, `account ${word} ${REDACTION_MARKERS.bank_account}`, word);
    }
  });
});

describe("hostile #91: applyFindings takes findings in any order", () => {
  it("applies composed findings in redactor order to the original, and nothing after the first kind leaks", () => {
    const text = `card 4111 1111 1111 1111, health ${ONTARIO}, sin ${SIN}, account 12345678, card again 4111111111111111`;
    const result = all.redact(text);
    assert.deepEqual(result.findings.map((f) => f.kind), ["card_number", "card_number", "health_card", "sin", "bank_account"], "redactor order, as documented");
    assert.equal(applyFindings(text, result.findings), result.text);
    assert.equal(/\d{3}/.test(applyFindings(text, result.findings)), false);
  });

  it("merges overlapping findings, so no part of either is left", () => {
    const text = "a 0123456789 b";
    const findings = [
      { kind: "sin" as const, start: 6, end: 12 },
      { kind: "card_number" as const, start: 2, end: 8 },
      { kind: "bank_account" as const, start: 2, end: 4 },
    ];
    assert.equal(applyFindings(text, findings), `a ${REDACTION_MARKERS.card_number} b`);
    assert.equal(applyFindings(text, []), text);
    assert.deepEqual(findings[1], { kind: "card_number", start: 2, end: 8 }, "the caller's findings are left as they were");
  });
});
