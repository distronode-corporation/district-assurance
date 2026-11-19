// Hostile-pass regressions for #91 (PRV-6): SIN, health card and bank number redactors.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  REDACTION_MARKERS,
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
