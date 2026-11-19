import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  applyFindings,
  bankAccountRedactor,
  cardNumberRedactor,
  composeRedactors,
  findBankNumbers,
  findCardNumbers,
  findHealthCardNumbers,
  findSocialInsuranceNumbers,
  healthCardRedactor,
  luhnValid,
  REDACTION_MARKERS,
  sinRedactor,
  type RedactionFinding,
  type RedactionKind,
  type Redactor,
} from "../src/core/redaction.ts";

/** A shared corpus file: each case lists the exact substrings a redactor must find, in order. */
interface Corpus {
  description: string;
  kind: RedactionKind;
  cases: { lang: "en" | "fr"; text: string; found: string[] }[];
}

const corpus = (name: string): Corpus =>
  JSON.parse(readFileSync(join(import.meta.dirname, "corpus", name), "utf8")) as Corpus;

function runCorpus(name: string, find: (text: string) => RedactionFinding[], redactor: Redactor): void {
  const { kind, cases } = corpus(name);
  it(`passes every case in corpus/${name}`, () => {
    assert.ok(cases.some((c) => c.lang === "en") && cases.some((c) => c.lang === "fr"));
    for (const c of cases) {
      const findings = find(c.text);
      assert.deepEqual(findings.map((f) => c.text.slice(f.start, f.end)), c.found, c.text);
      for (const f of findings) assert.equal(f.kind, kind, c.text);
      const result = redactor.redact(c.text);
      assert.deepEqual(result, { text: applyFindings(c.text, findings), findings }, c.text);
      for (const found of c.found) assert.ok(!result.text.includes(found), c.text);
    }
  });
}

const M = REDACTION_MARKERS.card_number;
const redact = (text: string) => cardNumberRedactor.redact(text).text;

describe("luhnValid", () => {
  it("accepts valid test numbers and refuses others", () => {
    for (const n of ["4242424242424242", "4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "0"]) {
      assert.equal(luhnValid(n), true, n);
    }
    for (const n of ["4242424242424241", "1234567812345678", "", "42a2"]) assert.equal(luhnValid(n), false, n);
  });
});

describe("findCardNumbers", () => {
  it("finds card numbers written with or without separators", () => {
    assert.equal(redact("card 4242424242424242 thanks"), `card ${M} thanks`);
    assert.equal(redact("4242 4242 4242 4242"), M);
    assert.equal(redact("4242-4242-4242-4242."), `${M}.`);
    assert.equal(redact("amex 3782 822463 10005, ok"), `amex ${M}, ok`);
    assert.equal(redact("4242.4242.4242.4242"), M);
  });

  it("finds numbers spoken as digit words in English and French", () => {
    const en = "four two four two four two four two four two four two four two four two";
    assert.equal(redact(`my card is ${en} okay`), `my card is ${M} okay`);
    const fr = "quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux";
    assert.equal(redact(`ma carte est ${fr}`), `ma carte est ${M}`);
    assert.equal(redact("Four Two 4242 four two four two, 4242 4242"), M);
    assert.equal(redact("oh zero zéro une un neuf huit sept six cinq trois deux 4"), "oh zero zéro une un neuf huit sept six cinq trois deux 4");
  });

  it("leaves numbers that fail Luhn or are too short or too long", () => {
    for (const text of ["4242424242424241", "424242424242", "phone 416 555 0100", "42424242424242424242", "order 2026-11-18"]) {
      assert.equal(redact(text), text, text);
    }
  });

  it("does not join digits across words or other punctuation", () => {
    assert.equal(redact("4242 4242 and 4242 4242"), "4242 4242 and 4242 4242");
    assert.equal(redact("4242/4242/4242/4242"), "4242/4242/4242/4242");
    assert.equal(redact("4242 4242 4242 4242 is mine"), `${M} is mine`);
  });

  it("takes the longest valid match at each position and finds several", () => {
    // 4111 1111 1111 1111 followed by more digits: the 16 digits pass, longer runs do not.
    assert.equal(redact("4111 1111 1111 1111 7"), `${M} 7`);
    const both = findCardNumbers("a 4242424242424242 b 5555 5555 5555 4444 c");
    assert.deepEqual(both, [
      { kind: "card_number", start: 2, end: 18 },
      { kind: "card_number", start: 21, end: 40 },
    ]);
    // A leading digit that does not belong is skipped, the card after it is found.
    assert.equal(redact("9 4242 4242 4242 4242"), `9 ${M}`);
  });
});

describe("findSocialInsuranceNumbers", () => {
  runCorpus("sin.json", findSocialInsuranceNumbers, sinRedactor);

  it("replaces a SIN with its marker and reports offsets", () => {
    const result = sinRedactor.redact("SIN 046 454 286.");
    assert.equal(result.text, `SIN ${REDACTION_MARKERS.sin}.`);
    assert.deepEqual(result.findings, [{ kind: "sin", start: 4, end: 15 }]);
  });
});

describe("findHealthCardNumbers", () => {
  runCorpus("health-cards.json", findHealthCardNumbers, healthCardRedactor);

  it("replaces a health card number with its marker, letters and all for Quebec", () => {
    assert.equal(healthCardRedactor.redact("RAMQ TREM 7501 0112").text, `RAMQ ${REDACTION_MARKERS.health_card}`);
    assert.deepEqual(findHealthCardNumbers("x TREM 7501 0112"), [{ kind: "health_card", start: 2, end: 16 }]);
  });

  it("checks British Columbia numbers by mod 11 alone", () => {
    // Neither number passes Luhn, so only the British Columbia rule can find or refuse them.
    assert.equal(luhnValid("9123456702"), false);
    assert.equal(luhnValid("9123456712"), false);
    assert.equal(findHealthCardNumbers("9123456702").length, 1);
    // 912345671 leaves a remainder of 1: no check digit can follow it.
    assert.equal(findHealthCardNumbers("9123456712").length, 0);
  });
});

describe("findBankNumbers", () => {
  runCorpus("bank-accounts.json", findBankNumbers, bankAccountRedactor);

  it("replaces a bank number with its marker", () => {
    assert.equal(bankAccountRedactor.redact("compte 1234567").text, `compte ${REDACTION_MARKERS.bank_account}`);
  });
});

describe("the redactors together", () => {
  it("compose, card numbers first, and their markers trip none of the others", () => {
    const all = composeRedactors(cardNumberRedactor, sinRedactor, healthCardRedactor, bankAccountRedactor);
    const text = "card 4242 4242 4242 4242, SIN 046 454 286, OHIP 1234 567 897, account 1234567";
    const result = all.redact(text);
    assert.equal(
      result.text,
      `card ${M}, SIN ${REDACTION_MARKERS.sin}, OHIP ${REDACTION_MARKERS.health_card}, account ${REDACTION_MARKERS.bank_account}`,
    );
    assert.deepEqual(result.findings.map((f) => f.kind), ["card_number", "sin", "health_card", "bank_account"]);
    for (const marker of Object.values(REDACTION_MARKERS)) assert.deepEqual(all.redact(`account ${marker}`).findings, []);
  });

  it("each finds only its own kind", () => {
    assert.deepEqual(findSocialInsuranceNumbers("1234 567 897 and 4242424242424242"), []);
    assert.deepEqual(findHealthCardNumbers("046 454 286 and 4242424242424242"), []);
    assert.deepEqual(findBankNumbers("046 454 286 and 1234 567 897"), []);
  });
});

describe("applyFindings and composeRedactors", () => {
  it("replaces spans and keeps the rest", () => {
    assert.equal(applyFindings("abcdef", [{ kind: "card_number", start: 1, end: 3 }]), `a${M}def`);
    assert.equal(applyFindings("abc", []), "abc");
  });

  it("runs redactors in order and collects findings", () => {
    const shout: Redactor = { redact: (text) => ({ text: text.toUpperCase(), findings: [] }) };
    const composed = composeRedactors(cardNumberRedactor, shout);
    const result = composed.redact("pan 4242424242424242");
    assert.equal(result.text, `PAN ${M.toUpperCase()}`);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(composeRedactors().redact("x"), { text: "x", findings: [] });
  });
});
