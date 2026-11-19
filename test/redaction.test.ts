import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  applyFindings,
  cardNumberRedactor,
  composeRedactors,
  findCardNumbers,
  luhnValid,
  REDACTION_MARKERS,
  type Redactor,
} from "../src/core/redaction.ts";

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

  it("finds numbers spoken as digit words in Spanish, alone or mixed with digits and other languages", () => {
    const es = "cuatro dos cuatro dos cuatro dos cuatro dos cuatro dos cuatro dos cuatro dos cuatro dos";
    assert.equal(redact(`mi tarjeta es ${es}, gracias`), `mi tarjeta es ${M}, gracias`);
    // 4111 1111 1111 1111 with each Spanish word for one, and capitals.
    assert.equal(redact("Cuatro uno una un 1111 uno-uno-uno-uno 1111"), M);
    // 6011 1111 1111 1117 and 3782 8224 6310 005: seis, cero, siete, ocho, tres, dos, nueve aside.
    assert.equal(redact("seis cero uno uno 1111 1111 uno uno uno siete"), M);
    assert.equal(redact("tres siete ocho dos ocho dos dos cuatro seis tres uno cero cero cero cinco"), M);
    // Each word maps to its digit: 13 to 19 of them that fail Luhn are left alone.
    const nine = "cero uno dos tres cuatro cinco seis siete ocho nueve cero uno dos";
    assert.equal(findCardNumbers(nine).length, 0, "0123456789012 fails Luhn");
    assert.equal(redact("nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve"), "nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve nueve");
    // Words between the digits break the run, in Spanish as in English.
    const split = "cuatro dos cuatro dos cuatro dos cuatro dos y cuatro dos cuatro dos cuatro dos cuatro dos";
    assert.equal(redact(split), split);
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
