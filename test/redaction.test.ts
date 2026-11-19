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
  cases: { lang: "en" | "fr" | "es"; text: string; found: string[] }[];
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
    assert.equal(redact("4242;4242;4242;4242"), "4242;4242;4242;4242");
    assert.equal(redact("4242/4242/4242/4242"), M, "a slash joins a run");
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

  it("finds a number after every Spanish bank word, singular or plural, accented, bare or decomposed", () => {
    const words = [
      "banco", "bancos", "bancaria", "bancarias", "bancario", "bancarios", "sucursal", "sucursales", "cuenta", "cuentas",
      "tránsito", "tránsitos", "transito", "transitos", "institución", "instituciones", "institucion",
    ];
    for (const word of [...words, ...words.map((w) => w.toUpperCase()), ...words.map((w) => w.normalize("NFD"))]) {
      const text = `${word} 1234567`;
      assert.deepEqual(findBankNumbers(text).map((f) => text.slice(f.start, f.end)), ["1234567"], word);
    }
  });

  it("counts a decomposed accented word as one word in the look-back", () => {
    // Split at its accent, "nu\u0301mero" would be two words and push "cuenta" out of the last 4.
    const text = "cuenta nu\u0301mero de la 1234567";
    assert.deepEqual(findBankNumbers(text).map((f) => text.slice(f.start, f.end)), ["1234567"]);
  });
});

describe("the Quebec look-back", () => {
  it("reads only a short window before each run, however long the transcript", () => {
    const exec = RegExp.prototype.exec;
    let longest = 0;
    let calls = 0;
    RegExp.prototype.exec = function (this: RegExp, input: string) {
      if (this.source.includes("\\p{L}{4}")) {
        calls++;
        longest = Math.max(longest, input.length);
      }
      return exec.call(this, input);
    };
    const text = "date 7501 0112, ".repeat(400);
    let found: RedactionFinding[];
    try {
      found = findHealthCardNumbers(text);
    } finally {
      RegExp.prototype.exec = exec;
    }
    assert.equal(found.length, 400, "every one is still found");
    assert.ok(calls >= 400);
    assert.ok(longest <= 48, `read ${longest} characters before a run`);
  });

  it("keeps the letter check at the edge of the window", () => {
    const pad = "x".repeat(60);
    assert.deepEqual(findHealthCardNumbers(`${pad} TREM 7501 0112`).length, 1);
    assert.deepEqual(findHealthCardNumbers(`${pad}TREM 7501 0112`), [], "a word longer than four letters is no code");
    assert.deepEqual(findHealthCardNumbers(`T${" ".repeat(9)}R E M 7501 0112`), [], "a gap of more than 8 separators ends the letters");
    assert.deepEqual(findHealthCardNumbers(`${"y".repeat(44)}TREM 7501 0112`), [], "the letter before the code is seen at the window's edge");
  });
});

describe("the redactors together", () => {
  it("compose, card numbers first, and their markers trip none of the others", () => {
    const all = composeRedactors(cardNumberRedactor, healthCardRedactor, sinRedactor, bankAccountRedactor);
    const text = "card 4242 4242 4242 4242, SIN 046 454 286, OHIP 1234 567 897, account 1234567";
    const result = all.redact(text);
    assert.equal(
      result.text,
      `card ${M}, SIN ${REDACTION_MARKERS.sin}, OHIP ${REDACTION_MARKERS.health_card}, account ${REDACTION_MARKERS.bank_account}`,
    );
    assert.deepEqual(result.findings.map((f) => f.kind), ["card_number", "health_card", "sin", "bank_account"]);
    for (const f of result.findings) assert.ok(/^[\d ]+$/.test(text.slice(f.start, f.end)));
    for (const marker of Object.values(REDACTION_MARKERS)) assert.deepEqual(all.redact(`account ${marker}`).findings, []);
  });

  it("keep a health card number whole when it starts with a valid SIN", () => {
    const all = composeRedactors(cardNumberRedactor, healthCardRedactor, sinRedactor, bankAccountRedactor);
    const text = "one two three four five six seven eight two two";
    assert.equal(luhnValid("123456782"), true);
    assert.equal(luhnValid("1234567822"), true);
    assert.deepEqual(all.redact(text), {
      text: REDACTION_MARKERS.health_card,
      findings: [{ kind: "health_card", start: 0, end: text.length }],
    });
    // A SIN alone is still found.
    assert.equal(all.redact("SIN 046 454 286").text, `SIN ${REDACTION_MARKERS.sin}`);
  });

  it("report offsets into the original input", () => {
    const all = composeRedactors(cardNumberRedactor, healthCardRedactor, sinRedactor, bankAccountRedactor);
    assert.deepEqual(all.redact("4242424242424242 046454286").findings, [
      { kind: "card_number", start: 0, end: 16 },
      { kind: "sin", start: 17, end: 26 },
    ]);
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

  it("maps a later finding that covers an earlier marker to all it replaced", () => {
    // A later stage that takes everything from "<" to ">", markers included.
    const wide: Redactor = {
      redact(text) {
        const start = text.indexOf("<");
        const end = text.indexOf(">") + 1;
        const findings: RedactionFinding[] = [{ kind: "bank_account", start, end }];
        return { text: applyFindings(text, findings), findings };
      },
    };
    const text = "046454286 a 4242424242424242 < 4242424242424242 c 046454286 > 046454286";
    const inner = composeRedactors(cardNumberRedactor, sinRedactor, wide).redact(text);
    assert.equal(inner.text, `${REDACTION_MARKERS.sin} a ${M} ${REDACTION_MARKERS.bank_account} ${REDACTION_MARKERS.sin}`);
    const b = text.indexOf("<");
    const d = text.indexOf(">") + 1;
    assert.deepEqual(inner.findings, [
      { kind: "card_number", start: 12, end: 28 },
      { kind: "card_number", start: 31, end: 47 },
      { kind: "sin", start: 0, end: 9 },
      { kind: "sin", start: 50, end: 59 },
      { kind: "sin", start: 62, end: 71 },
      { kind: "bank_account", start: b, end: d },
    ]);
    // A finding that starts or ends inside a marker covers all the marker replaced.
    const inside: Redactor = {
      redact(text) {
        const findings: RedactionFinding[] = [{ kind: "bank_account", start: 3, end: text.length - 3 }];
        return { text: applyFindings(text, findings), findings };
      },
    };
    const sins = "046454286 x 046454286";
    assert.deepEqual(composeRedactors(sinRedactor, inside).redact(sins).findings.at(-1), {
      kind: "bank_account",
      start: 0,
      end: sins.length,
    });
  });
});
