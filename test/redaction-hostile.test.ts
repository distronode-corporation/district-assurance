// Hostile-pass regressions for #89 (PAY-5): a live card-number detector, and spoken numbers in redaction.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { LiveCardNumberDetector } from "../src/core/live-detector.ts";
import { NUMBER_LANGUAGES, REDACTION_MARKERS, applyFindings, cardNumberRedactor, digitRuns, findCardNumbers, numberLanguagesFor } from "../src/core/redaction.ts";
import { setup } from "./helpers.ts";

const PAN = "4111111111111111";
const redacted = (text: string) => applyFindings(text, findCardNumbers(text));
const grouped = (sep: string) => [PAN.slice(0, 4), PAN.slice(4, 8), PAN.slice(8, 12), PAN.slice(12)].join(sep);
const MARKER = REDACTION_MARKERS.card_number;

describe("hostile #89: separators a transcript or a text can carry", () => {
  // Dashes other than the hyphen-minus, the minus sign, invisible format characters and combining
  // marks: a card number with these between its groups reached storage whole.
  const separators: Record<string, string> = {
    "en dash": "–",
    "em dash": "\u2014",
    "non-breaking hyphen": "‑",
    "minus sign": "−",
    "zero-width space": "​",
    "zero-width joiner": "‍",
    "soft hyphen": "­",
    "right-to-left override": "‮",
    "word joiner": "⁠",
    "combining mark": "́",
  };

  for (const [name, sep] of Object.entries(separators)) {
    it(`redacts and interrupts a card number grouped with a ${name}`, () => {
      assert.equal(redacted(grouped(sep)), MARKER, name);
      assert.equal(redacted(`card ${[...PAN].join(sep)} thanks`), `card ${MARKER} thanks`, `${name} between every digit`);
      assert.equal(new LiveCardNumberDetector().push(grouped(sep)).interrupt, true, name);
      const live = new LiveCardNumberDetector();
      live.push(`${PAN.slice(0, 4)}${sep}`);
      assert.equal(live.push(PAN.slice(4, 8)).interrupt, true, `${name} across two chunks`);
    });
  }
});

describe("hostile #89: what holds", () => {
  it("never reads prototype keys or lookalike words as numbers, and never throws on hostile text", () => {
    for (const text of ["constructor toString __proto__ hasOwnProperty", "𐀀\ud800 4111", "‮1111‬", "x".repeat(200_000)]) {
      assert.doesNotThrow(() => redacted(text));
      assert.doesNotThrow(() => new LiveCardNumberDetector().push(text));
    }
    assert.equal(new LiveCardNumberDetector().push("constructor constructor constructor").digits, 0);
  });

  it("keeps counting a run fed one digit per chunk, and forgets it on reset", () => {
    const live = new LiveCardNumberDetector();
    const answers = Array.from(PAN.slice(0, 8), (d) => live.push(d));
    assert.deepEqual(answers.map((a) => a.interrupt), [false, false, false, false, false, false, false, true]);
    live.reset();
    assert.equal(live.push("1").digits, 1);
  });

  it("keeps what it holds short however long a spoken run grows", () => {
    const live = new LiveCardNumberDetector();
    let last = { interrupt: false, digits: 0 };
    for (let i = 0; i < 5000; i++) last = live.push("nine");
    assert.equal(last.digits, 5000);
    assert.equal(last.interrupt, true);
  });
});

describe("hostile #89: more separators, and decimal digits in any script", () => {
  const script = (zero: number) => (digits: string) => Array.from(digits, (d) => String.fromCodePoint(zero + Number(d))).join("");
  const scripts: Record<string, (d: string) => string> = {
    fullwidth: script(0xff10),
    "Arabic-Indic": script(0x0660),
    "Extended Arabic-Indic": script(0x06f0),
    Devanagari: script(0x0966),
    "mathematical bold (astral)": script(0x1d7ce),
  };

  for (const [name, sep] of Object.entries({ slash: "/", underscore: "_", "middle dot": "·" })) {
    it(`redacts and interrupts a card number grouped with a ${name}`, () => {
      assert.equal(redacted(grouped(sep)), MARKER);
      assert.equal(new LiveCardNumberDetector().push(grouped(sep)).interrupt, true);
    });
  }

  for (const [name, write] of Object.entries(scripts)) {
    it(`reads a card number written in ${name} digits by their values, and removes the original span`, () => {
      assert.equal(redacted(`card ${write(PAN)} thanks`), `card ${MARKER} thanks`);
      assert.equal(redacted(`card ${write(PAN.slice(0, 8))} ${write(PAN.slice(8))} thanks`), `card ${MARKER} thanks`, "in groups");
      const invalid = `${PAN.slice(0, 15)}2`;
      assert.equal(redacted(write(invalid)), write(invalid), "the Luhn check runs on the values: a number that fails it is kept");
      assert.equal(new LiveCardNumberDetector().push(write(PAN.slice(0, 8))).interrupt, true);
    });
  }

  it("reads mixed scripts in one number", () => {
    const mixed = `${scripts.fullwidth!(PAN.slice(0, 4))} ${PAN.slice(4, 8)} ${scripts["Arabic-Indic"]!(PAN.slice(8))}`;
    assert.equal(redacted(mixed), MARKER);
  });
});

describe("hostile #89: Spanish numbers, read as people say them", () => {
  const runs = (text: string) => digitRuns(text).map((run) => run.map((p) => p.digits).join(""));
  it("reads Spanish cardinals like the English and French ones", () => {
    const cases: Array<[string, string]> = [
      ["cero uno dos tres cuatro cinco seis siete ocho nueve", "0123456789"],
      ["cuarenta y uno", "41"],
      ["noventa y nueve", "99"],
      ["veinte", "20"],
      ["veintiuno", "21"],
      ["veintidós", "22"],
      ["diez once doce quince", "10111215"],
      ["dieciséis diecinueve", "1619"],
      ["cien", "100"],
      ["ciento once", "111"],
      ["doscientos cuarenta y uno", "241"],
      ["quinientos", "500"],
      ["mil", "1000"],
      ["cuatro mil ciento once", "4111"],
      ["dos mil veinte", "2020"],
      ["una", "1"],
    ];
    for (const [text, digits] of cases) assert.deepEqual(runs(text), [digits], text);
  });

  it("never multiplies a Spanish hundred word: cuatro doscientos is 4 then 200", () => {
    assert.deepEqual(runs("cuatro doscientos"), ["4200"]);
    assert.deepEqual(runs("tres quinientos"), ["3500"]);
    assert.deepEqual(runs("cuatro ciento once"), ["4111"]);
    assert.deepEqual(runs("four hundred"), ["400"], "a multiplier scale still multiplies");
    assert.deepEqual(runs("dos mil"), ["2000"]);
    const pan = "cuatro doscientos 4200 4200 4200";
    assert.equal(redacted(pan), MARKER, "4200420042004200 is a card number");
  });

  it("reads a combining mark after a number word as a separator, and keeps a decomposed accent inside a word", () => {
    const marked = Array(8).fill("four\u0301 two\u0301").join(" ");
    assert.deepEqual(runs(marked), ["4242424242424242"]);
    assert.equal(redacted(marked).includes("four"), false, "redacted");
    const live = new LiveCardNumberDetector();
    assert.equal(live.push(marked).interrupt, true);
    assert.deepEqual(runs("veintiu\u0301n"), ["21"], "an accent inside a word is still part of it");
  });

  it("redacts and interrupts a card number read in Spanish pairs or groups", () => {
    const pairs = "cuarenta y uno once, once once, once once, once once";
    assert.equal(redacted(`es ${pairs} gracias`), `es ${MARKER} gracias`);
    const groups = "cuatro mil ciento once, mil ciento once, mil ciento once, mil ciento once";
    assert.equal(redacted(groups), MARKER);
    const live = new LiveCardNumberDetector();
    live.push("cuarenta y");
    assert.equal(live.push("uno once once once").interrupt, true, "a y at a chunk's end still joins the run");
  });
});

describe("hostile #89: each call reads its own language's number words", () => {
  const runsIn = (text: string, languages: Array<"en" | "fr" | "es">) => digitRuns(text, languages).map((run) => run.map((p) => p.digits).join(""));

  it("never reads English text's once, dos, mil or y as Spanish numbers on an English call", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall({ locale: "en" });
    const text = "card 4111 1111 1111 11 once, dos mil y more";
    const result = await t.engine.redact(callId, text);
    assert.equal(result.text, text, "nothing redacted: once is not eleven in English");
    assert.equal(result.interrupt, false);
    assert.deepEqual(runsIn("forty y two", ["en"]), ["40", "2"], "y is no connector in English: forty and two are two runs");
    assert.deepEqual(runsIn("once dos mil", ["en"]), []);
    const live = new LiveCardNumberDetector({ locale: "en" });
    assert.equal(live.push("4111 1111 once once").interrupt, true, "8 numerals interrupt whatever the words");
    assert.equal(new LiveCardNumberDetector({ locale: "en" }).push("1111 once once once").digits, 0, "once ends the run in English");
  });

  it("reads French words on a French call, and every language's when no call is named", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall({ locale: "fr" });
    const fr = `carte ${Array.from(PAN, (d) => ["zéro", "un", "deux", "trois", "quatre", "cinq", "six", "sept", "huit", "neuf"][Number(d)]).join(" ")}`;
    assert.equal((await t.engine.redact(callId, fr)).text, `carte ${MARKER}`);
    assert.deepEqual(runsIn("once", ["fr"]), []);
    assert.deepEqual(runsIn("cuarenta y uno", NUMBER_LANGUAGES as Array<"en" | "fr" | "es">), ["41"], "with no call, Spanish too");
    assert.equal(redacted("4111 1111 1111 11 once"), MARKER, "the standalone redactor reads every language: the safe side");
    assert.throws(() => new LiveCardNumberDetector({ locale: "pt" as never }), /locale must be one of/);
  });
});

describe("hostile #89: English and French on every call, Spanish on a Spanish call", () => {
  const FR = ["zéro", "un", "deux", "trois", "quatre", "cinq", "six", "sept", "huit", "neuf"];
  const EN = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];

  it("an English call redacts a card number read in French digit words, and a French call one read in English", async () => {
    const t = setup();
    const en = await t.engine.startCall({ locale: "en" });
    const fr = await t.engine.startCall({ locale: "fr" });
    const inFrench = `it is ${Array.from(PAN, (d) => FR[Number(d)]).join(" ")}`;
    const inEnglish = `c'est ${Array.from(PAN, (d) => EN[Number(d)]).join(" ")}`;
    assert.equal((await t.engine.redact(en.callId, inFrench)).text, `it is ${MARKER}`);
    assert.equal((await t.engine.redact(fr.callId, inEnglish)).text, `c'est ${MARKER}`);
    assert.equal(new LiveCardNumberDetector({ locale: "en" }).push(FR.slice(1, 9).join(" ")).interrupt, true);
  });

  it("reads Spanish words, with English and French, only on a Spanish call", () => {
    const spanish = cardNumberRedactor.redact("cuarenta y uno once once once once once once once", { locale: "es" });
    assert.equal(spanish.findings.length, 1);
    assert.equal(cardNumberRedactor.redact("cuarenta y uno once once once once once once once", { locale: "fr" }).findings.length, 0);
    assert.deepEqual(numberLanguagesFor("es"), ["en", "fr", "es"]);
    assert.deepEqual(numberLanguagesFor("en"), ["en", "fr"]);
    assert.deepEqual(numberLanguagesFor(undefined), ["en", "fr", "es"]);
  });
});
