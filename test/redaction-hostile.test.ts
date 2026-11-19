// Hostile-pass regressions for #89 (PAY-5): a live card-number detector, and spoken numbers in redaction.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { LiveCardNumberDetector } from "../src/core/live-detector.ts";
import { REDACTION_MARKERS, applyFindings, digitRuns, findCardNumbers } from "../src/core/redaction.ts";

const PAN = "4111111111111111";
const redacted = (text: string) => applyFindings(text, findCardNumbers(text));
const grouped = (sep: string) => [PAN.slice(0, 4), PAN.slice(4, 8), PAN.slice(8, 12), PAN.slice(12)].join(sep);
const MARKER = REDACTION_MARKERS.card_number;

describe("hostile #89: separators a transcript or a text can carry", () => {
  // Dashes other than the hyphen-minus, the minus sign, invisible format characters and combining
  // marks: a card number with these between its groups reached storage whole.
  const separators: Record<string, string> = {
    "en dash": "–",
    "em dash": "—",
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
