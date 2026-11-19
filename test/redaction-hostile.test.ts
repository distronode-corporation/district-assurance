// Hostile-pass regressions for #89 (PAY-5): a live card-number detector, and spoken numbers in redaction.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { LiveCardNumberDetector } from "../src/core/live-detector.ts";
import { REDACTION_MARKERS, applyFindings, findCardNumbers } from "../src/core/redaction.ts";

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
