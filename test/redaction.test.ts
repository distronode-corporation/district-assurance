import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { EngineError } from "../src/core/errors.ts";
import { LIVE_DETECTOR_MIN_DIGITS, LiveCardNumberDetector } from "../src/core/live-detector.ts";
import {
  applyFindings,
  cardNumberRedactor,
  composeRedactors,
  digitRuns,
  findCardNumbers,
  luhnValid,
  REDACTION_MARKERS,
  SEPARATOR_CLASS,
  type Redactor,
} from "../src/core/redaction.ts";

const M = REDACTION_MARKERS.card_number;
const redact = (text: string) => cardNumberRedactor.redact(text).text;

/** The shared corpus (test/corpus/card-numbers.json), the test source for any implementation. */
interface Corpus {
  version: number;
  runs: Array<{ name: string; text: string; runs: string[] }>;
  redact: Array<{ name: string; text: string; redacted: string }>;
  live: Array<{ name: string; minDigits?: number; chunks: string[]; interrupts: boolean[]; digits: number[] }>;
}
const corpus = JSON.parse(readFileSync(new URL("./corpus/card-numbers.json", import.meta.url), "utf8")) as Corpus;

describe("the card-number corpus", () => {
  it("is version 1 and uses the same marker", () => {
    assert.equal(corpus.version, 1);
    assert.equal(M, "[card number removed]");
  });

  for (const c of corpus.runs) {
    it(`reads runs of digits: ${c.name}`, () => {
      assert.deepEqual(digitRuns(c.text).map((run) => run.map((p) => p.digits).join("")), c.runs);
    });
  }

  for (const c of corpus.redact) {
    it(`redacts: ${c.name}`, () => {
      assert.equal(redact(c.text), c.redacted);
    });
  }

  for (const c of corpus.live) {
    it(`detects live: ${c.name}`, () => {
      assert.equal(c.interrupts.length, c.chunks.length);
      assert.equal(c.digits.length, c.chunks.length);
      const detector = new LiveCardNumberDetector(c.minDigits === undefined ? {} : { minDigits: c.minDigits });
      const seen = c.chunks.map((chunk) => detector.push(chunk));
      assert.deepEqual(seen.map((s) => s.interrupt), c.interrupts);
      assert.deepEqual(seen.map((s) => s.digits), c.digits);
    });
  }
});

describe("digitRuns", () => {
  it("gives each part its offsets", () => {
    assert.deepEqual(digitRuns("is forty-two 4242, double 7 ok"), [
      [
        { digits: "42", start: 3, end: 12 },
        { digits: "4242", start: 13, end: 17 },
        { digits: "77", start: 19, end: 27 },
      ],
    ]);
  });

  it("needs separators inside a spoken number", () => {
    // A semicolon between words of a number splits it, as it splits numerals.
    assert.deepEqual(digitRuns("forty;two").map((r) => r.map((p) => p.digits)), [["40"], ["2"]]);
    assert.deepEqual(digitRuns("four hundred;two").map((r) => r.map((p) => p.digits)), [["400"], ["2"]]);
    assert.deepEqual(digitRuns("double;4 double").map((r) => r.map((p) => p.digits)), [["4"]]);
    assert.deepEqual(digitRuns("vingt et;un").map((r) => r.map((p) => p.digits)), [["20"], ["1"]]);
  });

  it("joins only the right words to tens, teens and scales", () => {
    const read = (text: string) => digitRuns(text).map((r) => r.map((p) => p.digits));
    assert.deepEqual(read("vingt et deux"), [["20"], ["2"]]);
    assert.deepEqual(read("twenty oh"), [["20", "0"]]);
    assert.deepEqual(read("ten seven"), [["10", "7"]]);
    assert.deepEqual(read("dix six"), [["10", "6"]]);
    assert.deepEqual(read("quatre trente"), [["4", "30"]]);
    assert.deepEqual(read("hundred and"), [["100"]]);
    assert.deepEqual(read("thousand hundred"), [["1100"]]);
    assert.deepEqual(read("soixante seize"), [["76"]]);
    assert.deepEqual(read("sixty sixteen"), [["60", "16"]]);
  });
});

describe("LiveCardNumberDetector", () => {
  it("interrupts at 8 digits by default and refuses another threshold out of range", () => {
    assert.equal(LIVE_DETECTOR_MIN_DIGITS, 8);
    const detector = new LiveCardNumberDetector();
    assert.deepEqual(detector.push("4242 424"), { interrupt: false, digits: 7 });
    assert.deepEqual(detector.push("2"), { interrupt: true, digits: 8 });
    for (const minDigits of [3, 20, 7.5, Number.NaN]) {
      assert.throws(
        () => new LiveCardNumberDetector({ minDigits }),
        (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && !e.message.includes(String(minDigits)),
      );
    }
    assert.doesNotThrow(() => new LiveCardNumberDetector({ minDigits: 19 }));
  });

  it("forgets the open run on reset", () => {
    const detector = new LiveCardNumberDetector();
    assert.deepEqual(detector.push("four two four two four two"), { interrupt: false, digits: 6 });
    detector.reset();
    assert.deepEqual(detector.push("four two"), { interrupt: false, digits: 2 });
  });

  it("keeps what it reads bounded when chunks are empty or only separators", () => {
    const longest = (feed: (d: LiveCardNumberDetector) => void) => {
      const detector = new LiveCardNumberDetector();
      const matchAll = String.prototype.matchAll;
      let max = 0;
      String.prototype.matchAll = function (this: string, ...args: Parameters<typeof matchAll>) {
        max = Math.max(max, this.length);
        return matchAll.apply(this, args);
      } as typeof matchAll;
      try {
        feed(detector);
      } finally {
        String.prototype.matchAll = matchAll;
      }
      return { detector, max };
    };
    for (const first of ["four", "double"]) {
      const { detector, max } = longest((d) => {
        d.push(first);
        for (let i = 0; i < 500; i++) d.push(i % 2 === 0 ? "" : " , - .");
      });
      assert.ok(max < 40, `${first}: read ${max} characters`);
      assert.deepEqual(detector.push("four two four two four two four"), { interrupt: true, digits: 8 }, first);
    }
  });

  it("reads a decomposed accent as the same word", () => {
    const nfd = "z\u0065\u0301ro";
    assert.deepEqual(digitRuns(`quatre ${nfd} ${nfd} deux`).map((r) => r.map((p) => p.digits).join("")), ["4002"]);
    const card = "quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux quatre deux";
    assert.equal(redact(`c'est ${card.normalize("NFD")}`), `c'est ${M}`);
    assert.equal(redact(`${nfd} 4242424242424242`.replace(nfd, "Z\u00e9ro")).includes(M), true);
    const detector = new LiveCardNumberDetector();
    assert.deepEqual(detector.push(`quatre ${nfd} quatre ${nfd} quatre ${nfd} quatre ${nfd}`), { interrupt: true, digits: 8 });
  });

  it("keeps a trailing double or triple with no run before it", () => {
    const detector = new LiveCardNumberDetector();
    assert.deepEqual(detector.push("it is triple"), { interrupt: false, digits: 0 });
    assert.deepEqual(detector.push("four 42424"), { interrupt: true, digits: 8 });
    // A word that only ends in "double" is not one.
    const other = new LiveCardNumberDetector();
    assert.deepEqual(other.push("redouble"), { interrupt: false, digits: 0 });
    assert.deepEqual(other.push("four 4242424"), { interrupt: true, digits: 8 });
    assert.deepEqual(other.push("thanks"), { interrupt: false, digits: 0 });
    assert.deepEqual(other.push(""), { interrupt: false, digits: 0 });
  });

  it("reads a long run one word at a time as it reads it whole", () => {
    const detector = new LiveCardNumberDetector({ minDigits: 19 });
    for (let n = 1; n <= 500; n++) {
      assert.deepEqual(detector.push("four"), { interrupt: n >= 19, digits: n });
    }
    // A late scale word still changes only the unsettled end of the run.
    assert.deepEqual(detector.push("hundred and"), { interrupt: true, digits: 502 });
    assert.deepEqual(detector.push("two"), { interrupt: true, digits: 502 });
    assert.deepEqual(detector.push("thanks"), { interrupt: false, digits: 0 });
  });

  it("agrees with a reader that keeps the whole open run", () => {
    // The reader this detector replaced: it read the whole open run again on every push.
    class WholeRun {
      #tail = "";
      push(chunk: string): { interrupt: boolean; digits: number } {
        const text = this.#tail === "" ? chunk : `${this.#tail} ${chunk}`;
        const fresh = text.length - chunk.length;
        const runs = digitRuns(text);
        const count = (run: Array<{ digits: string }>) => run.reduce((n, p) => n + p.digits.length, 0);
        const interrupt = runs.some((run) => run.at(-1)!.end > fresh && count(run) >= 8);
        const last = runs.at(-1);
        if (last !== undefined && new RegExp(`^${SEPARATOR_CLASS}*(?:(?:and|et|double|triple)${SEPARATOR_CLASS}*)?$`, "iu").test(text.slice(last.at(-1)!.end))) {
          this.#tail = text.slice(last[0]!.start);
          return { interrupt, digits: count(last) };
        }
        const pending = new RegExp(`(?<!\\p{L})(?:double|triple)${SEPARATOR_CLASS}*$`, "iu").exec(text);
        this.#tail = pending === null ? "" : text.slice(pending.index);
        return { interrupt, digits: 0 };
      }
    }
    const vocabulary = [
      "four", "two", "oh", "seven", "ten", "dix", "sept", "neuf", "seize", "forty", "twenty", "vingt", "vingts",
      "quatre", "soixante", "quatre-vingt-dix-sept", "hundred", "cent", "cents", "thousand", "mille", "and", "et",
      "un", "onze", "double", "triple", "4242", "7", "please", "-", ",", "/",
    ];
    let seed = 29;
    const random = (n: number) => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed % n;
    };
    for (let trial = 0; trial < 300; trial++) {
      const live = new LiveCardNumberDetector();
      const whole = new WholeRun();
      for (let push = 0; push < 30; push++) {
        const words = Array.from({ length: 1 + random(4) }, () => vocabulary[random(vocabulary.length)]!);
        const chunk = words.join(random(3) === 0 ? "-" : " ");
        assert.deepEqual(live.push(chunk), whole.push(chunk), `trial ${trial}, push ${push}: ${chunk}`);
      }
    }
  });

  it("never returns the text it heard", () => {
    const detector = new LiveCardNumberDetector();
    const result = detector.push("4242 4242 4242 4242");
    assert.deepEqual(Object.keys(result).sort(), ["digits", "interrupt"]);
    assert.ok(!JSON.stringify(result).includes("4242"));
  });
});

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
