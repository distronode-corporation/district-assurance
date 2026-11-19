// Live card-number detection, for a transcript while the caller is still speaking.
//
// Redaction (redaction.ts) finds whole card numbers once a text is complete. This detector is fed
// a call's transcript a chunk at a time and says to interrupt as soon as a run of digits reaches a
// threshold (8 by default), before the caller has read a whole number. A run is read the same way
// redaction reads it: numerals and spoken numbers in English or French ("forty two",
// "quarante-deux", "double four"), with only spaces, hyphens, dots or commas between them. There is
// no Luhn check: a partial number cannot pass one. A phone number read aloud also interrupts;
// over-interrupting is accepted.
//
// The detector keeps only the open end of the transcript, never returns it, and drops it on
// `reset()`. Of the run still being read it keeps the digit count of the parts that more words can
// no longer change, and the text of the last few parts only, so each push reads a short text however
// long the run grows.

import { EngineError } from "./errors.ts";
import { digitRuns, LEXEME } from "./redaction.ts";
import { isIntegerIn } from "./shape.ts";

export const LIVE_DETECTOR_MIN_DIGITS = 8;

export interface LiveDetectorOptions {
  /** Digits in one run that trigger an interrupt: an integer from 4 to 19, 8 by default. */
  minDigits?: number;
}

export interface LiveDetection {
  /** True when a run that this chunk added to has `minDigits` digits or more. */
  interrupt: boolean;
  /** How many digits the run still open at the end of the transcript holds (0 when none). */
  digits: number;
}

// After the last run, these may still continue it: separators, then at most one word that only
// makes sense before more digits ("and" or "et" inside a number, "double", "triple").
const PENDING = /^[\s\-.,]*(?:(?:and|et|double|triple)[\s\-.,]*)?$/iu;
const PENDING_WORD = /(?<!\p{L})(?:double|triple)[\s\-.,]*$/iu;
// Separators at the end of what is kept: dropped, since the next chunk is joined with a space,
// so empty or separator-only chunks never grow the kept text.
const TRAILING = /[\s\-.,]+$/u;

// How a part of a run is read depends on its own words and on at most three words after it
// (redaction.ts looks that far for "and", "et" and "quatre-vingt-dix-sept"); one more for margin.
// A part with this many words after it is settled: more words cannot change it or the parts before.
const LOOKAHEAD = 4;

type Part = { digits: string };

/** One per call (or per caller channel). Not shared between calls. */
export class LiveCardNumberDetector {
  readonly #minDigits: number;
  /** Digits of the open run's settled parts, whose text is no longer kept. */
  #settled = 0;
  /** The open run from its first unsettled part, or a trailing "double" or "triple". */
  #tail = "";

  constructor(options: LiveDetectorOptions = {}) {
    const minDigits = options.minDigits ?? LIVE_DETECTOR_MIN_DIGITS;
    if (!isIntegerIn(minDigits, 4, 19)) {
      throw new EngineError("invalid_input", "minDigits must be an integer from 4 to 19");
    }
    this.#minDigits = minDigits;
  }

  /**
   * Feeds the next chunk of the transcript. Each chunk is taken to end at a word boundary: chunks
   * are joined with a space, so a word split across two chunks is not read as a number.
   */
  push(chunk: string): LiveDetection {
    const text = this.#tail === "" ? chunk : `${this.#tail} ${chunk}`;
    const fresh = text.length - chunk.length;
    const runs = digitRuns(text);
    // When digits were settled, `#tail` starts with a part of their run, so the first run continues it.
    const carried = this.#settled;
    const total = (run: readonly Part[]) => digitCount(run) + (run === runs[0] ? carried : 0);
    let interrupt = false;
    for (const run of runs) {
      if (run.at(-1)!.end > fresh && total(run) >= this.#minDigits) interrupt = true;
    }
    const last = runs.at(-1);
    if (last !== undefined && PENDING.test(text.slice(last.at(-1)!.end))) {
      const digits = total(last);
      // The last part has at most one word after it, so it is never settled and `keep` is found.
      const settledBy = settledEnd(text);
      const keep = last.findIndex((p) => p.end > settledBy);
      this.#settled = digits - digitCount(last.slice(keep));
      this.#tail = text.slice(last[keep]!.start).replace(TRAILING, "");
      return { interrupt, digits };
    }
    const pending = PENDING_WORD.exec(text);
    this.#settled = 0;
    this.#tail = pending === null ? "" : text.slice(pending.index).replace(TRAILING, "");
    return { interrupt, digits: 0 };
  }

  /** Forgets the open end of the transcript, for example at the end of the caller's turn. */
  reset(): void {
    this.#settled = 0;
    this.#tail = "";
  }
}

/** A part ending at or before this offset has LOOKAHEAD words after it (-1: no part does). */
function settledEnd(text: string): number {
  const starts: number[] = [];
  for (const m of text.matchAll(LEXEME)) starts.push(m.index);
  return starts.length < LOOKAHEAD ? -1 : starts[starts.length - LOOKAHEAD]!;
}

function digitCount(run: readonly Part[]): number {
  return run.reduce((n, p) => n + p.digits.length, 0);
}
