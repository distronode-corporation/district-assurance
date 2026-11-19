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
// The detector keeps only the open end of the transcript (the run still being read, if any), never
// returns it, and drops it on `reset()`.

import { EngineError } from "./errors.ts";
import { digitRuns } from "./redaction.ts";
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

/** One per call (or per caller channel). Not shared between calls. */
export class LiveCardNumberDetector {
  readonly #minDigits: number;
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
    let interrupt = false;
    for (const run of runs) {
      if (run.at(-1)!.end > fresh && digitCount(run) >= this.#minDigits) interrupt = true;
    }
    const last = runs.at(-1);
    if (last !== undefined && PENDING.test(text.slice(last.at(-1)!.end))) {
      this.#tail = text.slice(last[0]!.start);
      return { interrupt, digits: digitCount(last) };
    }
    const pending = PENDING_WORD.exec(text);
    this.#tail = pending === null ? "" : text.slice(pending.index);
    return { interrupt, digits: 0 };
  }

  /** Forgets the open end of the transcript, for example at the end of the caller's turn. */
  reset(): void {
    this.#tail = "";
  }
}

function digitCount(run: ReadonlyArray<{ digits: string }>): number {
  return run.reduce((n, p) => n + p.digits.length, 0);
}
