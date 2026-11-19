// Redaction of transcripts and any other text before it is stored or sent on.
//
// The first detector is card numbers (PANs): 13 to 19 digits that pass the Luhn check, written as
// digits or spoken as single digit words in English or French, with spaces, hyphens, dots or
// commas between groups. A match is replaced by a fixed marker. Over-redaction is accepted; the
// risk this guards against is a card number reaching storage.

export type RedactionKind = "card_number";

export interface RedactionFinding {
  kind: RedactionKind;
  /** UTF-16 offsets into the input text. */
  start: number;
  end: number;
}

export interface RedactionResult {
  text: string;
  findings: RedactionFinding[];
}

/** The redaction interface: a host can add detectors and compose them. */
export interface Redactor {
  redact(text: string): RedactionResult;
}

export const REDACTION_MARKERS: Record<RedactionKind, string> = {
  card_number: "[card number removed]",
};

/** The Luhn (mod 10) check over a string of digits. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const DIGIT_WORDS: Record<string, string> = {
  zero: "0", oh: "0", one: "1", two: "2", three: "3", four: "4", five: "5", six: "6", seven: "7",
  eight: "8", nine: "9",
  "zéro": "0", un: "1", une: "1", deux: "2", trois: "3", quatre: "4", cinq: "5", sept: "7", huit: "8",
  neuf: "9",
};

interface Token {
  digits: string;
  start: number;
  end: number;
}

const TOKEN = /\d+|\p{L}+/gu;
const SEPARATOR = /^[\s\-.,]*$/u;

/** Runs of digit tokens with only separators between them. */
function digitRuns(text: string): Token[][] {
  const runs: Token[][] = [];
  let run: Token[] = [];
  let lastEnd = 0;
  for (const match of text.matchAll(TOKEN)) {
    const raw = match[0];
    const start = match.index;
    const digits = /^\d/.test(raw) ? raw : DIGIT_WORDS[raw.toLowerCase()];
    const joined = run.length > 0 && SEPARATOR.test(text.slice(lastEnd, start));
    if (!joined && run.length > 0) {
      runs.push(run);
      run = [];
    }
    if (digits === undefined) {
      if (run.length > 0) runs.push(run);
      run = [];
    } else {
      run.push({ digits, start, end: start + raw.length });
    }
    lastEnd = start + raw.length;
  }
  if (run.length > 0) runs.push(run);
  return runs;
}

/** Card numbers in a text, leftmost first, longest match at each position, never overlapping. */
export function findCardNumbers(text: string): RedactionFinding[] {
  const findings: RedactionFinding[] = [];
  for (const run of digitRuns(text)) {
    let i = 0;
    while (i < run.length) {
      let best = -1;
      let digits = "";
      for (let j = i; j < run.length; j++) {
        digits += run[j]!.digits;
        if (digits.length > 19) break;
        if (digits.length >= 13 && luhnValid(digits)) best = j;
      }
      if (best >= 0) {
        findings.push({ kind: "card_number", start: run[i]!.start, end: run[best]!.end });
        i = best + 1;
      } else {
        i++;
      }
    }
  }
  return findings;
}

/**
 * Replaces each finding with its marker, in any order: the findings are sorted by position first,
 * and overlapping ones are merged into one span, marked with the kind of the one that starts first
 * (the longer at a tie), so no part of any finding is left in the text.
 */
export function applyFindings(text: string, findings: readonly RedactionFinding[]): string {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const spans: RedactionFinding[] = [];
  for (const f of sorted) {
    const last = spans.at(-1);
    if (last !== undefined && f.start < last.end) last.end = Math.max(last.end, f.end);
    else spans.push({ ...f });
  }
  let out = "";
  let at = 0;
  for (const f of spans) {
    out += text.slice(at, f.start) + REDACTION_MARKERS[f.kind];
    at = f.end;
  }
  return out + text.slice(at);
}

export const cardNumberRedactor: Redactor = {
  redact(text) {
    const findings = findCardNumbers(text);
    return { text: applyFindings(text, findings), findings };
  },
};

/**
 * Runs redactors in order, each over the previous one's output. Finding offsets refer to the text
 * each redactor saw, so they are reported per stage, in order.
 */
export function composeRedactors(...redactors: Redactor[]): Redactor {
  return {
    redact(text) {
      let current = text;
      const findings: RedactionFinding[] = [];
      for (const r of redactors) {
        const result = r.redact(current);
        current = result.text;
        findings.push(...result.findings);
      }
      return { text: current, findings };
    },
  };
}
