// Redaction of transcripts and any other text before it is stored or sent on.
//
// The first detector is card numbers (PANs): 13 to 19 digits that pass the Luhn check, written as
// digits or spoken as single digit words in English or French, with separators between groups:
// spaces, dashes, dots, commas and invisible characters (SEPARATOR_CLASS). A match is replaced by a fixed marker. Over-redaction is accepted; the
// risk this guards against is a card number reaching storage.
//
// Further detectors, each its own `Redactor` over the same digit runs (PRV-6): Canadian social
// insurance numbers, provincial health card numbers, and bank transit and account numbers. A
// host composes the ones it wants with `composeRedactors`, card numbers first, then health card
// numbers, SINs and bank numbers.

export type RedactionKind = "card_number" | "sin" | "health_card" | "bank_account";

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

/**
 * The fixed line a host speaks when a redactor fires, per kind and language. Only a card number is
 * offered a payment link instead; the other numbers are never needed on a call.
 */
export const INTERRUPT_LINES: Readonly<Record<RedactionKind, { en: string; fr: string }>> = {
  card_number: {
    en: "Please do not read card numbers aloud. I can text you a secure payment link instead.",
    fr: "Veuillez ne pas lire de numéro de carte à voix haute. Je peux plutôt vous envoyer un lien de paiement sécurisé par texto.",
  },
  health_card: {
    en: "Please do not read your health card number aloud. I do not need it on this call.",
    fr: "Veuillez ne pas lire votre numéro d'assurance maladie à voix haute. Je n'en ai pas besoin pendant cet appel.",
  },
  sin: {
    en: "Please do not read your social insurance number aloud. I do not need it on this call.",
    fr: "Veuillez ne pas lire votre numéro d'assurance sociale à voix haute. Je n'en ai pas besoin pendant cet appel.",
  },
  bank_account: {
    en: "Please do not read your banking details aloud. I do not need them on this call.",
    fr: "Veuillez ne pas lire vos renseignements bancaires à voix haute. Je n'en ai pas besoin pendant cet appel.",
  },
};

/** Which kind's line is spoken when several fire at once: a card number first, then this order. */
const INTERRUPT_ORDER: readonly RedactionKind[] = ["card_number", "health_card", "sin", "bank_account"];

/** The line for a set of findings in a language, or null when there are none. */
export function interruptLine(findings: readonly RedactionFinding[], locale: "en" | "fr"): string | null {
  const kind = INTERRUPT_ORDER.find((k) => findings.some((f) => f.kind === k));
  return kind === undefined ? null : INTERRUPT_LINES[kind][locale];
}

export const REDACTION_MARKERS: Record<RedactionKind, string> = {
  card_number: "[card number removed]",
  sin: "[SIN removed]",
  health_card: "[health card number removed]",
  bank_account: "[banking details removed]",
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
/**
 * What may lie between the groups of one number: spaces, any dash (the hyphen-minus, en and em
 * dashes, the non-breaking hyphen), the minus sign, dots and commas, and what a reader never sees:
 * format characters (zero-width spaces and joiners, soft hyphens, bidi controls) and combining marks.
 */
export const SEPARATOR_CLASS = String.raw`[\s\p{Pd}\u2212\p{Cf}\p{M}.,]`;
const SEPARATOR = new RegExp(`^${SEPARATOR_CLASS}*$`, "u");

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

/** Replaces each finding with its marker. Findings must be sorted and must not overlap. */
export function applyFindings(text: string, findings: readonly RedactionFinding[]): string {
  let out = "";
  let at = 0;
  for (const f of findings) {
    out += text.slice(at, f.start) + REDACTION_MARKERS[f.kind];
    at = f.end;
  }
  return out + text.slice(at);
}

function redactorFor(find: (text: string) => RedactionFinding[]): Redactor {
  return {
    redact(text) {
      const findings = find(text);
      return { text: applyFindings(text, findings), findings };
    },
  };
}

export const cardNumberRedactor: Redactor = redactorFor(findCardNumbers);

/** A number with a fixed count of digits, the places a written form may break, and a check. */
interface NumberFormat {
  length: number;
  /** Digit offsets where written groups may break: 3 and 6 for "046 454 286". */
  breaks: readonly number[];
  valid(digits: string): boolean;
  /** Four letters come just before the digits, as one word or spelled out ("TREM", "t r e m"). */
  afterFourLetters?: boolean;
}

/**
 * Whether tokens i to j of a run are grouped as the format allows. A break between two written
 * groups must fall on one of the format's breaks; single digits (spoken digit words, or digits
 * read one by one) may break anywhere.
 */
function groupedAs(run: readonly Token[], i: number, j: number, breaks: readonly number[]): boolean {
  let at = 0;
  for (let k = i; k < j; k++) {
    at += run[k]!.digits.length;
    const singles = run[k]!.digits.length === 1 && run[k + 1]!.digits.length === 1;
    if (!singles && !breaks.includes(at)) return false;
  }
  return true;
}

// Four letters, each gap and the gap before the digits at most 8 separators, so a match is at most
// 40 UTF-16 code units (astral letters included) and only a short window before a run is read.
const FOUR_LETTERS_BEFORE = new RegExp(String.raw`(?<!\p{L})(?:\p{L}{4}|\p{L}(?:${SEPARATOR_CLASS}{1,8}\p{L}){3})${SEPARATOR_CLASS}{0,8}$`, "u");
/**
 * The look-back window, longer than any match (40), so a match never starts at the window's first
 * character and its letter check always sees the real character before it.
 */
const FOUR_LETTERS_WINDOW = 48;

/**
 * Where the four letters before a run start, if they are there. Only the last few characters before
 * the run are read, so a long transcript with many candidate runs stays linear.
 */
function fourLettersBefore(text: string, at: number): number | undefined {
  const from = Math.max(0, at - FOUR_LETTERS_WINDOW);
  const found = FOUR_LETTERS_BEFORE.exec(text.slice(from, at));
  return found === null ? undefined : from + found.index;
}

/**
 * Numbers of the given formats in a text, leftmost first, longest match at each position, never
 * overlapping. A match starts at the first run token it uses, or at its four letters.
 */
function findFormatted(text: string, kind: RedactionKind, formats: readonly NumberFormat[]): RedactionFinding[] {
  const longest = Math.max(...formats.map((f) => f.length));
  const findings: RedactionFinding[] = [];
  for (const run of digitRuns(text)) {
    let i = 0;
    while (i < run.length) {
      let best = -1;
      let start = 0;
      let digits = "";
      for (let j = i; j < run.length; j++) {
        digits += run[j]!.digits;
        if (digits.length > longest) break;
        for (const f of formats) {
          if (f.length !== digits.length || !groupedAs(run, i, j, f.breaks) || !f.valid(digits)) continue;
          // The letters must come before the run itself, never be a digit word inside it.
          let from: number | undefined = run[i]!.start;
          if (f.afterFourLetters === true) from = i === 0 ? fourLettersBefore(text, from) : undefined;
          if (from !== undefined) {
            best = j;
            start = from;
          }
        }
      }
      if (best >= 0) {
        findings.push({ kind, start, end: run[best]!.end });
        i = best + 1;
      } else {
        i++;
      }
    }
  }
  return findings;
}

/** Canadian social insurance numbers: 9 digits, Luhn, grouped 3-3-3 when written in groups. */
export function findSocialInsuranceNumbers(text: string): RedactionFinding[] {
  return findFormatted(text, "sin", [{ length: 9, breaks: [3, 6], valid: luhnValid }]);
}

export const sinRedactor: Redactor = redactorFor(findSocialInsuranceNumbers);

/** The British Columbia personal health number check: a 9, then mod 11 over digits 2 to 9. */
function bcPhnValid(digits: string): boolean {
  if (digits[0] !== "9") return false;
  const weights = [2, 4, 8, 5, 10, 9, 7, 3];
  let sum = 0;
  for (let k = 0; k < 8; k++) sum += (digits.charCodeAt(k + 1) - 48) * weights[k]!;
  const check = 11 - (sum % 11);
  return check < 10 && check === digits.charCodeAt(9) - 48;
}

/** Quebec health insurance digits: birth year, month (plus 50 for women), day, then two more. */
function ramqDigitsValid(digits: string): boolean {
  const month = Number(digits.slice(2, 4)) % 50;
  const day = Number(digits.slice(4, 6));
  return month >= 1 && month <= 12 && day >= 1 && day <= 31;
}

const HEALTH_CARDS: readonly NumberFormat[] = [
  // Ontario: 10 digits, Luhn, written 1234 567 890. A version code may follow and is kept.
  { length: 10, breaks: [4, 7], valid: luhnValid },
  // British Columbia: 10 digits starting with 9, mod 11 check digit, written 9123 456 789.
  { length: 10, breaks: [4, 7], valid: bcPhnValid },
  // Quebec: four letters, then 8 digits, written TREM 7501 0112. The letters are removed too.
  { length: 8, breaks: [4], valid: ramqDigitsValid, afterFourLetters: true },
];

/** Provincial health card numbers in the Ontario, British Columbia and Quebec formats. */
export function findHealthCardNumbers(text: string): RedactionFinding[] {
  return findFormatted(text, "health_card", HEALTH_CARDS);
}

export const healthCardRedactor: Redactor = redactorFor(findHealthCardNumbers);

/** Words that mark a number after them as a bank number, in English and French, plurals too. */
const BANK_WORDS = new Set([
  "bank", "banks", "branch", "branches", "transit", "transits", "institution", "institutions", "account", "accounts",
  "banque", "banques", "bancaire", "bancaires", "succursale", "succursales", "compte", "comptes", "folio", "folios",
]);

const WORD = /\p{L}+/gu;

/**
 * Bank numbers: a digit run of 3 or more digits (an institution number is 3, a transit number 5,
 * an account number 7 to 12, or several read together) with a bank word among the last 4 words
 * before it, since the previous run. Bank numbers carry no check digit, so the word marks them.
 */
export function findBankNumbers(text: string): RedactionFinding[] {
  const findings: RedactionFinding[] = [];
  let from = 0;
  for (const run of digitRuns(text)) {
    const first = run[0]!;
    const last = run[run.length - 1]!;
    const words = text.slice(from, first.start).match(WORD) ?? [];
    from = last.end;
    const digits = run.reduce((n, t) => n + t.digits.length, 0);
    if (digits >= 3 && words.slice(-4).some((w) => BANK_WORDS.has(w.toLowerCase()))) {
      findings.push({ kind: "bank_account", start: first.start, end: last.end });
    }
  }
  return findings;
}

export const bankAccountRedactor: Redactor = redactorFor(findBankNumbers);

/** A marker in the composed text so far, with the span of the original input it replaced. */
interface Replaced {
  start: number;
  end: number;
  originalStart: number;
  originalEnd: number;
}

/**
 * Maps an offset in the composed text back to the original input. An offset inside a marker maps
 * to the start or the end of what the marker replaced, so a finding over it covers all of it.
 */
function toOriginal(at: number, replaced: readonly Replaced[], side: "start" | "end"): number {
  let shift = 0;
  for (const r of replaced) {
    if (at <= r.start) break;
    if (at < r.end) return side === "start" ? r.originalStart : r.originalEnd;
    shift = r.originalEnd - r.end;
  }
  return at + shift;
}

/**
 * Runs redactors in order, each over the previous one's output, and reports their findings in that
 * order, with offsets into the original input. Each redactor must replace each of its findings
 * with its kind's marker and leave the rest of the text as it was, as the redactors here do, and
 * report its findings sorted and not overlapping. A composed redactor does not, so list every
 * redactor in one call rather than composing compositions.
 *
 * Put health card numbers before SINs: a 10-digit health card number can start with a valid SIN,
 * and a SIN pass run first would replace that prefix and leave the last digit.
 */
export function composeRedactors(...redactors: Redactor[]): Redactor {
  return {
    redact(text) {
      let current = text;
      let replaced: Replaced[] = [];
      const findings: RedactionFinding[] = [];
      for (const r of redactors) {
        const result = r.redact(current);
        const next: Replaced[] = [];
        let delta = 0;
        let k = 0;
        for (const f of result.findings) {
          // Earlier markers before this finding move by the length change so far; any it covers go.
          for (; k < replaced.length && replaced[k]!.start < f.end; k++) {
            const old = replaced[k]!;
            if (old.end <= f.start) next.push({ ...old, start: old.start + delta, end: old.end + delta });
          }
          const originalStart = toOriginal(f.start, replaced, "start");
          const originalEnd = toOriginal(f.end, replaced, "end");
          const start = f.start + delta;
          const end = start + REDACTION_MARKERS[f.kind].length;
          next.push({ start, end, originalStart, originalEnd });
          findings.push({ kind: f.kind, start: originalStart, end: originalEnd });
          delta = end - f.end;
        }
        for (const old of replaced.slice(k)) next.push({ ...old, start: old.start + delta, end: old.end + delta });
        replaced = next;
        current = result.text;
      }
      return { text: current, findings };
    },
  };
}
