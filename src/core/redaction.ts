// Redaction of transcripts and any other text before it is stored or sent on.
//
// The first detector is card numbers (PANs): 13 to 19 digits that pass the Luhn check, written as
// digits or spoken in English, French or Spanish (digit by digit, as numbers such as "forty two" or
// "quarante-deux", or with "double" and "triple"), in any script's decimal digits, with separators
// between groups: spaces, dashes, dots, commas, slashes, underscores, middle dots and invisible
// characters (SEPARATOR_CLASS). The same reading of spoken numbers feeds the live detector (live-detector.ts). A match
// is replaced by a fixed marker. Over-redaction is accepted; the risk this guards against is a card
// number reaching storage.

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

/** What a redactor knows of the text's call: its language, whose number words are read. Absent: every language. */
export interface RedactionContext {
  locale?: NumberLanguage;
}

/** The redaction interface: a host can add detectors and compose them. */
export interface Redactor {
  redact(text: string, context?: RedactionContext): RedactionResult;
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

type NumberWordKind = "unit" | "teen" | "tens" | "hundred" | "thousand" | "repeat";

interface NumberWord {
  kind: NumberWordKind;
  value: number;
}

/**
 * The languages number words are read in. A call reads only its own language's words (`once`, `dos`
 * and `y` are Spanish numbers but English words); text redacted with no call reads every language,
 * the safe side.
 */
export type NumberLanguage = "en" | "fr" | "es";
export const NUMBER_LANGUAGES: readonly NumberLanguage[] = ["en", "fr", "es"];

type WordList = ReadonlyArray<readonly [NumberWordKind, string, number]>;
const each = (kind: NumberWordKind, list: ReadonlyArray<readonly [string, number]>): WordList => list.map(([w, v]) => [kind, w, v] as const);

const ENGLISH: WordList = [
  ...each("unit", [["zero", 0], ["oh", 0], ["one", 1], ["two", 2], ["three", 3], ["four", 4], ["five", 5], ["six", 6], ["seven", 7], ["eight", 8], ["nine", 9]]),
  ...each("teen", [
    ["ten", 10], ["eleven", 11], ["twelve", 12], ["thirteen", 13], ["fourteen", 14], ["fifteen", 15],
    ["sixteen", 16], ["seventeen", 17], ["eighteen", 18], ["nineteen", 19],
  ]),
  ...each("tens", [["twenty", 20], ["thirty", 30], ["forty", 40], ["fifty", 50], ["sixty", 60], ["seventy", 70], ["eighty", 80], ["ninety", 90]]),
  ...each("hundred", [["hundred", 100]]),
  ...each("thousand", [["thousand", 1000]]),
  ...each("repeat", [["double", 2], ["triple", 3]]),
];

const FRENCH: WordList = [
  ...each("unit", [["zéro", 0], ["un", 1], ["une", 1], ["deux", 2], ["trois", 3], ["quatre", 4], ["cinq", 5], ["six", 6], ["sept", 7], ["huit", 8], ["neuf", 9]]),
  ...each("teen", [["dix", 10], ["onze", 11], ["douze", 12], ["treize", 13], ["quatorze", 14], ["quinze", 15], ["seize", 16]]),
  ...each("tens", [
    ["vingt", 20], ["vingts", 20], ["trente", 30], ["quarante", 40], ["cinquante", 50], ["soixante", 60],
    ["septante", 70], ["huitante", 80], ["octante", 80], ["nonante", 90],
  ]),
  ...each("hundred", [["cent", 100], ["cents", 100]]),
  ...each("thousand", [["mille", 1000]]),
  ...each("repeat", [["double", 2], ["triple", 3]]),
];

const SPANISH: WordList = [
  ...each("unit", [["cero", 0], ["uno", 1], ["una", 1], ["un", 1], ["dos", 2], ["tres", 3], ["cuatro", 4], ["cinco", 5], ["seis", 6], ["siete", 7], ["ocho", 8], ["nueve", 9]]),
  // 10 to 19, and 21 to 29, which Spanish writes as one word ("veintiuno"), with or without accents.
  ...each("teen", [
    ["diez", 10], ["once", 11], ["doce", 12], ["trece", 13], ["catorce", 14], ["quince", 15],
    ["dieciséis", 16], ["dieciseis", 16], ["diecisiete", 17], ["dieciocho", 18], ["diecinueve", 19],
    ["veintiuno", 21], ["veintiún", 21], ["veintiun", 21], ["veintiuna", 21], ["veintidós", 22], ["veintidos", 22],
    ["veintitrés", 23], ["veintitres", 23], ["veinticuatro", 24], ["veinticinco", 25], ["veintiséis", 26],
    ["veintiseis", 26], ["veintisiete", 27], ["veintiocho", 28], ["veintinueve", 29],
  ]),
  ...each("tens", [["veinte", 20], ["treinta", 30], ["cuarenta", 40], ["cincuenta", 50], ["sesenta", 60], ["setenta", 70], ["ochenta", 80], ["noventa", 90]]),
  // Spanish writes its hundreds as one word each ("doscientos" is 200), read like "hundred" with its count.
  ...each("hundred", [
    ["cien", 100], ["ciento", 100], ["doscientos", 200], ["doscientas", 200], ["trescientos", 300], ["trescientas", 300],
    ["cuatrocientos", 400], ["cuatrocientas", 400], ["quinientos", 500], ["quinientas", 500], ["seiscientos", 600],
    ["seiscientas", 600], ["setecientos", 700], ["setecientas", 700], ["ochocientos", 800], ["ochocientas", 800],
    ["novecientos", 900], ["novecientas", 900],
  ]),
  ...each("thousand", [["mil", 1000]]),
];

// Maps, not object literals, so that a word such as "constructor" is never read as a number.
const NUMBER_WORDS: Readonly<Record<NumberLanguage, ReadonlyMap<string, NumberWord>>> = {
  en: new Map(ENGLISH.map(([kind, w, value]) => [w, { kind, value }])),
  fr: new Map(FRENCH.map(([kind, w, value]) => [w, { kind, value }])),
  es: new Map(SPANISH.map(([kind, w, value]) => [w, { kind, value }])),
};

/** The word inside a number in each language: "four hundred and two", "vingt et un", "cuarenta y uno". */
export const NUMBER_CONNECTORS: Readonly<Record<NumberLanguage, string>> = { en: "and", fr: "et", es: "y" };

/** The number words and connectors of some languages. Unknown names are ignored. */
interface Vocabulary {
  number(word: string): NumberWord | undefined;
  connects(word: string): boolean;
}

function vocabulary(languages: readonly NumberLanguage[]): Vocabulary {
  const known = NUMBER_LANGUAGES.filter((l) => languages.includes(l));
  const connectors = new Set(known.map((l) => NUMBER_CONNECTORS[l]));
  return {
    number: (word) => {
      for (const l of known) {
        const w = NUMBER_WORDS[l].get(word);
        if (w !== undefined) return w;
      }
      return undefined;
    },
    connects: (word) => connectors.has(word),
  };
}

interface Lexeme {
  raw: string;
  /** A numeral's digits in ASCII, whatever script it was written in; null for a word. */
  digits: string | null;
  /** Lower case, for the word table. */
  word: string;
  /** The number word it is in the languages read, if any. */
  number: NumberWord | undefined;
  /** Whether it is a connector ("and", "et", "y") in the languages read. */
  connects: boolean;
  start: number;
  end: number;
  /** Only separators lie between this lexeme and the one before it. */
  joined: boolean;
}

/** Part of a run of digits: one numeral or one spoken number, with its UTF-16 offsets. */
export interface DigitPart {
  digits: string;
  start: number;
  end: number;
}

interface Parsed {
  value: number;
  /** The index of the first lexeme after the number. */
  next: number;
}

type Parser = (lx: readonly Lexeme[], i: number, first: boolean) => Parsed | undefined;

/**
 * A word or numeral, as runs are read (live-detector.ts counts words with it too). A word keeps its
 * combining marks, so "zéro" written decomposed (e and U+0301) is one word, not "ze" and "ro".
 */
export const LEXEME = /\p{Nd}+|\p{L}[\p{L}\p{M}]*/gu;
/**
 * What may lie between the groups of one number: spaces, any dash (the hyphen-minus, en and em
 * dashes, the non-breaking hyphen), the minus sign, dots, commas, slashes, underscores and middle
 * dots, and what a reader never sees: format characters (zero-width spaces and joiners, soft
 * hyphens, bidi controls) and combining marks.
 * The live detector uses the same class, so both read one run alike.
 */
export const SEPARATOR_CLASS = String.raw`[\s\p{Pd}\u2212\p{Cf}\p{M}.,/_\u00b7]`;
const SEPARATOR = new RegExp(`^${SEPARATOR_CLASS}*$`, "u");

const NUMERAL = /^\p{Nd}/u;
const DECIMAL_DIGIT = /^\p{Nd}$/u;

/**
 * The value of one Unicode decimal digit. Unicode encodes every decimal digit in runs of ten, 0 to
 * 9, so a digit's value is its distance from the first digit of its run, modulo 10.
 */
function digitValue(cp: number): number {
  let first = cp;
  while (DECIMAL_DIGIT.test(String.fromCodePoint(first - 1))) first--;
  return (cp - first) % 10;
}

/** A numeral in any script as ASCII digits ("٤١" is "41", "４１" is "41"), for the checks; its span stays the original's. */
function asciiDigits(raw: string): string {
  let out = "";
  for (const ch of raw) out += String(digitValue(ch.codePointAt(0)!));
  return out;
}

function lexemes(text: string, vocab: Vocabulary): Lexeme[] {
  const out: Lexeme[] = [];
  let lastEnd = 0;
  for (const match of text.matchAll(LEXEME)) {
    const raw = match[0];
    const start = match.index;
    const joined = out.length > 0 && SEPARATOR.test(text.slice(lastEnd, start));
    const word = raw.normalize("NFC").toLowerCase();
    out.push({ raw, digits: NUMERAL.test(raw) ? asciiDigits(raw) : null, word, number: vocab.number(word), connects: vocab.connects(word), start, end: start + raw.length, joined });
    lastEnd = start + raw.length;
  }
  return out;
}

/**
 * The number word at `i`. Every word of a spoken number after its first must be joined to the one
 * before it, so `first` is true only where a number starts.
 */
function numberWord(lx: readonly Lexeme[], i: number, first: boolean): NumberWord | undefined {
  const l = lx[i];
  return l !== undefined && (first || l.joined) ? l.number : undefined;
}

/** Whether `word` ("and", "et", "y") is at `i`, joined to the word before it. */
function connector(lx: readonly Lexeme[], i: number, word: string): boolean {
  const l = lx[i];
  return l !== undefined && l.joined && l.connects && l.word === word;
}

/** 1 to 9, continuing a number. */
function unitAfter(lx: readonly Lexeme[], i: number): Parsed | undefined {
  const w = numberWord(lx, i, false);
  return w?.kind === "unit" && w.value > 0 ? { value: w.value, next: i + 1 } : undefined;
}

/** 10 to 19, French "dix-sept" to "dix-neuf" included. */
function teen(lx: readonly Lexeme[], i: number, first: boolean): Parsed | undefined {
  const w = numberWord(lx, i, first);
  if (w?.kind !== "teen") return undefined;
  const unit = lx[i]!.word === "dix" ? unitAfter(lx, i + 1) : undefined;
  if (unit !== undefined && unit.value >= 7) return { value: 10 + unit.value, next: unit.next };
  return { value: w.value, next: i + 1 };
}

/**
 * 0 to 99: a unit, a teen, or tens with an optional unit ("forty two", "quarante-deux",
 * "vingt et un", "soixante-douze", "quatre-vingt-dix-sept").
 */
function below100(lx: readonly Lexeme[], i: number, first: boolean): Parsed | undefined {
  const w = numberWord(lx, i, first);
  if (w?.kind === "teen") return teen(lx, i, first);
  if (w?.kind === "unit") {
    if (lx[i]!.word === "quatre" && numberWord(lx, i + 1, false)?.kind === "tens") {
      // "quatre-vingts" ends a number (the plural is written only then); "quatre-vingt" goes on.
      const vingt = lx[i + 1]!.word;
      if (vingt === "vingts") return { value: 80, next: i + 2 };
      if (vingt === "vingt") {
        const rest = teen(lx, i + 2, false) ?? unitAfter(lx, i + 2);
        return rest === undefined ? { value: 80, next: i + 2 } : { value: 80 + rest.value, next: rest.next };
      }
    }
    return { value: w.value, next: i + 1 };
  }
  if (w?.kind !== "tens") return undefined;
  if (connector(lx, i + 1, "et")) {
    const after = numberWord(lx, i + 2, false);
    if (after?.value === 1 || after?.value === 11) return { value: w.value + after.value, next: i + 3 };
  }
  // Spanish: tens, "y", a unit ("cuarenta y uno").
  if (connector(lx, i + 1, "y")) {
    const unit = unitAfter(lx, i + 2);
    if (unit !== undefined) return { value: w.value + unit.value, next: unit.next };
  }
  const rest = (lx[i]!.word === "soixante" ? teen(lx, i + 1, false) : undefined) ?? unitAfter(lx, i + 1);
  return rest === undefined ? { value: w.value, next: i + 1 } : { value: w.value + rest.value, next: rest.next };
}

/**
 * A scale word ("hundred", "cent"; "thousand", "mille") with an optional count before it and an
 * optional remainder after it: "four hundred and two", "forty two hundred", "deux mille vingt".
 */
function scaled(kind: "hundred" | "thousand", below: Parser): Parser {
  return (lx, i, first) => {
    let value: number;
    let next: number;
    const w = numberWord(lx, i, first);
    if (w?.kind === kind) {
      value = w.value;
      next = i + 1;
    } else {
      const count = below(lx, i, first);
      if (count === undefined) return undefined;
      const scale = numberWord(lx, count.next, false);
      if (scale?.kind !== kind) return count;
      value = count.value * scale.value;
      next = count.next + 1;
    }
    // "deux cents" ends a number, as "quatre-vingts" does.
    if (lx[next - 1]!.word === "cents") return { value, next };
    const rest = (connector(lx, next, "and") ? below(lx, next + 1, false) : undefined) ?? below(lx, next, false);
    return rest === undefined ? { value, next } : { value: value + rest.value, next: rest.next };
  };
}

const spokenNumber = scaled("thousand", scaled("hundred", below100));

/** One part of a run at `i`: a numeral, "double" or "triple" and one digit, or a spoken number. */
function part(lx: readonly Lexeme[], i: number): { digits: string; next: number } | undefined {
  const l = lx[i]!;
  if (l.digits !== null) return { digits: l.digits, next: i + 1 };
  const w = l.number;
  if (w?.kind === "repeat") {
    const times = w.value;
    const after = lx[i + 1];
    if (after?.joined === true && after.digits?.length === 1) return { digits: after.digits.repeat(times), next: i + 2 };
    const unit = numberWord(lx, i + 1, false);
    return unit?.kind === "unit" ? { digits: String(unit.value).repeat(times), next: i + 2 } : undefined;
  }
  const n = spokenNumber(lx, i, true);
  return n === undefined ? undefined : { digits: String(n.value), next: n.next };
}

/**
 * Runs of digits in a text: numerals and spoken numbers in English, French or Spanish, with only
 * separators between them (SEPARATOR_CLASS). Spoken numbers are read as people say them: "forty two" is
 * 42, "quatre-vingt-dix" is 90, "double four" is 44, "forty two hundred" is 4200, and "four two"
 * is 4 then 2. Any other word ends a run. Only the given languages' words are read (every language
 * by default); numerals are read in any.
 */
export function digitRuns(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): DigitPart[][] {
  const lx = lexemes(text, vocabulary(languages));
  const runs: DigitPart[][] = [];
  let run: DigitPart[] = [];
  const close = () => {
    if (run.length > 0) runs.push(run);
    run = [];
  };
  let i = 0;
  while (i < lx.length) {
    if (!lx[i]!.joined) close();
    const p = part(lx, i);
    if (p === undefined) {
      close();
      i++;
    } else {
      run.push({ digits: p.digits, start: lx[i]!.start, end: lx[p.next - 1]!.end });
      i = p.next;
    }
  }
  close();
  return runs;
}

/** Card numbers in a text, leftmost first, longest match at each position, never overlapping. */
export function findCardNumbers(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): RedactionFinding[] {
  const findings: RedactionFinding[] = [];
  for (const run of digitRuns(text, languages)) {
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

export const cardNumberRedactor: Redactor = {
  redact(text, context) {
    const findings = findCardNumbers(text, context?.locale === undefined ? NUMBER_LANGUAGES : [context.locale]);
    return { text: applyFindings(text, findings), findings };
  },
};

/**
 * Runs redactors in order, each over the previous one's output. Finding offsets refer to the text
 * each redactor saw, so they are reported per stage, in order.
 */
export function composeRedactors(...redactors: Redactor[]): Redactor {
  return {
    redact(text, context) {
      let current = text;
      const findings: RedactionFinding[] = [];
      for (const r of redactors) {
        const result = r.redact(current, context);
        current = result.text;
        findings.push(...result.findings);
      }
      return { text: current, findings };
    },
  };
}
