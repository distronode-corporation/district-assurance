// Redaction of transcripts and any other text before it is stored or sent on.
//
// The first detector is card numbers (PANs): 13 to 19 digits that pass the Luhn check, written as
// digits or spoken in English, French or Spanish (digit by digit, as numbers such as "forty two" or
// "quarante-deux", or with "double" and "triple"), in any script's decimal digits, with separators
// between groups: spaces, dashes, dots, commas, slashes, underscores, middle dots and invisible
// characters (SEPARATOR_CLASS). The same reading of spoken numbers feeds the live detector (live-detector.ts). A match
// is replaced by a fixed marker. Over-redaction is accepted; the risk this guards against is a card
// number reaching storage.
//
// Further detectors, each its own `Redactor` over the same digit runs (PRV-6): Canadian social
// insurance numbers, provincial health card numbers, and bank transit and account numbers. A
// host composes the ones it wants with `composeRedactors`, card numbers first, then health card
// numbers, SINs and bank numbers.
import { SUPPORTED_LOCALES, type Locale } from "./runtime.ts";

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

/** What a redactor knows of the text's call: its language, whose number words are read. Absent: every language. */
export interface RedactionContext {
  locale?: NumberLanguage;
}

/** The redaction interface: a host can add detectors and compose them. */
export interface Redactor {
  redact(text: string, context?: RedactionContext): RedactionResult;
}

/**
 * The fixed line a host speaks when a redactor fires, per kind and language. Only a card number is
 * offered a payment link instead; the other numbers are never needed on a call.
 */
export const INTERRUPT_LINES: Record<Locale, Readonly<Record<RedactionKind, string>>> = {
  en: {
    card_number: "Please do not read card numbers aloud. I can text you a secure payment link instead.",
    health_card: "Please do not read your health card number aloud. I do not need it on this call.",
    sin: "Please do not read your social insurance number aloud. I do not need it on this call.",
    bank_account: "Please do not read your banking details aloud. I do not need them on this call.",
  },
  fr: {
    card_number: "Veuillez ne pas lire de numéro de carte à voix haute. Je peux plutôt vous envoyer un lien de paiement sécurisé par texto.",
    health_card: "Veuillez ne pas lire votre numéro d'assurance maladie à voix haute. Je n'en ai pas besoin pendant cet appel.",
    sin: "Veuillez ne pas lire votre numéro d'assurance sociale à voix haute. Je n'en ai pas besoin pendant cet appel.",
    bank_account: "Veuillez ne pas lire vos renseignements bancaires à voix haute. Je n'en ai pas besoin pendant cet appel.",
  },
  es: {
    card_number: "Por favor, no lea números de tarjeta en voz alta. Puedo enviarle por mensaje de texto un enlace de pago seguro.",
    health_card: "Por favor, no lea su número de tarjeta sanitaria en voz alta. No lo necesito en esta llamada.",
    sin: "Por favor, no lea su número de seguro social en voz alta. No lo necesito en esta llamada.",
    bank_account: "Por favor, no lea sus datos bancarios en voz alta. No los necesito en esta llamada.",
  },
};

/** Which kind's line is spoken when several fire at once: a card number first, then this order. */
const INTERRUPT_ORDER: readonly RedactionKind[] = ["card_number", "health_card", "sin", "bank_account"];

/** The line for a set of findings in a language, or null when there are none. */
export function interruptLine(findings: readonly RedactionFinding[], locale: Locale): string | null {
  const kind = INTERRUPT_ORDER.find((k) => findings.some((f) => f.kind === k));
  return kind === undefined ? null : INTERRUPT_LINES[locale][kind];
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

type NumberWordKind = "unit" | "teen" | "tens" | "hundred" | "thousand" | "repeat";

interface NumberWord {
  kind: NumberWordKind;
  value: number;
}

/**
 * The languages number words are read in. English and French are read on every call, since callers
 * switch between them and redaction errs towards removing more; Spanish words only on a Spanish call
 * (`once`, `dos` and `y` are Spanish numbers but English words). Text redacted with no call reads
 * every language, the safe side.
 */
export type NumberLanguage = Locale;
export const NUMBER_LANGUAGES: readonly NumberLanguage[] = SUPPORTED_LOCALES;

/** The languages whose number words are read on a call in each locale. */
export const NUMBER_LANGUAGES_BY_LOCALE: Record<Locale, readonly NumberLanguage[]> = { en: ["en", "fr"], fr: ["en", "fr"], es: NUMBER_LANGUAGES };

/** The languages whose number words are read on a call in `locale`; every language with none. */
export function numberLanguagesFor(locale: NumberLanguage | undefined): readonly NumberLanguage[] {
  return locale === undefined ? NUMBER_LANGUAGES : NUMBER_LANGUAGES_BY_LOCALE[locale];
}

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

/** Spanish hundreds are whole numbers ("doscientos" is 200), never a scale a count multiplies: "cuatro doscientos" is 4, 200. */
const SPANISH_HUNDREDS: ReadonlySet<string> = new Set(SPANISH.filter(([kind]) => kind === "hundred").map(([, w]) => w));

// Maps, not object literals, so that a word such as "constructor" is never read as a number.
const NUMBER_WORDS: Readonly<Record<NumberLanguage, ReadonlyMap<string, NumberWord>>> = {
  en: new Map(ENGLISH.map(([kind, w, value]) => [w, { kind, value }])),
  fr: new Map(FRENCH.map(([kind, w, value]) => [w, { kind, value }])),
  es: new Map(SPANISH.map(([kind, w, value]) => [w, { kind, value }])),
};

/** The word inside a number in each language: "four hundred and two", "vingt et un", "cuarenta y uno". */
export const NUMBER_CONNECTORS: Record<Locale, string> = { en: "and", fr: "et", es: "y" };

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
    let raw = match[0];
    const start = match.index;
    const joined = out.length > 0 && SEPARATOR.test(text.slice(lastEnd, start));
    let word = raw.normalize("NFC").toLowerCase();
    // Marks after a word that is no word with them ("four" and U+0301) are separators, as marks
    // between words are; a decomposed accent inside a word ("veintiu" U+0301 "n") stays part of it.
    const bare = raw.replace(/\p{M}+$/u, "");
    if (bare !== raw && vocab.number(word) === undefined && vocab.number(bare.normalize("NFC").toLowerCase()) !== undefined) {
      raw = bare;
      word = bare.normalize("NFC").toLowerCase();
    }
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
      if (scale?.kind !== kind || SPANISH_HUNDREDS.has(lx[count.next]!.word)) return count;
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

/** One match in a run: the tokens it uses (first to last) and where in the text it starts. */
interface RunMatch {
  first: number;
  last: number;
  start: number;
}

/**
 * The spans to remove from one run, given every match that starts at each token (`at(i)`, shortest
 * first). Matches are taken leftmost first and longest at each position, never overlapping, as
 * before. A match taken that way can be a false one (digits before a card, such as a phone number,
 * that pass the check with its first digits), and skipping past it would leave the rest of the real
 * number in clear. So every match is then checked against what was taken: one with a token left
 * uncovered is taken too, and overlapping spans are merged into one. Every match, the real number
 * included, is then inside a span, and two numbers side by side stay two spans. Each token starts
 * at most 19 matches (every token holds a digit, and no number is longer than 19), so a run is
 * read in linear time.
 */
function coverMatches(run: readonly DigitPart[], at: (i: number) => RunMatch[]): RunMatch[] {
  const matches = run.map((_, i) => at(i));
  const taken: RunMatch[] = [];
  const covered = new Uint8Array(run.length);
  for (let i = 0; i < run.length; ) {
    const longest = matches[i]!.at(-1);
    if (longest === undefined) {
      i++;
      continue;
    }
    taken.push(longest);
    covered.fill(1, longest.first, longest.last + 1);
    i = longest.last + 1;
  }
  for (const m of matches.flat()) if (covered.subarray(m.first, m.last + 1).includes(0)) taken.push(m);
  taken.sort((a, b) => a.first - b.first);
  const spans: RunMatch[] = [];
  for (const m of taken) {
    const open = spans.at(-1);
    if (open !== undefined && m.first <= open.last) {
      open.last = Math.max(open.last, m.last);
      open.start = Math.min(open.start, m.start);
    } else {
      spans.push({ ...m });
    }
  }
  return spans;
}

/**
 * Card numbers in a text: every match (13 to 19 digits that pass the Luhn check, starting and
 * ending on a numeral or spoken number) is inside a finding (coverMatches), so digits read just
 * before a card never leave part of it in clear.
 * Findings are sorted and never overlap.
 */
export function findCardNumbers(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): RedactionFinding[] {
  const findings: RedactionFinding[] = [];
  for (const run of digitRuns(text, languages)) {
    const at = (i: number): RunMatch[] => {
      const found: RunMatch[] = [];
      let digits = "";
      for (let j = i; j < run.length; j++) {
        digits += run[j]!.digits;
        if (digits.length > 19) break;
        if (digits.length >= 13 && luhnValid(digits)) found.push({ first: i, last: j, start: run[i]!.start });
      }
      return found;
    };
    for (const m of coverMatches(run, at)) findings.push({ kind: "card_number", start: m.start, end: run[m.last]!.end });
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

function redactorFor(find: (text: string, languages: readonly NumberLanguage[]) => RedactionFinding[]): Redactor {
  return {
    redact(text, context) {
      const findings = find(text, numberLanguagesFor(context?.locale));
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
function groupedAs(run: readonly DigitPart[], i: number, j: number, breaks: readonly number[]): boolean {
  let at = 0;
  for (let k = i; k < j; k++) {
    at += run[k]!.digits.length;
    const singles = run[k]!.digits.length === 1 && run[k + 1]!.digits.length === 1;
    if (!singles && !breaks.includes(at)) return false;
  }
  return true;
}

// Four letters, each gap and the gap before the digits at most 8 separators, so a match is at most
// 36 characters, 72 UTF-16 code units when each is astral (a letter, or a mark such as U+1D165),
// and only a short window before a run is read.
const FOUR_LETTERS_BEFORE = new RegExp(String.raw`(?<!\p{L})(?:\p{L}{4}|\p{L}(?:${SEPARATOR_CLASS}{1,8}\p{L}){3})${SEPARATOR_CLASS}{0,8}$`, "u");
/**
 * The look-back window in UTF-16 code units: the longest match (72) and the character before it
 * (2 when astral), so a match always fits whole and its letter check always sees the real
 * character before it.
 */
const FOUR_LETTERS_WINDOW = 74;

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
 * Numbers of the given formats in a text. Every match is inside a finding, as for card numbers
 * (coverMatches); findings are sorted and never overlap. A match starts at the first run token it
 * uses, or at its four letters.
 */
function findFormatted(text: string, kind: RedactionKind, formats: readonly NumberFormat[], languages: readonly NumberLanguage[]): RedactionFinding[] {
  const longest = Math.max(...formats.map((f) => f.length));
  const findings: RedactionFinding[] = [];
  for (const run of digitRuns(text, languages)) {
    const at = (i: number): RunMatch[] => {
      const found: RunMatch[] = [];
      let digits = "";
      for (let j = i; j < run.length; j++) {
        digits += run[j]!.digits;
        if (digits.length > longest) break;
        let start: number | undefined;
        for (const f of formats) {
          if (f.length !== digits.length || !groupedAs(run, i, j, f.breaks) || !f.valid(digits)) continue;
          // The letters must come before the run itself, never be a digit word inside it.
          let from: number | undefined = run[i]!.start;
          if (f.afterFourLetters === true) from = i === 0 ? fourLettersBefore(text, from) : undefined;
          if (from !== undefined) start = from;
        }
        if (start !== undefined) found.push({ first: i, last: j, start });
      }
      return found;
    };
    for (const m of coverMatches(run, at)) findings.push({ kind, start: m.start, end: run[m.last]!.end });
  }
  return findings;
}

/** Canadian social insurance numbers: 9 digits, Luhn, grouped 3-3-3 when written in groups. */
export function findSocialInsuranceNumbers(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): RedactionFinding[] {
  return findFormatted(text, "sin", [{ length: 9, breaks: [3, 6], valid: luhnValid }], languages);
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
export function findHealthCardNumbers(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): RedactionFinding[] {
  return findFormatted(text, "health_card", HEALTH_CARDS, languages);
}

export const healthCardRedactor: Redactor = redactorFor(findHealthCardNumbers);

/**
 * Words that mark a number after them as a bank number, by language: plurals too, and Spanish with
 * or without its accents. A call reads the languages #89 reads number words in (numberLanguagesFor):
 * English and French on every call, Spanish on a Spanish call and on text with no call.
 */
export const BANK_WORDS: Record<Locale, readonly string[]> = {
  en: ["bank", "banks", "branch", "branches", "transit", "transits", "institution", "institutions", "account", "accounts"],
  fr: ["banque", "banques", "bancaire", "bancaires", "succursale", "succursales", "transit", "transits", "institution", "institutions", "compte", "comptes", "folio", "folios"],
  es: [
    "banco", "bancos", "bancaria", "bancarias", "bancario", "bancarios", "sucursal", "sucursales", "cuenta", "cuentas",
    "tránsito", "tránsitos", "transito", "transitos", "institución", "instituciones", "institucion",
  ],
};

const BANK_WORD_SETS: Record<Locale, ReadonlySet<string>> = {
  en: new Set(BANK_WORDS.en),
  fr: new Set(BANK_WORDS.fr),
  es: new Set(BANK_WORDS.es),
};

/** A word, with any combining accents kept in it, so a decomposed "tránsito" is still one word. */
const WORD = /[\p{L}\p{M}]+/gu;
const MARKER_TEXTS = Object.values(REDACTION_MARKERS);

/**
 * Bank numbers: a digit run of 3 or more digits (an institution number is 3, a transit number 5,
 * an account number 7 to 12, or several read together) with a bank word among the last 4 words
 * before it, since the previous run. Bank numbers carry no check digit, so the word marks them.
 */
export function findBankNumbers(text: string, languages: readonly NumberLanguage[] = NUMBER_LANGUAGES): RedactionFinding[] {
  const findings: RedactionFinding[] = [];
  const isBankWord = (w: string) => languages.some((l) => BANK_WORD_SETS[l].has(w.normalize("NFC").toLowerCase()));
  let from = 0;
  for (const run of digitRuns(text, languages)) {
    const first = run[0]!;
    const last = run[run.length - 1]!;
    // A marker an earlier redactor left (composeRedactors) is not words: the bank word before it still counts.
    const gap = text.slice(from, first.start);
    const words = MARKER_TEXTS.reduce((g, marker) => g.replaceAll(marker, " "), gap).match(WORD) ?? [];
    from = last.end;
    const digits = run.reduce((n, t) => n + t.digits.length, 0);
    // Digits right after a marker are the rest of the run it replaced part of: any count goes.
    const rest = MARKER_TEXTS.some((marker) => gap.trimEnd().endsWith(marker));
    if ((digits >= 3 || rest) && words.slice(-4).some(isBankWord)) {
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
  // The last marker that starts before the offset (or at it, for a start: a finding that starts
  // where a marker starts covers it), by binary search: the markers are sorted and do not overlap,
  // so each call reads O(log n) of them, never every earlier one.
  let lo = 0;
  let hi = replaced.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    const from = replaced[mid]!.start;
    if (from < at || (side === "start" && from === at)) lo = mid + 1;
    else hi = mid;
  }
  if (lo === 0) return at;
  const r = replaced[lo - 1]!;
  if (at < r.end) return side === "start" ? r.originalStart : r.originalEnd;
  return at + r.originalEnd - r.end;
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
    redact(text, context) {
      let current = text;
      let replaced: Replaced[] = [];
      const findings: RedactionFinding[] = [];
      for (const r of redactors) {
        const result = r.redact(current, context);
        const next: Replaced[] = [];
        let delta = 0;
        let k = 0;
        // The end of the previous finding: an earlier marker's text from here on is still there.
        let after = 0;
        // What is left of an earlier marker (all of it, or the parts a finding did not replace) moves by
        // the length change so far and still maps to everything the marker replaced.
        const keep = (old: Replaced, upTo: number) => {
          const from = Math.max(old.start, after);
          if (from < upTo) next.push({ start: from + delta, end: upTo + delta, originalStart: old.originalStart, originalEnd: old.originalEnd });
        };
        for (const f of result.findings) {
          for (; k < replaced.length && replaced[k]!.start < f.end; k++) {
            const old = replaced[k]!;
            keep(old, Math.min(old.end, f.start));
            // A marker that goes on past this finding is kept for the next one, or for the end.
            if (old.end > f.end) break;
          }
          const originalStart = toOriginal(f.start, replaced, "start");
          const originalEnd = toOriginal(f.end, replaced, "end");
          const start = f.start + delta;
          const end = start + REDACTION_MARKERS[f.kind].length;
          next.push({ start, end, originalStart, originalEnd });
          findings.push({ kind: f.kind, start: originalStart, end: originalEnd });
          delta = end - f.end;
          after = f.end;
        }
        for (const old of replaced.slice(k)) keep(old, old.end);
        replaced = next;
        current = result.text;
      }
      return { text: current, findings };
    },
  };
}
