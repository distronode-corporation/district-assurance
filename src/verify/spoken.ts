// Spoken answers for values a keypad cannot enter: Canadian postal codes, US ZIP codes and short
// alphanumeric references.
//
// A transcript is read token by token into letters and digits, then checked against the field's
// format. The rules are exact: a token is a digit, a single letter, a mix of the two as written
// (`K1A`), or a word from the call's language (digit words, letter names, the NATO spelling
// alphabet, and in French the traditional one). "B as in bravo" and "B comme Berthe" confirm the
// letter before them, and a confirming word that starts with another letter makes the answer
// unusable. Any other word, any other character, or a result that is not the field's format makes
// the answer unusable. Nothing is guessed: "oh" is the letter O, never zero, and there is no near
// match. The normalised value is compared like a keypad field (spoken_knowledge in factors.ts).
import { EngineError } from "../core/errors.ts";
import { SPOKEN_FORMATS, type SpokenFormat } from "../core/policy.ts";
import type { Locale } from "../core/runtime.ts";

/** A normalised value (upper case letters and digits, no spaces), or `unusable`. Never a near match. */
export type SpokenAnswer = { status: "normalised"; value: string } | { status: "unusable" };

/** Longer transcripts are unusable: an answer to one prompt is a few words. */
export const MAX_SPOKEN_TRANSCRIPT = 200;

/** The normalised form of each format. */
const FORMATS: Readonly<Record<SpokenFormat, RegExp>> = {
  // Letter, digit, letter, digit, letter, digit. D, F, I, O, Q and U are never used; W and Z never first.
  ca_postal_code: /^[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d$/,
  // Five digits. ZIP+4 is not accepted.
  us_zip_code: /^\d{5}$/,
  reference: /^[A-Z0-9]{4,12}$/,
};

/** After case and accent folding, only letters, digits and these separators may appear. */
const ALLOWED = /^[a-z0-9\s.,;:!?'"-]*$/;
const SEPARATORS = /[\s.,;:!?'"-]+/;

const NATO: ReadonlyArray<readonly [string, string]> = [
  ["alpha", "A"], ["alfa", "A"], ["bravo", "B"], ["charlie", "C"], ["delta", "D"], ["echo", "E"], ["foxtrot", "F"],
  ["golf", "G"], ["hotel", "H"], ["india", "I"], ["juliet", "J"], ["juliett", "J"], ["kilo", "K"], ["lima", "L"],
  ["mike", "M"], ["november", "N"], ["oscar", "O"], ["papa", "P"], ["quebec", "Q"], ["romeo", "R"], ["sierra", "S"],
  ["tango", "T"], ["uniform", "U"], ["victor", "V"], ["whiskey", "W"], ["whisky", "W"], ["xray", "X"], ["x ray", "X"],
  ["yankee", "Y"], ["zulu", "Z"],
];

const ENGLISH: ReadonlyArray<readonly [string, string]> = [
  ["zero", "0"], ["one", "1"], ["two", "2"], ["three", "3"], ["four", "4"], ["five", "5"], ["six", "6"], ["seven", "7"],
  ["eight", "8"], ["nine", "9"], ["niner", "9"],
  ["bee", "B"], ["be", "B"], ["cee", "C"], ["see", "C"], ["sea", "C"], ["dee", "D"], ["ef", "F"], ["eff", "F"], ["gee", "G"],
  ["aitch", "H"], ["haitch", "H"], ["eye", "I"], ["jay", "J"], ["kay", "K"], ["el", "L"], ["ell", "L"], ["em", "M"],
  ["en", "N"], ["oh", "O"], ["pee", "P"], ["cue", "Q"], ["queue", "Q"], ["ar", "R"], ["are", "R"], ["ess", "S"],
  ["tee", "T"], ["tea", "T"], ["you", "U"], ["yew", "U"], ["vee", "V"], ["double u", "W"], ["double you", "W"],
  ["ex", "X"], ["why", "Y"], ["wye", "Y"], ["zee", "Z"], ["zed", "Z"],
];

// Accents are folded before lookup: "zéro" is read as "zero", "Célestin" as "celestin".
const FRENCH: ReadonlyArray<readonly [string, string]> = [
  ["zero", "0"], ["un", "1"], ["une", "1"], ["deux", "2"], ["trois", "3"], ["quatre", "4"], ["cinq", "5"], ["six", "6"],
  ["sept", "7"], ["huit", "8"], ["neuf", "9"],
  ["be", "B"], ["ce", "C"], ["de", "D"], ["eu", "E"], ["ef", "F"], ["effe", "F"], ["ge", "G"], ["ache", "H"], ["ji", "J"],
  ["ka", "K"], ["el", "L"], ["elle", "L"], ["em", "M"], ["emme", "M"], ["en", "N"], ["enne", "N"], ["pe", "P"],
  ["ku", "Q"], ["qu", "Q"], ["er", "R"], ["erre", "R"], ["es", "S"], ["esse", "S"], ["te", "T"], ["ve", "V"],
  ["double ve", "W"], ["double v", "W"], ["ixe", "X"], ["iks", "X"], ["i grec", "Y"], ["zed", "Z"], ["zede", "Z"],
  // The traditional French spelling alphabet.
  ["anatole", "A"], ["berthe", "B"], ["celestin", "C"], ["desire", "D"], ["eugene", "E"], ["francois", "F"],
  ["gaston", "G"], ["henri", "H"], ["irma", "I"], ["joseph", "J"], ["kleber", "K"], ["louis", "L"], ["marcel", "M"],
  ["nicolas", "N"], ["pierre", "P"], ["quintal", "Q"], ["raoul", "R"], ["suzanne", "S"], ["therese", "T"],
  ["ursule", "U"], ["william", "W"], ["xavier", "X"], ["yvonne", "Y"], ["zoe", "Z"],
];

interface Vocabulary {
  /** A word, or two words joined by one space, to the letter or digit it stands for. */
  words: ReadonlyMap<string, string>;
  /** Words that introduce a word confirming the letter before them, longest first. */
  connectors: ReadonlyArray<readonly string[]>;
}

const VOCABULARIES: Readonly<Record<Locale, Vocabulary>> = {
  en: { words: new Map([...NATO, ...ENGLISH]), connectors: [["as", "in"], ["for"]] },
  fr: { words: new Map([...NATO, ...FRENCH]), connectors: [["comme", "dans"], ["comme"]] },
};

const UNUSABLE: SpokenAnswer = { status: "unusable" };

/**
 * Normalises a spoken answer for an exact comparison. `field` is the value's format; `locale` the
 * call's language, which chooses the words that are understood. Returns `unusable` for anything
 * that is not exactly one value of the format, so the host can ask again before an attempt is used.
 */
export function normaliseSpokenAnswer(input: { field: SpokenFormat; transcript: string; locale: Locale }): SpokenAnswer {
  if (!(SPOKEN_FORMATS as readonly string[]).includes(input.field)) throw new EngineError("invalid_input", `field must be one of ${SPOKEN_FORMATS.join(", ")}`);
  if (input.locale !== "en" && input.locale !== "fr") throw new EngineError("invalid_input", "locale must be en or fr");
  const { transcript } = input;
  if (typeof transcript !== "string" || transcript.length > MAX_SPOKEN_TRANSCRIPT) return UNUSABLE;
  const folded = transcript.toLowerCase().normalize("NFD").replace(/\p{M}/gu, "");
  if (!ALLOWED.test(folded)) return UNUSABLE;
  const chars = readTokens(folded.split(SEPARATORS).filter((t) => t !== ""), VOCABULARIES[input.locale]);
  if (chars === null) return UNUSABLE;
  const value = chars.join("");
  return FORMATS[input.field].test(value) ? { status: "normalised", value } : UNUSABLE;
}

/** The letters and digits the tokens spell, or null when any token cannot be read exactly. */
function readTokens(tokens: readonly string[], vocabulary: Vocabulary): string[] | null {
  const chars: string[] = [];
  // Whether the last thing read was one letter, which a connector may then confirm.
  let letter: string | null = null;
  let i = 0;
  while (i < tokens.length) {
    const connector = vocabulary.connectors.find((words) => words.every((w, k) => tokens[i + k] === w));
    if (connector !== undefined) {
      const word = tokens[i + connector.length];
      if (letter === null || word === undefined || !/^[a-z]+$/.test(word) || word[0]!.toUpperCase() !== letter) return null;
      letter = null;
      i += connector.length + 1;
      continue;
    }
    const token = tokens[i]!;
    const pair = vocabulary.words.get(`${token} ${tokens[i + 1]}`);
    const read = pair ?? (/^[a-z]$/.test(token) ? token.toUpperCase() : vocabulary.words.get(token));
    if (read !== undefined) {
      chars.push(read);
      letter = /^[A-Z]$/.test(read) ? read : null;
      i += pair === undefined ? 1 : 2;
      continue;
    }
    // Digits, or letters and digits written together (K1A), are read one character at a time.
    if (!/\d/.test(token)) return null;
    chars.push(...token.toUpperCase());
    letter = null;
    i++;
  }
  return chars;
}
