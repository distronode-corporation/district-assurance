// Supported locales (#47): one list, and every catalog of text the engine builds has an entry for
// each, so adding a locale makes every catalog grow with it.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { SUPPORTED_LOCALES, isSupportedLocale } from "../src/engine.ts";
import { DIGIT_WORDS_BY_LOCALE } from "../src/core/redaction.ts";
import { AMOUNT_READBACK_TEXT } from "../src/pay/amount.ts";
import { AMOUNT_REGION, PAYMENT_TEXT } from "../src/pay/paylink.ts";
import { IDENTITY_TEXT } from "../src/verify/badge.ts";
import { ACCESS_CODE_TEXT } from "../src/gate/codes.ts";
import { rejects, setup } from "./helpers.ts";

/** Every catalog in src/, by its exported name. The source scan below fails when one is missing here. */
const CATALOGS: Record<string, Record<string, unknown>> = { IDENTITY_TEXT, PAYMENT_TEXT, AMOUNT_READBACK_TEXT, AMOUNT_REGION, DIGIT_WORDS_BY_LOCALE, ACCESS_CODE_TEXT };

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : path.endsWith(".ts") ? [path] : [];
  });
}

const SOURCES = sourceFiles(fileURLToPath(new URL("../src", import.meta.url))).map((path) => ({ path, text: readFileSync(path, "utf8") }));
/** The demo, the e2e demo and the UI's server code: they start calls too, and could grow a catalog of their own. */
const DEMO_SOURCES = sourceFiles(fileURLToPath(new URL("../examples/reference-server/src", import.meta.url))).map((path) => ({ path, text: readFileSync(path, "utf8") }));

describe("supported locales", () => {
  it("are en and fr, in one frozen list", () => {
    assert.deepEqual([...SUPPORTED_LOCALES], ["en", "fr"]);
    assert.ok(Object.isFrozen(SUPPORTED_LOCALES));
    for (const locale of SUPPORTED_LOCALES) assert.equal(isSupportedLocale(locale), true);
    for (const value of ["es", "EN", "", "en-CA", undefined, null, 1, ["en"]]) assert.equal(isSupportedLocale(value), false, String(value));
  });

  it("are what startCall takes, and nothing else", async () => {
    const t = setup();
    for (const locale of SUPPORTED_LOCALES) assert.equal((await t.engine.startCall({ callId: `call_${locale}`, locale })).callId, `call_${locale}`);
    for (const locale of ["es", "EN", "", "en-CA", 1]) {
      await assert.rejects(t.engine.startCall({ locale: locale as "en" }), rejects("invalid_input", /locale must be one of en, fr/), String(locale));
    }
  });

  it("each have an entry in every catalog, and nothing else", () => {
    for (const [name, catalog] of Object.entries(CATALOGS)) {
      assert.deepEqual(Object.keys(catalog).sort(), [...SUPPORTED_LOCALES].sort(), name);
      for (const locale of SUPPORTED_LOCALES) {
        const entry = catalog[locale];
        if (typeof entry === "function") assert.ok(String(entry("A", "B")).trim() !== "", `${name}.${locale}`);
        else if (typeof entry === "string") assert.ok(entry.trim() !== "", `${name}.${locale}`);
        else assert.ok(Object.keys(entry as object).length > 0, `${name}.${locale}`);
      }
    }
  });

  it("each say every sent text in their own words: no locale reuses another's", () => {
    for (const name of ["IDENTITY_TEXT", "PAYMENT_TEXT"]) {
      const said = SUPPORTED_LOCALES.map((locale) => (CATALOGS[name]![locale] as (a: string, b: string) => string)("A", "B"));
      assert.equal(new Set(said).size, said.length, name);
    }
  });

  it("are the only way code picks its words: every Record<Locale, ...> is a listed catalog, and no locale ternary or en/fr literal type is left", () => {
    const declared = SOURCES.flatMap(({ text }) => [...text.matchAll(/export const (\w+): Record<Locale\b/g)].map((m) => m[1]!));
    assert.deepEqual(declared.sort(), Object.keys(CATALOGS).sort(), "a catalog in src/ that this test does not check, or one it lists that is gone");
    for (const { path, text } of SOURCES) {
      assert.doesNotMatch(text, /locale === "|locale !== "/, `${path}: pick words from a Record<Locale, ...> catalog`);
      assert.doesNotMatch(text, /"en" \| "fr"/, `${path}: use the Locale type`);
    }
  });

  it("are the only locales the demo, the e2e demo and the UI start calls in, and the demo keeps no catalog of its own", () => {
    const passed = DEMO_SOURCES.flatMap(({ path, text }) => [...text.matchAll(/startCall\(\{[^}]*\blocale:\s*([^,}\s]+)/g)].map((m) => ({ path, value: m[1]! })));
    assert.ok(passed.length >= 3, "the scan finds the demo's calls");
    for (const { path, value } of passed) {
      const literal = /^"([^"]*)"$/.exec(value);
      assert.ok(literal !== null, `${path}: a call's locale is a literal, so this scan can check it (${value})`);
      assert.equal(isSupportedLocale(literal[1]), true, `${path}: ${value}`);
    }
    for (const { path, text } of DEMO_SOURCES) {
      // A demo-side Record<Locale, ...> would need a place in CATALOGS above; there is none today.
      assert.doesNotMatch(text, /Record<Locale\b/, `${path}: register a demo catalog in CATALOGS`);
      assert.doesNotMatch(text, /locale === "|locale !== "|"en" \| "fr"/, `${path}: pick words by Locale`);
    }
  });
});
