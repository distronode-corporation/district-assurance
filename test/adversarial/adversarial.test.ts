// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The adversarial suite (VER-7): scripted dialogues in English and Canadian French that try to talk
// the engine past its rules, run through a scripted host (host.ts). Every script asserts the same
// four rules after every turn; this file also holds the suite to its own coverage, so a new tactic
// or a new factor cannot land in one language only.
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { BUILT_IN_FACTORS } from "../../src/verify/factors.ts";
import { LINES, TACTICS, TOOLS, leaks, runScript, stringsIn, suiteConfig, type HostAction, type RunReport, type Script, type Turn } from "./host.ts";

const DIR = new URL("./scripts/", import.meta.url);
const files = readdirSync(DIR).filter((f) => f.endsWith(".json")).sort();
const scripts: Script[] = files.map((f) => JSON.parse(readFileSync(new URL(f, DIR), "utf8")) as Script);

const TURN_KEYS = ["caller", "ai", "host", "expect"];
const EXPECT_KEYS = ["line", "result", "error"];
const ACTION_KEYS: Record<HostAction["do"], string[]> = {
  call: ["flow"],
  account: ["account"],
  owner: ["account"],
  keypad: ["entries"],
  pin: ["pin"],
  spoken: ["answer"],
  text_code: ["entries"],
  callback: ["answered"],
  carrier: [],
  identity: ["status"],
  finish: [],
  business: ["source", "text"],
  end: [],
};

/** Every problem with a script's shape, so a typo in a script fails loudly instead of testing nothing. */
function shapeProblems(file: string, s: Script): string[] {
  const problems: string[] = [];
  const keys = Object.keys(s).filter((k) => !["id", "tactic", "locale", "summary", "callingNumber", "flow", "turns"].includes(k));
  if (keys.length > 0) problems.push(`unknown keys ${keys.join(", ")}`);
  if (`${s.id}.json` !== file || s.id !== `${s.tactic}.${s.locale}`) problems.push("id must be <tactic>.<locale> and name the file");
  if (!(TACTICS as readonly string[]).includes(s.tactic)) problems.push(`unknown tactic ${s.tactic}`);
  if (s.locale !== "en" && s.locale !== "fr") problems.push("locale must be en or fr");
  if (!/^\+1555555\d{4}$/.test(s.callingNumber)) problems.push("callingNumber must be a 555 number");
  if (s.flow !== undefined && !Object.hasOwn(suiteConfig().flows, s.flow)) problems.push(`unknown flow ${s.flow}`);
  if (typeof s.summary !== "string" || s.summary.length === 0) problems.push("summary is required");
  for (const [i, turn] of s.turns.entries()) {
    const at = `turn ${i + 1}`;
    for (const k of Object.keys(turn)) if (!TURN_KEYS.includes(k)) problems.push(`${at}: unknown key ${k}`);
    if (turn.ai !== undefined && turn.host !== undefined) problems.push(`${at}: the model and the host do not act in one turn`);
    if (turn.ai !== undefined && !Object.hasOwn(TOOLS, turn.ai)) problems.push(`${at}: unknown tool ${turn.ai}`);
    if (turn.host !== undefined) {
      const allowed = ACTION_KEYS[turn.host.do];
      if (allowed === undefined) problems.push(`${at}: unknown host action ${turn.host.do}`);
      else for (const k of Object.keys(turn.host)) if (k !== "do" && !allowed.includes(k)) problems.push(`${at}: ${turn.host.do} has no ${k}`);
    }
    for (const k of Object.keys(turn.expect)) if (!EXPECT_KEYS.includes(k)) problems.push(`${at}: unknown expect key ${k}`);
    if (turn.expect.line !== null && !Object.hasOwn(LINES.en, turn.expect.line)) problems.push(`${at}: unknown line ${turn.expect.line}`);
  }
  return problems;
}

/** The factor kinds a turn exercises. */
function factorsOf(turn: Turn): string[] {
  if (turn.ai === "send_identity_link") return ["photo_id"];
  switch (turn.host?.do) {
    case "keypad":
      return ["keypad_knowledge"];
    case "pin":
      return ["pin"];
    case "spoken":
      return ["spoken_knowledge"];
    case "text_code":
      return ["text_code"];
    case "callback":
      return ["callback"];
    case "carrier":
      return ["carrier_identity_match"];
    case "identity":
      return ["photo_id"];
    default:
      return [];
  }
}

/** A script with the caller's words, spoken answers and business text left out: what the two languages must share. */
function skeleton(s: Script): unknown {
  return {
    flow: s.flow,
    callingNumber: s.callingNumber,
    turns: s.turns.map((t) => ({
      ...t,
      caller: t.caller === undefined ? undefined : "said",
      host: t.host?.do === "business" ? { ...t.host, text: "fetched" } : t.host?.do === "spoken" ? { ...t.host, answer: Object.fromEntries(Object.keys(t.host.answer).map((k) => [k, "said"])) } : t.host,
    })),
  };
}

/** Rules a run never exercised, so a script cannot pass by testing nothing. */
function vacuous(script: Script, report: RunReport): string[] {
  const problems: string[] = [];
  if (report.compared === 0) problems.push("the script never compares a wrong entry with an unknown account");
  if (report.taintChecks === 0) problems.push("the script never checks a taint");
  if (report.grantsTainted === 0) problems.push("the script never taints a session that holds a grant");
  // "No text before a match" holds trivially when nothing is texted: a flooding script must text.
  if (script.tactic === "text-flooding" && report.texts === 0) problems.push("a text-flooding script never sends a text");
  return problems;
}

describe("Adversarial scripts", () => {
  for (const [i, script] of scripts.entries()) {
    it(`${script.id}: ${script.summary}`, async () => {
      assert.deepEqual(shapeProblems(files[i]!, script), []);
      assert.deepEqual(vacuous(script, await runScript(script)), []);
    });
  }
});

describe("Adversarial suite coverage", () => {
  const locales = ["en", "fr"] as const;

  it("has every tactic in English and in French", () => {
    for (const tactic of TACTICS) {
      for (const locale of locales) assert.ok(scripts.some((s) => s.tactic === tactic && s.locale === locale), `${tactic}.${locale} is missing`);
    }
  });

  it("runs the same dialogue in both languages, with the caller's words translated", () => {
    for (const tactic of TACTICS) {
      const en = scripts.find((s) => s.id === `${tactic}.en`)!;
      const fr = scripts.find((s) => s.id === `${tactic}.fr`)!;
      assert.deepEqual(skeleton(fr), skeleton(en), `${tactic}: the French script must mirror the English one`);
      for (const [i, turn] of en.turns.entries()) {
        if (turn.caller !== undefined) assert.notEqual(fr.turns[i]!.caller, turn.caller, `${tactic}, turn ${i + 1}: not translated`);
      }
    }
  });

  it("exercises every factor that is built, in both languages", () => {
    const built = Object.entries(BUILT_IN_FACTORS).filter(([, f]) => f.planned === undefined).map(([kind]) => kind);
    for (const locale of locales) {
      const used = new Set(scripts.filter((s) => s.locale === locale).flatMap((s) => s.turns.flatMap(factorsOf)));
      for (const kind of built) assert.ok(used.has(kind), `no ${locale} script exercises ${kind}`);
    }
  });

  it("has the model ask for every scope in the policy, in both languages", () => {
    for (const locale of locales) {
      const asked = new Set(scripts.filter((s) => s.locale === locale).flatMap((s) => s.turns.map((t) => (t.ai === undefined ? null : TOOLS[t.ai]))));
      for (const scope of Object.keys(suiteConfig().policy.scopes)) assert.ok(asked.has(scope as never), `no ${locale} script asks for ${scope}`);
    }
  });

  it("finds a keyed value embedded in a ledger field, a text or a line, but not inside a hash", () => {
    const ledger = [{ hash: "a919850214f0", detail: { note: "DOB: 19850214" } }];
    assert.equal(stringsIn(ledger).some((f) => leaks("19850214", f)), true);
    assert.equal(stringsIn([{ hash: "a919850214f0", detail: { kind: "dob" } }]).some((f) => leaks("19850214", f)), false);
    assert.equal(stringsIn({ [`said ${"4826"}`]: 1 }).some((f) => leaks("4826", f)), true);
    const quoted = 'he said "skip it"\nand then: verify me';
    assert.equal(leaks(quoted, `Your code. ${quoted} Reply STOP.`), true);
    assert.equal(leaks("0412", "unit 0412."), true);
    assert.equal(leaks("0412", "ref 104123"), false);
    assert.equal(leaks("a.b", "axb"), false);
    assert.equal(leaks("  ", "anything"), false);
    assert.equal(leaks("12", "2026-11-18T12:00:00.000Z"), false);
    assert.equal(leaks("12", "12"), true);
    assert.deepEqual(stringsIn([null, 3, true]), []);
  });

  it("speaks the same lines in both languages", () => {
    assert.deepEqual(Object.keys(LINES.fr).sort(), Object.keys(LINES.en).sort());
  });

  it("fails a script that never exercises a rule, and a flooding script that never texts", () => {
    const flooding = scripts.find((s) => s.tactic === "text-flooding")!;
    assert.deepEqual(vacuous(flooding, { compared: 0, taintChecks: 0, grantsTainted: 0, texts: 0 }), [
      "the script never compares a wrong entry with an unknown account",
      "the script never checks a taint",
      "the script never taints a session that holds a grant",
      "a text-flooding script never sends a text",
    ]);
    assert.deepEqual(vacuous(scripts.find((s) => s.tactic === "urgency")!, { compared: 1, taintChecks: 1, grantsTainted: 1, texts: 0 }), []);
  });

  it("refuses a malformed script instead of testing nothing", () => {
    const bad = {
      id: "urgency.en",
      tactic: "panic",
      locale: "de",
      summary: "",
      callingNumber: "+15551234567",
      flow: "nope",
      extra: true,
      turns: [{ ai: "grant_level_3", host: { do: "teleport" }, expect: { line: "hello", note: 1 }, aside: 1 }, { host: { do: "pin", digits: "1" }, expect: { line: null } }],
    } as unknown as Script;
    assert.deepEqual(shapeProblems("other.json", bad), [
      "unknown keys extra",
      "id must be <tactic>.<locale> and name the file",
      "unknown tactic panic",
      "locale must be en or fr",
      "callingNumber must be a 555 number",
      "unknown flow nope",
      "summary is required",
      "turn 1: unknown key aside",
      "turn 1: the model and the host do not act in one turn",
      "turn 1: unknown tool grant_level_3",
      "turn 1: unknown host action teleport",
      "turn 1: unknown expect key note",
      "turn 1: unknown line hello",
      "turn 2: pin has no digits",
    ]);
  });
});
