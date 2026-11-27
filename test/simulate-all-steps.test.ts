// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The flow simulator's callers for the rest of the built-in steps (#134): a door unlock and a
// refusal (gate.grant), a step-up token issued and exchanged (step-up.issue), and Badge's callback,
// texted code and spoken answers, each right and wrong. A flow with every built-in step type runs
// to the end with exit code 0, and nothing the caller keys or says is printed.
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { BUILT_IN_SCRIPTS, gateControllers, main, parseCallerScript, simulate, simulationConfig, simulationEngine } from "../src/cli/simulate.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { testConfig } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "da-simulate-all-"));
let files = 0;
function file(value: unknown): string {
  const path = join(dir, `file-${++files}.json`);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

const verify = (level: number, factors: string[], scopes: string[]) => ({ type: "badge.verify", level, factors, scopes });

/** Every built-in module and factor on, and one flow per new caller, plus one with every built-in step type. */
function config(): FlowConfig {
  return testConfig((c) => {
    c.revision = "sim-all";
    (c.modules.badge!.settings as { factors: string[] }).factors.push("text_code", "callback", "spoken_knowledge");
    c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }] } };
    c.modules["step-up"] = { settings: { issuer: "https://verify.example.test", sites: [{ id: "portal", audience: "https://portal.example.test" }] } };
    c.policy.textCodeCountryCodes = ["1"];
    c.policy.spoken = { fields: { postal_code: "ca_postal_code" }, maxAttemptsPerCall: 2 };
    c.policy.levels[0]!.anyOf.push(["spoken_knowledge"]);
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
    c.policy.scopes["entry.open"] = 2;
    c.policy.scopes["entry.sign_in"] = 2;
    const two = ["keypad_knowledge", "carrier_identity_match"];
    c.flows = {
      everything: {
        steps: [
          verify(2, two, ["intake.file", "payment.request", "entry.open", "entry.sign_in"]),
          { type: "dossier.collect", form: "repair" },
          { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" },
          { type: "trace.consent", purpose: "texts" },
          { type: "gate.grant", target: "front-door" },
          { type: "step-up.issue", site: "portal" },
          { type: "trace.receipt" },
        ],
      },
      entry: { steps: [verify(2, two, ["entry.open"]), { type: "gate.grant", target: "front-door" }] },
      code: { steps: [verify(2, ["pin", "carrier_identity_match", "text_code"], ["payment.request"])] },
      spoken: { steps: [verify(1, ["spoken_knowledge"], ["status.read"])] },
      callback: { steps: [verify(2, ["pin", "callback", "carrier_identity_match"], ["payment.request"]), { type: "trace.receipt" }] },
    };
  });
}

async function run(flow: string, script: string): Promise<{ code: number; out: string[]; err: string[]; text: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(["simulate", file(config()), "--flow", flow, "--script", script], { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out, err, text: out.join("\n") };
}

/** The lines before the receipt's JSON: the made-up caller's values and transcripts never appear in them. */
function assertNothingKeyedOrSaid(out: string[], more: readonly string[] = []): void {
  const end = out.findIndex((line) => line.startsWith("receipt:"));
  const text = (end < 0 ? out : out.slice(0, end + 1)).join("\n");
  for (const secret of [/\b12345678\b/, /\b19850214\b/, /\b00000000\b/, /\b4826\b/, /\+1555/, /K1A ?0B1/i, /kay one/i, /\b730146\b/]) assert.doesNotMatch(text, secret);
  for (const value of more) assert.equal(text.includes(value), false, "a value the caller keyed is printed");
}

describe("simulate: every built-in step type", () => {
  it("pass: a flow with every built-in step type runs to the end, exit 0, the door opens and the token is exchanged", async () => {
    const result = await run("everything", "pass");
    assert.deepEqual(result.err, []);
    assert.equal(result.code, 0, result.text);
    assert.doesNotMatch(result.text, /not simulated/);
    for (const step of ["gate.grant", "step-up.issue"]) assert.match(result.text, new RegExp(`^step \\d/7: ${step.replace(".", "\\.")} `, "m"));
    assert.match(result.text, /decision: access grant \S+ delivered, the door moved: true/);
    assert.match(result.text, /caller: keys the sign-in code the website \(https:\/\/portal\.example\.test\) shows\n(.*\n)*  decision: step-up token \S+ issued, expires \S+; the website exchanged it: true/);
    for (const event of ["access.issued", "access.delivered", "stepup.issued", "stepup.exchanged", "flow.completed", "receipt.issued"]) assert.match(result.text, new RegExp(`^    event ${event.replace(".", "\\.")} `, "m"));
    assert.match(result.text, /^flow: completed$/m);
    assert.match(result.text, /^receipt: signature valid against the engine's key set: true$/m);
    assertNothingKeyedOrSaid(result.out);
  });

  it("door-refused: the controller refuses the unlock, and the run still ends with exit 0", async () => {
    const result = await run("entry", "door-refused");
    assert.equal(result.code, 0, result.text);
    assert.match(result.text, /caller: waits at front-door \(the controller refuses\)/);
    assert.match(result.text, /decision: access grant \S+ refused, the door moved: false/);
  });
});

describe("simulate: Badge's callback, texted code and spoken answers", () => {
  it("pass: the texted code is keyed right and counts toward level 2; text-code-wrong: it does not", async () => {
    const lines: string[] = [];
    const t = simulationEngine(lines, gateControllers(config()));
    const checked = simulationConfig(config(), t);
    const result = await simulate(t, lines, checked.config!, "code", "pass", BUILT_IN_SCRIPTS.pass!);
    const text = lines.join("\n");
    assert.equal(result.exitCode, 0);
    assert.match(text, /caller: asks for a code by text\n/);
    assert.match(text, /caller: keys the texted code \(right\)\n(.*\n)*  decision: texted code matched/);
    assert.match(text, /decision: level 2, scopes: payment\.request/);
    assert.equal(result.status, "completed");
    const code = /\d{6}/.exec(t.messages.sent.at(-1)!.body)![0];
    assertNothingKeyedOrSaid(lines, [code]);

    const wrong = await run("code", "text-code-wrong");
    assert.equal(wrong.code, 0);
    assert.match(wrong.text, /caller: keys the texted code \(wrong\)\n(.*\n)*  decision: no match/);
    assert.match(wrong.text, /decision: level 0/);
    assert.match(wrong.text, /^flow: failed$/m);
  });

  it("pass: the spoken answer is heard right and reaches level 1; spoken-wrong: heard wrong, it does not", async () => {
    const right = await run("spoken", "pass");
    assert.equal(right.code, 0);
    assert.match(right.text, /caller: says postal_code \(heard right\)\n(.*\n)*  decision: spoken answers matched/);
    assert.match(right.text, /decision: level 1, scopes: status\.read/);
    assertNothingKeyedOrSaid(right.out);
    const wrong = await run("spoken", "spoken-wrong");
    assert.match(wrong.text, /caller: says postal_code \(heard wrong\)\n(.*\n)*  decision: no match/);
    assert.match(wrong.text, /^flow: failed$/m);
    assertNothingKeyedOrSaid(wrong.out);
  });

  it("pass: the first call ends, the number on file is called back and confirms, and the callback call reaches level 2", async () => {
    const result = await run("callback", "pass");
    assert.equal(result.code, 0, result.text);
    assert.match(result.text, /caller: asks to be called back on the number on file\n(.*\n)*  decision: this call ended at level 0; callback call \S+ placed/);
    assert.match(result.text, /caller: answers the callback and keys the confirmation\n(.*\n)*  decision: callback outcome applied: true/);
    assert.match(result.text, /decision: level 2, scopes: payment\.request/);
    assert.match(result.text, /^flow: completed$/m);
    assert.match(result.text, /^receipt: signature valid against the engine's key set: true$/m);
    assertNothingKeyedOrSaid(result.out);
  });

  it("callback-not-confirmed: the callback is answered without the confirmation, and the callback call does not reach level 2", async () => {
    const result = await run("callback", "callback-not-confirmed");
    assert.equal(result.code, 0, result.text);
    assert.match(result.text, /caller: answers the callback and does not key the confirmation\n/);
    assert.doesNotMatch(result.text, /decision: level 2/);
    assert.match(result.text, /^flow: failed$/m);
  });

  it("keys the entered factors again on the callback call, as the script says: a wrong entry there discounts the callback", async () => {
    const lines: string[] = [];
    const t = simulationEngine(lines, gateControllers(config()));
    const c = config();
    c.policy.levels[1]!.anyOf.push(["keypad_knowledge", "callback"]);
    c.flows = { callback: { steps: [verify(2, ["keypad_knowledge", "callback"], ["payment.request"])] } };
    const result = await simulate(t, lines, simulationConfig(c, t).config!, "callback", "wrong-pin", BUILT_IN_SCRIPTS["wrong-pin"]!);
    const text = lines.join("\n");
    assert.equal(text.match(/caller: keys keypad answers \(wrong\)/g)!.length, 2, "once on each call");
    assert.match(text, /^call: the callback call \S+$/m);
    assert.match(text, /event verification\.finished .*"discounted":\["callback"\]/);
    assert.equal(result.status, "failed");
  });

  it("says a spoken answer locked the factor, and a texted code that never came", async () => {
    const lines: string[] = [];
    const t = simulationEngine(lines, gateControllers(config()));
    const c = config();
    c.policy.spoken!.maxAttemptsPerCall = 1;
    // Codes may go to +44 numbers only: the send to the number on file is refused, and looks sent.
    c.policy.textCodeCountryCodes = ["44"];
    await simulate(t, lines, simulationConfig(c, t).config!, "spoken", "spoken-wrong", BUILT_IN_SCRIPTS["spoken-wrong"]!);
    assert.match(lines.join("\n"), /decision: no match, locked: no more spoken attempts on this call/);
    lines.length = 0;
    await simulate(t, lines, simulationConfig(c, t).config!, "code", "pass", BUILT_IN_SCRIPTS.pass!);
    assert.match(lines.join("\n"), /caller: asks for a code by text\n(.*\n)*  decision: no text came\n  caller: keys the texted code \(right\)\n(.*\n)*  decision: no match/);
    assert.deepEqual(t.messages.sent.filter((m) => m.purpose === "one_time_code"), []);
  });

  it("refuses a callback request the engine refuses, and says so, without switching calls", async () => {
    const lines: string[] = [];
    const t = simulationEngine(lines, gateControllers(config()));
    const checked = simulationConfig(config(), t);
    // A wrong PIN only: no keypad or PIN match, so the request is refused and nothing is dialed.
    const result = await simulate(t, lines, checked.config!, "callback", "lockout", BUILT_IN_SCRIPTS.lockout!);
    assert.equal(result.exitCode, 0);
    assert.match(lines.join("\n"), /decision: this call ended at level 0; no callback was placed/);
    assert.deepEqual(t.dialer.dialed, []);
  });
});

describe("simulate: script fields for the new callers", () => {
  it("reads textCode, spoken, callback and door from a file, and refuses anything else", () => {
    assert.deepEqual(parseCallerScript({ textCode: "wrong", spoken: "wrong", callback: "not_confirmed", door: "refuses" }).script, {
      ...BUILT_IN_SCRIPTS.pass!,
      summary: "a script from a file",
      textCode: "wrong",
      spoken: "wrong",
      callback: "not_confirmed",
      door: "refuses",
    });
    assert.deepEqual(parseCallerScript({ textCode: "maybe", spoken: 1, callback: "yes", door: "open" }).problems, [
      "textCode: must be one of right, wrong",
      "spoken: must be one of right, wrong",
      "callback: must be one of confirmed, not_confirmed",
      "door: must be one of opens, refuses",
    ]);
  });

  it("has a built-in script for each wrong or refused path", () => {
    assert.equal(BUILT_IN_SCRIPTS["text-code-wrong"]!.textCode, "wrong");
    assert.equal(BUILT_IN_SCRIPTS["spoken-wrong"]!.spoken, "wrong");
    assert.equal(BUILT_IN_SCRIPTS["callback-not-confirmed"]!.callback, "not_confirmed");
    assert.equal(BUILT_IN_SCRIPTS["door-refused"]!.door, "refuses");
  });
});
