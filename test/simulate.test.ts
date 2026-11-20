// The flow simulator (MOD-4): every built-in script, script files, refused configs, the command line and the output format.
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { BUILT_IN_SCRIPTS, USAGE, isEntryPoint, main, parseCallerScript } from "../src/cli/simulate.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { IntakeForm } from "../src/file/intake.ts";
import { defaultConfig } from "../src/modules.ts";
import { testConfig } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "da-simulate-"));
let files = 0;

function file(value: unknown): string {
  const path = join(dir, `file-${++files}.json`);
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
  return path;
}

/** The test config, with a PIN at level 1, and four flows. */
function flows(): FlowConfig {
  return testConfig((c) => {
    c.revision = "sim-1";
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    c.flows = {
      deposit: {
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
          { type: "dossier.collect", form: "repair" },
          { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" },
          { type: "trace.consent", purpose: "texts" },
          { type: "trace.receipt" },
        ],
      },
      owner: { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] },
      photo: { steps: [{ type: "badge.verify", level: 3, factors: ["photo_id", "keypad_knowledge"] }, { type: "trace.receipt" }] },
    };
  });
}

async function run(args: string[]): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(args, { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out, err };
}

async function simulate(flow: string, script: string, config: unknown = flows()): Promise<string[]> {
  const result = await run(["simulate", file(config), "--flow", flow, "--script", script]);
  assert.deepEqual(result.err, []);
  assert.equal(result.code, 0);
  return result.out;
}

/** The lines before the receipt's JSON: nothing the caller keyed may appear in them. */
function narrative(out: string[]): string {
  const end = out.findIndex((line) => line.startsWith("receipt:"));
  return out.slice(0, end + 1).join("\n");
}

function assertNoSecrets(out: string[]): void {
  const text = narrative(out);
  for (const secret of [/\b12345678\b/, /\b19850214\b/, /\b00000000\b/, /\b4826\b/, /\b0000\b/, /\+1555/]) assert.doesNotMatch(text, secret);
}

describe("simulate: built-in scripts", () => {
  it("pass: the whole deposit flow completes, every event is printed, and the receipt is signed", async () => {
    const out = await simulate("deposit", "pass");
    const text = out.join("\n");
    assert.equal(out[0], "simulate: flow deposit, steps: 5, config revision sim-1");
    assert.match(text, /^script: pass: /m);
    for (const step of ["step 1/5: badge.verify", "step 2/5: dossier.collect", "step 3/5: paylink.request", "step 4/5: trace.consent"]) assert.match(text, new RegExp(`^${step} `, "m"));
    for (const event of [
      "call.started",
      "flow.started",
      "verification.started",
      "verification.factor",
      "verification.carrier_checked",
      "verification.finished",
      "grant.issued",
      "intake.started",
      "intake.confirmed",
      "payment.link_sent",
      "payment.settled",
      "consent.recorded",
      "flow.step_completed",
      "flow.completed",
      "call.ended",
      "receipt.issued",
    ]) {
      assert.match(text, new RegExp(`^    event ${event.replace(".", "\\.")} `, "m"));
    }
    assert.match(text, /decision: keypad answers matched/);
    assert.match(text, /decision: level 2, scopes: intake\.file, payment\.request/);
    assert.match(text, /decision: settled paid/);
    assert.match(text, /^flow: completed$/m);
    assert.match(text, /^receipt: signature valid against the engine's key set: true$/m);
    const receipt = JSON.parse(out.slice(out.findIndex((line) => line.startsWith("receipt:")) + 1).join("\n"));
    assert.equal(receipt.body.verification.level, 2);
    assert.equal(receipt.body.payments[0].status, "paid");
    assert.equal(receipt.body.consents[0].answer, "yes");
    assertNoSecrets(out);
  });

  it("pass: a photo ID flow reaches level 3", async () => {
    const out = await simulate("photo", "pass");
    const text = out.join("\n");
    assert.match(text, /caller: opens the texted link \(the provider reports verified\)\n.*\n.*\n.*decision: link texted to the number on file, outcome applied: true/);
    assert.match(text, /decision: level 3, scopes: /);
    assert.match(text, /^flow: completed$/m);
    assertNoSecrets(out);
  });

  it("wrong-pin: one wrong PIN, then the right one", async () => {
    const out = await simulate("owner", "wrong-pin");
    const text = out.join("\n");
    assert.match(text, /caller: keys PIN \(wrong\)\n.*"passed":false.*\n  decision: no match\n  caller: keys PIN \(right\)\n.*"passed":true.*\n  decision: PIN matched/);
    assert.match(text, /decision: level 1, scopes: owner\.command/);
    assert.match(text, /^flow: completed$/m);
    assert.match(text, /^receipt: none \(the flow has no trace\.receipt step\)$/m);
    assertNoSecrets(out);
  });

  it("wrong-pin: a wrong keypad answer on a keypad flow, then the right one", async () => {
    const text = (await simulate("deposit", "wrong-pin")).join("\n");
    assert.match(text, /keys keypad answers \(wrong\)\n.*\n  decision: no match\n  caller: keys keypad answers \(right\)/);
    assert.match(text, /^flow: completed$/m);
  });

  it("lockout: the line stops judging the PIN and the flow fails", async () => {
    const out = await simulate("owner", "lockout");
    const text = out.join("\n");
    assert.equal(text.match(/caller: keys PIN \(wrong\)/g)!.length, 3);
    assert.doesNotMatch(text, /keys PIN \(right\)/);
    assert.match(text, /decision: no match, locked: no more PIN attempts on this call/);
    assert.match(text, /decision: level 0, scopes: none/);
    assert.match(text, /event flow\.failed /);
    assert.match(text, /^flow: failed$/m);
    assertNoSecrets(out);
  });

  it("lockout: what the engine refuses is printed, and the caller goes on", async () => {
    const text = (await simulate("photo", "lockout")).join("\n");
    assert.equal(text.match(/caller: keys keypad answers \(wrong\)/g)!.length, 2);
    assert.match(text, /opens the texted link.*\n  refused: the keypad or PIN checks have not matched on this call/);
    assert.match(text, /^flow: failed$/m);
    assert.match(text, /^receipt: signature valid/m);
  });

  it("consent-no: the consent step fails the flow, and the receipt still records the answer", async () => {
    const out = await simulate("deposit", "consent-no");
    const text = out.join("\n");
    assert.match(text, /caller: answers no to texts/);
    assert.match(text, /^flow: failed$/m);
    const receipt = JSON.parse(out.slice(out.findIndex((line) => line.startsWith("receipt:")) + 1).join("\n"));
    assert.equal(receipt.body.consents[0].answer, "no");
  });

  it("payment-paid: completed unpaid settles nothing, the later success settles it paid", async () => {
    const text = (await simulate("deposit", "payment-paid")).join("\n");
    assert.match(text, /the provider reports \{"kind":"completed","paymentStatus":"unpaid"\}\n  decision: nothing settled yet/);
    assert.match(text, /the provider reports \{"kind":"async_succeeded"\}\n.*\n.*\n  decision: settled paid/);
    assert.match(text, /^flow: completed$/m);
  });

  it("payment-expired: the link expires and the flow fails", async () => {
    const text = (await simulate("deposit", "payment-expired")).join("\n");
    assert.match(text, /decision: settled expired/);
    assert.match(text, /event flow\.failed \(code\) \{"flow":"deposit","step":2,"type":"paylink\.request"\}/);
    assert.match(text, /^flow: failed$/m);
  });

  it("the built-in scripts are the six the documents name", () => {
    assert.deepEqual(Object.keys(BUILT_IN_SCRIPTS), ["pass", "wrong-pin", "lockout", "consent-no", "payment-paid", "payment-expired"]);
  });

  it("runs a config without the PIN, or without Badge at all", async () => {
    const consent = (c: FlowConfig) => {
      c.modules.trace = { settings: { wordings: [{ purpose: "texts", version: "1", text: { en: "Texts?", fr: "Textos?" } }] } };
      c.flows = { ask: { steps: [{ type: "trace.consent", purpose: "texts" }] } };
      return c;
    };
    assert.match((await simulate("ask", "pass", consent(defaultConfig()))).join("\n"), /^flow: completed$/m);
    const noBadge = consent(defaultConfig());
    delete noBadge.modules.badge;
    assert.match((await simulate("ask", "consent-no", noBadge)).join("\n"), /^flow: failed$/m);
  });
});

describe("simulate: script files", () => {
  it("a script file fills what it leaves out from pass", async () => {
    const text = (await simulate("deposit", file({ summary: "a declined card", wrongKeypad: 1, carrier: "match", payment: "failed" }))).join("\n");
    assert.match(text, /^script: .*file-\d+\.json: a declined card$/m);
    assert.match(text, /decision: settled failed/);
    assert.match(text, /^flow: failed$/m);
    assert.deepEqual(parseCallerScript({}).script, { ...BUILT_IN_SCRIPTS.pass, summary: "a script from a file" });
  });

  it("refuses a script file with every problem", async () => {
    const path = file({ summary: 1, wrongPins: 6, wrongKeypad: -1, carrier: "maybe", photoId: "yes", consent: true, payment: "free", pin: "4826" });
    const result = await run(["simulate", file(flows()), "--flow", "deposit", "--script", path]);
    assert.equal(result.code, 1);
    assert.equal(result.err[0], "simulate: refused, 8 problem(s):");
    for (const problem of [
      "pin: not a script field",
      "summary: must be a string",
      "wrongKeypad: must be an integer from 0 to 5",
      "wrongPins: must be an integer from 0 to 5",
      "carrier: must be one of match, no_match, unavailable",
      "photoId: must be one of verified, requires_input, canceled",
      "consent: must be one of yes, no",
      "payment: must be one of paid, paid_later, failed, expired",
    ]) {
      assert.ok(result.err.includes(`  - ${path}: ${problem}`), problem);
    }
    assert.deepEqual(result.out, []);
    assert.deepEqual(parseCallerScript([]).problems, ["a script must be a JSON object"]);
  });

  it("refuses a script that is neither built in nor a readable file", async () => {
    const result = await run(["simulate", file(flows()), "--flow", "deposit", "--script", "sunny-day"]);
    assert.equal(result.code, 1);
    assert.match(result.err[1]!, /^  - sunny-day: .*\(not a built-in script: pass, wrong-pin, lockout, consent-no, payment-paid, payment-expired\)$/);
  });
});

describe("simulate: refused configs", () => {
  it("prints every problem validateConfig finds, and exits 1", async () => {
    const config = flows() as unknown as Record<string, unknown>;
    config.version = 2;
    (config.flows as FlowConfig["flows"]).deposit!.steps[0] = { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] };
    const result = await run(["simulate", file(config), "--flow", "deposit", "--script", "pass"]);
    assert.equal(result.code, 1);
    assert.equal(result.err[0], "simulate: refused, 2 problem(s):");
    assert.equal(result.err[1], "  - version: must be 1");
    assert.match(result.err[2]!, /^  - flows\.deposit\.steps\[2\] \(paylink\.request\): needs the scope payment\.request at level 2/);
    assert.deepEqual(result.out, []);
  });

  it("refuses an outside module the config turns on, with that reason, and every other problem", async () => {
    const config = flows();
    config.modules.acme = { settings: {} };
    config.modules.other = { enabled: false };
    config.modules.broken = true as never;
    config.flows.deposit!.steps.push({ type: "acme.check" });
    const result = await run(["simulate", file(config), "--flow", "deposit", "--script", "pass"]);
    assert.equal(result.code, 1);
    assert.deepEqual(result.err, [
      "simulate: refused, 3 problem(s):",
      "  - modules.acme: acme is an outside module; the simulator runs the built-in modules only (badge, dossier, paylink, trace, gate, step-up)",
      "  - modules.broken: broken is an outside module; the simulator runs the built-in modules only (badge, dossier, paylink, trace, gate, step-up)",
      "  - flows.deposit.steps[5]: no installed module provides the step acme.check",
    ]);
  });

  it("runs a config whose outside module is switched off", async () => {
    const config = flows();
    config.modules.acme = { enabled: false, settings: {} };
    assert.match((await simulate("owner", "pass", config)).join("\n"), /^flow: completed$/m);
  });

  it("answers a text field within its maxLength, so the form can be filed", async () => {
    const config = flows();
    (config.modules.dossier!.settings as unknown as { forms: IntakeForm[] }).forms[0]!.fields[0]!.maxLength = 1;
    const text = (await simulate("deposit", "pass", config)).join("\n");
    assert.match(text, /decision: normalised: \{"ok":true,"value":"A"\}/);
    assert.match(text, /^flow: completed$/m);
  });

  it("prints the flow's status after the call ends: a flow still running is abandoned", async () => {
    const config = flows();
    // A pattern the sample answer never matches, so the form cannot be filed and the flow stays running.
    (config.modules.dossier!.settings as unknown as { forms: IntakeForm[] }).forms[0]!.fields[0]!.pattern = "[0-9]+";
    const out = await simulate("deposit", "pass", config);
    const text = out.join("\n");
    assert.match(text, /^  refused: /m);
    assert.match(text, /^    event flow\.abandoned /m);
    assert.match(text, /^flow: abandoned$/m);
    assert.doesNotMatch(text, /^flow: running$/m);
    assert.ok(out.indexOf("call: ending") < out.indexOf("flow: abandoned"));
  });

  it("refuses a config that is not an object, is not JSON or cannot be read", async () => {
    const notObject = await run(["simulate", file([]), "--flow", "deposit", "--script", "pass"]);
    assert.deepEqual(notObject.err, ["simulate: refused, 1 problem(s):", "  - the config must be an object"]);
    const notJson = await run(["simulate", file("{ not json"), "--flow", "deposit", "--script", "pass"]);
    assert.equal(notJson.code, 1);
    assert.match(notJson.err[1]!, /file-\d+\.json: .*JSON/);
    const missing = await run(["simulate", join(dir, "missing.json"), "--flow", "deposit", "--script", "pass"]);
    assert.equal(missing.code, 1);
    assert.match(missing.err[1]!, /missing\.json: ENOENT/);
  });

  it("refuses a flow the config does not have", async () => {
    const result = await run(["simulate", file(flows()), "--flow", "refund", "--script", "pass"]);
    assert.equal(result.code, 1);
    assert.equal(result.err[1], `  - flows: no flow named refund; the config's flows are ["deposit","owner","photo"]`);
  });
});

describe("simulate: the command line", () => {
  it("prints the usage and exits 2 on bad arguments", async () => {
    for (const args of [[], ["simulate", "c.json"], ["run", "c.json", "--flow", "f", "--script", "pass"], ["simulate", "--flow", "f", "--script", "pass"]]) {
      const result = await run(args);
      assert.equal(result.code, 2, args.join(" "));
      assert.deepEqual(result.err, [USAGE]);
    }
    const unknown = await run(["simulate", "c.json", "--flow", "f", "--script", "pass", "--key", "k"]);
    assert.equal(unknown.code, 2);
    assert.match(unknown.err[0]!, /--key/);
    assert.equal(unknown.err[1], USAGE);
  });

  it("every printed line has its place: a heading, a caller action, a decision or refusal, an event, or the receipt", async () => {
    for (const [flow, script] of [["deposit", "pass"], ["photo", "lockout"]] as const) {
      const out = await simulate(flow, script);
      const end = out.findIndex((line) => line.startsWith("receipt:"));
      for (const line of out.slice(0, end + 1)) {
        assert.match(line, /^(simulate|script|call|step \d+\/\d+|flow|receipt): |^  (caller|decision|refused): |^    event [a-z_]+\.[a-z_]+ \((system|code|caller)\) \{/);
      }
      assert.deepEqual(JSON.parse(out.slice(end + 1).join("\n")).alg, "ES256");
    }
  });

  it("runs as a program, which the package's bin and simulate script name", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.deepEqual(pkg.bin, { "district-assurance": "./dist/cli/simulate.js" });
    assert.equal(pkg.scripts.simulate, "node src/cli/simulate.ts simulate");
    const program = fileURLToPath(new URL("../src/cli/simulate.ts", import.meta.url));
    const out = execFileSync(process.execPath, [program, "simulate", file(flows()), "--flow", "owner", "--script", "pass"], { encoding: "utf8" });
    assert.match(out, /^simulate: flow owner, steps: 1/);
    assert.match(out, /^flow: completed$/m);
    assert.throws(
      () => execFileSync(process.execPath, [program], { encoding: "utf8", stdio: "pipe" }),
      (e: { status: number; stderr: string }) => e.status === 2 && e.stderr.includes(USAGE),
    );
  });

  it("knows it is the program from argv[1], through a symlink, and not when a test imports it", () => {
    const moduleUrl = new URL("../src/cli/simulate.ts", import.meta.url).href;
    const program = fileURLToPath(moduleUrl);
    assert.equal(isEntryPoint(program, moduleUrl), true);
    const link = join(dir, "district-assurance-link.ts");
    let linked = true;
    try {
      symlinkSync(program, link);
    } catch (e) {
      // Windows refuses symlinks to an account without the privilege; the check is the same there.
      if ((e as NodeJS.ErrnoException).code !== "EPERM") throw e;
      linked = false;
    }
    if (linked) assert.equal(isEntryPoint(link, moduleUrl), true);
    assert.equal(isEntryPoint(fileURLToPath(import.meta.url), moduleUrl), false);
    assert.equal(isEntryPoint(join(dir, "missing.ts"), moduleUrl), false);
    assert.equal(isEntryPoint(undefined, moduleUrl), false);
  });
});
