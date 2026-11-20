// Hostile-pass regressions for the flow simulator (MOD-4, PR #133 review): a configured backoff
// longer than 900 seconds is waited out, and a badge.verify step with a factor the simulator has no
// caller for stops the run (exit 3) instead of silently skipping that factor.
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { main } from "../src/cli/simulate.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { testConfig } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "da-simulate-review-"));
let files = 0;
function file(value: unknown): string {
  const path = join(dir, `file-${++files}.json`);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

async function run(config: FlowConfig, flow: string, script: string): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(["simulate", file(config), "--flow", flow, "--script", script], { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out, err };
}

/** A PIN-only flow at level 1, with the given badge settings changes. */
function pinFlow(change: (badge: Record<string, unknown>) => void, factors: string[] = ["pin"]): FlowConfig {
  return testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    change(c.modules.badge!.settings as Record<string, unknown>);
    c.flows = { owner: { steps: [{ type: "badge.verify", level: 1, factors, scopes: ["owner.command"] }] } };
  });
}

describe("hostile: the simulator waits out the configured backoff", () => {
  it("S1: with lockout.backoffSeconds of an hour each, wrong-pin still keys the right PIN after the wait", async () => {
    const config = pinFlow((badge) => (badge.lockout = { backoffSeconds: [3600, 3600, 3600, 3600, 3600] }));
    const result = await run(config, "owner", "wrong-pin");
    assert.deepEqual(result.err, []);
    assert.equal(result.code, 0);
    const text = result.out.join("\n");
    assert.match(text, /caller: keys PIN \(right\)\n.*"passed":true.*\n  decision: PIN matched/);
    assert.match(text, /^flow: completed$/m);
  });

  it("S2: the lockout script still locks on the per-call limit with a long backoff: counts are never cleared", async () => {
    const config = pinFlow((badge) => (badge.lockout = { backoffSeconds: [3600, 3600, 3600, 3600, 3600] }));
    const result = await run(config, "owner", "lockout");
    const text = result.out.join("\n");
    assert.equal(text.match(/caller: keys PIN \(wrong\)/g)!.length, 3);
    assert.doesNotMatch(text, /keys PIN \(right\)/);
    assert.match(text, /^flow: failed$/m);
  });

  it("S3: with a hard lock after 2 failures, the lockout script stops at the hard lock and never keys the right PIN", async () => {
    const config = pinFlow((badge) => (badge.lockout = { lockAfterFailures: 2 }));
    const result = await run(config, "owner", "lockout");
    const text = result.out.join("\n");
    assert.equal(text.match(/caller: keys PIN \(wrong\)/g)!.length, 2);
    assert.match(text, /decision: no match, locked/);
    assert.doesNotMatch(text, /keys PIN \(right\)/);
    assert.match(text, /^flow: failed$/m);
  });
});

describe("hostile: a badge.verify factor the simulator has no caller for", () => {
  it("F1: factors pin and callback, callback enabled: the run stops at the step with exit 3, PIN never keyed", async () => {
    const config = pinFlow((badge) => (badge.factors = ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"]), ["pin", "callback"]);
    const result = await run(config, "owner", "pass");
    assert.deepEqual(result.err, []);
    assert.equal(result.code, 3);
    assert.ok(result.out.includes("step badge.verify factor callback is not simulated"), result.out.join("\n"));
    assert.equal(result.out.some((l) => l.startsWith("  caller:")), false, "no caller acts on the step");
    assert.match(result.out.join("\n"), /^flow: abandoned$/m);
  });

  it("F3: a valid config whose flow reaches a Gate step stops there with exit 3, apart from a refused config (exit 1)", async () => {
    const config = testConfig((c) => {
      c.policy.scopes["entry.open"] = 2;
      c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "door", ref: "door-1" }] } };
      c.flows = { entry: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] }, { type: "gate.grant", target: "front-door" }] } };
    });
    const result = await run(config, "entry", "pass");
    assert.deepEqual(result.err, []);
    assert.equal(result.code, 3);
    assert.ok(result.out.includes("step gate.grant is not simulated"), result.out.join("\n"));
    assert.match(result.out.join("\n"), /decision: level 2/, "the steps before it ran");
  });

  it("F2: a PIN-only step runs as before, exit 0", async () => {
    const result = await run(pinFlow(() => undefined), "owner", "pass");
    assert.equal(result.code, 0);
    assert.match(result.out.join("\n"), /decision: PIN matched/);
  });
});
