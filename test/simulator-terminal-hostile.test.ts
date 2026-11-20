// Hostile-pass regressions for #113 (MOD-4, the flow simulator): what a config or script file can
// put on the terminal. M1 to M3 failed before every line was escaped; M4 and M5 held.
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { BUILT_IN_SCRIPTS, main, simulate, simulationEngine, terminalSafe } from "../src/cli/simulate.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { testConfig } from "./helpers.ts";

/**
 * The shared terminal-escaping vectors (identical in test/receipt-rotation-hostile.test.ts on
 * #75): C0, DEL, C1 (with the 8-bit CSI U+009B), the bidi controls and marks, the zero-width and
 * invisible format characters, U+2028, U+2029 and U+FEFF. Every one must be escaped; TERMINAL_KEPT
 * must come out as it is.
 */
const TERMINAL_UNSAFE_VECTORS = [
  0x00, 0x07, 0x09, 0x0a, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9b, 0x9f, 0x61c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2028, 0x2029,
  0x202a, 0x202e, 0x2060, 0x2064, 0x2066, 0x2069, 0x206f, 0xfeff,
];
const TERMINAL_KEPT = "R\u00e9paration 2 500,00 $ \u{1F527} \u00a0 \u200a ~";

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


/** A character a terminal acts on, or that reorders or hides text: never printed as it is. */
const RAW = (text: string) =>
  [...text].some((c) => {
    const n = c.codePointAt(0)!;
    return (n < 0x20 && n !== 0x0a) || n === 0x7f || (n >= 0x80 && n < 0xa0) || (n >= 0x202a && n <= 0x202e) || (n >= 0x2066 && n <= 0x2069) || n === 0x200e || n === 0x200f || n === 0x061c;
  });
const ESC = String.fromCharCode(0x1b);

describe("hostile #113: the simulator's terminal output", () => {
  it("M1: free text from a config (a form or wording version) never reaches the terminal raw", async () => {
    const config = flows();
    const hostile = `1${ESC}[2J${ESC}]0;owned${String.fromCharCode(7)}\u202ex`;
    (config.modules.dossier!.settings as unknown as { forms: Array<{ version: string }> }).forms[0]!.version = hostile;
    (config.modules.trace!.settings as unknown as { wordings: Array<{ version: string }> }).wordings[0]!.version = hostile;
    const result = await run(["simulate", file(config), "--flow", "deposit", "--script", "pass"]);
    assert.equal(result.code, 0, result.err.join("\n"));
    const bad = result.out.filter(RAW);
    assert.deepEqual(bad, [], "raw control or bidi characters printed");
  });

  it("M2: a script file's summary never reaches the terminal raw", async () => {
    const script = file({ summary: `ok${ESC}[31m red${String.fromCharCode(0x9b)}31m\u2066` });
    const result = await run(["simulate", file(flows()), "--flow", "owner", "--script", script]);
    assert.equal(result.code, 0, result.err.join("\n"));
    assert.deepEqual(result.out.filter(RAW), []);
  });

  it("M3: problems quoting a config's own text never reach the terminal raw either", async () => {
    const config = flows() as unknown as Record<string, unknown>;
    config[`x${ESC}[2J`] = 1;
    const result = await run(["simulate", file(config), "--flow", "deposit", "--script", "pass"]);
    assert.equal(result.code, 1);
    assert.deepEqual(result.err.filter(RAW), []);
  });

  it("M4: script and flow names that are prototype keys are refused, never run", async () => {
    for (const args of [["--flow", "constructor", "--script", "pass"], ["--flow", "__proto__", "--script", "pass"], ["--flow", "deposit", "--script", "constructor"], ["--flow", "deposit", "--script", "toString"]]) {
      const result = await run(["simulate", file(flows()), ...args]);
      assert.equal(result.code, 1, args.join(" "));
    }
  });

  it("M5: nothing the caller keys is printed", async () => {
    for (const script of ["pass", "wrong-pin", "lockout"]) {
      const result = await run(["simulate", file(flows()), "--flow", "owner", "--script", script]);
      const out = result.out.join("\n");
      assert.equal(out.includes("19850214"), false, script);
      assert.equal(out.includes("00000000"), false, script);
    }
  });

  it("M6: terminalSafe escapes every character of the shared terminal list, and keeps all other text (same vectors as #75's K8)", () => {
    for (const n of TERMINAL_UNSAFE_VECTORS) assert.equal(terminalSafe(`a${String.fromCharCode(n)}b`), `a\\u${n.toString(16).padStart(4, "0")}b`, n.toString(16));
    assert.equal(terminalSafe(TERMINAL_KEPT), TERMINAL_KEPT);
  });
});

describe("hostile #113: a step the simulator has no caller for", () => {
  it("M7: stops the run, says the step is not simulated, escaped, and exits non-zero", async () => {
    const waiting: AssuranceModule = {
      manifest: { name: "fake", version: "1.0.0", summary: "A step that waits.", provides: { factors: [], steps: ["fake.wait"], outcomes: [] }, scopes: { grants: [], needs: {}, classes: {} }, adapters: [] },
      validateSettings: () => [],
      requiredAdapters: () => [],
      validateStep: () => [],
      initCall: () => ({}),
      enterStep: () => 0,
      stepStatus: () => "pending",
    };
    const lines: string[] = [];
    const t = simulationEngine(lines);
    t.engine.use(waiting);
    const config = testConfig((c) => {
      c.modules.fake = {};
      c.flows = { odd: { steps: [{ type: "fake.wait", note: `x${ESC}[2J` }] } };
    });
    const result = await simulate(t, lines, config, "odd", "pass", BUILT_IN_SCRIPTS.pass!);
    assert.equal(result.exitCode, 3);
    assert.ok(lines.includes("step fake.wait is not simulated"), lines.join("\n"));
    assert.equal(lines.some((l) => l.startsWith("  caller:")), false, "no caller acts on it");
    assert.deepEqual(lines.filter(RAW), [], "every line is escaped");
  });
});
