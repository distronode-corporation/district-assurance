// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Node.js 24.2, the floor before 24.19, sets import.meta.main to false for a .ts entry, so an
// entry guarded by it does nothing there. Node 24.19 does not, so this load hook gives the demo
// entries what 24.2 gives them: every `import.meta.main` in their source reads false.
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const NODE_24_2_MAIN = `data:text/javascript,${encodeURIComponent(`
import { registerHooks } from "node:module";
registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!/\\/(examples\\/reference-server\\/src\\/(demo|e2e)|bench\\/(main|compare))\\.ts$/.test(url)) return result;
    return { ...result, source: String(result.source).replaceAll("import.meta.main", "false") };
  },
});
`)}`;

const entry = (name: string) => fileURLToPath(new URL(name.startsWith("bench/") ? `../${name}` : `../examples/reference-server/src/${name}`, import.meta.url));

function run(file: string, env: NodeJS.ProcessEnv, args: string[] = []): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", NODE_24_2_MAIN, entry(file), ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("the demo entries run where import.meta.main is false for a .ts entry, as on Node.js 24.2", () => {
  it("npm run demo runs the demo and prints the receipt", { timeout: 60_000 }, async () => {
    const { code, stdout, stderr } = await run("demo.ts", { ...process.env });
    assert.equal(code, 0, stderr);
    assert.match(stdout, /Deposit receipt body:/, "the demo ran");
  });

  it("npm run demo:e2e checks its Stripe key, not silently exiting 0", { timeout: 60_000 }, async () => {
    const env = { ...process.env };
    delete env.STRIPE_TEST_SECRET_KEY;
    const { code, stderr } = await run("e2e.ts", env);
    assert.equal(code, 1, "the entry ran and refused the missing key");
    assert.match(stderr, /demo:e2e: /);
  });
});

describe("the benchmark entries run where import.meta.main is false for a .ts entry, as on Node.js 24.2", () => {
  it("npm run bench measures and writes its results file", { timeout: 120_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "da-bench-"));
    try {
      const out = join(dir, "bench.json");
      const { code, stderr } = await run("bench/main.ts", { ...process.env }, ["--budget-ms", "1", "--min-iterations", "1", "--out", out]);
      assert.equal(code, 0, stderr);
      assert.equal((JSON.parse(readFileSync(out, "utf8")) as { results: unknown[] }).results.length > 0, true, "the bench ran and wrote its file");
      const compared = await run("bench/compare.ts", { ...process.env, GITHUB_STEP_SUMMARY: "" }, [out, out]);
      assert.equal(compared.code, 0, compared.stderr);
      assert.match(compared.stdout, /Benchmarks against the previous release/, "the comparison ran");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
