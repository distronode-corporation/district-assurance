// The benchmark scripts (SRV-10): the loop measures, and the release comparison reports a case
// more than 20% slower without failing. The timings themselves are not tested; CI runs a short
// `npm run bench` so the cases cannot rot.
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { validateConfig } from "../src/index.ts";
import { createTestEngine } from "../src/testing/index.ts";
import { benchConfig, largeConfig } from "../bench/cases.ts";
import { compareResults, comparisonReport, readResults } from "../bench/compare.ts";
import { measure, resultsTable, type CaseResult } from "../bench/harness.ts";
import { RESULTS_FORMAT, type BenchResults } from "../bench/main.ts";

function result(name: string, meanUs: number): CaseResult {
  return { name, unit: "one", iterations: 10, opsPerSec: 1e6 / meanUs, meanUs, p50Us: meanUs, p99Us: meanUs, minUs: meanUs, maxUs: meanUs };
}

function run(results: CaseResult[], patch: Partial<BenchResults> = {}): BenchResults {
  return {
    format: RESULTS_FORMAT,
    commit: "0123456789abcdef0123456789abcdef01234567",
    node: "v24.2.0",
    os: { type: "Linux", platform: "linux", release: "6.8.0", arch: "x64" },
    cpu: { model: "Test CPU", cores: 4 },
    runner: "ubuntu-24.04",
    date: "2026-01-01T00:00:00.000Z",
    budgetMs: 1000,
    results,
    ...patch,
  };
}

describe("bench", () => {
  it("measures at least the minimum number of operations, whatever the budget", async () => {
    let calls = 0;
    const r = await measure({ name: "noop", unit: "nothing", setup: async () => () => calls++ }, { budgetMs: 1, minIterations: 20 });
    assert.equal(r.name, "noop");
    assert.ok(r.iterations >= 20);
    assert.ok(calls > r.iterations, "the warm-up runs too");
    assert.ok(r.minUs <= r.p50Us && r.p50Us <= r.p99Us && r.p99Us <= r.maxUs);
    assert.match(resultsTable([r]), /^\| Case \|.*\n\|---\|.*\n\| noop \| nothing \|/);
  });

  it("uses configs the validator accepts", () => {
    const registry = createTestEngine({ config: benchConfig() }).engine.registry;
    assert.deepEqual(validateConfig(benchConfig(), registry), []);
    assert.deepEqual(validateConfig(largeConfig(), registry), []);
  });

  it("reports a case more than 20% slower, and new and removed cases", () => {
    const previous = run([result("same", 100), result("slower", 100), result("faster", 100), result("edge", 100), result("gone", 5)]);
    const current = run([result("same", 100), result("slower", 125), result("faster", 50), result("edge", 120), result("added", 7)]);
    const rows = compareResults(previous, current);
    assert.deepEqual(
      rows.map((r) => [r.name, r.slower]),
      [["same", false], ["slower", true], ["faster", false], ["edge", false], ["added", false], ["gone", false]],
    );
    const report = comparisonReport(previous, current);
    assert.match(report, /\| slower \| 100\.00 \| 125\.00 \| \*\*\+25\.0% slower\*\* \|/);
    assert.match(report, /\| faster \| 100\.00 \| 50\.00 \| -50\.0% \|/);
    assert.match(report, /\| added \| {2}\| 7\.00 \| new case \|/);
    assert.match(report, /\| gone \| 5\.00 \| {2}\| removed case \|/);
    assert.match(report, /1 case\(s\) more than 20% slower: slower\. .*This does not fail the release\./);
    assert.doesNotMatch(report, /different machines/);
    assert.match(comparisonReport(previous, previous), /No case is more than 20% slower\./);
  });

  it("says when the two runs are on different machines", () => {
    const report = comparisonReport(run([]), run([], { node: "v24.9.0", runner: null }));
    assert.match(report, /different machines or Node versions/);
  });

  it("reads a results file, and says why it cannot read one", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "bench-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const good = join(dir, "good.json");
    writeFileSync(good, JSON.stringify(run([result("a", 1)])));
    assert.deepEqual(readResults(good), run([result("a", 1)]));
    const old = join(dir, "old.json");
    writeFileSync(old, JSON.stringify({ format: 0, results: [] }));
    assert.match(readResults(old) as string, /is not a results file of format 1$/);
    writeFileSync(old, "null");
    assert.match(readResults(old) as string, /is not a results file/);
    assert.match(readResults(join(dir, "missing.json")) as string, /cannot be read as JSON/);
  });
});
