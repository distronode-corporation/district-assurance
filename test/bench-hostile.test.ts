// Hostile pass on #123 (SRV-10 benchmarks): the release comparison reads the previous release's
// results file, and a missing or unreadable one is reported and skipped, never a failed step.
// Kept as regressions.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { compareResults, readResults } from "../bench/compare.ts";
import { RESULTS_FORMAT } from "../bench/main.ts";

const good = {
  format: RESULTS_FORMAT,
  commit: null,
  node: "v24.2.0",
  os: { type: "Linux", platform: "linux", release: "6.8.0", arch: "x64" },
  cpu: { model: "Test CPU", cores: 4 },
  runner: null,
  date: "2026-01-01T00:00:00.000Z",
  budgetMs: 1000,
  results: [{ name: "a", unit: "one", iterations: 10, opsPerSec: 1, meanUs: 1, p50Us: 1, p99Us: 1, minUs: 1, maxUs: 1 }],
};

const malformed: Array<[string, unknown]> = [
  ["a result without a mean", { ...good, results: [{ name: "a" }] }],
  ["a mean that is text", { ...good, results: [{ ...good.results[0], meanUs: "1" }] }],
  ["a negative mean", { ...good, results: [{ ...good.results[0], meanUs: -1 }] }],
  ["a mean of null (NaN or Infinity written as JSON)", { ...good, results: [{ ...good.results[0], meanUs: null }] }],
  ["a name that is not text", { ...good, results: [{ ...good.results[0], name: 7 }] }],
  ["a result that is not an object", { ...good, results: [null] }],
  ["no machine", { format: RESULTS_FORMAT, results: [] }],
  ["a machine without a CPU model", { ...good, cpu: {} }],
  ["a commit that is not text", { ...good, commit: 7 }],
];

describe("#123 hostile: the previous release's results file", () => {
  it("H1 a file of the right format with a malformed result or machine is not a results file", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "bench-hostile-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "r.json");
    writeFileSync(path, JSON.stringify(good));
    assert.equal(typeof readResults(path), "object", "a good file reads");
    for (const [what, body] of malformed) {
      writeFileSync(path, JSON.stringify(body));
      assert.equal(typeof readResults(path), "string", what);
    }
  });

  it("H2 the comparison step reports a malformed previous file and skips it, exit 0", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "bench-hostile-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const current = join(dir, "current.json");
    const previous = join(dir, "previous.json");
    writeFileSync(current, JSON.stringify(good));
    const compare = fileURLToPath(new URL("../bench/compare.ts", import.meta.url));
    for (const [what, body] of malformed) {
      writeFileSync(previous, JSON.stringify(body));
      const run = spawnSync(process.execPath, [compare, previous, current], { encoding: "utf8", env: { PATH: process.env.PATH ?? "" } });
      assert.equal(run.status, 0, `${what}: ${run.stderr}`);
      assert.match(run.stdout, /No comparison: .*is not a results file/, what);
    }
  });

  it("H3 duplicate case names and a zero previous mean never report a slowdown that is not there", () => {
    const rows = compareResults(
      { ...good, results: [{ ...good.results[0], meanUs: 0 }] } as never,
      { ...good, results: [good.results[0], { ...good.results[0], meanUs: 5 }] } as never,
    );
    assert.deepEqual(rows.map((r) => [r.change, r.slower]), [[null, false], [null, false]]);
  });
});
