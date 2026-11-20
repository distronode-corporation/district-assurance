// `npm run bench`: measures the engine's own costs on the memory adapters and prints a table.
// With `--out file.json` it also writes the results with the machine they ran on (CPU, operating
// system, Node version, commit), the shape `bench/compare.ts` reads.
//
//   npm run bench                                  about a second per case
//   npm run bench -- --budget-ms 50 --out b.json   a short run, as CI does
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { arch, cpus, platform, release, type } from "node:os";
import { parseArgs } from "node:util";

import { cases } from "./cases.ts";
import { measure, resultsTable, type CaseResult } from "./harness.ts";

/** Bumped when the file's shape changes; the comparison refuses a format it does not know. */
export const RESULTS_FORMAT = 1;

export interface BenchResults {
  format: typeof RESULTS_FORMAT;
  /** The commit measured, or null outside a git checkout. */
  commit: string | null;
  node: string;
  os: { type: string; platform: string; release: string; arch: string };
  cpu: { model: string; cores: number };
  /** The CI runner label (`BENCH_RUNNER`), or null on a person's machine. */
  runner: string | null;
  date: string;
  budgetMs: number;
  results: CaseResult[];
}

function commit(): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return process.env.GITHUB_SHA ?? null;
  }
}

function positiveInteger(name: string, value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new TypeError(`--${name} must be a positive integer, not ${JSON.stringify(value)}`);
  return n;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "budget-ms": { type: "string", default: "1000" },
      "min-iterations": { type: "string", default: "5" },
      out: { type: "string" },
    },
    strict: true,
  });
  const budgetMs = positiveInteger("budget-ms", values["budget-ms"]);
  const minIterations = positiveInteger("min-iterations", values["min-iterations"]);
  const cpuList = cpus();
  const run: BenchResults = {
    format: RESULTS_FORMAT,
    commit: commit(),
    node: process.version,
    os: { type: type(), platform: platform(), release: release(), arch: arch() },
    cpu: { model: cpuList[0]?.model.trim() ?? "unknown", cores: cpuList.length },
    runner: process.env.BENCH_RUNNER ?? null,
    date: new Date().toISOString(),
    budgetMs,
    results: [],
  };
  console.log(`district-assurance bench: ${run.cpu.model} (${run.cpu.cores} cores), ${run.os.type} ${run.os.release} ${run.os.arch}, Node ${run.node}, commit ${run.commit ?? "unknown"}`);
  console.log("Engine costs on memory adapters and fakes, not call latency.\n");
  for (const bench of cases) {
    run.results.push(await measure(bench, { budgetMs, minIterations }));
  }
  console.log(resultsTable(run.results));
  if (values.out !== undefined) {
    writeFileSync(values.out, `${JSON.stringify(run, null, 2)}\n`);
    console.log(`\nResults written to ${values.out}`);
  }
}

if (import.meta.main) await main();
