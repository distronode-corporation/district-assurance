// Compares two `npm run bench -- --out` files, the previous release's and this one's, case by
// case on the mean time of one operation. A case more than 20% slower is reported, in the table
// and as a warning; nothing here fails a run, because one run on a shared runner is noisy.
//
//   node bench/compare.ts previous.json current.json
//
// In GitHub Actions the report is also appended to the run summary (GITHUB_STEP_SUMMARY). A
// missing or unreadable previous file (a first release, or one from before benchmarks) is
// reported and skipped.
import { appendFileSync, readFileSync } from "node:fs";

import { RESULTS_FORMAT, type BenchResults } from "./main.ts";

/** A case this much slower than before (as a fraction of the previous mean) is reported. */
export const SLOWDOWN_THRESHOLD = 0.2;

export interface CaseComparison {
  name: string;
  previousUs: number | null;
  currentUs: number | null;
  /** current / previous - 1: 0.25 is 25% slower, -0.1 is 10% faster. Null for a new or removed case. */
  change: number | null;
  slower: boolean;
}

export function compareResults(previous: BenchResults, current: BenchResults, threshold = SLOWDOWN_THRESHOLD): CaseComparison[] {
  const before = new Map(previous.results.map((r) => [r.name, r.meanUs]));
  const rows: CaseComparison[] = current.results.map((r) => {
    const previousUs = before.get(r.name) ?? null;
    const change = previousUs === null || previousUs <= 0 ? null : r.meanUs / previousUs - 1;
    return { name: r.name, previousUs, currentUs: r.meanUs, change, slower: change !== null && change > threshold };
  });
  const now = new Set(current.results.map((r) => r.name));
  for (const r of previous.results) {
    if (!now.has(r.name)) rows.push({ name: r.name, previousUs: r.meanUs, currentUs: null, change: null, slower: false });
  }
  return rows;
}

const machine = (r: BenchResults): string => `${r.cpu.model}, ${r.os.type} ${r.os.arch}, Node ${r.node}`;
const short = (sha: string | null): string => (sha === null ? "unknown" : sha.slice(0, 12));
const us = (n: number | null): string => (n === null ? "" : n.toFixed(2));

function changeText(row: CaseComparison): string {
  if (row.previousUs === null) return "new case";
  if (row.currentUs === null) return "removed case";
  if (row.change === null) return "";
  const percent = `${row.change > 0 ? "+" : ""}${(row.change * 100).toFixed(1)}%`;
  return row.slower ? `**${percent} slower**` : percent;
}

/** The Markdown report: the two machines, a table of mean times, and a line on the slowdowns. */
export function comparisonReport(previous: BenchResults, current: BenchResults, threshold = SLOWDOWN_THRESHOLD): string {
  const rows = compareResults(previous, current, threshold);
  const lines = [
    "## Benchmarks against the previous release",
    "",
    `Previous: commit ${short(previous.commit)} on ${machine(previous)}${previous.runner === null ? "" : ` (${previous.runner})`}.`,
    `Current: commit ${short(current.commit)} on ${machine(current)}${current.runner === null ? "" : ` (${current.runner})`}.`,
  ];
  if (machine(previous) !== machine(current)) {
    lines.push("", "The two runs are on different machines or Node versions, so the changes below say little.");
  }
  lines.push("", "| Case | previous mean (µs) | current mean (µs) | change |", "|---|---:|---:|---:|");
  for (const row of rows) lines.push(`| ${row.name} | ${us(row.previousUs)} | ${us(row.currentUs)} | ${changeText(row)} |`);
  const slower = rows.filter((r) => r.slower);
  lines.push(
    "",
    slower.length === 0
      ? `No case is more than ${threshold * 100}% slower.`
      : `${slower.length} case(s) more than ${threshold * 100}% slower: ${slower.map((r) => r.name).join(", ")}. ` +
          "Shared runners are noisy: run the benchmarks again before treating this as a regression. This does not fail the release.",
    "",
    "Engine costs on memory adapters, not call latency (BENCHMARKS.md).",
  );
  return lines.join("\n");
}

/** Reads a results file, or says why it cannot be compared. */
export function readResults(path: string): BenchResults | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    return `${path} cannot be read as JSON (${e instanceof Error ? e.message : String(e)})`;
  }
  const r = parsed as Partial<BenchResults> | null;
  if (r === null || typeof r !== "object" || r.format !== RESULTS_FORMAT || !Array.isArray(r.results)) {
    return `${path} is not a results file of format ${RESULTS_FORMAT}`;
  }
  return r as BenchResults;
}

function main(): void {
  const [previousPath, currentPath] = process.argv.slice(2);
  if (previousPath === undefined || currentPath === undefined) {
    console.error("usage: node bench/compare.ts previous.json current.json");
    process.exit(2);
  }
  const current = readResults(currentPath);
  if (typeof current === "string") {
    console.error(current);
    process.exit(1);
  }
  const previous = readResults(previousPath);
  let report: string;
  if (typeof previous === "string") {
    report = `## Benchmarks against the previous release\n\nNo comparison: ${previous}. Shown on its own:\n\n${current.results.map((r) => `- ${r.name}: ${r.meanUs.toFixed(2)} µs`).join("\n")}`;
  } else {
    report = comparisonReport(previous, current);
    for (const row of compareResults(previous, current).filter((r) => r.slower)) {
      console.log(`::warning title=Benchmark slowdown::${row.name} is ${((row.change ?? 0) * 100).toFixed(1)}% slower than the previous release (one run on a shared runner; not a failure).`);
    }
  }
  console.log(report);
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary !== undefined && summary !== "") appendFileSync(summary, `${report}\n`);
}

if (import.meta.main) main();
