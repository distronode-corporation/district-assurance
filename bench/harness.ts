// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The measuring loop for `npm run bench`, on `node:perf_hooks` only: `performance.now()` around
// each operation and a `createHistogram()` of the times, in nanoseconds. No dependency.
import { createHistogram, performance } from "node:perf_hooks";

export interface BenchCase {
  /** Stable across releases: the release comparison matches cases by name. */
  name: string;
  /** What one operation is, in a few words, for the table. */
  unit: string;
  /** Builds the state the case needs (an engine, a key, a config) and returns one operation. */
  setup(): Promise<() => unknown>;
}

export interface CaseResult {
  name: string;
  unit: string;
  iterations: number;
  opsPerSec: number;
  meanUs: number;
  p50Us: number;
  p99Us: number;
  minUs: number;
  maxUs: number;
}

export interface MeasureOptions {
  /** Time spent measuring each case, after the warm-up. */
  budgetMs: number;
  /** At least this many measured operations, whatever the budget. */
  minIterations: number;
}

const round = (n: number, digits = 2): number => Number(n.toFixed(digits));

/**
 * Runs one case: a warm-up of a tenth of the budget (so the JIT has compiled the hot paths), then
 * operations one after another until the budget is spent and `minIterations` are done. Each
 * operation is awaited before the next starts, so the numbers are latency on an idle engine, not
 * throughput under concurrency.
 */
export async function measure(bench: BenchCase, options: MeasureOptions): Promise<CaseResult> {
  const op = await bench.setup();
  const warmUntil = performance.now() + options.budgetMs / 10;
  do await op();
  while (performance.now() < warmUntil);

  const histogram = createHistogram();
  let iterations = 0;
  let total = 0;
  const started = performance.now();
  const until = started + options.budgetMs;
  for (;;) {
    const t0 = performance.now();
    await op();
    const elapsed = performance.now() - t0;
    total += elapsed;
    // Nanoseconds, at least 1: the histogram only takes positive integers.
    histogram.record(Math.max(1, Math.round(elapsed * 1e6)));
    iterations++;
    if (iterations >= options.minIterations && t0 + elapsed >= until) break;
  }
  const us = (ns: number): number => round(ns / 1e3);
  return {
    name: bench.name,
    unit: bench.unit,
    iterations,
    opsPerSec: round(iterations / (total / 1e3), 1),
    meanUs: round((total * 1e3) / iterations),
    p50Us: us(histogram.percentile(50)),
    p99Us: us(histogram.percentile(99)),
    minUs: us(histogram.min),
    maxUs: us(histogram.max),
  };
}

/** A Markdown table of results, for the terminal, BENCHMARKS.md and a run summary. */
export function resultsTable(results: readonly CaseResult[]): string {
  const lines = ["| Case | One operation | ops/s | mean (µs) | p50 (µs) | p99 (µs) | runs |", "|---|---|---:|---:|---:|---:|---:|"];
  for (const r of results) {
    lines.push(`| ${r.name} | ${r.unit} | ${r.opsPerSec.toFixed(1)} | ${r.meanUs.toFixed(2)} | ${r.p50Us.toFixed(2)} | ${r.p99Us.toFixed(2)} | ${r.iterations} |`);
  }
  return lines.join("\n");
}
