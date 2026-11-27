// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The fuzz harness itself: every example runs whatever the budget, a replay sees the same stream
// as the run that printed its path, and a case still running when the budget is spent is awaited.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const FIXTURE = fileURLToPath(new URL("./fixtures/harness-run.ts", import.meta.url));

function run(mode: string, env: Record<string, string>): number | null {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("DA_FUZZ_")));
  return spawnSync(process.execPath, [FIXTURE, mode], { env: { ...clean, ...env }, stdio: "ignore", timeout: 60_000 }).status;
}

describe("the fuzz harness", () => {
  it("runs every example, also when there are more examples than minimum runs", () => {
    assert.equal(run("examples", { DA_FUZZ_MS: "0" }), 2, "the 21st example fails the property");
  });

  it("replays a printed path on the stream with the examples, as the run that printed it", () => {
    assert.equal(run("replay", { DA_FUZZ_SEED: "1", DA_FUZZ_PATH: "0" }), 2, "path 0 is the failing example");
  });

  it("awaits a case still running when the time budget is spent, and reports its failure", () => {
    assert.equal(run("late", { DA_FUZZ_MS: "50" }), 2, "the late failure is reported, not dropped or replaced by an interruption");
  });
});
