// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #119 (SRV-5): the release workflow's own checks, run as they are written in it.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

/** Line endings as the checks expect them: a Windows checkout can hold the file with CRLF. */
const lf = (text: string): string => text.replace(/\r\n/g, "\n");
const raw = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
const workflow = lf(raw);

/** Every `run:` script, single line or block, each as its lines. */
function runScripts(text: string): string[][] {
  const lines = text.split("\n");
  const scripts: string[][] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)(?:- )?run: (.*)$/.exec(lines[i]!);
    if (m === null) continue;
    const body = [m[2]!];
    if (m[2] === "|") for (let j = i + 1; j < lines.length && (lines[j]!.trim() === "" || lines[j]!.search(/\S/) > m[1]!.length); j++) body.push(lines[j]!);
    scripts.push(body);
  }
  return scripts;
}

/** The `node -e '...'` script of the step whose name is given, as the runner gets it. */
function nodeScript(step: string): string {
  const at = workflow.indexOf(`- name: ${step}`);
  assert.ok(at >= 0, step);
  const body = workflow.slice(at, workflow.indexOf("\n      - ", at + 1));
  const m = /node -e '([\s\S]*?)'/.exec(body);
  assert.ok(m, `a node -e script in ${step}`);
  return m[1]!;
}

const dir = mkdtempSync(join(tmpdir(), "release-"));
function environmentCheck(environment: unknown, policies: unknown): { ok: boolean; out: string } {
  const write = (name: string, value: unknown) => {
    const file = join(dir, `${name}-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value));
    return file;
  };
  const run = spawnSync(process.execPath, ["-e", nodeScript("The npm-publish environment admits only main"), write("env", environment), write("policies", policies)], { encoding: "utf8" });
  return { ok: run.status === 0, out: run.stdout + run.stderr };
}

const custom = { protected_branches: false, custom_branch_policies: true };
const mainOnly = { total_count: 1, branch_policies: [{ id: 1, name: "main", type: "branch" }] };

describe("the npm-publish environment check: main only", () => {
  it("lets a publish through only when the environment's one custom deployment rule is the branch main", () => {
    assert.equal(environmentCheck({ protection_rules: [], deployment_branch_policy: custom }, mainOnly).ok, true);
    // A reviewer is no longer required, and one left on the environment does not stop it.
    const reviewers = { type: "required_reviewers", reviewers: [{ type: "User", reviewer: { login: "someone" } }] };
    assert.equal(environmentCheck({ protection_rules: [reviewers], deployment_branch_policy: custom }, mainOnly).ok, true);
  });

  it("fails closed on every environment that would admit anything but main", () => {
    const refused: Array<[unknown, unknown]> = [
      [{}, mainOnly],
      [{ deployment_branch_policy: null }, mainOnly],
      [{ deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } }, mainOnly],
      [{ deployment_branch_policy: { protected_branches: false, custom_branch_policies: "true" } }, mainOnly],
      [{ deployment_branch_policy: { custom_branch_policies: true } }, mainOnly],
      [{ deployment_branch_policy: custom }, { branch_policies: [] }],
      [{ deployment_branch_policy: custom }, { branch_policies: [{ name: "v*", type: "tag" }] }],
      [{ deployment_branch_policy: custom }, { branch_policies: [{ name: "main", type: "tag" }] }],
      [{ deployment_branch_policy: custom }, { branch_policies: [{ name: "*", type: "branch" }] }],
      [{ deployment_branch_policy: custom }, { branch_policies: [{ name: "main", type: "branch" }, { name: "v*", type: "tag" }] }],
      [{ deployment_branch_policy: custom }, {}],
      [{ deployment_branch_policy: custom }, { message: "Not Found", status: "404" }],
      [{ message: "Not Found", status: "404" }, mainOnly],
      ["not json", mainOnly],
      [{ deployment_branch_policy: custom }, ""],
    ];
    for (const [environment, policies] of refused) assert.equal(environmentCheck(environment, policies).ok, false, JSON.stringify([environment, policies]));
  });
});

describe("hostile #119: the npm version check", () => {
  const check = (version: string) => {
    const at = workflow.indexOf("- name: npm is new enough for trusted publishing");
    const script = /node -e '([^']*)'/.exec(workflow.slice(at))![1]!;
    return spawnSync(process.execPath, ["-e", script, version]).status === 0;
  };
  it("takes 11.5.1 and later, and refuses anything older or unreadable", () => {
    for (const v of ["11.5.1", "11.6.0", "11.10.0", "12.0.0", "20.1.2"]) assert.equal(check(v), true, v);
    for (const v of ["11.5.0", "11.4.9", "10.99.99", "11.5", "x", "", "11.5.1-beta"]) assert.equal(check(v), false, v);
  });
});

describe("hostile #119: what the workflow can be made to run", () => {
  it("never interpolates a ref name, a version or an input into a shell line", () => {
    // Every `run:` script, single line or block: values reach them through `env:`, never `${{ }}`.
    const scripts = runScripts(workflow);
    for (const line of scripts.flat()) assert.doesNotMatch(line, /\$\{\{/, line);
    assert.ok(scripts.length >= 10, `found ${scripts.length} run scripts`);
  });

  it("reads the workflow the same with CRLF line endings, as a Windows checkout may hold it", () => {
    assert.deepEqual(runScripts(lf(raw.replace(/\r?\n/g, "\r\n"))), runScripts(workflow));
  });

  it("publishes only in this repository, after the guard passed on its own signed tag, never on a dry run", () => {
    const publish = workflow.slice(workflow.indexOf("  publish:"), workflow.indexOf("  github-release:"));
    assert.match(publish, /github\.repository == 'distronode-corporation\/district-assurance'/);
    assert.match(publish, /needs\.decide\.outputs\.dry == 'false'/);
    assert.match(publish, /needs\.guard\.result == 'success'/);
    for (const need of ["ci", "supply-chain", "pack"]) assert.match(publish, new RegExp(`needs\\.${need}\\.result == 'success'`), need);
    assert.match(publish, /environment: npm-publish/);
    assert.doesNotMatch(workflow.slice(0, workflow.indexOf("jobs:")), /id-token: write/, "no OIDC scope at the top level");
    // The private guard is tested on fixture manifests (test/release-steps.test.ts), so the pull
    // request that removes "private" for the first release (ADR-12) does not have to edit this file.
  });

  it("says the trusted publisher must allow a direct npm publish, which the publish job runs", () => {
    // npm trusted publishers created since September 2026 allow only `npm stage publish` until
    // `npm publish` is ticked as an allowed action; set up without it, the publish step fails.
    // The header's prose, its comment markers and line breaks folded into single spaces.
    const header = workflow.slice(0, workflow.indexOf("\non:")).replace(/\n# ?/g, " ");
    assert.match(workflow.slice(workflow.indexOf("  publish:"), workflow.indexOf("  dry-run:")), /\bnpm publish "\$RUNNER_TEMP/);
    assert.match(header, /`npm publish` ticked as an allowed action/);
  });
});
