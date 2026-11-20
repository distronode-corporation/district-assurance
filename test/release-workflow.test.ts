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
function environmentCheck(environment: unknown): { ok: boolean; out: string } {
  const file = join(dir, `env-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, typeof environment === "string" ? environment : JSON.stringify(environment));
  const run = spawnSync(process.execPath, ["-e", nodeScript("The npm-publish environment requires a reviewer"), file], { encoding: "utf8" });
  return { ok: run.status === 0, out: run.stdout + run.stderr };
}

const reviewers = { type: "required_reviewers", reviewers: [{ type: "User", reviewer: { login: "someone" } }] };
const tagRule = { protected_branches: false, custom_branch_policies: true };

describe("hostile #119: the npm-publish environment check", () => {
  it("lets a publish through only with a required reviewer and custom deployment rules", () => {
    assert.equal(environmentCheck({ protection_rules: [reviewers], deployment_branch_policy: tagRule }).ok, true);
  });

  it("fails closed on every environment that would not hold a publish back", () => {
    const refused: unknown[] = [
      {},
      { protection_rules: [] },
      { protection_rules: [reviewers] },
      { protection_rules: [reviewers], deployment_branch_policy: null },
      { protection_rules: [reviewers], deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } },
      { protection_rules: [{ type: "required_reviewers", reviewers: [] }], deployment_branch_policy: tagRule },
      { protection_rules: [{ type: "wait_timer", wait_timer: 30 }], deployment_branch_policy: tagRule },
      { protection_rules: [{ type: "required_reviewers" }], deployment_branch_policy: tagRule },
      { protection_rules: [reviewers], deployment_branch_policy: { custom_branch_policies: "true" } },
      { message: "Not Found", status: "404" },
      "not json",
      "",
    ];
    for (const environment of refused) assert.equal(environmentCheck(environment).ok, false, JSON.stringify(environment));
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

  it("publishes only from a manual run on a tag of this repository, and a tag push never does", () => {
    const publish = workflow.slice(workflow.indexOf("  publish:"), workflow.indexOf("  dry-run:"));
    assert.match(publish, /github\.repository == 'distronode-corporation\/district-assurance'/);
    assert.match(publish, /github\.event_name == 'workflow_dispatch'/);
    assert.match(publish, /github\.ref_type == 'tag'/);
    assert.match(publish, /inputs\.publish/);
    assert.match(publish, /environment: npm-publish/);
    assert.doesNotMatch(workflow.slice(0, workflow.indexOf("jobs:")), /id-token: write/, "no OIDC scope outside the publish job");
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
