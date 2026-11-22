// Release workflow steps run as written, with stand-in `npm`, `gh` and `git` commands on PATH: the
// registry check that makes a rerun after a publish recoverable, the private guard on fixture
// manifests, and the choice of the previous release the benchmarks compare with.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

const lf = (text: string): string => text.replace(/\r\n/g, "\n");
const workflow = lf(readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8"));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { publishConfig?: Record<string, unknown> };

/** One job's text, from its key to the next job's. */
function job(name: string): string {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0, `job ${name}`);
  const next = workflow.slice(start + 1).search(/\n  [a-z-]+:\n/);
  return next < 0 ? workflow.slice(start) : workflow.slice(start, start + 1 + next);
}

/** The names of a job's steps, in order (an unnamed `uses:` step by its action). */
function stepNames(jobText: string): string[] {
  return [...jobText.matchAll(/\n      - (?:name: (.+)|uses: ([^@\s]+))/g)].map((m) => m[1] ?? m[2]!);
}

/** A named step's block, from its `- name:` line to the next step. */
function step(jobText: string, name: string): string {
  const at = jobText.indexOf(`      - name: ${name}\n`);
  assert.ok(at >= 0, `step ${name}`);
  const end = jobText.indexOf("\n      - ", at + 1);
  // Without the comment lines that open the next step.
  return jobText.slice(at, end < 0 ? undefined : end).replace(/(\n      #[^\n]*)+$/, "");
}

/** A step's `run: |` script, dedented, as the runner gets it. */
function script(stepText: string): string {
  const lines = stepText.split("\n");
  const run = lines.findIndex((l) => l.trim() === "run: |");
  assert.ok(run >= 0, "a run block");
  const indent = lines[run + 1]!.length - lines[run + 1]!.trimStart().length;
  const body: string[] = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && line.length - line.trimStart().length < indent) break;
    body.push(line.slice(indent));
  }
  return body.join("\n");
}

const root = mkdtempSync(join(tmpdir(), "da-release-steps-"));
after(() => rmSync(root, { recursive: true, force: true }));
let n = 0;

/** Runs a script in a fresh directory with these stand-in commands (each a bash body) first on PATH. */
function runStep(body: string, fakes: Record<string, string>, env: Record<string, string> = {}, files: Record<string, string> = {}) {
  const dir = join(root, String(n++));
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  for (const [name, text] of Object.entries(fakes)) {
    writeFileSync(join(bin, name), `#!/usr/bin/env bash\n${text}\n`);
    chmodSync(join(bin, name), 0o755);
  }
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  writeFileSync(join(dir, "output"), "");
  writeFileSync(join(dir, "summary"), "");
  const r = spawnSync("bash", ["-c", body], {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: dir, GITHUB_OUTPUT: join(dir, "output"), GITHUB_STEP_SUMMARY: join(dir, "summary"), ...env },
  });
  return { code: r.status, out: `${r.stdout}${r.stderr}`, output: readFileSync(join(dir, "output"), "utf8"), summary: readFileSync(join(dir, "summary"), "utf8") };
}

const unix = process.platform === "win32" ? "bash and stand-in commands as on the Linux runner" : false;

describe("the release workflow publishes once, and a rerun after a publish finishes the release", { skip: unix }, () => {
  const publish = job("publish");
  const dryRun = job("dry-run");
  const tarball = "district-assurance-1.2.3.tgz";
  const bytes = "the verified tarball";
  // The SRI integrity npm keeps for a tarball: sha512 of its bytes, in base64.
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  const check = (npm: string) =>
    runStep(script(step(publish, "Registry check")), { npm }, { FILE: tarball, VERSION: "1.2.3" }, { [`release/${tarball}`]: bytes });

  it("uploads the verified files before it publishes, and publishes only when the registry check says so", () => {
    const names = stepNames(publish);
    const upload = names.indexOf("actions/upload-artifact");
    assert.ok(upload >= 0 && upload < names.indexOf("Registry check") && names.indexOf("Registry check") < names.indexOf("npm publish"), names.join(" | "));
    assert.match(step(publish, "npm publish"), /if: steps\.registry\.outputs\.publish == 'true'/);
    assert.match(publish.slice(publish.indexOf("uses: actions/upload-artifact")), /overwrite: true/, "a rerun replaces the first attempt's files");
  });

  it("runs the same registry check in the dry run", () => {
    assert.equal(step(dryRun, "Registry check"), step(publish, "Registry check"));
  });

  it("publishes a version the registry does not have", () => {
    for (const npm of ["exit 0", 'echo "npm error code E404" >&2; exit 1']) {
      const r = check(npm);
      assert.equal(r.code, 0, r.out);
      assert.equal(r.output, "publish=true\n", npm);
    }
  });

  it("skips npm publish when the registry already serves these very bytes", () => {
    const r = check(`echo "${integrity}"`);
    assert.equal(r.code, 0, r.out);
    assert.equal(r.output, "publish=false\n");
    assert.match(r.summary, /already published with these bytes/);
  });

  it("fails loudly when the registry serves other bytes under this version", () => {
    const r = check('echo "sha512-c29tZXRoaW5nIGVsc2U="');
    assert.equal(r.code, 1);
    assert.match(r.out, /::error::.*already published with other bytes/);
    assert.equal(r.output, "");
  });

  it("fails when the registry cannot be asked, never guessing", () => {
    const r = check('echo "npm error code ETIMEDOUT" >&2; exit 1');
    assert.equal(r.code, 1);
    assert.match(r.out, /::error::The registry could not be asked/);
    assert.equal(r.output, "");
  });

  it("keeps provenance on the workflow's publish, and none in the manifest for a local publish", () => {
    assert.equal(pkg.publishConfig?.provenance, undefined, "a local bootstrap publish has no CI provider");
    assert.match(step(publish, "npm publish"), /npm publish "\$RUNNER_TEMP\/release\/\$FILE" --provenance /);
  });
});

describe("the release workflow's private guard, on fixture manifests", { skip: unix }, () => {
  const guard = script(step(job("publish"), "The package is not private"));

  it("stops a publish while package.json is private", () => {
    const r = runStep(guard, {}, {}, { "package.json": '{ "name": "district-assurance", "private": true }' });
    assert.equal(r.code, 1);
    assert.match(r.out, /::error::package\.json has "private": true/);
  });

  it("lets a publishable manifest through", () => {
    for (const manifest of ['{ "name": "district-assurance" }', '{ "name": "district-assurance", "private": false }']) {
      assert.equal(runStep(guard, {}, {}, { "package.json": manifest }).code, 0, manifest);
    }
  });
});

describe("the previous release the benchmarks compare with", { skip: unix }, () => {
  const previous = script(step(job("bench"), "The previous release"));
  const tags = ["v0.3.0", "v0.2.1", "v0.2.0", "v0.2.0-rc.1", "v0.1.0"];
  /** gh answers for `release view <tag>`: true for a published release with files. */
  const gh = (published: string[]) => `tag="$3"; case " ${published.join(" ")} " in *" $tag "*) echo true ;; *) echo false ;; esac`;
  const run = (published: string[]) =>
    runStep(previous, { git: `printf '%s\\n' ${tags.join(" ")}`, gh: gh(published) }, { VERSION: "0.3.0", GITHUB_REPOSITORY: "o/r", GH_TOKEN: "x" });

  it("takes the nearest earlier tag that has a published GitHub release with its files", () => {
    const r = run(["v0.2.0", "v0.1.0"]);
    assert.equal(r.code, 0, r.out);
    assert.equal(r.output, "tag=v0.2.0\n", "v0.2.1 was tagged but never released");
  });

  it("finds none, and says in the summary that nothing is compared", () => {
    const r = run([]);
    assert.equal(r.code, 0, r.out);
    assert.equal(r.output, "tag=\n");
    assert.match(r.summary, /No earlier tag has a published GitHub release/);
  });

  it("skips the comparison when there is no baseline", () => {
    assert.match(step(job("bench"), "Compare with the previous release"), /if: steps\.previous\.outputs\.tag != ''/);
  });
});
