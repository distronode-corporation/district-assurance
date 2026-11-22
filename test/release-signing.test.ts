// The release workflow releases main's version on its own, once, under a tag it signed itself:
// the decide step's every branch (the no-op included) run as the runner runs it, and the shape
// that keeps an unsigned or hand-pushed tag from ever publishing.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8").replace(/\r\n/g, "\n");

/** A job's text, from its name to the next job. */
function job(name: string): string {
  const start = workflow.indexOf(`\n  ${name}:\n`);
  assert.ok(start >= 0, name);
  const next = workflow.slice(start + 1).search(/\n {2}[a-z][a-z-]*:\n/);
  return next < 0 ? workflow.slice(start) : workflow.slice(start, start + 1 + next);
}

/** A step's `run: |` script, dedented, as the runner gets it. */
function script(jobText: string, name: string): string {
  const at = jobText.indexOf(`      - name: ${name}\n`);
  assert.ok(at >= 0, name);
  const end = jobText.indexOf("\n      - ", at + 1);
  const lines = jobText.slice(at, end < 0 ? undefined : end).split("\n");
  const run = lines.findIndex((l) => l.trim() === "run: |");
  assert.ok(run >= 0, `a run block in ${name}`);
  const indent = lines[run + 1]!.length - lines[run + 1]!.trimStart().length;
  const body: string[] = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && line.length - line.trimStart().length < indent) break;
    body.push(line.slice(indent));
  }
  return body.join("\n");
}

const root = mkdtempSync(join(tmpdir(), "da-release-signing-"));
after(() => rmSync(root, { recursive: true, force: true }));
let n = 0;

/** A checkout in `dir` as the job sees one: CHANGELOG.md and the release-notes script it runs. */
function checkout(dir: string, changelog: string) {
  mkdirSync(join(dir, "scripts"), { recursive: true });
  copyFileSync(new URL("../scripts/release-notes.mjs", import.meta.url), join(dir, "scripts", "release-notes.mjs"));
  writeFileSync(join(dir, "CHANGELOG.md"), changelog);
}

const SHA = "a".repeat(40);
const OTHER = "b".repeat(40);
const CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2026-11-22\n\n### Added\n\n- a line\n";

interface World {
  version?: string;
  /** The commit `v<version>` names on the remote (peeled), or none. */
  tag?: string | null;
  /** The versions the registry document lists. */
  versions?: string[];
  /** The registry document as served, when not the default. */
  document?: string;
  curlFails?: boolean;
  changelog?: string;
  event?: string;
  dryRun?: string;
  /** What GitHub answers for the tag's release: one with files, none (404), a draft, or a failure. */
  release?: "complete" | "none" | "draft" | "empty" | "partial" | "starter" | "fails";
}

/** The decide step, run with stand-in git and curl, the real node and grep. */
function decide(world: World = {}) {
  const dir = join(root, String(n++));
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  const version = world.version ?? "1.2.3";
  const tag = world.tag === undefined ? null : world.tag;
  const fake = (name: string, body: string) => {
    writeFileSync(join(bin, name), `#!/usr/bin/env bash\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  };
  // `git -c http.extraheader=... ls-remote --tags origin <ref>`: refused (as GitHub refuses a runner's
  // request with no credential) unless it carries the token's header; then the peeled line for
  // `^{}`, the tag's own line otherwise.
  const header = `AUTHORIZATION: basic ${Buffer.from("x-access-token:the-job-token").toString("base64")}`;
  fake(
    "git",
    `if [ "$1" != -c ] || [ "$2" != "http.extraheader=${header}" ]; then echo "fatal: The requested URL returned error: 403" >&2; exit 128; fi\n` +
      (tag === null ? "exit 0" : `case "$*" in *'^{}'*) printf '%s\\t%s\\n' "${tag}" "\${@: -1}" ;; *) printf '%s\\t%s\\n' "${"c".repeat(40)}" "\${@: -1}" ;; esac`),
  );
  const document = world.document ?? JSON.stringify({ name: "district-assurance", versions: Object.fromEntries((world.versions ?? ["0.1.0"]).map((v) => [v, {}])) });
  writeFileSync(join(dir, "document.json"), document);
  fake("curl", world.curlFails === true ? "exit 22" : `while [ $# -gt 0 ]; do if [ "$1" = -o ]; then cp "${join(dir, "document.json")}" "$2"; shift; fi; shift; done`);
  const release = world.release ?? "complete";
  const all = ["district-assurance-1.2.3.tgz", "district-assurance-1.2.3.cdx.json", "district-assurance-1.2.3.tgz.sbom.sigstore.json"].map((name) => ({ name, state: "uploaded" }));
  const answer = {
    complete: { draft: false, assets: all },
    draft: { draft: true, assets: all },
    empty: { draft: false, assets: [] },
    partial: { draft: false, assets: all.slice(0, 1) },
    // A failed upload's placeholder: every name is there, one never finished uploading.
    starter: { draft: false, assets: [...all.slice(0, 2), { ...all[2]!, state: "starter" }] },
  } as Record<string, unknown>;
  fake(
    "gh",
    release === "none"
      ? `echo 'gh: Not Found (HTTP 404)' >&2; exit 1`
      : release === "fails"
        ? `echo 'gh: Server Error (HTTP 502)' >&2; exit 1`
        : `printf '%s' '${JSON.stringify(answer[release])}'`,
  );
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "district-assurance", version }));
  checkout(dir, world.changelog ?? CHANGELOG);
  writeFileSync(join(dir, "output"), "");
  writeFileSync(join(dir, "summary"), "");
  const r = spawnSync("bash", ["-c", script(job("decide"), "Decide")], {
    cwd: dir,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: dir,
      GITHUB_OUTPUT: join(dir, "output"),
      GITHUB_STEP_SUMMARY: join(dir, "summary"),
      GITHUB_SHA: SHA,
      GITHUB_REPOSITORY: "distronode-corporation/district-assurance",
      GH_TOKEN: "the-job-token",
      EVENT: world.event ?? "push",
      DRY_RUN: world.dryRun ?? "",
    },
  });
  const output = Object.fromEntries(
    readFileSync(join(dir, "output"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => l.split("=") as [string, string]),
  );
  return { code: r.status, out: `${r.stdout}${r.stderr}`, output, summary: readFileSync(join(dir, "summary"), "utf8") };
}

const unix = process.platform === "win32" ? "bash and stand-in commands as on the Linux runner" : false;

describe("the release decision", { skip: unix }, () => {
  it("is a no-op, and a success, when main's version is tagged and on npm: an ordinary merge changes nothing", () => {
    const r = decide({ tag: SHA, versions: ["0.1.0", "1.2.3"] });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.output, { version: "1.2.3", state: "done", dry: "false" });
    assert.match(r.summary, /nothing to release/);
  });

  it("releases a version with no tag that is not on npm and has a dated CHANGELOG.md section", () => {
    const r = decide();
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.output, { version: "1.2.3", state: "release", dry: "false" });
  });

  it("refuses to release a version whose CHANGELOG.md section is missing, undated or only a prefix", () => {
    for (const changelog of ["# Changelog\n\n## [Unreleased]\n", "## [1.2.3] - Unreleased\n", "## [1.2.3]\n", "## [1.2.30] - 2026-11-22\n", "## [1x2x3] - 2026-11-22\n", "## [1.2.3] - 2026-11-22 (late)\n"]) {
      const r = decide({ changelog });
      assert.notEqual(r.code, 0, changelog);
      assert.match(r.out, /no dated '## \[1\.2\.3\] - YYYY-MM-DD' section/, changelog);
      assert.equal(r.output.state, undefined, "nothing decided");
    }
  });

  it("finishes a release that is on npm but whose tag has no GitHub release with its files, from this commit only", () => {
    for (const release of ["none", "draft", "empty", "partial", "starter"] as const) {
      const r = decide({ tag: SHA, versions: ["1.2.3"], release });
      assert.equal(r.code, 0, r.out);
      assert.equal(r.output.state, "resume", release);
      assert.match(r.summary, /GitHub release is missing/, release);
    }
    // A later merge, on another commit, is a no-op whatever the old release holds: GitHub is not asked.
    const later = decide({ tag: OTHER, versions: ["1.2.3"], release: "fails" });
    assert.equal(later.code, 0, later.out);
    assert.equal(later.output.state, "done");
  });

  it("fails closed when GitHub cannot be asked about the tag's release", () => {
    const r = decide({ tag: SHA, versions: ["1.2.3"], release: "fails" });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /could not be asked whether v1\.2\.3 has its release/);
    assert.equal(r.output.state, undefined);
  });

  it("resumes a run that tagged this very commit and then failed before npm had the version", () => {
    const r = decide({ tag: SHA });
    assert.equal(r.code, 0, r.out);
    assert.equal(r.output.state, "resume");
  });

  it("refuses a tag on another commit while the version is not on npm", () => {
    const r = decide({ tag: OTHER });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /is on b+, not this commit/);
  });

  it("refuses a version on npm that has no tag, for a person to look at", () => {
    const r = decide({ versions: ["1.2.3"] });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /on npm but has no tag/);
  });

  it("fails closed when the registry cannot be asked, or answers something that is not a package document", () => {
    for (const world of [{ curlFails: true }, { document: "not json" }, { document: "{}" }, { document: JSON.stringify({ versions: null }) }, { document: "" }] as World[]) {
      const r = decide(world);
      assert.notEqual(r.code, 0, JSON.stringify(world));
      assert.equal(r.output.state, undefined, `never read as "not published": ${JSON.stringify(world)}`);
    }
  });

  it("refuses a package.json version that is not a release version", () => {
    for (const version of ["1.2", "v1.2.3", "1.2.3 ", "latest", "1.2.3+build"]) {
      const r = decide({ version });
      assert.notEqual(r.code, 0, version);
    }
  });

  it("a manual run with dry_run ticked is a dry run; a push, or dry_run unticked, never is", () => {
    assert.equal(decide({ event: "workflow_dispatch", dryRun: "true" }).output.dry, "true");
    assert.equal(decide({ event: "workflow_dispatch", dryRun: "false" }).output.dry, "false");
    assert.equal(decide({ event: "push", dryRun: "true" }).output.dry, "false");
  });
});

describe("the shape that keeps an unsigned tag from publishing", () => {
  const head = workflow.slice(0, workflow.indexOf("\njobs:"));

  it("runs on a push to main and by hand, never on a tag push, one run at a time and never cancelled", () => {
    const on = head.slice(head.indexOf("\non:"), head.indexOf("\npermissions:"));
    assert.match(on, /\n {2}push:\n {4}branches: \[main\]\n/);
    assert.match(on, /\n {2}workflow_dispatch:/);
    assert.doesNotMatch(on, /tags:/);
    assert.match(head, /\nconcurrency:\n {2}group: release\n {2}cancel-in-progress: false\n/);
  });

  it("decides only upstream, and only from main", () => {
    assert.match(job("decide"), /if: github\.repository == 'distronode-corporation\/district-assurance'/);
    assert.match(script(job("decide"), "Only from main"), /"\$REF" != "refs\/heads\/main"/);
    assert.match(script(job("decide"), "The commit is on main"), /git merge-base --is-ancestor "\$GITHUB_SHA" origin\/main/);
  });

  it("tags only a new version, signs it offline with the pinned gitsign, verifies it before pushing, and pushes with the workflow token", () => {
    const tag = job("tag");
    assert.match(tag, /if: needs\.decide\.outputs\.state == 'release' && needs\.decide\.outputs\.dry == 'false'/);
    assert.match(tag, /contents: write/);
    assert.match(tag, /id-token: write/);
    assert.match(tag, /GITSIGN_REKOR_MODE: offline/);
    const sign = script(tag, "Create the signed tag");
    assert.match(sign, /git tag -s -m "district-assurance \$VERSION" "v\$VERSION" "\$GITHUB_SHA"/);
    assert.ok(sign.indexOf("git tag -s") < sign.indexOf("gitsign verify-tag"), "verified after it is made");
    assert.match(script(tag, "Push the tag"), /push origin "refs\/tags\/v\$VERSION"/);
    assert.ok(tag.indexOf("Create the signed tag") < tag.indexOf("Push the tag"), "verified before it is pushed");
  });

  it("checks the gitsign download against the same pinned SHA-256 in both jobs that run it", () => {
    for (const name of ["tag", "guard"]) {
      assert.match(job(name), /GITSIGN_VERSION: 0\.18\.0\n/, name);
      assert.match(job(name), /GITSIGN_SHA256: 2bc625472a08fea3bb6a57982c7d8b4978d1032251d305ceef3bf2ded0ca4483\n/, name);
      assert.match(script(job(name), "Install gitsign"), /sha256sum -c -/, name);
    }
  });

  it("verifies the tag as the server holds it against this file on main and GitHub's issuer, in the signing job and the guard", () => {
    const identity = /--certificate-identity "https:\/\/github\.com\/\$\{GITHUB_REPOSITORY\}\/\.github\/workflows\/release\.yml@refs\/heads\/main"/;
    const issuer = /--certificate-oidc-issuer https:\/\/token\.actions\.githubusercontent\.com/;
    for (const text of [script(job("tag"), "Create the signed tag"), script(job("guard"), "The tag is signed by this workflow on main")]) {
      assert.match(text, identity);
      assert.match(text, issuer);
    }
    const guard = script(job("guard"), "The tag is signed by this workflow on main");
    assert.match(guard, /fetch --no-tags origin "\+refs\/tags\/v\$\{VERSION\}:refs\/tags\/v\$\{VERSION\}"/);
    assert.match(guard, /git cat-file -t/);
    assert.match(guard, /\^\{commit\}"\)" != "\$GITHUB_SHA"/);
  });

  it("builds and publishes nothing unless the guard passed, except a dry run, which never publishes", () => {
    for (const name of ["ci", "supply-chain", "pack", "bench"]) {
      const text = job(name);
      assert.match(text, /needs: \[decide, guard\]/, name);
      assert.match(text, /needs\.guard\.result == 'success' \|\| \(needs\.decide\.outputs\.dry == 'true' && needs\.guard\.result == 'skipped'\)/, name);
      // A no-op skips them; an explicit dry run goes through them even for a released version.
      assert.match(text, /\(needs\.decide\.outputs\.state != 'done' \|\| needs\.decide\.outputs\.dry == 'true'\)/, name);
    }
    assert.match(job("publish"), /needs: \[decide, guard, ci, supply-chain, pack\]/);
    assert.match(job("dry-run"), /needs\.decide\.outputs\.dry == 'true'/);
    assert.doesNotMatch(job("dry-run"), /id-token|contents: write/);
  });

  it("holds the OIDC scope only in the tag and publish jobs, and write access to contents only in the tag and release jobs", () => {
    const jobs = [...workflow.matchAll(/\n {2}([a-z][a-z-]*):\n/g)].map((m) => m[1]!).filter((name) => workflow.indexOf(`\n  ${name}:\n`) > workflow.indexOf("\njobs:"));
    assert.ok(jobs.length >= 10, jobs.join(", "));
    for (const name of jobs) {
      // The keys themselves, not a comment that names them.
      assert.equal(/^ +id-token: write/m.test(job(name)), ["tag", "publish"].includes(name), `id-token in ${name}`);
      assert.equal(/^ +contents: write/m.test(job(name)), ["tag", "github-release"].includes(name), `contents: write in ${name}`);
    }
  });
});

describe("the GitHub release job: creates the release, or repairs the one a failed run left", { skip: unix }, () => {
  const VERSION = "1.2.3";
  const FILE = `district-assurance-${VERSION}.tgz`;
  const bytes = "the checked tarball";

  /** The Create the release step with a stand-in gh that logs its calls; `view` is what `gh release view` does. */
  function create(view: "exists" | "missing" | "fails", expected?: string) {
    const dir = join(root, String(n++));
    const bin = join(dir, "bin");
    const release = join(dir, "release");
    mkdirSync(bin, { recursive: true });
    mkdirSync(release, { recursive: true });
    writeFileSync(join(release, FILE), bytes);
    checkout(dir, "# Changelog\n\n## [1.2.3] - 2026-11-22\n\nA plain paragraph,\nwrapped.\n\n### Added\n\n- **A line.**\n");
    const sha = spawnSync("sha256sum", [join(release, FILE)], { encoding: "utf8" }).stdout.split(" ")[0]!;
    const onView = { exists: "exit 0", missing: "echo 'release not found' >&2; exit 1", fails: "echo 'HTTP 502' >&2; exit 1" }[view];
    writeFileSync(join(bin, "gh"), `#!/usr/bin/env bash\necho "$*" >> "${join(dir, "calls")}"\nif [ "$2" = view ]; then ${onView}; fi\nexit 0\n`);
    chmodSync(join(bin, "gh"), 0o755);
    const r = spawnSync("bash", ["-c", script(job("github-release"), "Create the release")], {
      cwd: dir,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: dir, GITHUB_WORKSPACE: dir, GH_TOKEN: "x", GITHUB_REPOSITORY: "o/r", FILE, VERSION, EXPECTED_SHA256: expected ?? sha },
    });
    let calls: string[] = [];
    try {
      calls = readFileSync(join(dir, "calls"), "utf8").trim().split("\n");
    } catch {
      calls = [];
    }
    let notes = "";
    try {
      notes = readFileSync(join(release, "notes.md"), "utf8");
    } catch {
      notes = "";
    }
    return { code: r.status, out: `${r.stdout}${r.stderr}`, calls: calls.map((c) => c.split(" ").slice(0, 2).join(" ")), notes };
  }

  it("creates the release with the three files when the tag has none", () => {
    const r = create("missing");
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.calls, ["release view", "release create"]);
  });

  it("writes the notes: the CHANGELOG.md section, unwrapped, its link, then the files", () => {
    const r = create("missing");
    assert.equal(r.code, 0, r.out);
    assert.ok(
      r.notes.startsWith(
        "A plain paragraph, wrapped.\n\n### Added\n\n- **A line.**\n\nThe full changelog is in the [1.2.3 section of CHANGELOG.md](https://github.com/o/r/blob/main/CHANGELOG.md#123---2026-11-22).\n\n---\n\ndistrict-assurance 1.2.3, published to npm with provenance.\n",
      ),
      r.notes,
    );
    assert.ok(r.notes.includes(`| \`${FILE}\` | the published tarball, SHA-256 \``));
    assert.ok(r.notes.endsWith('To check this release, see "Checking a release" in README.md.\n'));
  });

  it("uploads the three files to a release a failed run left, replacing any copy, and publishes it", () => {
    const r = create("exists");
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.calls, ["release view", "release upload", "release edit"]);
    const step = script(job("github-release"), "Create the release");
    assert.match(step, /gh release upload "v\$VERSION" --repo "\$GITHUB_REPOSITORY" --clobber "\$\{files\[@\]\}"/);
    assert.match(step, /--draft=false/);
  });

  it("stops when GitHub cannot be asked, and checks the tarball before any call", () => {
    const failed = create("fails");
    assert.notEqual(failed.code, 0);
    assert.match(failed.out, /could not be asked whether v1\.2\.3 has a release/);
    assert.deepEqual(failed.calls, ["release view"]);
    const wrong = create("missing", "0".repeat(64));
    assert.notEqual(wrong.code, 0);
    assert.match(wrong.out, /differs from the one the pack job checked/);
    assert.deepEqual(wrong.calls, [], "nothing asked or attached");
  });
});

describe("every git call that reaches GitHub carries the job's token", () => {
  /** Each run script's commands, with backslash-continued lines joined, and the step text they are in. */
  function commands(): Array<{ step: string; command: string }> {
    const out: Array<{ step: string; command: string }> = [];
    const steps = workflow.split(/\n(?= {6}- )/);
    for (const step of steps) {
      const run = step.indexOf("run: |");
      if (run < 0) continue;
      const body = step.slice(run).split("\n").slice(1).join("\n").replace(/\\\n\s*/g, " ");
      for (const line of body.split("\n")) out.push({ step, command: line.trim() });
    }
    return out;
  }
  const network = /\bgit\b.*?\s(?:fetch|push|pull|clone|ls-remote)\s/;

  it("finds the network calls: the fetch of main, the two tag lookups, the tag push and the guard's fetch", () => {
    assert.equal(commands().filter((c) => network.test(c.command)).length, 5);
  });

  it("gives each one the token as a header for that command alone, from github.token, never in a URL", () => {
    for (const { step, command } of commands().filter((c) => network.test(c.command))) {
      assert.match(command, /git -c http\.extraheader="AUTHORIZATION: basic \$auth" +(?:fetch|push|ls-remote) /, command);
      assert.match(step, /auth="\$\(printf 'x-access-token:%s' "\$GH_TOKEN" \| base64 -w0\)"/, command);
      assert.match(step, /\n {10}GH_TOKEN: \$\{\{ github\.token \}\}\n/, command);
    }
    assert.doesNotMatch(workflow, /https:\/\/[^\s"]*@github\.com|x-access-token:[^%]/, "no credential in a URL");
    // The credential is never written to git's config: every checkout keeps persist-credentials off.
    const checkouts = workflow.split("uses: actions/checkout@").slice(1);
    assert.ok(checkouts.length > 0);
    for (const checkout of checkouts) assert.match(checkout.slice(0, 200), /persist-credentials: false/);
  });
});
