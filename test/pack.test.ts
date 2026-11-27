// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// What `npm pack` ships. `files` lists dist/, which only a build makes and git never holds, so a
// pack from a fresh checkout would ship the documents and no code. A local `npm pack` or
// `npm publish` builds first (prepack); the release workflow builds explicitly, packs with
// install scripts off, and checks the tarball's entry points.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  files: string[];
  scripts: Record<string, string>;
};
/** Line endings as the checks expect them: a Windows checkout can hold the file with CRLF. */
const lf = (text: string): string => text.replace(/\r\n/g, "\n");
const raw = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
const release = lf(raw);

/** Each `npm pack` line, and how many of them follow their own build, in the workflow text given. */
function packs(text: string): { lines: string[]; built: number } {
  const lines = [...text.matchAll(/npm pack[^\n]*/g)].map((m) => m[0]);
  const built = (text.match(/npm run build\n\s+mkdir -p "\$RUNNER_TEMP\/(pack-\$n|release)"\n\s+npm pack/g) ?? []).length;
  return { lines, built };
}

describe("the package", () => {
  it("builds before every local pack or publish, since dist/ is not in git", () => {
    assert.ok(pkg.files.includes("dist/"));
    assert.equal(pkg.scripts.prepack, "npm run build");
    assert.match(pkg.scripts.build!, /^node scripts\/clean\.mjs && /, "a clean build, so no stale file is packed");
  });

  it("the release workflow builds before each pack and requires the built entry points", () => {
    const { lines, built } = packs(release);
    assert.ok(lines.length >= 3);
    for (const line of lines) assert.match(line, /--ignore-scripts/, line);
    assert.equal(built, lines.length, "every pack follows its own build");
    for (const entry of ["package/dist/index.js", "package/dist/index.d.ts", "package/dist/testing/index.js", "package/dist/testing/index.d.ts"]) {
      assert.ok(release.includes(entry), entry);
    }
  });

  it("reads the release workflow the same with CRLF line endings, as a Windows checkout may hold it", () => {
    assert.deepEqual(packs(lf(raw.replace(/\r?\n/g, "\r\n"))), packs(release));
  });
});

describe("the release workflow's tarball allow-list", () => {
  const allowed = new RegExp(/allowed='([^']+)'/.exec(release)![1]!);
  const required = [...release.matchAll(/package\/[\w./-]+/g)].map((m) => m[0]);

  it("admits every path `files` ships, so a new published file cannot fail the release pack", () => {
    const shipped = ["package/package.json"];
    for (const entry of pkg.files) {
      if (entry === "dist/") shipped.push("package/dist/index.js", "package/dist/testing/index.d.ts");
      else if (entry.endsWith("/")) {
        for (const name of readdirSync(new URL(`../${entry}`, import.meta.url), { recursive: true }) as string[]) shipped.push(`package/${entry}${name}`);
      } else shipped.push(`package/${entry}`);
    }
    for (const path of shipped) assert.match(path, allowed, path);
  });

  it("still refuses what must never ship", () => {
    for (const path of ["package/src/index.ts", "package/test/pack.test.ts", "package/schema/x.ts", "package/schema/../src/a.json", "package/.env", "package/examples/a.json"]) {
      assert.doesNotMatch(path, allowed, path);
    }
  });

  it("requires every export target in the tarball", () => {
    const exportsMap = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, unknown> }).exports;
    const targets = new Set<string>();
    const walk = (v: unknown): void => {
      if (typeof v === "string") targets.add(`package/${v.replace(/^\.\//, "")}`);
      else if (v !== null && typeof v === "object") for (const x of Object.values(v)) walk(x);
    };
    walk(exportsMap);
    for (const target of targets) assert.ok(required.includes(target), `release.yml requires ${target}`);
  });
});

describe("SPEC's published package section", () => {
  it("names every path the exports map publishes, and says how many there are", () => {
    const spec = readFileSync(new URL("../SPEC.md", import.meta.url), "utf8");
    const section = spec.slice(spec.indexOf("## 30. The published package"));
    const paragraph = section.slice(0, section.indexOf("\n\n", section.indexOf("\n\n") + 2));
    const exportsMap = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, unknown> }).exports;
    const names = Object.keys(exportsMap).map((key) => (key === "." ? "district-assurance" : `district-assurance/${key.slice(2)}`));
    for (const name of names) assert.ok(paragraph.includes(`\`${name}\``), `SPEC names ${name}`);
    const words = ["one", "two", "three", "four", "five", "six"];
    assert.match(paragraph, new RegExp(`has ${words[names.length - 1]} entry points`), `${names.length} entry points`);
  });
});

/** The run script of the release workflow's "Tarball contents" step, as the runner gets it. */
function tarballCheck(): string {
  const lines = release.split("\n");
  const start = lines.findIndex((l) => l.trim() === "- name: Tarball contents");
  const run = lines.findIndex((l, i) => i > start && l.trim() === "run: |");
  const indent = lines[run + 1]!.length - lines[run + 1]!.trimStart().length;
  const body: string[] = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && line.length - line.trimStart().length < indent) break;
    body.push(line.slice(indent));
  }
  return body.join("\n");
}

describe("the release workflow's tarball check, run as written", { skip: process.platform === "win32" ? "bash and tar as on the Linux runner" : false }, () => {
  const required = [
    "package/dist/index.js",
    "package/dist/index.d.ts",
    "package/dist/testing/index.js",
    "package/dist/testing/index.d.ts",
    "package/dist/stripe/index.js",
    "package/dist/stripe/index.d.ts",
    "package/dist/carrier/index.js",
    "package/dist/carrier/index.d.ts",
    "package/schema/flow-config.v1.json",
    "package/package.json",
    "package/LICENSE",
    "package/NOTICE",
  ];
  const complete = [...required, "package/dist/core/engine.js", "package/README.md", "package/SPEC.md"];

  /** Packs these paths into a tarball and runs the step on it: its exit code. */
  function check(paths: readonly string[]): number | null {
    const dir = mkdtempSync(join(tmpdir(), "da-tarball-"));
    try {
      for (const path of paths) {
        mkdirSync(join(dir, "tree", dirname(path)), { recursive: true });
        writeFileSync(join(dir, "tree", path), "x");
      }
      mkdirSync(join(dir, "release"));
      const tar = spawnSync("tar", ["-czf", join(dir, "release", "p.tgz"), "-C", join(dir, "tree"), ...paths]);
      assert.equal(tar.status, 0, String(tar.stderr));
      return spawnSync("bash", ["-c", tarballCheck()], { env: { ...process.env, RUNNER_TEMP: dir, FILE: "p.tgz" }, stdio: "ignore" }).status;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("passes a tarball with everything it requires", () => {
    assert.equal(check(complete), 0);
  });

  it("fails a tarball missing any one required path", () => {
    for (const path of required) assert.equal(check(complete.filter((p) => p !== path)), 1, `without ${path}`);
  });

  it("fails a tarball holding a path outside the published set", () => {
    for (const extra of ["package/src/index.ts", "package/schema/x.ts", "package/.env"]) assert.equal(check([...complete, extra]), 1, extra);
  });
});
