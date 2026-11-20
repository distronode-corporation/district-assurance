// What `npm pack` ships. `files` lists dist/, which only a build makes and git never holds, so a
// pack from a fresh checkout would ship the documents and no code. A local `npm pack` or
// `npm publish` builds first (prepack); the release workflow builds explicitly, packs with
// install scripts off, and checks the tarball's entry points.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
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
