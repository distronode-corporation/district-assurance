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
const release = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");

describe("the package", () => {
  it("builds before every local pack or publish, since dist/ is not in git", () => {
    assert.ok(pkg.files.includes("dist/"));
    assert.equal(pkg.scripts.prepack, "npm run build");
    assert.match(pkg.scripts.build!, /^node scripts\/clean\.mjs && /, "a clean build, so no stale file is packed");
  });

  it("the release workflow builds before each pack and requires the built entry points", () => {
    const packs = [...release.matchAll(/npm pack[^\n]*/g)].map((m) => m[0]);
    assert.ok(packs.length >= 3);
    for (const line of packs) assert.match(line, /--ignore-scripts/, line);
    const builds = release.match(/npm run build\n\s+mkdir -p "\$RUNNER_TEMP\/(pack-\$n|release)"\n\s+npm pack/g) ?? [];
    assert.equal(builds.length, packs.length, "every pack follows its own build");
    for (const entry of ["package/dist/index.js", "package/dist/index.d.ts", "package/dist/testing/index.js", "package/dist/testing/index.d.ts"]) {
      assert.ok(release.includes(entry), entry);
    }
  });
});
