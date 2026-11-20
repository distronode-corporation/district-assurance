// Hostile pass on the audit pack's paths (SRV-8, PR #133 review): the v8 coverage temp folder never
// overlaps --out (so its cleanup can never remove the pack or an ancestor of it), and a supplied
// SBOM never shares a name with the manifests copied next to it. Imported, never run: importing
// scripts/audit-pack.mjs builds no pack.
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

// A plain .mjs script has no type declarations: its exports are typed here, from a URL import.
const { MANIFESTS, SUPPLIED_SBOM_DIR, suppliedSbomPath, v8TempProblem } = (await import(new URL("../scripts/audit-pack.mjs", import.meta.url).href)) as {
  MANIFESTS: readonly string[];
  SUPPLIED_SBOM_DIR: string;
  suppliedSbomPath(given: string): string;
  v8TempProblem(out: string, temp: string): string | null;
};

const base = mkdtempSync(join(tmpdir(), "audit-pack-paths-"));
after(() => rmSync(base, { recursive: true, force: true }));

describe("audit pack: the v8 temp folder and --out", () => {
  it("P1 --out under the temp folder, the temp folder itself, or an ancestor of it is refused", () => {
    const temp = join(base, "v8");
    mkdirSync(temp, { recursive: true });
    for (const out of [join(temp, "release"), temp, base, join(temp, "a", "b")]) {
      assert.notEqual(v8TempProblem(out, temp), null, out);
    }
  });

  it("P2 an --out beside the temp folder, or one whose name only starts like it, is allowed", () => {
    const temp = join(base, "v8b");
    mkdirSync(temp, { recursive: true });
    for (const out of [join(base, "pack"), `${temp}-release`, join(base, "v8")]) assert.equal(v8TempProblem(out, temp), null, out);
  });

  it("P3 overlap through a symlink to an ancestor of the temp folder is refused", () => {
    const temp = join(base, "real", "v8");
    mkdirSync(temp, { recursive: true });
    const link = join(base, "link");
    // A junction on Windows, which needs no symbolic-link privilege; other platforms ignore the type.
    symlinkSync(join(base, "real"), link, "junction");
    assert.notEqual(v8TempProblem(link, temp), null);
    assert.notEqual(v8TempProblem(join(link, "v8", "new"), temp), null, "a new folder under it, through the link");
  });
});

describe("audit pack: a supplied SBOM", () => {
  it("S1 an --sbom named package.json or package-lock.json lands apart from the copied manifests", () => {
    for (const name of [...MANIFESTS, "sbom.cdx.json", "release.spdx.json"]) {
      const path = suppliedSbomPath(join(base, "given", name));
      assert.equal(path, `sbom/${SUPPLIED_SBOM_DIR}/${name}`);
      for (const manifest of MANIFESTS) assert.notEqual(path, `sbom/${manifest}`);
    }
  });
});
