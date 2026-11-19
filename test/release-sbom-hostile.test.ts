// Hostile-pass regressions for #125 (SRV-6, signed releases): the release workflow's SBOM check,
// run here on SBOMs a release could produce, its two copies kept the same, and which job may sign.
// Every attack held.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");

/** Each inline sbom-check.mjs in the workflow, with the YAML block's indentation taken off. */
function checkScripts(): string[] {
  return [...workflow.matchAll(/cat > "\$RUNNER_TEMP\/sbom-check\.mjs" <<'EOF'\n([\s\S]*?)\n\s*EOF\n/g)].map((m) => {
    const lines = m[1]!.split("\n");
    const indent = Math.min(...lines.filter((l) => l.trim() !== "").map((l) => l.length - l.trimStart().length));
    return lines.map((l) => l.slice(indent)).join("\n");
  });
}

function runCheck(script: string, bom: unknown, version: string): { ok: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), "zz125-"));
  try {
    writeFileSync(join(dir, "check.mjs"), script);
    writeFileSync(join(dir, "bom.json"), JSON.stringify(bom));
    const r = spawnSync(process.execPath, [join(dir, "check.mjs"), join(dir, "bom.json"), version], { encoding: "utf8" });
    return { ok: r.status === 0, output: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const good = { bomFormat: "CycloneDX", specVersion: "1.5", metadata: { component: { name: "checkout-folder", purl: "pkg:npm/district-assurance@1.2.3" } }, components: [] };

describe("hostile #125: the release workflow's SBOM check", () => {
  it("R1: the publish and dry-run jobs carry the same check", () => {
    const scripts = checkScripts();
    assert.equal(scripts.length, 2);
    assert.equal(scripts[0], scripts[1]);
  });

  it("R2: passes the SBOM of this package and refuses every SBOM a release must not attest", () => {
    const [script] = checkScripts();
    assert.equal(runCheck(script!, good, "1.2.3").ok, true);
    assert.equal(runCheck(script!, { ...good, components: undefined }, "1.2.3").ok, true, "no components field is none");
    for (const [why, bom, version] of [
      ["a runtime dependency", { ...good, components: [{ purl: "pkg:npm/left-pad@1.3.0" }] }, "1.2.3"],
      ["another version", good, "1.2.4"],
      ["another package", { ...good, metadata: { component: { purl: "pkg:npm/district-assurance-fork@1.2.3" } } }, "1.2.3"],
      ["a scoped look-alike", { ...good, metadata: { component: { purl: "pkg:npm/%40evil/district-assurance@1.2.3" } } }, "1.2.3"],
      ["not CycloneDX", { ...good, bomFormat: "SPDX" }, "1.2.3"],
      ["no root component", { ...good, metadata: {} }, "1.2.3"],
      ["not JSON at all", "<html>", "1.2.3"],
    ] as const) {
      assert.equal(runCheck(script!, bom, version).ok, false, why);
    }
  });

  it("R3: only the publish job may sign, and the job that writes the release holds no OIDC token", () => {
    const jobs = workflow.split(/\n  (?=[a-z-]+:\n)/);
    /** A job's permissions, as `scope: access` lines, comments left out. */
    const job = (name: string) => {
      const text = jobs.find((j) => j.startsWith(`${name}:`))!;
      const block = /\n    permissions:\n((?: {6}.*\n)+)/.exec(text)?.[1] ?? "";
      const uses = [...text.matchAll(/uses: (\S+)/g)].map((m) => m[1]).join("\n");
      return `${block.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n")}\n${uses}`;
    };
    assert.match(job("publish"), /id-token: write/);
    assert.match(job("publish"), /attestations: write/);
    assert.doesNotMatch(job("publish"), /contents: write/);
    assert.match(job("github-release"), /contents: write/);
    assert.doesNotMatch(job("github-release"), /id-token/);
    assert.doesNotMatch(job("dry-run"), /id-token|attestations: write|attest-sbom/);
  });
});
