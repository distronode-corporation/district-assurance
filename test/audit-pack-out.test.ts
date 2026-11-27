// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile pass on #121 (SRV-8 audit pack): the --out folder is emptied, so only a new folder, an
// empty one or an earlier pack may be named. Kept as regressions.
import { strict as assert } from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { MARKER, outProblem } from "../scripts/audit-pack-out.ts";

const base = mkdtempSync(join(tmpdir(), "audit-pack-out-"));
after(() => rmSync(base, { recursive: true, force: true }));

function folder(name: string, entries: Record<string, string | null>): string {
  const dir = join(base, name);
  mkdirSync(dir, { recursive: true });
  for (const [entry, text] of Object.entries(entries)) {
    if (text === null) mkdirSync(join(dir, entry), { recursive: true });
    else writeFileSync(join(dir, entry), text);
  }
  return dir;
}

describe("#121 hostile: the audit pack's --out folder", () => {
  it("O1 a folder of someone's own work that only uses the pack's names (docs/, tests/, an INDEX.md) is refused", () => {
    for (const [name, entries] of [
      ["site", { docs: null }],
      ["project", { tests: null, docs: null }],
      ["notes", { "INDEX.md": "# my notes\n" }],
      ["sums", { SHA256SUMS: "x  y\n", coverage: null }],
    ] as const) {
      assert.notEqual(outProblem(folder(name, entries)), null, name);
    }
  });

  it("O2 a new folder, an empty one, and an earlier pack, finished or not, may be emptied", () => {
    assert.equal(outProblem(join(base, "new")), null);
    assert.equal(outProblem(folder("empty", {})), null);
    assert.equal(outProblem(folder("started", { [MARKER]: "", tests: null })), null, "a pack that stopped part way");
    assert.equal(outProblem(folder("done", { [MARKER]: "", tests: null, coverage: null, contracts: null, sbom: null, docs: null, "INDEX.md": "", SHA256SUMS: "" })), null);
  });

  it("O3 an earlier pack with anything else in it is refused", () => {
    assert.notEqual(outProblem(folder("added", { [MARKER]: "", tests: null, "mine.txt": "" })), null);
  });
});
