// CodeRabbit's review of 0aa6a63 on #133: the audit tables and SPEC claim no more than the code gives.
// The listener is told best effort, not at least once; an open draft holds sensitive values in the
// call record; Telnyx's check is tested with an RFC 8032 vector, not a Telnyx example.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

const model = readFileSync(new URL("../SECURITY-MODEL.md", import.meta.url), "utf8");
const spec = readFileSync(new URL("../SPEC.md", import.meta.url), "utf8");
const row = (id: string): string => model.split(/\r?\n/).find((line) => line.startsWith(`| ${id} |`))!;

describe("docs: delivery, draft and carrier claims (#133 review)", () => {
  it("core-18 and SPEC say the listener is told best effort, never at least once", () => {
    assert.doesNotMatch(row("core-18"), /at least once/);
    assert.match(row("core-18"), /best effort/);
    assert.doesNotMatch(spec, /at least once and best effort/);
    assert.match(spec, /best effort and possibly more than\s+once, so not at least once/);
  });

  it("dossier-4 and fieldcipher-1 name the plaintext an open or filing draft holds", () => {
    for (const id of ["dossier-4", "fieldcipher-1"]) {
      assert.doesNotMatch(row(id), /stored, and kept in the clear nowhere else|plaintext is kept nowhere else, including/, id);
      assert.match(row(id), /in the clear in the call record/, id);
    }
  });

  it("webhooks-4 names RFC 8032 as Telnyx's evidence, not a published Telnyx example", () => {
    assert.doesNotMatch(row("webhooks-4"), /the vendors' published examples/);
    assert.match(row("webhooks-4"), /Telnyx's against RFC 8032's first Ed25519 test vector/);
  });
});
