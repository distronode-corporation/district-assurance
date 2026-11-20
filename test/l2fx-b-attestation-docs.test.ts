// The host maps its carrier's caller ID result (no code here maps it): the reference server's
// README table and SPEC section 4 pin Twilio's Diverted and Passthrough StirVerstat values.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

const readme = readFileSync(new URL("../examples/reference-server/README.md", import.meta.url), "utf8");
const spec = readFileSync(new URL("../SPEC.md", import.meta.url), "utf8");

/**
 * Each Twilio StirVerstat value the table lists, with its attestation: one attestation for the
 * row, or one per value (`A`, `B`, `C`). A value written `-B` after `X-A-Y` is `X-B-Y`.
 */
function twilioRows(): Map<string, string> {
  const ticked = (cell: string) => [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1]!);
  const mapped = new Map<string, string>();
  // A Windows checkout may hold the README with CRLF endings: a "\r" left on a line would stop the `$` match.
  for (const line of readme.split(/\r?\n/)) {
    const row = /^\| Twilio `StirVerstat`: (.*) \| (.*) \|$/.exec(line);
    if (row === null) continue;
    const values = ticked(row[1]!).filter((v) => v !== "StirVerstat");
    const attestations = ticked(row[2]!);
    const first = values[0]!;
    const base = first.slice(0, first.lastIndexOf("-A"));
    values.forEach((value, i) => {
      const full = value.startsWith("-") ? base + value : value;
      assert.equal(mapped.has(full), false, `${full} is listed once`);
      mapped.set(full, attestations.length === 1 ? attestations[0]! : attestations[i]!);
    });
  }
  return mapped;
}

describe("docs: Twilio StirVerstat Diverted and Passthrough values", () => {
  const rows = twilioRows();
  for (const level of ["A", "B", "C"]) {
    for (const via of ["Diverted", "Passthrough"]) {
      it(`TN-Validation-Passed-${level}-${via} is none, TN-Validation-Failed-${level}-${via} is failed`, () => {
        assert.equal(rows.get(`TN-Validation-Passed-${level}-${via}`), "none");
        assert.equal(rows.get(`TN-Validation-Failed-${level}-${via}`), "failed");
      });
    }
  }

  it("keeps the plain values: Passed is its level, Failed and NULL are failed, No-TN-Validation is none", () => {
    for (const level of ["A", "B", "C"]) {
      assert.equal(rows.get(`TN-Validation-Passed-${level}`), level);
      assert.equal(rows.get(`TN-Validation-Failed-${level}`), "failed");
    }
    for (const value of ["TN-Validation-Failed", "NULL"]) assert.equal(rows.get(value), "failed", value);
    assert.equal(rows.get("No-TN-Validation"), "none");
  });

  it("SPEC section 4 names the Passed Diverted and Passthrough values as none, and why", () => {
    const section = spec.slice(spec.indexOf("**Caller ID attestation.**"));
    assert.match(section, /`TN-Validation-Passed-\{A,B,C\}-Diverted` or\s+`-Passthrough` maps to `none`, because Twilio did not verify the original signer's attestation\s+end to end/);
  });
});
