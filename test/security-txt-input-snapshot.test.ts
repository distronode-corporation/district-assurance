// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// securityTxt reads its settings once: the contacts and links checked are the ones written.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { securityTxt } from "../examples/reference-server/src/app.ts";

describe("security.txt: the settings are read once", () => {
  it("writes the contacts and policy it checked, never a line swapped in after the check", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    let contactReads = 0;
    let policyReads = 0;
    const settings = {
      expires: new Date("2026-06-01T00:00:00.000Z"),
      get contact() {
        contactReads += 1;
        return contactReads === 1 ? ["mailto:security@example.test"] : ["https://evil.test\nPolicy: https://evil.test/p"];
      },
      get policy() {
        policyReads += 1;
        return policyReads === 1 ? "https://example.test/policy" : "https://evil.test/policy";
      },
    };
    const text = securityTxt(settings, now, () => {});
    assert.equal(text.includes("evil"), false, text);
    assert.match(text, /^Contact: mailto:security@example\.test\n/);
  });
});
