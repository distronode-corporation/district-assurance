// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// CodeRabbit's review of #148: the Stripe recorder wrote each hosted page URL with
// `writeFileSync(path, url, { mode: 0o600 })`, and a mode applies only to a file the call creates,
// so an existing URL file readable by others stayed readable with the fresh URL in it. The URL now
// goes to a new private file that is renamed over the old one.
import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { writePrivateFile } from "./fixtures/stripe-real/private-file.ts";

describe("the Stripe recorder writes a URL file private, even over an existing one (#148 review)", () => {
  it("replaces an existing file readable by others with a 0600 file holding the new text, and leaves nothing else", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "private-file-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "record-platform.url");
    writeFileSync(path, "old");
    chmodSync(path, 0o644);
    writePrivateFile(path, "https://checkout.stripe.com/redacted");
    assert.equal(readFileSync(path, "utf8"), "https://checkout.stripe.com/redacted");
    // Windows has no group or other permission bits to check.
    if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(dir), ["record-platform.url"], "no temporary file is left");
  });

  it("creates the file private when there is none", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "private-file-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, "record-connect.url");
    writePrivateFile(path, "u");
    assert.equal(readFileSync(path, "utf8"), "u");
    if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
  });
});
