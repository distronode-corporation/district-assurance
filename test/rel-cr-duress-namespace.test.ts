// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// CodeRabbit's review of the 0.1.0 release diff (#149): SECURITY-MODEL.md gave a duress PIN record
// the `pin:` namespace, while the code keys it under `duress:`. The doc's formulas are held to the
// records the engine writes.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, PIN, pinOnFile, setup, testConfig } from "./helpers.ts";

const model = readFileSync(new URL("../SECURITY-MODEL.md", import.meta.url), "utf8").replace(/\s+/g, " ");
const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const duressConfig = () =>
  testConfig((c: FlowConfig) => {
    (c.modules.badge!.settings as unknown as { pin: PinSettings }).pin.duress = { refuseScopes: [] };
  });

describe("SECURITY-MODEL.md names the namespace of each PIN record (#149 review)", () => {
  it("documents `pin:` for a PIN record and `duress:` for a duress PIN record", () => {
    assert.match(model, /a PIN on file is Argon2id \(19 MiB, 2 passes, 1 lane, a random 16-byte salt\) over `HMAC-SHA256\(knowledgeKey, "pin:" \+ subjectKey \+ ":" \+ pin\)`/);
    assert.match(model, /a duress PIN on file over `HMAC-SHA256\(knowledgeKey, "duress:" \+ subjectKey \+ ":" \+ pin\)`/);
  });

  it("keys a PIN record under `pin:`, never `duress:`", async () => {
    const t = setup();
    const subject = await t.records.getSubject("ws_test", OWNER);
    assert.ok(await pinOnFile(subject!.pinDigest, OWNER, PIN, "pin"));
    assert.equal(await pinOnFile(subject!.pinDigest, OWNER, PIN, "duress"), false);
  });

  it("keys an enrolled duress PIN under `duress:`, never `pin:`", async () => {
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: { notify: () => Promise.resolve() } } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const subject = await t.records.getSubject("ws_test", OWNER);
    assert.ok(await pinOnFile(subject!.duressDigest, OWNER, DURESS, "duress"));
    assert.equal(await pinOnFile(subject!.duressDigest, OWNER, DURESS, "pin"), false);
  });
});
