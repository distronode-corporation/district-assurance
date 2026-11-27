// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// CodeRabbit's review of the 0.1.0 release diff (#149, CWE-208): a PIN record was checked at its own
// stored cost, anything from today's cost up to a ceiling, while an unknown subject's stand-in ran
// at today's cost, so a wrong PIN for a subject with a dearer record took longer than for an
// unknown subject. A record is now read only at today's cost: a dearer one never matches and is
// never run at its own cost, so every check is one Argon2id run at today's cost.
import { strict as assert } from "node:assert";
import { argon2Sync } from "node:crypto";
import { describe, it } from "node:test";

import { hmacSha256Hex } from "../src/core/hash.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { PIN_HASH_PARAMETERS, checkPinRecord } from "../src/verify/pin-hash.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, PHONE_ON_FILE, PIN, setup } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const keyedPin = (pin: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, `pin:${OWNER}:${pin}`);
const b64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** A correctly computed record of `keyed` at `cost`: the right PIN would match it if it were run. */
function recordAt(keyed: string, cost: { memory: number; passes: number; parallelism: number }): string {
  const salt = Buffer.alloc(16, 9);
  const tag = argon2Sync("argon2id", { message: Buffer.from(keyed, "hex"), nonce: salt, tagLength: 32, ...cost });
  return `$pin1$argon2id$v=19$m=${cost.memory},t=${cost.passes},p=${cost.parallelism}$${b64(salt)}$${b64(tag)}`;
}

const dearer = [
  { ...PIN_HASH_PARAMETERS, memory: PIN_HASH_PARAMETERS.memory * 2 },
  { ...PIN_HASH_PARAMETERS, passes: PIN_HASH_PARAMETERS.passes + 1 },
  { ...PIN_HASH_PARAMETERS, parallelism: PIN_HASH_PARAMETERS.parallelism + 1 },
];

describe("a PIN check is the same work whatever the record's cost (#149 review)", () => {
  it("matches a record at today's cost", async () => {
    assert.deepEqual(await checkPinRecord(recordAt(keyedPin(PIN), PIN_HASH_PARAMETERS), keyedPin(PIN)), { match: true, upgrade: false });
  });

  it("never runs a dearer record at its own cost: the right PIN fails, as on a stand-in", async () => {
    for (const cost of dearer) {
      assert.deepEqual(await checkPinRecord(recordAt(keyedPin(PIN), cost), keyedPin(PIN)), { match: false, upgrade: false }, JSON.stringify(cost));
    }
  });

  it("fails the right PIN on the PIN factor for a dearer record, and leaves the record as it was", async () => {
    const t = setup();
    const stored = recordAt(keyedPin(PIN), dearer[0]!);
    t.records.putSubject("ws_test", { subjectKey: OWNER, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pinDigest: stored });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: false });
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, stored);
  });
});
