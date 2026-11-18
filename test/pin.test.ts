// The PIN factor (keyed hash or the host's verifier) and factor plug-ins.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { badgeModule } from "../src/verify/badge.ts";
import type { FactorJudgeInput } from "../src/verify/factors.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, PIN, rejects, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

describe("PIN factor, keyed hash", () => {
  it("matches the PIN on file, on a subject the host chose, and reaches level 1 alone when the policy says so", async () => {
    const t = setup({ config: testConfig((c) => (c.policy.levels[0] = { level: 1, anyOf: [["pin"]] })) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.beginVerification(callId, { subjectKey: "not-hex" }), rejects("invalid_input"));
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] });
    const entries = await t.ledger.list();
    assert.deepEqual(entries[1]!.detail, { subject: "host" });
    assert.deepEqual(entries[2]!.detail, { kind: "pin", passed: true });
    assert.equal(JSON.stringify(entries).includes(`"${PIN}"`), false, "the PIN is never written");
  });

  it("counts malformed, wrong and unknown-subject entries the same way, and locks after the limit", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, "12"), { matched: false, locked: false }, "too short");
    assert.deepEqual(await t.engine.submitPin(callId, "123456789"), { matched: false, locked: false }, "too long");
    assert.deepEqual(await t.engine.submitPin(callId, "48a6"), { matched: false, locked: true }, "not digits, and the third attempt");
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "even the right PIN is not judged now");
    for (const account of ["99999999", "x"]) {
      const other = await t.engine.startCall();
      await t.engine.beginVerification(other.callId, { accountNumber: account });
      assert.deepEqual(await t.engine.submitPin(other.callId, PIN), { matched: false, locked: false });
    }
  });

  it("refuses a subject that has no PIN on file, and a keypad map as a PIN", async () => {
    const t = setup();
    t.records.putSubject("ws_test", { subjectKey: OWNER, phoneOnFile: "+15555550100", knowledge: {} });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false);
    assert.equal((await t.engine.submitFactor(callId, "pin", { pin: PIN })).matched, false);
    assert.equal((await t.engine.submitFactor(callId, "keypad_knowledge", "19850214")).matched, false, "keypad knowledge is a map of fields");
  });

  it("binds the digest to the subject", () => {
    assert.notEqual(pinDigest(TEST_KNOWLEDGE_KEY, "a".repeat(64), PIN), pinDigest(TEST_KNOWLEDGE_KEY, "b".repeat(64), PIN));
  });

  it("lets a PIN match unlock the photo ID link, as a keypad match does", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, PIN);
    assert.deepEqual(await t.engine.startPhotoId(callId), { sent: true });
  });
});

describe("PIN factor, the host's verifier", () => {
  const verifierConfig = () =>
    testConfig((c) => {
      (c.modules.badge!.settings as { pin: { mode: string } }).pin.mode = "verifier";
    });

  it("asks the host's PIN store every time, with a stand-in for a malformed entry or a non-keypad account (review item 11)", async () => {
    const t = setup({ config: verifierConfig() });
    t.pinVerifier.set("ws_test", OWNER, PIN);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, "0000")).matched, false);
    assert.equal((await t.engine.submitPin(callId, "12")).matched, false);
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.deepEqual(t.pinVerifier.asked, [OWNER, OWNER, OWNER], "the malformed entry was asked too, as a stand-in");
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: "12a" });
    t.pinVerifier.verify = async (input) => {
      t.pinVerifier.asked.push(input.subjectKey);
      return { matched: true }; // a verifier that says yes to a stand-in still never passes it
    };
    assert.equal((await t.engine.submitPin(other.callId, PIN)).matched, false);
    assert.equal((await t.engine.submitPin(other.callId, "1")).matched, false);
    assert.equal(t.pinVerifier.asked.length, 5);
  });

  it("never passes a subject the records do not have, whatever the verifier says", async () => {
    const t = setup({ config: verifierConfig() });
    const ghost = subjectKeyFor(TEST_KNOWLEDGE_KEY, "55555555");
    t.pinVerifier.set("ws_test", ghost, PIN);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: ghost });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false);
    assert.deepEqual(t.pinVerifier.asked, [ghost]);
  });

  it("counts the attempt before asking, so a verifier that fails still uses it", async () => {
    const t = setup({ config: verifierConfig() });
    t.pinVerifier.verify = async () => {
      throw new Error("pin store down");
    };
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    for (let i = 0; i < 3; i++) await assert.rejects(t.engine.submitPin(callId, PIN), /pin store down/);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true });
    assert.equal((await t.engine.state(callId)).factors.length, 0);
  });
});

describe("factor plug-ins", () => {
  it("judges a host's own factor with the keyed hash, never the key, and limits its attempts", async () => {
    const seen: FactorJudgeInput[] = [];
    const badge = badgeModule({
      factors: [
        {
          kind: "voice_passphrase",
          summary: "a passphrase the host's speech pipeline normalised",
          maxAttemptsPerCall: 1,
          adapters: [],
          judge: async (input) => {
            seen.push(input);
            return input.entry === "open sesame" && input.subject !== null;
          },
        },
        { kind: "truthy_judge", summary: "returns a non-boolean", maxAttemptsPerCall: 2, adapters: [], judge: async () => "yes" as unknown as boolean },
      ],
    });
    const config = testConfig((c) => {
      c.policy.levels[0] = { level: 1, anyOf: [["voice_passphrase"], ["truthy_judge"]] };
      (c.modules.badge!.settings as { factors: string[] }).factors.push("voice_passphrase", "truthy_judge");
    });
    const t = setup({ config, badge });
    assert.ok(t.engine.registry.factorKinds().includes("voice_passphrase"));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "truthy_judge", "x"), { matched: false, locked: false }, "only true passes");
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "open sesame"), { matched: true, locked: false });
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "open sesame"), { matched: false, locked: true });
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.subjectKey, OWNER);
    assert.match(seen[0]!.hmac("x"), /^[0-9a-f]{64}$/);
    assert.equal(Object.values(seen[0]!).includes(TEST_KNOWLEDGE_KEY), false);
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    const again = await t.engine.startCall();
    await t.engine.beginVerification(again.callId, { accountNumber: ACCOUNT });
    await t.engine.submitFactor(again.callId, "voice_passphrase", "open sesame");
    await assert.rejects(t.engine.startPhotoId(again.callId), rejects("precondition_failed"), "a plug-in match does not unlock texts to the number on file");
  });
});
