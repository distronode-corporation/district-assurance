// VER-2: texted one-time codes. Expiry, tries, single use, the send limits, the country allow-list,
// and refused sends that look exactly like sent ones.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { CodeSendKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { defaultVerificationPolicy, validatePolicy } from "../src/core/policy.ts";
import { MemoryCodeStore, TEST_KNOWLEDGE_KEY, codeStoreContract, testSubject, type TestEngine } from "../src/testing/index.ts";
import { TEXT_CODE_LIMITS, textCodeDestinationAllowed, textCodeText } from "../src/verify/text-code.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const MINUTE = 60_000;

/** Keypad, carrier signals and texted codes on; codes may go to +1 numbers. */
function codeSetup(patch: (c: FlowConfig) => void = () => undefined, codes = new MemoryCodeStore()): TestEngine {
  const config = testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
    patch(c);
  });
  return setup({ config, adapters: { codes } });
}

/** A call verifying, past a keypad match. */
async function matchedCall(t: TestEngine, input: { account?: string; callingNumber?: string; locale?: "en" | "fr" } = {}): Promise<string> {
  const { callId } = await t.engine.startCall({ locale: input.locale ?? "en" });
  const begin = input.callingNumber === undefined ? { accountNumber: input.account ?? ACCOUNT } : { accountNumber: input.account ?? ACCOUNT, callingNumber: input.callingNumber };
  await t.engine.beginVerification(callId, begin);
  assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
  return callId;
}

function lastCode(t: TestEngine): string {
  return /\d{6}/.exec(t.messages.sent.at(-1)!.body)![0];
}

/** A code that is not this one. */
function wrong(code: string): string {
  return `${(Number(code[0]) + 1) % 10}${code.slice(1)}`;
}

async function events(t: TestEngine, name: string): Promise<unknown[]> {
  return (await t.ledger.list()).filter((e) => e.event === name).map((e) => e.detail);
}

describe("MemoryCodeStore passes the CodeStore contract", () => {
  for (const c of codeStoreContract(() => new MemoryCodeStore())) it(c.name, c.run);
});

describe("the CodeStore contract suite", () => {
  it("fails a store that ignores its limits", async () => {
    const careless = { take: async () => true };
    const failures: unknown[] = [];
    for (const c of codeStoreContract(() => careless)) await c.run().catch((e: unknown) => failures.push(e));
    assert.equal(failures.length, 4);
  });
});

describe("texted codes", () => {
  it("texts a 6-digit code to the number on file in English and French, and keeps only its HMAC", async () => {
    const t = codeSetup();
    for (const locale of ["en", "fr"] as const) {
      const callId = await matchedCall(t, { locale });
      assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
      const code = lastCode(t);
      assert.equal(t.messages.sent.at(-1)!.body, textCodeText(locale, code));
      assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE);
      const record = JSON.stringify(await t.sessions.get("ws_test", callId));
      assert.equal(record.includes(code), false, "the call record holds the HMAC, never the code");
      t.clock.advance(MINUTE);
    }
    assert.match(t.messages.sent[0]!.body, /^Your one-time verification code: \d{6}\. It expires in 10 minutes\. Do not share it\.$/);
    assert.match(t.messages.sent[1]!.body, /^Votre code de vérification à usage unique : \d{6}\. Il expire dans 10 minutes\. Ne le communiquez à personne\.$/);
    assert.deepEqual(await events(t, "verification.code_sent"), [{}, {}]);
  });

  it("records a text_code factor that counts toward level 2 only under the policy's carrier rule", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    const code = lastCode(t);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: true, locked: false });
    assert.deepEqual((await t.engine.finishVerification(callId)).level, 1, "no carrier answer: the code does not count");
    const ledger = JSON.stringify(await t.ledger.list());
    assert.equal(ledger.includes(code), false, "the code is never written");
    assert.deepEqual((await events(t, "verification.factor")).at(-1), { kind: "text_code", passed: true });

    const clean = await matchedCall(t);
    await t.engine.checkCarrier(clean);
    t.clock.advance(MINUTE);
    await t.engine.sendTextCode(clean);
    await t.engine.checkTextCode(clean, lastCode(t));
    assert.equal((await t.engine.finishVerification(clean)).level, 2);
  });

  it("is single use and bound to its call", async () => {
    const t = codeSetup();
    const first = await matchedCall(t);
    const second = await matchedCall(t, { callingNumber: CALLING });
    await t.engine.sendTextCode(first);
    const code = lastCode(t);
    t.clock.advance(MINUTE);
    await t.engine.sendTextCode(second);
    const other = lastCode(t);
    if (other !== code) assert.deepEqual(await t.engine.checkTextCode(second, code), { matched: false, locked: false }, "another call's code");
    assert.deepEqual(await t.engine.checkTextCode(first, code), { matched: true, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(first, code), { matched: false, locked: true }, "used");
    assert.deepEqual(await t.engine.checkTextCode(second, other), { matched: true, locked: false });
  });

  it("allows 5 tries, a malformed entry being one, and then judges nothing, not even the right code", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    const code = lastCode(t);
    assert.deepEqual(await t.engine.checkTextCode(callId, "12"), { matched: false, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(callId, `${code}0`), { matched: false, locked: false });
    for (let i = 0; i < 2; i++) assert.deepEqual(await t.engine.checkTextCode(callId, wrong(code)), { matched: false, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(callId, wrong(code)), { matched: false, locked: true }, "the fifth try");
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: false, locked: true });
    assert.equal((await events(t, "verification.factor")).filter((d) => (d as { kind: string }).kind === "text_code").length, 5);
    // A new send gives a new code and new tries.
    t.clock.advance(MINUTE);
    await t.engine.sendTextCode(callId);
    assert.deepEqual(await t.engine.checkTextCode(callId, lastCode(t)), { matched: true, locked: false });
  });

  it("expires after 10 minutes", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    const code = lastCode(t);
    t.clock.advance(10 * MINUTE - 1);
    assert.deepEqual(await t.engine.checkTextCode(callId, wrong(code)), { matched: false, locked: false });
    t.clock.advance(1);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: false, locked: true });
  });

  it("refuses to check without a code, off the verifying phase, or with the factor off", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await assert.rejects(t.engine.checkTextCode(callId, "123456"), rejects("precondition_failed", /no code was sent/));
    await t.engine.sendTextCode(callId);
    await t.engine.finishVerification(callId);
    await assert.rejects(t.engine.checkTextCode(callId, "123456"), rejects("invalid_transition"));
    await assert.rejects(t.engine.sendTextCode(callId), rejects("invalid_transition", /while verifying, not while open/));
    const off = setup();
    const { callId: offCall } = await off.engine.startCall();
    await off.engine.beginVerification(offCall, { accountNumber: ACCOUNT });
    await off.engine.submitKeypad(offCall, { dob: DOB });
    await assert.rejects(off.engine.sendTextCode(offCall), rejects("precondition_failed", /text_code factor is turned off/));
    await assert.rejects(off.engine.checkTextCode(offCall, "123456"), rejects("precondition_failed", /text_code factor is turned off/));
  });

  it("drops the code on a taint or a change of subject", async () => {
    const t = codeSetup();
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "22222222", phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    const tainted = await matchedCall(t);
    await t.engine.sendTextCode(tainted);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.checkTextCode(tainted, lastCode(t)), rejects("precondition_failed", /no code was sent/));
    const moved = await matchedCall(t, { callingNumber: CALLING });
    t.clock.advance(MINUTE);
    await t.engine.sendTextCode(moved);
    await t.engine.finishVerification(moved);
    await t.engine.beginVerification(moved, { accountNumber: "22222222" });
    await assert.rejects(t.engine.checkTextCode(moved, lastCode(t)), rejects("precondition_failed", /no code was sent/));
  });

  it("refuses a malformed calling number, and keeps the first one through a restart without it", async () => {
    const t = codeSetup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "5555550199" }), rejects("invalid_input", /E\.164/));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const slice = ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { numberKey: string } } }).modules.badge;
    assert.equal(slice.numberKey, hmacSha256Hex(TEST_KNOWLEDGE_KEY, `number:${CALLING}`));
    assert.equal(JSON.stringify(slice).includes(CALLING), false, "the calling number is kept only as a keyed hash");
  });

  it("does not apply a send judged for an earlier verification", async () => {
    let restart = async (): Promise<void> => undefined;
    class Restarting extends MemoryCodeStore {
      override async take(input: { workspaceId: string; key: CodeSendKey; at: string; max: number; windowSeconds: number; minIntervalSeconds: number }): Promise<boolean> {
        await restart();
        return super.take(input);
      }
    }
    const t = codeSetup(undefined, new Restarting());
    const callId = await matchedCall(t);
    restart = async () => {
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    };
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed", /verification restarted/));
    assert.equal(t.messages.sent.length, 0);
  });
});

describe("send limits", () => {
  it("allows 5 codes per subject per 24 hours, across calls", async () => {
    const t = codeSetup();
    for (let i = 0; i < 5; i++) {
      await t.engine.sendTextCode(await matchedCall(t));
      t.clock.advance(MINUTE);
    }
    const sixth = await matchedCall(t);
    assert.deepEqual(await t.engine.sendTextCode(sixth), { sent: true });
    assert.equal(t.messages.sent.length, 5);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "subject_limit" }]);
    t.clock.advance(TEXT_CODE_LIMITS.subject.windowSeconds * 1000 - 5 * MINUTE);
    await t.engine.sendTextCode(await matchedCall(t));
    assert.equal(t.messages.sent.length, 6, "the first send left the window");
  });

  it("waits 60 seconds between sends, and a refused send keeps the live code", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    const code = lastCode(t);
    t.clock.advance(MINUTE - 1);
    assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
    assert.equal(t.messages.sent.length, 1);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: true, locked: false }, "the live code still works");
    t.clock.advance(1);
    await t.engine.sendTextCode(callId);
    assert.equal(t.messages.sent.length, 2);
  });

  it("limits sends per calling number, across subjects", async () => {
    const t = codeSetup();
    const accounts = ["11111111", "22222222", "33333333"];
    for (const accountNumber of accounts) t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    for (let i = 0; i < TEXT_CODE_LIMITS.number.max; i++) {
      await t.engine.sendTextCode(await matchedCall(t, { account: accounts[Math.floor(i / 5)]!, callingNumber: CALLING }));
      t.clock.advance(MINUTE);
    }
    assert.equal(t.messages.sent.length, 10);
    await t.engine.sendTextCode(await matchedCall(t, { account: accounts[2]!, callingNumber: CALLING }));
    assert.equal(t.messages.sent.length, 10);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "number_limit" }]);
    t.clock.advance(MINUTE);
    await t.engine.sendTextCode(await matchedCall(t, { account: accounts[2]!, callingNumber: "+15555550198" }));
    assert.equal(t.messages.sent.length, 11, "another number, same subject");
  });

  it("texts only to countries the policy allows, and counts nothing it refuses for that", async () => {
    const t = codeSetup((c) => (c.policy.textCodeCountryCodes = ["33", "1204"]));
    const callId = await matchedCall(t);
    assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
    assert.equal(t.messages.sent.length, 0);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "country" }]);
    t.engine.configure(testConfig((c) => {
      c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
      c.policy.textCodeCountryCodes = ["1555"];
    }));
    for (let i = 0; i < 5; i++) {
      await t.engine.sendTextCode(await matchedCall(t));
      t.clock.advance(MINUTE);
    }
    assert.equal(t.messages.sent.length, 5, "the refusal by country used none of the subject's five");
  });

  it("refused and sent sends look the same to the caller", async () => {
    const run = async (refuse: boolean) => {
      const t = codeSetup((c) => (c.policy.textCodeCountryCodes = refuse ? ["44"] : ["1"]));
      const callId = await matchedCall(t);
      const answers: unknown[] = [await t.engine.sendTextCode(callId)];
      // The caller keys a wrong code: anything, when none was texted.
      const entry = refuse ? "000000" : wrong(lastCode(t));
      for (let i = 0; i < 6; i++) answers.push(await t.engine.checkTextCode(callId, entry));
      return answers;
    };
    assert.deepEqual(await run(true), await run(false));
    // And the same expiry.
    const t = codeSetup((c) => (c.policy.textCodeCountryCodes = ["44"]));
    const callId = await matchedCall(t);
    await t.engine.sendTextCode(callId);
    assert.deepEqual(await t.engine.checkTextCode(callId, "000000"), { matched: false, locked: false });
    t.clock.advance(10 * MINUTE);
    assert.deepEqual(await t.engine.checkTextCode(callId, "000000"), { matched: false, locked: true });
  });

  it("works in a flow whose verify step lists text_code", async () => {
    const t = codeSetup((c) => {
      c.flows = { code: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match", "text_code"], scopes: ["payment.request"] }] } };
    });
    const { callId } = await t.engine.startCall({ flow: "code" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.sendTextCode(callId);
    await t.engine.checkTextCode(callId, lastCode(t));
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 2, scopes: ["payment.request"] });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
  });
});

describe("the country allow-list in the policy", () => {
  it("is checked by validatePolicy", () => {
    const at = (countries: unknown) => validatePolicy({ ...defaultVerificationPolicy(), textCodeCountryCodes: countries });
    const shape = "textCodeCountryCodes must list E.164 country calling codes, 1 to 6 digits without the +";
    assert.deepEqual(at(["1", "33", "1204"]), []);
    for (const bad of [[], ["+1"], ["0"], ["1234567"], [1], "1"]) assert.deepEqual(at(bad), [shape], JSON.stringify(bad));
    assert.deepEqual(at(["1", "1"]), ["textCodeCountryCodes has duplicates"]);
  });

  it("matches the number on file by prefix, and allows nowhere without a list", () => {
    const policy = { ...defaultVerificationPolicy(), textCodeCountryCodes: ["33", "1204"] };
    assert.equal(textCodeDestinationAllowed(policy, "+33612345678"), true);
    assert.equal(textCodeDestinationAllowed(policy, "+12045550100"), true);
    assert.equal(textCodeDestinationAllowed(policy, "+14165550100"), false);
    assert.equal(textCodeDestinationAllowed(defaultVerificationPolicy(), "+33612345678"), false);
  });
});
