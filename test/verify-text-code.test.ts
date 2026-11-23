// VER-2: texted one-time codes. Expiry, tries, single use, the send limits, the country allow-list,
// and refused sends that look exactly like sent ones.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { CodeSendKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { defaultVerificationPolicy, validatePolicy as validatePolicyRaw } from "../src/core/policy.ts";
import { problemMessage } from "../src/core/module.ts";

/** The policy validator's sentences, as the tests read them. */
const validatePolicy = (...args: Parameters<typeof validatePolicyRaw>): string[] => validatePolicyRaw(...args).map(problemMessage);
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

/** Sends a code and lets the text go out: it is sent after the reply. */
async function sendCode(t: TestEngine, callId: string): Promise<{ sent: true }> {
  const answer = await t.engine.sendTextCode(callId);
  await settle();
  return answer;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

function lastCode(t: TestEngine): string {
  return /\d{6}/.exec(t.messages.sent.at(-1)!.body)![0];
}

/** A code that is not this one. */
function wrong(code: string): string {
  return `${(Number(code[0]) + 1) % 10}${code.slice(1)}`;
}

/**
 * Whether a stored value holds the code: as a string or number field value, or as a whole token
 * inside a string. Not a substring test of its JSON: a random 6-digit code can turn up inside a
 * timestamp, a hash or an id by chance, which made the substring test flaky. An integer field
 * matches at the code's width, so a code with a leading zero stored as a number is still caught.
 */
function holdsCode(value: unknown, code: string): boolean {
  if (typeof value === "string") return new RegExp(`(?<![0-9A-Za-z_])${code}(?![0-9A-Za-z_])`).test(value);
  // A number drops a leading zero, so an integer is compared at the code's width.
  if (typeof value === "number") return Number.isInteger(value) && value >= 0 && String(value).padStart(code.length, "0") === code;
  if (Array.isArray(value)) return value.some((v) => holdsCode(v, code));
  if (typeof value === "object" && value !== null) return Object.entries(value).some(([k, v]) => holdsCode(k, code) || holdsCode(v, code));
  return false;
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
    assert.equal(failures.length, 5);
  });
});

describe("texted codes", () => {
  it("texts a 6-digit code to the number on file in English and French, and keeps only its HMAC", async () => {
    const t = codeSetup();
    for (const locale of ["en", "fr"] as const) {
      const callId = await matchedCall(t, { locale });
      assert.deepEqual(await sendCode(t, callId), { sent: true });
      const code = lastCode(t);
      assert.equal(t.messages.sent.at(-1)!.body, textCodeText(locale, code));
      assert.equal(t.messages.sent.at(-1)!.to, PHONE_ON_FILE);
      const record: unknown = JSON.parse(JSON.stringify(await t.sessions.get("ws_test", callId)));
      assert.equal(holdsCode(record, code), false, "the call record holds the HMAC, never the code");
      t.clock.advance(MINUTE);
    }
    assert.match(t.messages.sent[0]!.body, /^Your one-time verification code: \d{6}\. It expires in 10 minutes\. Do not share it\.$/);
    assert.match(t.messages.sent[1]!.body, /^Votre code de vérification à usage unique : \d{6}\. Il expire dans 10 minutes\. Ne le communiquez à personne\.$/);
    assert.deepEqual(await events(t, "verification.code_sent"), [{}, {}]);
  });

  it("records a text_code factor that counts toward level 2 only under the policy's carrier rule", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    const code = lastCode(t);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: true, locked: false });
    assert.deepEqual((await t.engine.finishVerification(callId)).level, 1, "no carrier answer: the code does not count");
    const ledger: unknown = JSON.parse(JSON.stringify(await t.ledger.list()));
    assert.equal(holdsCode(ledger, code), false, "the code is never written");
    assert.deepEqual((await events(t, "verification.factor")).at(-1), { kind: "text_code", passed: true });

    const clean = await matchedCall(t);
    await t.engine.checkCarrier(clean);
    t.clock.advance(MINUTE);
    await sendCode(t, clean);
    await t.engine.checkTextCode(clean, lastCode(t));
    assert.equal((await t.engine.finishVerification(clean)).level, 2);

    // Level 2 only through the code: the keypad and carrier pair is not a level-2 rule here, so a
    // clean carrier answer alone gives level 1, and the matched code is what makes it 2.
    const onlyCode = codeSetup((c) => {
      c.policy.levels[1]!.anyOf = c.policy.levels[1]!.anyOf.filter((rule) => !rule.includes("carrier_identity_match"));
    });
    const without = await matchedCall(onlyCode);
    await onlyCode.engine.checkCarrier(without);
    assert.equal((await onlyCode.engine.finishVerification(without)).level, 1, "no code: the carrier answer alone is not level 2");
    const counted = await matchedCall(onlyCode);
    await onlyCode.engine.checkCarrier(counted);
    onlyCode.clock.advance(MINUTE);
    await sendCode(onlyCode, counted);
    assert.deepEqual(await onlyCode.engine.checkTextCode(counted, lastCode(onlyCode)), { matched: true, locked: false });
    assert.equal((await onlyCode.engine.finishVerification(counted)).level, 2, "the code counted toward level 2");
  });

  it("checks the code's absence by value and token, not as a substring of the ledger JSON (the old check could flake)", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    await t.engine.checkTextCode(callId, lastCode(t));
    await t.engine.finishVerification(callId);
    const json = JSON.stringify(await t.ledger.list());
    // A code forced to a 6-digit run already inside the ledger JSON (a timestamp, a hash, an id).
    const forced = /\d{6}/.exec(json)?.[0];
    assert.ok(forced !== undefined, "the ledger JSON holds a 6-digit run");
    assert.equal(json.includes(forced), true, "the old substring assertion fails on this code");
    assert.equal(holdsCode(JSON.parse(json), forced), false, "the new assertion passes: no field holds it");
    // It still catches the code written as a value, a number, a key, or a token in text.
    assert.equal(holdsCode({ detail: { code: forced } }, forced), true);
    assert.equal(holdsCode([482913], "482913"), true);
    assert.equal(holdsCode([12345], "012345"), true, "a code with a leading zero, stored as a number");
    assert.equal(holdsCode({ [forced]: true }, forced), true);
    assert.equal(holdsCode({ note: `sent ${forced}.` }, forced), true);
    assert.equal(holdsCode({ hash: `ab${forced}cd`, id: `ev_${forced}`, at: Number(`1${forced}`), none: null }, forced), false);
  });

  it("is single use and bound to its call", async () => {
    const t = codeSetup();
    const first = await matchedCall(t);
    const second = await matchedCall(t, { callingNumber: CALLING });
    await sendCode(t, first);
    const code = lastCode(t);
    t.clock.advance(MINUTE);
    await sendCode(t, second);
    const other = lastCode(t);
    if (other !== code) assert.deepEqual(await t.engine.checkTextCode(second, code), { matched: false, locked: false }, "another call's code");
    assert.deepEqual(await t.engine.checkTextCode(first, code), { matched: true, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(first, code), { matched: false, locked: true }, "used");
    assert.deepEqual(await t.engine.checkTextCode(second, other), { matched: true, locked: false });
  });

  it("allows 5 tries, a malformed entry being one, and then judges nothing, not even the right code", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    const code = lastCode(t);
    assert.deepEqual(await t.engine.checkTextCode(callId, "12"), { matched: false, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(callId, `${code}0`), { matched: false, locked: false });
    for (let i = 0; i < 2; i++) assert.deepEqual(await t.engine.checkTextCode(callId, wrong(code)), { matched: false, locked: false });
    assert.deepEqual(await t.engine.checkTextCode(callId, wrong(code)), { matched: false, locked: true }, "the fifth try");
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: false, locked: true });
    assert.equal((await events(t, "verification.factor")).filter((d) => (d as { kind: string }).kind === "text_code").length, 5);
    // A new send gives a new code and new tries.
    t.clock.advance(MINUTE);
    await sendCode(t, callId);
    assert.deepEqual(await t.engine.checkTextCode(callId, lastCode(t)), { matched: true, locked: false });
  });

  it("expires after 10 minutes", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
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
    await sendCode(t, callId);
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
    await sendCode(t, tainted);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.checkTextCode(tainted, lastCode(t)), rejects("precondition_failed", /no code was sent/));
    const moved = await matchedCall(t, { callingNumber: CALLING });
    t.clock.advance(MINUTE);
    await sendCode(t, moved);
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

  it("does not store a code from a send decided before a taint", async () => {
    let taint = async (): Promise<void> => undefined;
    class Tainting extends MemoryCodeStore {
      override async take(input: { workspaceId: string; key: CodeSendKey; at: string; max: number; windowSeconds: number; minIntervalSeconds: number }): Promise<boolean> {
        await taint();
        return super.take(input);
      }
    }
    const t = codeSetup(undefined, new Tainting());
    const callId = await matchedCall(t);
    taint = async () => {
      taint = async () => undefined;
      await t.engine.markUntrusted(callId, "crm_note");
    };
    await assert.rejects(t.engine.sendTextCode(callId), rejects("precondition_failed", /verification restarted|have not matched/));
    assert.equal(t.messages.sent.length, 0);
    const slice = ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { textCode: unknown } } }).modules.badge;
    assert.equal(slice.textCode, null, "no code was stored");
    await assert.rejects(t.engine.checkTextCode(callId, "123456"), rejects("precondition_failed", /no code was sent|have not matched/));
  });

  it("judges expiry by the clock when the check is written, not when it started", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    const code = lastCode(t);
    t.clock.advance(10 * MINUTE - 1000);
    const get = t.sessions.get.bind(t.sessions);
    let once = true;
    t.sessions.get = async (w, c) => {
      if (once) {
        once = false;
        t.clock.advance(1000);
      }
      return get(w, c);
    };
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: false, locked: true });
  });
});

describe("send limits", () => {
  it("allows 5 codes per subject per 24 hours, across calls", async () => {
    const t = codeSetup();
    for (let i = 0; i < 5; i++) {
      await sendCode(t, await matchedCall(t));
      t.clock.advance(MINUTE);
    }
    const sixth = await matchedCall(t);
    assert.deepEqual(await sendCode(t, sixth), { sent: true });
    assert.equal(t.messages.sent.length, 5);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "subject_limit" }]);
    t.clock.advance(TEXT_CODE_LIMITS.subject.windowSeconds * 1000 - 5 * MINUTE);
    await sendCode(t, await matchedCall(t));
    assert.equal(t.messages.sent.length, 6, "the first send left the window");
  });

  it("waits 60 seconds between sends, and a refused send keeps the live code", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    const code = lastCode(t);
    t.clock.advance(MINUTE - 1);
    assert.deepEqual(await sendCode(t, callId), { sent: true });
    assert.equal(t.messages.sent.length, 1);
    assert.deepEqual(await t.engine.checkTextCode(callId, code), { matched: true, locked: false }, "the live code still works");
    t.clock.advance(1);
    await sendCode(t, callId);
    assert.equal(t.messages.sent.length, 2);
  });

  it("limits sends per calling number, across subjects", async () => {
    const t = codeSetup();
    const accounts = ["11111111", "22222222", "33333333"];
    for (const accountNumber of accounts) t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    for (let i = 0; i < TEXT_CODE_LIMITS.number.max; i++) {
      await sendCode(t, await matchedCall(t, { account: accounts[Math.floor(i / 5)]!, callingNumber: CALLING }));
      t.clock.advance(MINUTE);
    }
    assert.equal(t.messages.sent.length, 10);
    await sendCode(t, await matchedCall(t, { account: accounts[2]!, callingNumber: CALLING }));
    assert.equal(t.messages.sent.length, 10);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "number_limit" }]);
    t.clock.advance(MINUTE);
    await sendCode(t, await matchedCall(t, { account: accounts[2]!, callingNumber: "+15555550198" }));
    assert.equal(t.messages.sent.length, 11, "another number, same subject");
  });

  it("texts only to countries the policy allows, and counts nothing it refuses for that", async () => {
    const t = codeSetup((c) => (c.policy.textCodeCountryCodes = ["33", "1204"]));
    const callId = await matchedCall(t);
    assert.deepEqual(await sendCode(t, callId), { sent: true });
    assert.equal(t.messages.sent.length, 0);
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "country" }]);
    t.engine.configure(testConfig((c) => {
      c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
      c.policy.textCodeCountryCodes = ["1555"];
    }));
    for (let i = 0; i < 5; i++) {
      await sendCode(t, await matchedCall(t));
      t.clock.advance(MINUTE);
    }
    assert.equal(t.messages.sent.length, 5, "the refusal by country used none of the subject's five");
  });

  it("refused and sent sends look the same to the caller", async () => {
    const run = async (refuse: boolean) => {
      const t = codeSetup((c) => (c.policy.textCodeCountryCodes = refuse ? ["44"] : ["1"]));
      const callId = await matchedCall(t);
      const answers: unknown[] = [await sendCode(t, callId)];
      // The caller keys a wrong code: anything, when none was texted.
      const entry = refuse ? "000000" : wrong(lastCode(t));
      for (let i = 0; i < 6; i++) answers.push(await t.engine.checkTextCode(callId, entry));
      return answers;
    };
    assert.deepEqual(await run(true), await run(false));
    // And the same expiry.
    const t = codeSetup((c) => (c.policy.textCodeCountryCodes = ["44"]));
    const callId = await matchedCall(t);
    await sendCode(t, callId);
    assert.deepEqual(await t.engine.checkTextCode(callId, "000000"), { matched: false, locked: false });
    t.clock.advance(10 * MINUTE);
    assert.deepEqual(await t.engine.checkTextCode(callId, "000000"), { matched: false, locked: true });
  });

  it("answers a sent send and a refused one with the same steps, never waiting for the SMS adapter (#79 review)", async () => {
    /** The store reads and writes a send makes before it answers, in order, with the SMS adapter never answering. */
    const trace = async (refuse: boolean) => {
      const steps: string[] = [];
      // A refused send: the subject's limit is used up.
      const store = new MemoryCodeStore();
      const codes = { take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => (steps.push("codes.take"), refuse ? false : store.take(input)) };
      const t = codeSetup(undefined, codes as unknown as MemoryCodeStore);
      const callId = await matchedCall(t);
      steps.length = 0;
      const get = t.sessions.get.bind(t.sessions);
      const cas = t.sessions.compareAndSet.bind(t.sessions);
      t.sessions.get = async (...args) => (steps.push("session.get"), get(...args));
      t.sessions.compareAndSet = async (...args) => (steps.push("session.write"), cas(...args));
      let asked = false;
      t.messages.sendText = () => ((asked = true), new Promise(() => undefined));
      assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
      const before = [...steps];
      assert.equal(asked, false, "the SMS adapter runs only after the reply");
      await settle();
      assert.equal(asked, !refuse);
      return before;
    };
    assert.deepEqual(await trace(true), await trace(false));
  });

  it("writes send_failed to the ledger when the SMS adapter fails, and nothing reaches the caller", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    t.messages.sendText = async () => {
      throw new Error("sms down");
    };
    assert.deepEqual(await sendCode(t, callId), { sent: true });
    assert.deepEqual(await events(t, "verification.code_refused"), [{ reason: "send_failed" }]);
    assert.deepEqual(await events(t, "verification.code_sent"), []);
    // A session store that fails for the ledger write after the reply raises nothing unhandled.
    t.clock.advance(60_000);
    t.messages.sendText = async () => {
      t.sessions.get = async () => {
        throw new Error("session store down");
      };
      return { messageId: "m" };
    };
    assert.deepEqual(await sendCode(t, callId), { sent: true });
  });

  it("works in a flow whose verify step lists text_code", async () => {
    const t = codeSetup((c) => {
      c.flows = { code: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match", "text_code"], scopes: ["payment.request"] }] } };
    });
    const { callId } = await t.engine.startCall({ flow: "code" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await sendCode(t, callId);
    await t.engine.checkTextCode(callId, lastCode(t));
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 2, scopes: ["payment.request"] });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
  });
});

describe("the country allow-list in the policy", () => {
  it("is checked by validatePolicy", () => {
    const at = (countries: unknown) => validatePolicy({ ...defaultVerificationPolicy(), textCodeCountryCodes: countries });
    const shape = "textCodeCountryCodes must list assigned E.164 country calling codes (or longer prefixes of one), 1 to 6 digits without the +";
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
