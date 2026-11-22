// PIN passes (0.3.0): a PIN keyed on one engine call (an owner's sign-in) carried to another call of
// the same caller, once, within 5 minutes, as the PIN factor only. The texted or emailed code is
// still needed there, and the receipt and the ledger say the PIN was reused.
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { FakeDuressNotifier, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { PIN_PASS_MAX_SECONDS, badgeModule, type BadgeSlice } from "../src/verify/badge.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const DURESS = "7391";
const OTHER_ACCOUNT = "87654321";
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

type Badge = { factors: string[]; pin: PinSettings; syntheticVoice?: unknown };

/** The PIN, a texted code and keypad knowledge on; PIN reuse on; texted codes to +1 numbers, trusted without a carrier answer. */
function passConfig(patch: (c: FlowConfig, badge: Badge) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "text_code"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3, reuse: { maxAgeSeconds: 300 } },
        syntheticVoice: { acme: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.8 } },
      },
    };
    c.policy.textCodeCountryCodes = ["1"];
    c.policy.trustTextCodeWithoutCarrierCheck = true;
    patch(c, c.modules.badge.settings as unknown as Badge);
  });
}

function passSetup(options: TestEngineOptions = {}, duress = false): TestEngine {
  const t = createTestEngine({ config: passConfig(), ...options });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN, ...(duress ? { duressPin: DURESS } : {}) }));
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OTHER_ACCOUNT, phoneOnFile: "+15555550101", knowledge: { dob: DOB }, pin: PIN }));
  return t;
}

/** The sign-in call: the PIN keyed and passed, its pass issued. */
async function signIn(t: TestEngine, pin = PIN, callingNumber: string | null = CALLING): Promise<{ callId: string; token: string; expiresAt: string }> {
  const { callId } = await t.engine.startCall({});
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, ...(callingNumber === null ? {} : { callingNumber }) });
  assert.equal((await t.engine.submitPin(callId, pin)).matched, true);
  return { callId, ...(await t.engine.issuePinPass(callId)) };
}

/** The second call of the same phone call, verifying the same subject from the same number. */
async function second(t: TestEngine, account = ACCOUNT, callingNumber: string | null = CALLING): Promise<string> {
  const { callId } = await t.engine.startCall({});
  await t.engine.beginVerification(callId, { accountNumber: account, ...(callingNumber === null ? {} : { callingNumber }) });
  return callId;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

async function textCode(t: TestEngine, callId: string): Promise<void> {
  await t.engine.sendTextCode(callId);
  await settle();
  const code = /\d{6}/.exec(t.messages.sent.at(-1)!.body)![0];
  assert.equal((await t.engine.checkTextCode(callId, code)).matched, true);
}

async function refusals(t: TestEngine, callId: string): Promise<unknown[]> {
  return (await t.ledger.list()).filter((e) => e.callId === callId && e.event === "verification.pin_reuse_refused").map((e) => e.detail.reason);
}

async function badgeOf(t: TestEngine, callId: string): Promise<BadgeSlice> {
  return ((await t.sessions.get("ws_test", callId))!.record as unknown as CallRecord).modules.badge as unknown as BadgeSlice;
}

describe("PIN pass: settings", () => {
  it("is off unless pin.reuse is set, and maxAgeSeconds is 30 to 300", () => {
    const module = badgeModule();
    const at = (reuse: unknown) => module.validateSettings({ factors: ["pin"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3, reuse } });
    assert.equal(PIN_PASS_MAX_SECONDS, 300);
    assert.deepEqual(at(undefined), []);
    assert.deepEqual(at({ maxAgeSeconds: 30 }), []);
    assert.deepEqual(at({ maxAgeSeconds: 300 }), []);
    for (const bad of [29, 301, 60.5, "60", null]) assert.deepEqual(at({ maxAgeSeconds: bad }), ["pin.reuse.maxAgeSeconds must be an integer from 30 to 300"], String(bad));
    assert.deepEqual(at({ maxAgeSeconds: 60, factors: ["text_code"] }), ["pin.reuse.factors is not a PIN reuse setting"]);
    for (const bad of [true, 60, "on", []]) assert.deepEqual(at(bad), ["pin.reuse must be an object with maxAgeSeconds"], String(bad));
  });
});

describe("PIN pass: carried to another call", () => {
  it("counts as the PIN factor only: the texted code is still needed, and the receipt marks the PIN reused", async () => {
    const t = passSetup();
    const a = await signIn(t);
    assert.equal(a.expiresAt, "2026-01-01T00:05:00.000Z");
    assert.match(a.token, /^[A-Za-z0-9_-]{43}$/);
    await t.engine.endCall(a.callId);
    const b = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: true });
    assert.equal((await t.engine.finishVerification(b)).level, 0, "a PIN alone reaches no level here");
    await t.engine.beginVerification(b, { accountNumber: ACCOUNT });
    await textCode(t, b);
    assert.equal((await t.engine.finishVerification(b)).level, 2);
    const entries = await t.ledger.list();
    const factor = entries.find((e) => e.callId === b && e.event === "verification.factor" && e.detail.kind === "pin")!;
    const { tag, ...detail } = factor.detail;
    assert.deepEqual(detail, { kind: "pin", passed: true, reused: true, fromCallId: a.callId });
    assert.match(String(tag), /^[0-9a-f]{64}$/, "keyed like any PIN entry's");
    const finished = entries.filter((e) => e.callId === b && e.event === "verification.finished").at(-1)!;
    assert.deepEqual([finished.detail.methods, finished.detail.reused], [["pin", "text_code"], ["pin"]]);
    assert.deepEqual(entries.find((e) => e.callId === a.callId && e.event === "verification.pin_pass_issued")!.detail, { expiresAt: a.expiresAt });
    const receipt = (await t.engine.endCall(b))!;
    assert.deepEqual(receipt.body.verification.methods, ["pin", "text_code"]);
    assert.deepEqual(receipt.body.verification.reused, ["pin"]);
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
    const everything = JSON.stringify([entries, receipt, await t.sessions.get("ws_test", a.callId), await t.sessions.get("ws_test", b)]);
    assert.equal(everything.includes(a.token), false, "the token is stored and written nowhere");
  });

  it("leaves the marker off a receipt whose PIN was keyed, and off once the factors are dropped", async () => {
    const t = passSetup();
    const a = await signIn(t);
    await textCode(t, a.callId);
    await t.engine.finishVerification(a.callId);
    assert.equal((await t.engine.endCall(a.callId))!.body.verification.reused, undefined);
    const again = await signIn(t);
    const b = await second(t);
    await t.engine.reusePin(b, again.token);
    await t.engine.finishVerification(b);
    await t.engine.beginVerification(b, { accountNumber: OTHER_ACCOUNT, callingNumber: CALLING });
    assert.equal((await badgeOf(t, b)).pinReuse, undefined, "another subject: the reused PIN goes with the other factors");
  });

  it("is spent once: a second call gets nothing, the same call again gets the same answer and no second factor", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    const c = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: true });
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: true });
    assert.equal((await t.engine.state(b)).factors.filter((f) => f.kind === "pin").length, 1);
    assert.deepEqual(await t.engine.reusePin(c, a.token), { reused: false });
    assert.deepEqual(await refusals(t, c), ["used"]);
  });

  it("lets exactly one of two calls redeeming at once have it", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    const c = await second(t);
    const answers = await Promise.all([t.engine.reusePin(b, a.token), t.engine.reusePin(c, a.token)]);
    assert.deepEqual(answers.map((r) => r.reused).sort(), [false, true]);
  });

  it("makes the call a duress call when the PIN keyed was the duress PIN, and the caller cannot tell", async () => {
    const config = passConfig((_c, badge) => (badge.pin.duress = { refuseScopes: [] }));
    const t = passSetup({ config, adapters: { duressNotifier: new FakeDuressNotifier() } }, true);
    assert.deepEqual(await t.engine.enrolDuressPin(SUBJECT, DURESS), { enrolled: true });
    const a = await signIn(t, DURESS);
    const b = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: true });
    await textCode(t, b);
    assert.equal((await t.engine.finishVerification(b)).level, 2);
    assert.equal(await t.engine.authorize(b, "payment.request"), false, "money is refused, as on any duress call");
    assert.deepEqual((await badgeOf(t, b)).duress, { refuseScopes: [] });

    // On an engine whose config has the duress PIN off, every scope is refused (fail closed).
    const plain = createTestEngine({ config: passConfig(), ids: t.ids, adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records, counters: t.counters, codes: t.codes } });
    const a2 = await signIn(t, DURESS);
    const c = await second(plain);
    assert.deepEqual(await plain.engine.reusePin(c, a2.token), { reused: true });
    assert.deepEqual((await badgeOf(plain, c)).duress!.refuseScopes, Object.keys(plain.engine.config.policy.scopes));
  });
});

describe("PIN pass: refused", () => {
  it("after its life, or after this call's own shorter maxAgeSeconds", async () => {
    const t = passSetup();
    const a = await signIn(t);
    t.clock.advance(300_001);
    const b = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false });
    const short = passSetup({ config: passConfig((_c, badge) => (badge.pin.reuse = { maxAgeSeconds: 60 })) });
    const a2 = await signIn(short);
    short.clock.advance(60_001);
    const c = await second(short);
    assert.deepEqual(await short.engine.reusePin(c, a2.token), { reused: false });
    assert.deepEqual([await refusals(t, b), await refusals(short, c)], [["expired"], ["expired"]]);
  });

  it("for another subject, another calling number, or none where the sign-in had one", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const other = await second(t, OTHER_ACCOUNT);
    const elsewhere = await second(t, ACCOUNT, "+15555550188");
    const withheld = await second(t, ACCOUNT, null);
    for (const call of [other, elsewhere, withheld]) assert.deepEqual(await t.engine.reusePin(call, a.token), { reused: false });
    assert.deepEqual([await refusals(t, other), await refusals(t, elsewhere), await refusals(t, withheld)], [["subject"], ["number"], ["number"]]);
    // A refusal spends nothing: the call it was meant for still has it.
    assert.deepEqual(await t.engine.reusePin(await second(t), a.token), { reused: true });
    // Neither withheld is the same withheld number.
    const b = await signIn(t, PIN, null);
    assert.deepEqual(await t.engine.reusePin(await second(t, ACCOUNT, null), b.token), { reused: true });
  });

  it("for a token no call issued, one issued on this very call, or one whose call is gone", async () => {
    const t = passSetup();
    const b = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, randomBytes(32).toString("base64url")), { reused: false });
    const a = await signIn(t);
    await t.engine.finishVerification(a.callId);
    await t.engine.beginVerification(a.callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    assert.deepEqual(await t.engine.reusePin(a.callId, a.token), { reused: false });
    await t.engine.endCall(a.callId);
    await t.engine.removeCall(a.callId);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false });
    assert.deepEqual([await refusals(t, b), await refusals(t, a.callId)], [["unknown", "unknown"], ["same_call"]]);
  });

  it("for a sign-in call tainted since, or one a synthetic voice score held to level 1", async () => {
    const t = passSetup();
    const tainted = await signIn(t);
    await t.engine.markUntrusted(tainted.callId, "a webhook reply");
    const voiced = await signIn(t);
    await t.engine.reportSyntheticVoice(voiced.callId, { score: 0.9, vendor: "acme" });
    const quiet = await signIn(t);
    await t.engine.reportSyntheticVoice(quiet.callId, { score: 0.6, vendor: "acme" });
    const b = await second(t);
    for (const pass of [tainted, voiced]) assert.deepEqual(await t.engine.reusePin(b, pass.token), { reused: false });
    assert.deepEqual(await refusals(t, b), ["tainted", "voice"]);
    assert.deepEqual(await t.engine.reusePin(b, quiet.token), { reused: true }, "a band that only stops spoken answers leaves the PIN, which is keyed");
  });

  it("while the PIN is locked for the subject or the number, as a keyed PIN would be", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const wrong = await second(t);
    assert.equal((await t.engine.submitPin(wrong, "0000")).matched, false);
    const b = await second(t);
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false });
    assert.deepEqual(await refusals(t, b), ["locked"]);
    // With the duress PIN on, the hidden counter is asked too; it holds no lock here, and the wait passes.
    const d = passSetup({ config: passConfig((_c, badge) => (badge.pin.duress = { refuseScopes: [] })), adapters: { duressNotifier: new FakeDuressNotifier() } });
    const a2 = await signIn(d);
    assert.deepEqual(await d.engine.reusePin(await second(d), a2.token), { reused: true });
  });

  it("for a pass the issuing call no longer holds (a damaged record)", async () => {
    const t = passSetup();
    for (const damage of [(r: CallRecord) => delete (r.modules.badge as unknown as BadgeSlice).pinPass, (r: CallRecord) => delete r.modules.badge]) {
      const a = await signIn(t);
      const stored = (await t.sessions.get("ws_test", a.callId))!;
      const record = structuredClone(stored.record) as unknown as CallRecord;
      damage(record);
      await t.sessions.compareAndSet("ws_test", a.callId, stored.version, record as never);
      const b = await second(t);
      assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false });
      assert.deepEqual(await refusals(t, b), ["unknown"]);
    }
  });

  it("passes a store failure reading the issuing call to the host", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    const real = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (ws, id) => {
      if (id === a.callId) throw new Error("store down");
      return real(ws, id);
    };
    await assert.rejects(t.engine.reusePin(b, a.token), /store down/);
    t.sessions.get = real;
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: true }, "nothing was spent");
  });

  it("refuses a token that is not one, with reuse off, off the verification, or with the PIN off on the step", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    for (const bad of [undefined, 42, "", "x".repeat(42), "x".repeat(44), `${"x".repeat(42)}=`]) await assert.rejects(t.engine.reusePin(b, bad as never), rejects("invalid_input", /PIN pass token/), String(bad));
    const open = (await t.engine.startCall({})).callId;
    await assert.rejects(t.engine.reusePin(open, a.token), rejects("invalid_transition", /running verification/));
    const off = passSetup({ config: passConfig((_c, badge) => delete (badge.pin as { reuse?: unknown }).reuse) });
    const a2 = await signIn(off);
    await assert.rejects(off.engine.reusePin(await second(off), a2.token), rejects("precondition_failed", /PIN reuse is off/));
    const stepped = passSetup({
      config: passConfig((c) => (c.flows = { codes: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge", "text_code"] }] } })),
    });
    const a3 = await signIn(stepped);
    const { callId } = await stepped.engine.startCall({ flow: "codes" });
    await stepped.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    await assert.rejects(stepped.engine.reusePin(callId, a3.token), rejects("precondition_failed", /does not use the pin factor/));
  });

  it("refuses a reuse whose verification restarted while the pass was checked, and keeps the pass spent", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    const real = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (ws, id) => {
      // The issuing call is read once the call to reuse it was: restart that call then.
      if (id === a.callId) {
        t.sessions.get = real;
        await t.engine.finishVerification(b);
        await t.engine.beginVerification(b, { accountNumber: ACCOUNT, callingNumber: CALLING });
      }
      return real(ws, id);
    };
    await assert.rejects(t.engine.reusePin(b, a.token), rejects("precondition_failed", /verification restarted/));
    assert.deepEqual(await t.engine.reusePin(await second(t), a.token), { reused: false });
  });

  it("refuses a call Badge was off for when it started", async () => {
    const t = passSetup({ config: passConfig((c) => (c.modules.badge!.enabled = false)) });
    const { callId } = await t.engine.startCall({});
    t.engine.configure(passConfig());
    await assert.rejects(t.engine.reusePin(callId, "x".repeat(43)), rejects("module_disabled", /was off when this call started/));
  });
});

describe("PIN pass: calls saved before taints and voice bands were kept", () => {
  it("reads a count that is not there as none, and a band that is not there as clear", async () => {
    const t = passSetup();
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as CallRecord;
    delete (record.modules.badge as unknown as BadgeSlice).taints;
    delete record.state.syntheticVoice;
    await t.sessions.compareAndSet("ws_test", callId, stored.version, record as never);
    const { token } = await t.engine.issuePinPass(callId);
    assert.equal((await badgeOf(t, callId)).pinPass!.taints, 0);
    assert.deepEqual(await t.engine.reusePin(await second(t), token), { reused: true });
  });
});

describe("PIN pass: the issuing call changes while the pass is redeemed", () => {
  it("refuses a pass whose issuing call was tainted, or held to level 1, after the first read, and keeps it spent", async () => {
    for (const [what, change] of [
      ["tainted", (t: TestEngine, id: string) => t.engine.markUntrusted(id, "a webhook reply")],
      ["voice", (t: TestEngine, id: string) => t.engine.reportSyntheticVoice(id, { score: 0.9, vendor: "acme" })],
    ] as const) {
      const t = passSetup();
      const a = await signIn(t);
      const b = await second(t);
      // The taint lands on the issuing call while the spend is bound.
      const bind = t.sessions.bindRef.bind(t.sessions);
      t.sessions.bindRef = async (ws, ref, id) => {
        if (ref.startsWith("pin_pass_used:")) await change(t, a.callId);
        return bind(ws, ref, id);
      };
      assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false }, what);
      assert.deepEqual(await refusals(t, b), [what]);
      t.sessions.bindRef = bind;
      assert.deepEqual(await t.engine.reusePin(await second(t), a.token), { reused: false }, "spent");
    }
  });

  it("refuses a pass whose issuing call was removed, or lost its pass, after the first read", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    const bind = t.sessions.bindRef.bind(t.sessions);
    t.sessions.bindRef = async (ws, ref, id) => {
      if (ref.startsWith("pin_pass_used:")) {
        const stored = (await t.sessions.get(ws, a.callId))!;
        const record = structuredClone(stored.record) as unknown as CallRecord;
        delete (record.modules.badge as unknown as BadgeSlice).pinPass;
        await t.sessions.compareAndSet(ws, a.callId, stored.version, record as never);
      }
      return bind(ws, ref, id);
    };
    assert.deepEqual(await t.engine.reusePin(b, a.token), { reused: false });
    assert.deepEqual(await refusals(t, b), ["unknown"]);
  });

  it("issues nothing when the reference cannot be bound, so the host may ask again", async () => {
    const t = passSetup();
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
    await t.engine.submitPin(callId, PIN);
    const bind = t.sessions.bindRef.bind(t.sessions);
    t.sessions.bindRef = async () => {
      throw new Error("store down");
    };
    await assert.rejects(t.engine.issuePinPass(callId), /store down/);
    assert.equal((await badgeOf(t, callId)).pinPass, undefined);
    t.sessions.bindRef = bind;
    const { token } = await t.engine.issuePinPass(callId);
    assert.deepEqual(await t.engine.reusePin(await second(t), token), { reused: true });
  });
});

describe("PIN pass: issued", () => {
  it("only for a PIN that passed on this call within 5 minutes, once, on an open, untainted call", async () => {
    const t = passSetup();
    const none = await second(t);
    await assert.rejects(t.engine.issuePinPass(none), rejects("precondition_failed", /no PIN passed/));
    await t.engine.submitKeypad(none, { dob: DOB });
    await assert.rejects(t.engine.issuePinPass(none), rejects("precondition_failed", /no PIN passed/), "keypad knowledge is not a PIN");
    const failed = await second(t);
    await t.engine.submitPin(failed, "0000");
    await assert.rejects(t.engine.issuePinPass(failed), rejects("precondition_failed", /no PIN passed/));
    t.clock.advance(900_000);
    const a = await signIn(t);
    await assert.rejects(t.engine.issuePinPass(a.callId), rejects("precondition_failed", /issued its PIN pass already/));
    const late = await second(t);
    await t.engine.submitPin(late, PIN);
    t.clock.advance(300_000);
    await assert.rejects(t.engine.issuePinPass(late), rejects("precondition_failed", /more than 5 minutes ago/));
    const tainted = await second(t);
    await t.engine.submitPin(tainted, PIN);
    await t.engine.markUntrusted(tainted, "a document");
    await assert.rejects(t.engine.issuePinPass(tainted), rejects("precondition_failed", /untrusted content/));
    const ended = await second(t);
    await t.engine.submitPin(ended, PIN);
    await t.engine.endCall(ended);
    await assert.rejects(t.engine.issuePinPass(ended), rejects("invalid_transition", /has ended/));
  });

  it("never for a PIN this call reused, so a pass never outlives the PIN keyed", async () => {
    const t = passSetup();
    const a = await signIn(t);
    const b = await second(t);
    await t.engine.reusePin(b, a.token);
    await assert.rejects(t.engine.issuePinPass(b), rejects("precondition_failed", /reused from another call/));
  });
});
