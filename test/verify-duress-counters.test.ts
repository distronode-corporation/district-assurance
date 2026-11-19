// VER-12 "flag until cleared", from the iMac's re-check of jr/wp-au ec8d4cc: a known duress PIN must
// not clear an attacker's wrong guesses at the real PIN, and a subject that entered a duress PIN
// stays under duress, on every call, until the business clears it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { duressClearedSubject } from "../src/verify/duress-flag.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const HOUR = 3_600_000;
const badge = (c: FlowConfig) => c.modules.badge!.settings as unknown as { pin: PinSettings };
const cfg = () =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.levels[1]!.anyOf.push(["pin", "carrier_identity_match"]);
    badge(c).pin.duress = { refuseScopes: [] };
  });
const WRONG = ["1357", "2468", "3579", "4680", "5791", "6802", "7913", "8024", "9135", "0246", "1470", "2581", "3692", "4703", "5814", "6925", "8147", "9258", "0369", "1593"];

async function mk(): Promise<{ t: TestEngine; n: FakeDuressNotifier }> {
  const n = new FakeDuressNotifier();
  const t = setup({ config: cfg(), adapters: { duressNotifier: n } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return { t, n };
}
const tick = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};
const duressOf = async (t: TestEngine, c: string) => ((await t.sessions.get("ws_test", c))!.record as { modules: { badge: { duress?: unknown } } }).modules.badge.duress;

/** A call for the owner's account, number withheld, past any wait from an earlier entry. */
async function call(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return callId;
}

/** Whether a call that passed is a duress call: alerted, and a money scope refused even at level 2. */
async function asDuress(t: TestEngine, n: FakeDuressNotifier, callId: string): Promise<{ alerted: boolean; refused: boolean }> {
  const before = n.told.length;
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  await tick();
  return { alerted: n.told.length > before && (await duressOf(t, callId)) !== undefined, refused: !(await t.engine.authorize(callId, "payment.request")) };
}

describe("duress and the counters across calls (flag until cleared)", () => {
  it("control: 10 wrong guesses across calls hard-lock the subject", async () => {
    const { t } = await mk();
    for (let i = 0; i < 12; i++) await t.engine.submitPin(await call(t), WRONG[i]!);
    assert.equal((await t.engine.submitPin(await call(t), PIN)).matched, false, "hard-locked");
  });

  it("2 wrong guesses and a duress entry per call, 10 calls: the hidden count locks, and the real PIN, once the lock ends, is a duress pass", async () => {
    const { t, n } = await mk();
    let judgedWrong = 0;
    let lockedAnswers = 0;
    for (let c = 0; c < 10; c++) {
      const callId = await call(t);
      for (let g = 0; g < 2; g++) {
        t.clock.advance(900_000);
        const r = await t.engine.submitPin(callId, WRONG[c * 2 + g]!);
        assert.equal(r.matched, false);
        if (r.locked) lockedAnswers++;
        else judgedWrong++;
      }
      t.clock.advance(900_000);
      await t.engine.submitPin(callId, DURESS);
    }
    assert.ok(judgedWrong <= 10, `at most 10 wrong guesses judged in the window, not 20 (${judgedWrong})`);
    assert.ok(lockedAnswers > 0, "the hidden count's hard lock applies");
    assert.equal((await t.engine.submitPin(await call(t), PIN)).matched, false, "the real PIN is refused while the lock holds");
    // Once the window has passed, the real PIN passes, as a duress pass: the subject is flagged.
    t.clock.advance(25 * HOUR);
    const callId = await call(t);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    assert.deepEqual(await asDuress(t, n, callId), { alerted: true, refused: true });
  });

  it("the same attack from one calling number: the number counter still locks", async () => {
    const { t } = await mk();
    const out: string[] = [];
    for (let c = 0; c < 6; c++) {
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
      for (let g = 0; g < 2; g++) {
        t.clock.advance(900_000);
        out.push(JSON.stringify(await t.engine.submitPin(callId, WRONG[c * 2 + g]!)));
      }
      t.clock.advance(900_000);
      out.push(JSON.stringify(await t.engine.submitPin(callId, DURESS)));
    }
    assert.ok(out.some((o) => o.includes('"locked":true')));
  });

  it("keeps every later pass on the subject a duress pass, the keypad's too, until the business clears it, with a ledger entry", async () => {
    const { t, n } = await mk();
    const first = await call(t);
    assert.equal((await t.engine.submitPin(first, DURESS)).matched, true);
    await tick();
    // A later call with the real PIN, and one by keypad: both duress.
    const byPin = await call(t);
    assert.deepEqual(await t.engine.submitPin(byPin, PIN), { matched: true, locked: false });
    assert.deepEqual(await asDuress(t, n, byPin), { alerted: true, refused: true });
    const byKeypad = await call(t);
    assert.equal((await t.engine.submitKeypad(byKeypad, { dob: DOB })).matched, true);
    assert.deepEqual(await asDuress(t, n, byKeypad), { alerted: true, refused: true });
    // Indistinguishable to the caller: the same answer and the same tag-free ledger as a normal pass.
    const pinTags = (await t.ledger.list()).filter((e) => e.event === "verification.factor" && e.detail.kind === "pin").map((e) => t.engine.readPinTag(e));
    assert.deepEqual(pinTags, ["duress", "duress"]);
    // The business clears it, with its member id in the ledger; then the real PIN is a normal pass.
    await assert.rejects(t.engine.clearDuress("not-hex", "member_1"), rejects("invalid_input", /subjectKey/));
    await assert.rejects(t.engine.clearDuress(OWNER, "bad member"), rejects("invalid_input", /memberId/));
    await t.engine.clearDuress(OWNER, "member_1");
    const cleared = (await t.ledger.list()).find((e) => e.event === "duress.cleared")!;
    assert.deepEqual([cleared.actor, cleared.callId, cleared.detail], ["member", null, { subject: duressClearedSubject(TEST_KNOWLEDGE_KEY, OWNER), memberId: "member_1" }]);
    const after = await call(t);
    assert.equal((await t.engine.submitPin(after, PIN)).matched, true);
    assert.deepEqual(await asDuress(t, n, after), { alerted: false, refused: false });
  });

  it("clears the hidden count with the flag, so the subject starts again from nothing", async () => {
    const { t } = await mk();
    for (let i = 0; i < 9; i++) await t.engine.submitPin(await call(t), WRONG[i]!);
    await t.engine.submitPin(await call(t), DURESS);
    await t.engine.clearDuress(OWNER, "member_1");
    assert.equal((await t.engine.submitPin(await call(t), WRONG[9]!)).locked, false, "the 10th wrong guess after the clearing does not lock");
  });
});
