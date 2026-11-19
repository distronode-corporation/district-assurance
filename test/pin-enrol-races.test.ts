// VER-6 enrolment races, from the iMac's hostile pass on wp-d ebc0190: each finishes with one
// pin.enrolled for the one enrolment that stored the PIN, credited to the call whose try stored it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { DOB, setup, testConfig } from "./helpers.ts";

const NEW_ACCOUNT = "20481937";
const NEW_PHONE = "+15555550142";
const SUBJ = subjectKeyFor(TEST_KNOWLEDGE_KEY, NEW_ACCOUNT);
const X = "5831";
const Y = "6094";
const pinSettings = (c: FlowConfig) => c.modules.badge!.settings as { pin: { maxAttemptsPerCall: number } };

function enrolSetup(max = 5): TestEngine {
  const t = setup({ config: testConfig((c) => (pinSettings(c).pin.maxAttemptsPerCall = max)) });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NEW_ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
  t.carrier.set(NEW_PHONE, { identityMatch: "match" });
  return t;
}
async function verified(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}
const enrolledEvents = async (t: TestEngine) => (await t.ledger.list()).filter((e) => e.event === "pin.enrolled").map((e) => e.callId);
const settle = <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e) }));
const tick = () => new Promise((r) => setImmediate(r));

describe("wp-d: same PIN on two calls", () => {
  it("refuses the loser's retry of the same PIN even when its take-back write failed", async () => {
    const t = enrolSetup();
    const a = await verified(t);
    const b = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    let armed = true;
    t.records.putPinDigest = async (w, k, d, id) => {
      if (armed) {
        armed = false;
        // A wins first, then B's take-back write fails.
        assert.deepEqual(await t.engine.enrolPin(a, { pin: X, confirm: X }), { enrolled: true });
        const ok = await put(w, k, d, id);
        t.sessions.compareAndSet = async () => {
          t.sessions.compareAndSet = cas;
          throw new Error("session store down");
        };
        return ok;
      }
      return put(w, k, d, id);
    };
    const r1 = await settle(t.engine.enrolPin(b, { pin: X, confirm: X }));
    assert.equal(r1.ok, false, "B lost, and its take-back write failed");
    const r2 = await settle(t.engine.enrolPin(b, { pin: X, confirm: X }));
    assert.equal(r2.ok, false, "B's retry is refused: the PIN on file is A's");
    assert.deepEqual(await enrolledEvents(t), [a], "one enrolment, one pin.enrolled, A's");
  });

  it("never lets a second try in flight on the losing call resume the winner's enrolment", async () => {
    const t = enrolSetup();
    const a = await verified(t);
    const b = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    let step = 0;
    let b2: Promise<unknown> | null = null;
    t.records.putPinDigest = async (w, k, d, id) => {
      if (step === 0) {
        step = 1;
        // B1 is about to store; A stores X first, then B2 starts and reads the subject while B1's entry is still pending.
        assert.deepEqual(await t.engine.enrolPin(a, { pin: X, confirm: X }), { enrolled: true });
        b2 = settle(t.engine.enrolPin(b, { pin: X, confirm: X }));
        // let B2 reach its getSubject and its final update
        for (let i = 0; i < 20; i++) await tick();
      }
      return put(w, k, d, id);
    };
    const b1 = await settle(t.engine.enrolPin(b, { pin: X, confirm: X }));
    const r2 = (await b2!) as { ok: boolean };
    assert.equal(b1.ok, false);
    assert.equal(r2.ok, false, "B's second try never resumes A's enrolment");
    assert.deepEqual(await enrolledEvents(t), [a], "one enrolment, one pin.enrolled, A's");
  });
});

describe("wp-d: last try", () => {
  it("store succeeds on the last try, session write fails: same PIN finishes, other PIN locked, one pin.enrolled", async () => {
    const t = enrolSetup(1);
    const c = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (w, k, d, id) => {
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(w, k, d, id);
    };
    assert.equal((await settle(t.engine.enrolPin(c, { pin: X, confirm: X }))).ok, false);
    t.records.putPinDigest = put;
    assert.deepEqual(await t.engine.enrolPin(c, { pin: Y, confirm: Y }), { enrolled: false, reason: "locked" });
    assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: "0000" }), { enrolled: false, reason: "mismatch" }, "unconfirmed retry: judged, not stored");
    assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: X }), { enrolled: true });
    assert.equal((await enrolledEvents(t)).length, 1);
    // Uncounted past the limit: try many more.
    for (let i = 0; i < 5; i++) assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: X }), { enrolled: false, reason: "locked" }, "nothing left to finish");
  });

  it("over the limit, an unconfirmed entry never finishes and never stores", async () => {
    const t = enrolSetup(1);
    const c = await verified(t);
    assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: Y }), { enrolled: false, reason: "mismatch" });
    assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: X }), { enrolled: false, reason: "locked" });
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinDigest, undefined);
  });
});

describe("wp-d: different PINs", () => {
  it("two calls enrol X and Y at once: exactly one stored, the loser's retry of its own PIN fails", async () => {
    const t = enrolSetup();
    const a = await verified(t);
    const b = await verified(t);
    const [ra, rb] = await Promise.all([settle(t.engine.enrolPin(a, { pin: X, confirm: X })), settle(t.engine.enrolPin(b, { pin: Y, confirm: Y }))]);
    const on = (await t.records.getSubject("ws_test", SUBJ))!.pinDigest;
    assert.ok(on === pinDigest(TEST_KNOWLEDGE_KEY, SUBJ, X) || on === pinDigest(TEST_KNOWLEDGE_KEY, SUBJ, Y));
    assert.equal([ra, rb].filter((r) => r.ok).length, 1);
    const loser = ra.ok ? b : a;
    const pin = ra.ok ? Y : X;
    assert.equal((await settle(t.engine.enrolPin(loser, { pin, confirm: pin }))).ok, false);
    assert.equal((await enrolledEvents(t)).length, 1);
  });

  it("same call, X and Y in flight: the stored PIN is the one that answered enrolled", async () => {
    const t = enrolSetup();
    const c = await verified(t);
    const [rx, ry] = await Promise.all([settle(t.engine.enrolPin(c, { pin: X, confirm: X })), settle(t.engine.enrolPin(c, { pin: Y, confirm: Y }))]);
    const on = (await t.records.getSubject("ws_test", SUBJ))!.pinDigest;
    const winner = on === pinDigest(TEST_KNOWLEDGE_KEY, SUBJ, X) ? rx : ry;
    assert.equal(winner.ok && (winner.v as { enrolled: boolean }).enrolled, true);
    assert.equal((await enrolledEvents(t)).length, 1);
  });

  it("never credits a later call's enrolment of the same PIN, after a reset, to a call whose write failed", async () => {
    const t = enrolSetup();
    const a = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (w, k, d, id) => {
      t.records.putPinDigest = put;
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(w, k, d, id);
    };
    assert.equal((await settle(t.engine.enrolPin(a, { pin: X, confirm: X }))).ok, false);
    await t.engine.resetPin(SUBJ);
    const b = await verified(t);
    assert.deepEqual(await t.engine.enrolPin(b, { pin: X, confirm: X }), { enrolled: true });
    const r = await settle(t.engine.enrolPin(a, { pin: X, confirm: X }));
    assert.equal(r.ok, false, "A's retry never takes B's enrolment for its own");
    assert.deepEqual(await enrolledEvents(t), [b]);
  });
});
