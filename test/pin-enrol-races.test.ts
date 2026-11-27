// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// VER-6 enrolment races and enrolment ids, from the iMac's hostile passes on wp-d ebc0190 and d62c9c6:
// each finishes with one pin.enrolled for the one enrolment that stored the PIN, credited to the
// call whose try stored it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { DOB, pinOnFile, setup, testConfig } from "./helpers.ts";

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
/** Resolves with `p`, or rejects once `ms` pass, so a missed checkpoint fails the test instead of hanging it. */
function within<T>(p: Promise<T>, label: string, ms = 2000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error(`${label}: not reached in ${ms} ms`)), ms)));
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}
const enrolled = (r: Awaited<ReturnType<typeof settle>>) => r.ok && (r.v as { enrolled: boolean }).enrolled === true;

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
    const get = t.records.getSubject.bind(t.records);
    let step = 0;
    let b2: Promise<unknown> | null = null;
    let b2Started = false;
    let b2Read!: () => void;
    const b2Reached = new Promise<void>((r) => (b2Read = r));
    t.records.getSubject = async (w, k) => {
      const subject = await get(w, k);
      if (b2Started) b2Read();
      return subject;
    };
    t.records.putPinDigest = async (w, k, d, id) => {
      if (step === 0) {
        step = 1;
        // B1 is about to store; A stores X first, then B2 starts and reads the subject while B1's entry is still pending.
        assert.deepEqual(await t.engine.enrolPin(a, { pin: X, confirm: X }), { enrolled: true });
        b2Started = true;
        b2 = settle(t.engine.enrolPin(b, { pin: X, confirm: X }));
        await within(b2Reached, "B2's subject read while B1 is pending");
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
    for (let i = 0; i < 5; i++) assert.deepEqual(await t.engine.enrolPin(c, { pin: X, confirm: X }), { enrolled: false, reason: "locked" });
    assert.deepEqual(await enrolledEvents(t), [c], "still the one pin.enrolled");
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
    assert.equal([ra, rb].filter(enrolled).length, 1, "exactly one answered enrolled");
    const [winner, loser, pin] = enrolled(ra) ? [a, b, Y] : [b, a, X];
    const on = (await t.records.getSubject("ws_test", SUBJ))!.pinDigest;
    assert.ok(await pinOnFile(on, SUBJ, winner === a ? X : Y), "the stored PIN is the winner's");
    assert.deepEqual(await enrolledEvents(t), [winner], "the one pin.enrolled is the winner's");
    assert.equal((await settle(t.engine.enrolPin(loser, { pin, confirm: pin }))).ok, false);
    assert.deepEqual(await enrolledEvents(t), [winner]);
  });

  it("same call, X and Y in flight: the stored PIN is the one that answered enrolled", async () => {
    const t = enrolSetup();
    const c = await verified(t);
    const [rx, ry] = await Promise.all([settle(t.engine.enrolPin(c, { pin: X, confirm: X })), settle(t.engine.enrolPin(c, { pin: Y, confirm: Y }))]);
    const on = (await t.records.getSubject("ws_test", SUBJ))!.pinDigest;
    const [dx, dy] = [await pinOnFile(on, SUBJ, X), await pinOnFile(on, SUBJ, Y)];
    assert.ok(dx !== dy, "one of the two PINs is stored");
    const [winner, other] = dx ? [rx, ry] : [ry, rx];
    assert.equal(enrolled(winner), true, "the stored PIN's try answered enrolled");
    assert.equal(enrolled(other), false, "the other PIN's try did not");
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
    const ev = await enrolledEvents(t);
    assert.equal(r.ok, false, "A's retry refused");
    assert.deepEqual(ev, [b]);
  });
});

describe("re-check d62c9c6: ids", () => {
  const failSessionAfterPut = (t: TestEngine, once = true) => {
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (w, k, d, id) => {
      if (once) t.records.putPinDigest = put;
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(w, k, d, id);
    };
    return put;
  };

  it("stale id after reset: A's dangling A:1 never resumes A's own re-enrolment or a later one", async () => {
    const t = enrolSetup();
    const a = await verified(t);
    failSessionAfterPut(t);
    assert.equal((await settle(t.engine.enrolPin(a, { pin: X, confirm: X }))).ok, false);
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinEnrolmentId, `${a}:1`);
    await t.engine.resetPin(SUBJ);
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinEnrolmentId, undefined, "reset clears the id");
    assert.deepEqual(await t.engine.enrolPin(a, { pin: X, confirm: X }), { enrolled: true });
    assert.equal((await t.records.getSubject("ws_test", SUBJ))!.pinEnrolmentId, `${a}:2`);
    const again = await settle(t.engine.enrolPin(a, { pin: X, confirm: X }));
    assert.equal(again.ok, false, "a retry after it was recorded is refused");
    assert.deepEqual(await enrolledEvents(t), [a]);
  });

  it("crafted callIds 'a' and 'a:1' (and '1:2'-style) never share an id", async () => {
    const t = enrolSetup(5);
    const ids: string[] = [];
    for (const callId of ["a", "a:1", "a:1:1", "1", "1:1"]) {
      const { callId: c } = await t.engine.startCall({ callId });
      await t.engine.beginVerification(c, { accountNumber: NEW_ACCOUNT });
      await t.engine.submitKeypad(c, { dob: DOB });
      await t.engine.checkCarrier(c);
      await t.engine.finishVerification(c);
      for (let i = 1; i <= 5; i++) ids.push(`${c}:${i}`);
    }
    assert.equal(new Set(ids).size, ids.length, "callId:try is injective (try is an integer)");
    // Cross-call: 'a:1' stores X (session write fails), reset not done; 'a' with all its tries can never resume it.
    failSessionAfterPut(t);
    assert.equal((await settle(t.engine.enrolPin("a:1", { pin: X, confirm: X }))).ok, false);
    const tries = [];
    for (let i = 0; i < 6; i++) tries.push(await settle(t.engine.enrolPin("a", { pin: X, confirm: X })));
    assert.ok(tries.every((r) => !r.ok || (r.v as { enrolled: boolean }).enrolled === false));
    assert.deepEqual(await enrolledEvents(t), []);
    assert.deepEqual(await t.engine.enrolPin("a:1", { pin: X, confirm: X }), { enrolled: true });
    assert.deepEqual(await enrolledEvents(t), ["a:1"]);
  });

  it("never lets a reused call id, on a fresh session store, take an old enrolment for its own", async () => {
    const t1 = enrolSetup();
    const { callId } = await t1.engine.startCall({ callId: "dup" });
    await t1.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
    await t1.engine.submitKeypad(callId, { dob: DOB });
    await t1.engine.checkCarrier(callId);
    await t1.engine.finishVerification(callId);
    failSessionAfterPut(t1);
    const old = await settle(t1.engine.enrolPin("dup", { pin: X, confirm: X }));
    assert.equal(old.ok, false);
    assert.match(old.ok ? "" : old.e, /session store down/, "old 'dup' stored X, then its session write failed");
    const onFile = (await t1.records.getSubject("ws_test", SUBJ))!;
    assert.ok(await pinOnFile(onFile.pinDigest, SUBJ, X), "X is on file");
    assert.equal(onFile.pinEnrolmentId, "dup:1", "under the old call's id");
    // New call with the same id, against the same records (the old session expired, or another store).
    const t2 = setup({ config: testConfig(), adapters: { records: t1.records } });
    t2.carrier.set(NEW_PHONE, { identityMatch: "match" });
    await t2.engine.startCall({ callId: "dup" });
    await t2.engine.beginVerification("dup", { accountNumber: NEW_ACCOUNT });
    await t2.engine.submitKeypad("dup", { dob: DOB });
    await t2.engine.checkCarrier("dup");
    assert.equal((await t2.engine.finishVerification("dup")).level, 2, "the new call reached level 2");
    // Its try 1 is refused at the guard (PIN on file), so no pending entry is ever added: no resume.
    const r1 = await settle(t2.engine.enrolPin("dup", { pin: X, confirm: X }));
    const r2 = await settle(t2.engine.enrolPin("dup", { pin: X, confirm: X }));
    for (const r of [r1, r2]) assert.match(r.ok ? "" : r.e, /a PIN is on file/);
    assert.equal((await t2.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 0);
  });
});

describe("re-check d62c9c6: same call, same PIN", () => {
  it("three tries of X at once on one call: one stored, one pin.enrolled", async () => {
    const t = enrolSetup();
    const c = await verified(t);
    const rs = await Promise.all([1, 2, 3].map(() => settle(t.engine.enrolPin(c, { pin: X, confirm: X }))));
    assert.ok(rs.some((x) => x.ok && (x.v as { enrolled: boolean }).enrolled), "one of them enrolled");
    assert.deepEqual(await enrolledEvents(t), [c]);
    const later = await settle(t.engine.enrolPin(c, { pin: X, confirm: X }));
    assert.equal(later.ok && (later.v as { enrolled: boolean }).enrolled, false);
    assert.deepEqual(await enrolledEvents(t), [c]);
  });
});
