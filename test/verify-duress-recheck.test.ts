// VER-12 duress, from the iMac's re-check of jr/wp-au fb25a75: cases that held, kept as regressions.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { createTestEngine, FakeDuressNotifier, TEST_KNOWLEDGE_KEY, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
type Badge = { factors: string[]; pin: PinSettings };
const badgeSettings = (c: FlowConfig) => c.modules.badge!.settings as unknown as Badge;

function duressConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.levels[1]!.anyOf.push(["pin", "carrier_identity_match"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    badgeSettings(c).pin.duress = { refuseScopes: ["owner.command"] };
    patch(c);
  });
}

async function duressSetup(notifier: DuressNotifier = new FakeDuressNotifier()) {
  const t = setup({ config: duressConfig(), adapters: { duressNotifier: notifier } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return t;
}

const tick = async (n = 5) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
const settle = <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e) }));


describe("duress: the re-check of fb25a75", () => {
  it("reset lands between enrolDuressPin's read and its write: refused with conflict, nothing stored", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    await t.engine.removeDuressPin(OWNER);
    const realPut = t.records.putDuressDigest.bind(t.records);
    t.records.putDuressDigest = async (w, k, d, ifPin) => {
      await t.engine.resetPin(OWNER);
      return realPut(w, k, d, ifPin);
    };
    const r = await settle(t.engine.enrolDuressPin(OWNER, DURESS));
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.e, /conflict|PIN changed/);
    const s = await t.records.getSubject("ws_test", OWNER);
    assert.equal(s?.duressDigest, undefined);
    assert.equal(s?.pinDigest, undefined);
  });

  it("reset clears PIN, enrolment id and duress digest in one store call", async () => {
    const t = await duressSetup();
    const calls: string[] = [];
    const p = t.records.putPinDigest.bind(t.records);
    const d = t.records.putDuressDigest.bind(t.records);
    t.records.putPinDigest = async (...a) => (calls.push("pin:" + String(a[2])), p(...a));
    t.records.putDuressDigest = async (...a) => (calls.push("duress:" + String(a[2])), d(...a));
    await t.engine.resetPin(OWNER);
    assert.deepEqual(calls, ["pin:null"]);
    const s = (await t.records.getSubject("ws_test", OWNER))!;
    assert.deepEqual([s.pinDigest, s.pinEnrolmentId, s.duressDigest], [undefined, undefined, undefined]);
  });

  it("alertIds: two workspaces, same host callId, one shared notifier that drops repeats by alertId", async () => {
    const seen = new Set<string>();
    const delivered: DuressAlert[] = [];
    const dedupe: DuressNotifier = {
      async notify(a) {
        if (seen.has(a.alertId)) return; // the documented contract: drop repeats by alertId
        seen.add(a.alertId);
        delivered.push(a);
      },
    };
    const mk = async (workspaceId: string) => {
      const t = createTestEngine({ workspaceId, config: duressConfig(), adapters: { duressNotifier: dedupe } });
      t.records.putSubject(workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
      assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
      await t.engine.startCall({ callId: "call-1" });
      await t.engine.beginVerification("call-1", { accountNumber: ACCOUNT });
      assert.equal((await t.engine.submitPin("call-1", DURESS)).matched, true);
      await tick(10);
      return t;
    };
    await mk("ws_a");
    await mk("ws_b");
    assert.equal(delivered.length, 2, "both workspaces' duress alerts reach the business");
  });

  it("alertIds: crafted callIds cannot collide (JSON encoding), restart and re-verification never reuse n", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    for (const callId of ['a","1', "a", 'a",1,"']) {
      await t.engine.startCall({ callId });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitPin(callId, DURESS);
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitPin(callId, DURESS);
      await t.engine.finishVerification(callId);
    }
    // Restart: a fresh engine on the same stores, another entry on call "a".
    const fresh = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: n, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    await fresh.engine.beginVerification("a", { accountNumber: ACCOUNT });
    await fresh.engine.submitPin("a", DURESS);
    await tick(20);
    const ids = n.told.map((x) => x.alertId);
    assert.equal(ids.length, 7);
    assert.equal(new Set(ids).size, 7);
  });

  it("sweepAlerts on a store without listCallsOwingAlerts: refuses, not a silent no-op", async () => {
    const t = await duressSetup();
    const base = t.sessions;
    const bare = {
      create: base.create.bind(base),
      get: base.get.bind(base),
      compareAndSet: base.compareAndSet.bind(base),
      bindRef: base.bindRef.bind(base),
      resolveRef: base.resolveRef.bind(base),
    };
    const e = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: new FakeDuressNotifier(), sessions: bare, records: t.records } });
    const r = await settle(e.engine.sweepAlerts());
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.e, /listCallsOwingAlerts/);
  });

  it("verifier mode, duress only: alarm, and the caller's answer equals a normal pass", async () => {
    const n = new FakeDuressNotifier();
    const t = setup({ config: duressConfig((c) => (badgeSettings(c).pin.mode = "verifier")), adapters: { duressNotifier: n } });
    t.pinVerifier.set("ws_test", OWNER, PIN);
    t.pinVerifier.setDuress("ws_test", OWNER, DURESS);
    const { callId: c1 } = await t.engine.startCall();
    await t.engine.beginVerification(c1, { accountNumber: ACCOUNT });
    const pass = await t.engine.submitPin(c1, PIN);
    assert.deepEqual(pass, { matched: true, locked: false }, "the normal PIN matches: the control is a real pass");
    const { callId: c2 } = await t.engine.startCall();
    await t.engine.beginVerification(c2, { accountNumber: ACCOUNT });
    const dur = await t.engine.submitPin(c2, DURESS);
    await tick(10);
    assert.deepEqual(dur, pass);
    assert.equal(n.told.length, 1);
    const f1 = await t.engine.finishVerification(c1);
    const f2 = await t.engine.finishVerification(c2);
    assert.equal(f1.level, 1, "the normal pass reaches level 1");
    assert.deepEqual(f2, f1, "finishVerification looks the same");
  });

  it("every duress entry alerts: three entries on one call, three alerts, none suppressed", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    for (let i = 0; i < 3; i++) {
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await settle(t.engine.submitPin(callId, DURESS));
      await settle(t.engine.finishVerification(callId));
    }
    await tick(20);
    assert.equal(new Set(n.told.map((a) => a.alertId)).size, 3);
  });
});
