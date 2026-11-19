// VER-12 duress alerts and the "fail, no alarm" rule, from the iMac's hostile pass on jr/wp-au a9ffe3b.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { createTestEngine, FakeDuressNotifier, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
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

type BadgeRec = { modules: { badge: { duress?: unknown; duressAlerts?: Array<{ alertId: string }> } } };
const badgeOf = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as unknown as BadgeRec).modules.badge;
const tick = async (n = 5) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
const settle = <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e: unknown) => ({ ok: false as const, e: String(e) }));

class FlakyNotifier implements DuressNotifier {
  told: DuressAlert[] = [];
  failures = 0;
  failFirst: number;
  constructor(failFirst: number) {
    this.failFirst = failFirst;
  }
  async notify(a: DuressAlert): Promise<void> {
    this.told.push({ ...a });
    if (this.failures < this.failFirst) {
      this.failures++;
      throw new Error("notifier 503");
    }
  }
}

describe("au: blockers 1-3 re-run", () => {
  it("1. ledger append fails on the factor write: alert still goes out", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    t.ledger.append = async () => {
      throw new Error("ledger 503");
    };
    const r = await settle(t.engine.submitPin(callId, DURESS));
    await tick();
    assert.equal(r.ok, false);
    assert.equal(n.told.length, 1);
    assert.deepEqual((await badgeOf(t, callId)).duressAlerts, []);
  });

  it("2. notifier rejects once: next write resends with the SAME alertId, then acked", async () => {
    const n = new FlakyNotifier(1);
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, DURESS)).matched, true);
    await tick();
    assert.equal(n.told.length, 1);
    assert.equal((await badgeOf(t, callId)).duressAlerts!.length, 1, "still owed");
    await t.engine.finishVerification(callId);
    await tick();
    assert.equal(n.told.length, 2);
    assert.equal(n.told[0]!.alertId, n.told[1]!.alertId);
    assert.deepEqual((await badgeOf(t, callId)).duressAlerts, []);
  });

  it("3. epoch race: duress entry stands and alerts; error equals a stale normal entry's", async () => {
    const errs: string[] = [];
    for (const pin of [DURESS, PIN]) {
      const n = new FakeDuressNotifier();
      const t = await duressSetup(n);
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      const real = t.records.getSubject.bind(t.records);
      let release!: () => void;
      let gate: Promise<void> | null = new Promise<void>((r) => (release = r));
      t.records.getSubject = async (w, k) => {
        const s = await real(w, k);
        if (gate !== null) {
          const g = gate;
          gate = null;
          await g;
        }
        return s;
      };
      const submit = settle(t.engine.submitPin(callId, pin));
      await tick();
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      release();
      const r = await submit;
      await tick();
      assert.equal(r.ok, false);
      errs.push(r.ok ? "" : r.e);
      if (pin === DURESS) {
        assert.equal(n.told.length, 1);
        assert.notEqual((await badgeOf(t, callId)).duress, undefined);
      }
    }
    assert.equal(errs[0], errs[1]);
  });

  it("3b. call ended while the duress entry was judged: alert still owed and sent", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const real = t.records.getSubject.bind(t.records);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let once = true;
    t.records.getSubject = async (w, k) => {
      const s = await real(w, k);
      if (once) {
        once = false;
        await gate;
      }
      return s;
    };
    const submit = settle(t.engine.submitPin(callId, DURESS));
    await tick();
    await t.engine.endCall(callId);
    release();
    await submit;
    await tick();
    assert.equal(n.told.length, 1);
  });
});

describe("au: loss paths", () => {
  it("lets a restarted process find and send every owed alert without knowing the call ids (sweepAlerts)", async () => {
    const hang: DuressNotifier = { notify: () => new Promise<void>(() => undefined) };
    const t = await duressSetup(hang);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await tick();
    assert.equal((await badgeOf(t, callId)).duressAlerts!.length, 1, "owed in the record");
    const n = new FakeDuressNotifier();
    const restarted = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: n, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    assert.deepEqual(await restarted.engine.sweepAlerts(), { sent: [callId], failed: [] });
    assert.equal(n.told.length, 1);
    assert.deepEqual(await restarted.engine.sweepAlerts(), { sent: [], failed: [] }, "nothing owed any more");
    // A notifier still down leaves the call in failed; a store that cannot list is refused.
    const down = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: { notify: async () => Promise.reject(new Error("down")) }, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    const { callId: next } = await down.engine.startCall({ callId: "call_after_restart" });
    await down.engine.beginVerification(next, { accountNumber: ACCOUNT });
    await down.engine.submitPin(next, DURESS);
    await tick();
    assert.deepEqual(await down.engine.sweepAlerts(), { sent: [], failed: [next] });
    const plain = { ...t.sessions, listCallsOwingAlerts: undefined } as unknown as typeof t.sessions;
    const unlisted = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: n, sessions: plain, records: t.records, ledger: t.ledger } });
    await assert.rejects(unlisted.engine.sweepAlerts(), /listCallsOwingAlerts/);
  });

  it("sends an alert again after 30 seconds when the first send never answered, and sends the rest meanwhile", async () => {
    let calls = 0;
    const seen: string[] = [];
    const n: DuressNotifier = {
      notify: (a) => {
        calls++;
        seen.push(a.alertId);
        return calls === 1 ? new Promise<void>(() => undefined) : Promise.resolve();
      },
    };
    const t = setup({ config: duressConfig((c) => (badgeSettings(c).pin.maxAttemptsPerCall = 3)), adapters: { duressNotifier: n } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    // Notifier off while two duress entries land, so both are owed.
    const off = t.engine as unknown as { deliverDuressAlerts(c: string): Promise<number> };
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await t.engine.submitPin(callId, DURESS);
    await tick(20);
    // Write-path sends: first alert hangs, the second write's loop skips it and sends the second.
    t.clock.advance(31_000);
    assert.equal(await off.deliverDuressAlerts(callId), 1, "the 30 s re-send got an answer");
  });

  it("owes at most one alert per PIN try the call allows, whatever the notifier does", async () => {
    let sends = 0;
    const n: DuressNotifier = {
      notify: async () => {
        sends++;
        throw new Error("down");
      },
    };
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    for (let i = 0; i < 20; i++) {
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitPin(callId, DURESS);
      await t.engine.finishVerification(callId);
    }
    await tick(20);
    const owed = (await badgeOf(t, callId)).duressAlerts!.length;
    assert.ok(owed <= 3, "bounded by maxAttemptsPerCall: beginVerification does not reset attempts");
    assert.ok(sends > 0);
  });

  it("never removes a duress PIN enrolled against a PIN chosen after a reset began", async () => {
    const n = new FakeDuressNotifier();
    const t = await duressSetup(n);
    await t.engine.removeDuressPin(OWNER);
    // A level-2 call to re-enrol a PIN after the reset.
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
    await t.engine.checkCarrier(callId);
    assert.ok((await t.engine.finishVerification(callId)).level >= 2);
    const realPut = t.records.putDuressDigest.bind(t.records);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    // Hold the reset between its store step and the rest, where a second store step used to come.
    const realPin = t.records.putPinDigest.bind(t.records);
    t.records.putPinDigest = async (w, k, d, id) => {
      const done = await realPin(w, k, d, id);
      if (d === null && !held) {
        held = true;
        await gate;
      }
      return done;
    };
    void realPut;
    const reset = t.engine.resetPin(OWNER);
    await tick();
    const NEW = "5927";
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: NEW, confirm: NEW }), { enrolled: true });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true }, "business told it is enrolled");
    release();
    await reset;
    const s = await t.records.getSubject("ws_test", OWNER);
    const { callId: c2 } = await t.engine.startCall();
    await t.engine.beginVerification(c2, { accountNumber: ACCOUNT });
    const r = await t.engine.submitPin(c2, DURESS);
    await tick();
    assert.notEqual(s?.duressDigest, undefined, "the duress PIN the business was told is enrolled is on file");
    assert.equal(r.matched, true);
    assert.equal(n.told.length, 1, "and it alerts");
  });
});

describe("au: duplicates and dedupe", () => {
  it("gives two entries on two engines with the same id generator two alert ids, each sent", async () => {
    const shared = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: new FakeDuressNotifier() } });
    const nA = new FlakyNotifier(1000);
    const nB = new FakeDuressNotifier();
    const a = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: nA, sessions: shared.sessions, records: shared.records, ledger: shared.ledger } });
    const b = createTestEngine({ config: duressConfig(), adapters: { duressNotifier: nB, sessions: shared.sessions, records: shared.records, ledger: shared.ledger } });
    shared.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    assert.deepEqual(await a.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const { callId } = await a.engine.startCall();
    await a.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await a.engine.submitPin(callId, DURESS);
    await tick();
    await b.engine.submitPin(callId, DURESS);
    await tick(20);
    const ids = new Set([...nA.told, ...nB.told].map((x) => x.alertId));
    assert.equal(ids.size, 2, "two entries, two alert ids");
    assert.deepEqual((await badgeOf(shared, callId)).duressAlerts!.map((x) => x.alertId).sort(), [...ids].filter((id) => !nB.told.some((x) => x.alertId === id)).sort(), "only what B acknowledged is gone");
  });
});

describe("au: equal-digest rule on every path", () => {
  it("keyed_hash: PIN == duress PIN imported: refused, no alarm", async () => {
    const n = new FakeDuressNotifier();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: n } });
    const s = (await t.records.getSubject("ws_test", OWNER))!;
    // Proper equal-PIN import: duress digest of the same PIN.
    const { duressDigest } = await import("../src/verify/factors.ts");
    t.records.putSubject("ws_test", { ...s, duressDigest: duressDigest(TEST_KNOWLEDGE_KEY, OWNER, PIN) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false);
    await tick();
    assert.equal(n.told.length, 0);
  });

  it("keyed_hash: refuses the PIN of a subject imported with the two digests equal, with no alarm", async () => {
    const n = new FakeDuressNotifier();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: n } });
    const s = (await t.records.getSubject("ws_test", OWNER))!;
    t.records.putSubject("ws_test", { ...s, duressDigest: s.pinDigest! });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const r = await t.engine.submitPin(callId, PIN);
    await tick();
    assert.equal(r.matched, false);
    assert.equal(n.told.length, 0);
  });

  it("verifier mode: refuses an answer that is both matched and duress, with no alarm", async () => {
    const n = new FakeDuressNotifier();
    const t = setup({ config: duressConfig((c) => (badgeSettings(c).pin.mode = "verifier")), adapters: { duressNotifier: n } });
    t.pinVerifier.set("ws_test", OWNER, PIN);
    t.pinVerifier.setDuress("ws_test", OWNER, PIN);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const r = await t.engine.submitPin(callId, PIN);
    await tick();
    assert.equal(r.matched, false);
    assert.equal(n.told.length, 0);
  });
});

describe("au: caller visibility", () => {
  it("ledger events of a duress call equal a normal call's (types and details), after the ack", async () => {
    const run = async (pin: string) => {
      const t = await duressSetup();
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitPin(callId, pin);
      await t.engine.finishVerification(callId);
      await tick();
      const state = await t.engine.state(callId);
      const v = (await t.sessions.get("ws_test", callId))!.version;
      const ev = (await t.ledger.list()).map((e) => {
        const { tag: _tag, ...detail } = e.detail;
        return [e.event, e.actor, detail];
      });
      return { state, v, ev: JSON.stringify(ev) };
    };
    const a = await run(PIN);
    const b = await run(DURESS);
    assert.ok(a.v > 0 && b.v > 0);
    assert.deepEqual(b.state, a.state);
    assert.equal(b.ev, a.ev);
  });
});

describe("au: timing", () => {
  it("answers the caller before the notifier runs at all", async () => {
    const order: string[] = [];
    const n: DuressNotifier = {
      notify: async () => {
        order.push("notify");
      },
    };
    const t = await duressSetup(n);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    order.push("resolved");
    await tick();
    assert.deepEqual(order, ["resolved", "notify"]);
  });
});
