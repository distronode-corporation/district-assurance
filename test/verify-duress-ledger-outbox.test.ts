// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The second hostile pass on #124 (VER-12 "flag until cleared"), kept as regressions: the ledger's
// event ids, the alert outbox and clearDuress. Each attack asserts the safe behaviour; Z12 pins the
// fail-closed behaviour Sean accepted for a clearing that races an alert's delivery.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, DuressAlert, DuressNotifier, StoredSession } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const WRONG = ["1357", "2468", "3579", "4680", "5791", "6802", "7913", "8024", "9135", "0246"];
const badge = (c: FlowConfig) => c.modules.badge!.settings as unknown as { factors: string[]; pin: PinSettings };
const cfg = (patch: (c: FlowConfig) => void = () => undefined) =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    badge(c).pin.duress = { refuseScopes: ["owner.command"] };
    patch(c);
  });
const tick = async (n = 10) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

/** A notifier that can be down, and keeps what it was told. */
class Notifier implements DuressNotifier {
  readonly told: DuressAlert[] = [];
  down = false;
  async notify(input: DuressAlert): Promise<void> {
    if (this.down) throw new Error("notifier 503");
    this.told.push({ ...input });
  }
}

/** A session store that can fail a read, a write, or list a call it no longer holds. */
class FaultySessions extends MemorySessionStore {
  failGet: string | null = null;
  failWrite: ((record: JsonValue) => boolean) | null = null;
  extraListed: string[] = [];
  override async get(workspaceId: string, callId: string): Promise<StoredSession | null> {
    if (this.failGet === callId) throw new Error("sessions get 503");
    return super.get(workspaceId, callId);
  }
  override async compareAndSet(workspaceId: string, callId: string, expectedVersion: number, record: JsonValue) {
    if (this.failWrite?.(record) === true) {
      this.failWrite = null;
      throw new Error("sessions write 503");
    }
    return super.compareAndSet(workspaceId, callId, expectedVersion, record);
  }
  override async listCallsOwingAlerts(workspaceId: string): Promise<string[]> {
    return [...this.extraListed, ...(await super.listCallsOwingAlerts(workspaceId))];
  }
}

function mk(options: { sessions?: MemorySessionStore; counters?: MemoryAttemptCounters; workspaceId?: string; config?: FlowConfig } = {}) {
  const n = new Notifier();
  const workspaceId = options.workspaceId ?? "ws_test";
  const t = createTestEngine({
    workspaceId,
    config: options.config ?? cfg(),
    adapters: {
      duressNotifier: n,
      ...(options.sessions === undefined ? {} : { sessions: options.sessions }),
      ...(options.counters === undefined ? {} : { counters: options.counters }),
    },
  });
  t.records.putSubject(workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return { t, n };
}

async function enrolled(options: Parameters<typeof mk>[0] = {}) {
  const r = mk(options);
  assert.deepEqual(await r.t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return r;
}

async function call(t: TestEngine, callId?: string): Promise<string> {
  const started = await t.engine.startCall(callId === undefined ? {} : { callId });
  await t.engine.beginVerification(started.callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return started.callId;
}

/** The ledger's event ids of one call, with the call id taken out: what a reader of an export sees. */
async function eventIds(t: TestEngine, callId: string): Promise<string[]> {
  return (await t.ledger.list())
    .filter((e) => e.callId === callId)
    .map((e) => {
      const [, , ...rest] = JSON.parse(e.eventId!) as [string, string, ...number[]];
      return `${e.event}@${rest.join(".")}`;
    });
}

describe("#124 slot 1: the ledger never shows a duress entry", () => {
  it("Z1 a duress call's ledger event ids equal a normal call's: the alert's acknowledgement is not counted", async () => {
    const run = async (pin: string) => {
      const { t, n } = await enrolled();
      const callId = await call(t, "call_x");
      await t.engine.submitPin(callId, pin);
      await tick();
      await t.engine.finishVerification(callId);
      await tick();
      await t.engine.endCall(callId);
      return { ids: await eventIds(t, callId), told: n.told.length };
    };
    const normal = await run(PIN);
    const duress = await run(DURESS);
    assert.equal(normal.told, 0);
    assert.equal(duress.told, 1);
    assert.deepEqual(duress.ids, normal.ids);
  });

  it("Z1b a flagged subject's pass on a later call leaves the same event ids as an unflagged one's", async () => {
    const run = async (flag: boolean) => {
      const { t } = await enrolled();
      if (flag) {
        await t.engine.submitPin(await call(t), DURESS);
        await tick();
      }
      const callId = await call(t, "call_y");
      await t.engine.submitPin(callId, PIN);
      await tick();
      await t.engine.finishVerification(callId);
      await tick();
      await t.engine.endCall(callId);
      return eventIds(t, callId);
    };
    assert.deepEqual(await run(true), await run(false));
  });

  it("Z1c event ids stay unique on a call whose alert is acknowledged between two writes", async () => {
    const { t } = await enrolled();
    const callId = await call(t);
    await t.engine.submitPin(callId, DURESS);
    await tick();
    await t.engine.submitPin(callId, DURESS);
    await tick();
    await t.engine.finishVerification(callId);
    await t.engine.endCall(callId);
    const entries = (await t.ledger.list()).filter((e) => e.callId === callId);
    // The ledger drops an append whose id it holds, so a reused id shows as a missing event.
    assert.deepEqual(
      entries.map((e) => e.event),
      ["call.started", "verification.started", "verification.factor", "verification.factor", "verification.finished", "grant.issued", "call.ended", "receipt.issued"],
    );
    const ids = entries.map((e) => e.eventId);
    assert.equal(new Set(ids).size, ids.length);
  });

  it("Z1d a call saved before writes were counted continues above every event id it used", async () => {
    const { t } = await enrolled();
    const callId = await call(t);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const { ledgerWrites: _dropped, ...before } = stored.record as { ledgerWrites?: number };
    const write = (id: string | undefined) => (JSON.parse(id!) as number[])[3]!;
    const used = (await t.ledger.list()).filter((e) => e.callId === callId).map((e) => write(e.eventId));
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, before as JsonValue)).ok, true);
    await t.engine.submitPin(callId, PIN);
    await t.engine.endCall(callId);
    const entries = (await t.ledger.list()).filter((e) => e.callId === callId);
    // The ledger drops an append whose id it holds, so a reused id shows as a missing event.
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "verification.started", "verification.factor", "call.ended", "receipt.issued"]);
    const ids = entries.map((e) => e.eventId);
    assert.equal(new Set(ids).size, ids.length);
    const writes = ids.map(write);
    assert.deepEqual(writes, [...writes].sort((a, b) => a - b), "ids only go up");
    assert.ok(writes[used.length]! > Math.max(...used), `the first write after the resume (${writes[used.length]}) is above every one it used (${used.join(",")})`);
  });
});

describe("#124 slot 1: the alert outbox", () => {
  it("Z2 sweepAlerts goes on past a listed call the store no longer holds, and reports it failed", async () => {
    const sessions = new FaultySessions();
    const { t, n } = await enrolled({ sessions });
    n.down = true;
    const callId = await call(t);
    await t.engine.submitPin(callId, DURESS);
    await tick();
    n.down = false;
    sessions.extraListed = ["call_gone"];
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [callId], failed: ["call_gone"] });
    assert.equal(n.told.length, 1);
  });

  it("Z3 sweepAlerts goes on past one call whose read fails, and reports it failed", async () => {
    const sessions = new FaultySessions();
    const { t, n } = await enrolled({ sessions });
    n.down = true;
    const first = await call(t);
    await t.engine.submitPin(first, DURESS);
    const second = await call(t);
    await t.engine.submitPin(second, DURESS);
    await tick();
    n.down = false;
    sessions.failGet = first;
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [second], failed: [first] });
    sessions.failGet = null;
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [first], failed: [] });
    assert.equal(n.told.length, 2);
  });

  it("Z4 the write that records a duress PIN entry fails: the subject is still flagged, so the next pass alerts", async () => {
    const sessions = new FaultySessions();
    const { t, n } = await enrolled({ sessions });
    const coerced = await call(t);
    sessions.failWrite = (record) => JSON.stringify(record).includes('"duressAlerts"');
    await assert.rejects(t.engine.submitPin(coerced, DURESS), /sessions write 503/);
    await tick();
    assert.equal(n.told.length, 0, "the entry itself could not be recorded");
    const later = await call(t);
    assert.equal((await t.engine.submitPin(later, PIN)).matched, true);
    assert.equal((await t.engine.finishVerification(later)).level, 1);
    await tick();
    assert.equal(n.told.length, 1, "the subject's next pass alerts");
    assert.equal(await t.engine.authorize(later, "owner.command"), false);
  });

  it("Z4b ...while a normal pass whose write fails flags nothing", async () => {
    const sessions = new FaultySessions();
    const { t, n } = await enrolled({ sessions });
    const first = await call(t);
    sessions.failWrite = (record) => JSON.stringify(record).includes('"passed":true');
    await assert.rejects(t.engine.submitPin(first, PIN), /sessions write 503/);
    const later = await call(t);
    assert.equal((await t.engine.submitPin(later, PIN)).matched, true);
    assert.equal((await t.engine.finishVerification(later)).level, 1);
    await tick();
    assert.equal(n.told.length, 0);
    assert.equal(await t.engine.authorize(later, "owner.command"), true);
  });

  it("Z5 two workspaces on one session store, same call ids: each sweep sends only its own, ids never collide", async () => {
    const sessions = new MemorySessionStore();
    const counters = new MemoryAttemptCounters();
    const a = await enrolled({ sessions, counters, workspaceId: "ws_a" });
    const b = await enrolled({ sessions, counters, workspaceId: "ws_b" });
    a.n.down = true;
    b.n.down = true;
    await a.t.engine.submitPin(await call(a.t, "call_1"), DURESS);
    await b.t.engine.submitPin(await call(b.t, "call_1"), DURESS);
    await tick();
    a.n.down = false;
    assert.deepEqual(await a.t.engine.sweepAlerts(), { sent: ["call_1"], failed: [] });
    assert.deepEqual(await sessions.listCallsOwingAlerts("ws_b"), ["call_1"], "b's alert is still owed");
    b.n.down = false;
    await b.t.engine.sweepAlerts();
    assert.notEqual(a.n.told[0]!.alertId, b.n.told[0]!.alertId);
    assert.deepEqual([a.n.told[0]!.workspaceId, b.n.told[0]!.workspaceId], ["ws_a", "ws_b"]);
  });

  it("Z6 two engines sweep one call at once: one alert id, acknowledged, nothing left owed", async () => {
    const one = await enrolled();
    const n2 = new Notifier();
    const two = createTestEngine({ config: cfg(), adapters: { duressNotifier: n2, sessions: one.t.sessions, records: one.t.records, ledger: one.t.ledger, counters: one.t.counters }, clock: one.t.clock });
    one.n.down = true;
    const callId = await call(one.t);
    await one.t.engine.submitPin(callId, DURESS);
    await tick();
    one.n.down = false;
    await Promise.all([one.t.engine.sweepAlerts(), two.engine.sweepAlerts()]);
    const ids = new Set([...one.n.told, ...n2.told].map((a) => a.alertId));
    assert.equal(ids.size, 1);
    assert.deepEqual(await one.t.sessions.listCallsOwingAlerts!("ws_test"), []);
  });

  it("Z7 an alert owed when the call ends is still sent after it, and never reaches the receipt", async () => {
    const { t, n } = await enrolled();
    n.down = true;
    const callId = await call(t);
    await t.engine.submitPin(callId, DURESS);
    await t.engine.finishVerification(callId);
    const receipt = await t.engine.endCall(callId);
    assert.ok(receipt !== null && typeof receipt === "object", "the call issues a receipt");
    await tick();
    n.down = false;
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [callId], failed: [] });
    assert.deepEqual(Object.keys(n.told[0]!).sort(), ["alertId", "at", "callId", "subjectKey", "workspaceId"]);
    assert.equal(JSON.stringify(n.told).includes(DURESS), false);
    assert.equal(JSON.stringify(receipt).includes("duress"), false);
  });

  it("Z8 a call id of another workspace is unknown to this engine's delivery", async () => {
    const sessions = new MemorySessionStore();
    const a = await enrolled({ sessions, workspaceId: "ws_a" });
    const b = await enrolled({ sessions, workspaceId: "ws_b" });
    a.n.down = true;
    await a.t.engine.submitPin(await call(a.t, "call_a"), DURESS);
    await tick();
    await assert.rejects(b.t.engine.deliverDuressAlerts("call_a"), rejects("unknown_call"));
    assert.equal(b.n.told.length, 0);
  });
});

describe("#124 slot 1: clearDuress", () => {
  it("Z9 the ledger entry is the same for a flagged and an unflagged subject: it never says which", async () => {
    const entry = async (flag: boolean) => {
      const { t } = await enrolled();
      if (flag) {
        await t.engine.submitPin(await call(t), DURESS);
        await tick();
      }
      await t.engine.clearDuress(OWNER, "member-7");
      const e = (await t.ledger.list()).find((x) => x.event === "duress.cleared")!;
      return { actor: e.actor, callId: e.callId, detail: e.detail };
    };
    assert.deepEqual(await entry(true), await entry(false));
  });

  it("Z10 prototype-shaped member ids are stored as plain values; surrogates, bidi and huge ids are refused", async () => {
    const { t } = await enrolled();
    for (const id of ["__proto__", "constructor"]) {
      await t.engine.clearDuress(OWNER, id);
      const last = (await t.ledger.list()).at(-1)!;
      assert.equal(Object.hasOwn(last.detail, "memberId") && last.detail.memberId, id);
    }
    for (const id of ["a\ud800", "a‮b", "x".repeat(65), "", 7 as unknown as string, null as unknown as string]) {
      await assert.rejects(t.engine.clearDuress(OWNER, id), rejects("invalid_input"));
    }
    await assert.rejects(t.engine.clearDuress("__proto__", "m"), rejects("invalid_input"));
  });

  it("Z11 clears the hidden lock of a factor that was off when the subject was cleared", async () => {
    const { t } = await enrolled({ config: cfg((c) => (c.modules.badge!.settings as unknown as { lockout: object }).lockout = { lockAfterFailures: 3 }) });
    const locked = cfg((c) => (c.modules.badge!.settings as unknown as { lockout: object }).lockout = { lockAfterFailures: 3 });
    // Two wrong guesses, a duress entry (which resets only the visible counter), one more wrong guess: hidden lock.
    for (const pin of [WRONG[0]!, WRONG[1]!, DURESS, WRONG[2]!]) {
      await t.engine.submitPin(await call(t), pin);
      await tick();
    }
    assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: false, locked: true });
    // The PIN is turned off while the business clears the subject, then on again.
    t.engine.configure(cfg((c) => {
      (c.modules.badge!.settings as unknown as { lockout: object }).lockout = { lockAfterFailures: 3 };
      badge(c).factors = badge(c).factors.filter((k) => k !== "pin");
      c.policy.levels[0]!.anyOf.pop();
    }));
    await t.engine.clearDuress(OWNER, "member-7");
    t.engine.configure(locked);
    assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: true, locked: false });
  });

  // Sean, 2026-11-19: accepted and documented. AttemptCounters has no compare-and-set, so a clearing
  // that lands between a delivery's read of the clearings and its write of the flag is undone: the
  // subject stays flagged (fail closed), and clearing again works.
  it("Z12 a clearing that lands during an alert's delivery holds (U7): the delivery takes its flag back", async () => {
    class Holding extends MemoryAttemptCounters {
      hold: { gate: Promise<void>; reached: () => void } | null = null;
      override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
        const got = await super.get(key, since);
        const hold = this.hold;
        if (hold !== null && key.factor === "duress.clears") {
          this.hold = null;
          hold.reached();
          await hold.gate;
        }
        return got;
      }
    }
    const counters = new Holding();
    const { t, n } = await enrolled({ counters });
    n.down = true;
    const coerced = await call(t);
    await t.engine.submitPin(coerced, DURESS);
    await tick();
    n.down = false;
    let release!: () => void;
    let reached!: () => void;
    const at = new Promise<void>((r) => (reached = r));
    counters.hold = { gate: new Promise<void>((r) => (release = r)), reached };
    const delivery = t.engine.deliverDuressAlerts(coerced);
    await at;
    await t.engine.clearDuress(OWNER, "member-7");
    release();
    assert.equal(await delivery, 1);
    const owner = await call(t);
    await t.engine.submitPin(owner, PIN);
    await t.engine.finishVerification(owner);
    assert.equal(await t.engine.authorize(owner, "owner.command"), true, "the first clearing holds");
  });
});
