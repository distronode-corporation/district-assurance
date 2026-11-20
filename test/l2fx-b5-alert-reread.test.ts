// PR #130 review V4: a send that waits on one alert reads the call again before each later alert,
// so an alert a concurrent send delivered and acknowledged meanwhile is not sent twice.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const badgeSettings = (c: FlowConfig) => c.modules.badge!.settings as unknown as { pin: PinSettings };
const duressConfig = () =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    badgeSettings(c).pin.duress = { refuseScopes: ["owner.command"] };
    badgeSettings(c).pin.maxAttemptsPerCall = 3;
  });
const tick = async (n = 20) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
type Rec = { modules: { badge: { duressAlerts?: Array<{ alertId: string }> } } };

describe("l2fx-b5: an alert delivered meanwhile is not sent again (V4)", () => {
  it("skips an alert another send acknowledged while this one waited", async () => {
    const counters = new MemoryAttemptCounters();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: { notify: () => Promise.reject(new Error("down")) }, counters } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await t.engine.submitPin(callId, DURESS);
    await tick();
    const owed = async () => ((await t.sessions.get("ws_test", callId))!.record as unknown as Rec).modules.badge.duressAlerts!.map((a) => a.alertId);
    const [first, second] = (await owed()) as [string, string];
    assert.ok(first !== undefined && second !== undefined, "two alerts owed");

    const told: DuressAlert[] = [];
    let answerFirst!: () => void;
    const n: DuressNotifier = {
      notify: (a) => {
        told.push(a);
        return a.alertId === first ? new Promise<void>((resolve) => (answerFirst = resolve)) : Promise.resolve();
      },
    };
    const restarted = createTestEngine({ config: t.engine.config, clock: t.clock, adapters: { duressNotifier: n, counters, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    const waiting = restarted.engine.deliverDuressAlerts(callId);
    await tick();
    assert.deepEqual(told.map((a) => a.alertId), [first]);
    // A second send leaves the first to the send that has it, and delivers the second.
    assert.equal(await restarted.engine.deliverDuressAlerts(callId), 1);
    assert.deepEqual(await owed(), [first]);
    answerFirst();
    assert.equal(await waiting, 1, "the waiting send delivers only the first");
    assert.deepEqual(told.map((a) => a.alertId), [first, second], "the second is sent once");
    assert.deepEqual(await owed(), []);
  });

  it("keeps an alert owed when the read before its send fails", async () => {
    const counters = new MemoryAttemptCounters();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: { notify: () => Promise.reject(new Error("down")) }, counters } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await tick();
    const owed = async () => ((await t.sessions.get("ws_test", callId))!.record as unknown as Rec).modules.badge.duressAlerts!.map((a) => a.alertId);
    const [only] = (await owed()) as [string];
    assert.ok(only !== undefined, "one alert owed");

    const told: DuressAlert[] = [];
    const sessions = t.sessions;
    let reads = 0;
    // The send's first read (the owed list) answers; the read again before the notifier fails.
    const get: typeof sessions.get = (...args) => (++reads === 2 ? Promise.reject(new Error("store down")) : sessions.get(...args));
    const flaky = new Proxy(sessions, {
      get: (target, name) => {
        if (name === "get") return get;
        const value: unknown = Reflect.get(target, name);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const restarted = createTestEngine({
      config: t.engine.config,
      clock: t.clock,
      adapters: { duressNotifier: { notify: (a) => (told.push(a), Promise.resolve()) }, counters, sessions: flaky, records: t.records, ledger: t.ledger },
    });
    assert.equal(await restarted.engine.deliverDuressAlerts(callId), 0);
    assert.deepEqual(told, [], "nothing was sent on a read that failed");
    assert.deepEqual(await owed(), [only], "still owed");
    assert.equal(await restarted.engine.deliverDuressAlerts(callId), 1, "the next send delivers it");
    assert.equal(told.length, 1);
  });
});
