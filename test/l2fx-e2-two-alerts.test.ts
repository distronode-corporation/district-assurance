// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// PR #130 review U4: a call that owes two duress alerts, whose first notify never settles, still
// gets its second attempted once `notifyTimeoutMs` passes; the first stays owed.
import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it, mock } from "node:test";

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
const soon = async <T>(p: Promise<T>) => Promise.race([p, tick().then(() => "pending" as const)]);
type Rec = { modules: { badge: { duressAlerts?: Array<{ alertId: string }> } } };

describe("l2fx-e2: two alerts on one call (U4)", () => {
  beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
  afterEach(() => mock.timers.reset());

  it("attempts the second alert after the first notify times out, and keeps only the first owed", async () => {
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
    const n: DuressNotifier = {
      notify: (a) => {
        told.push(a);
        return a.alertId === first ? new Promise<void>(() => undefined) : Promise.resolve();
      },
    };
    const restarted = createTestEngine({ config: t.engine.config, clock: t.clock, adapters: { duressNotifier: n, counters, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    const delivery = restarted.engine.deliverDuressAlerts(callId);
    await tick();
    assert.deepEqual(told.map((a) => a.alertId), [first], "the second waits for the first's bound");
    mock.timers.tick(30_000);
    assert.equal(await soon(delivery), 1, "the second was sent and acknowledged");
    assert.deepEqual(told.map((a) => a.alertId), [first, second]);
    assert.deepEqual(await owed(), [first], "the unanswered first stays owed");
    const sweep = restarted.engine.sweepAlerts();
    assert.equal(await soon(sweep), "pending", "a sweep tries the first again, under the same bound");
    mock.timers.tick(30_000);
    assert.deepEqual(await soon(sweep), { sent: [], failed: [callId] });
    assert.deepEqual(told.map((a) => a.alertId), [first, second, first]);
  });
});
