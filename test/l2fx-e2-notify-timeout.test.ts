// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// PR #130 review T19 follow-up: a duress notify that does not settle within `notifyTimeoutMs` counts as
// failed, its alert stays owed, and a late answer changes nothing.
import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it, mock } from "node:test";

import type { DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { EngineError } from "../src/core/errors.ts";
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
  });
const tick = async (n = 20) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
/** The promise's value, or "pending" when it has not settled after a few turns of the event loop. */
const soon = async <T>(p: Promise<T>) => Promise.race([p, tick().then(() => "pending" as const)]);

/** A notifier held open per call until the test settles it; every other call is answered at once. */
class HeldNotifier implements DuressNotifier {
  readonly told: DuressAlert[] = [];
  readonly held = new Map<string, { resolve: () => void; reject: (e: Error) => void }>();
  hold = new Set<string>();
  notify(a: DuressAlert): Promise<void> {
    this.told.push({ ...a });
    if (!this.hold.has(a.callId)) return Promise.resolve();
    return new Promise<void>((resolve, reject) => this.held.set(a.callId, { resolve, reject }));
  }
}

/** Two calls that each owe a duress alert, saved while the notifier was down. */
async function owingCalls() {
  const counters = new MemoryAttemptCounters();
  const t = setup({ config: duressConfig(), adapters: { duressNotifier: { notify: () => Promise.reject(new Error("down")) }, counters } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  for (let i = 0; i < 2; i++) {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
  }
  await tick();
  const listed = await t.sessions.listCallsOwingAlerts!("ws_test");
  assert.equal(listed.length, 2);
  const restart = (n: DuressNotifier, notifyTimeoutMs?: number) =>
    createTestEngine({
      config: t.engine.config,
      clock: t.clock,
      ...(notifyTimeoutMs === undefined ? {} : { notifyTimeoutMs }),
      adapters: { duressNotifier: n, counters, sessions: t.sessions, records: t.records, ledger: t.ledger },
    }).engine;
  return { t, listed, restart, owing: () => t.sessions.listCallsOwingAlerts!("ws_test") };
}

describe("l2fx-e2: notifyTimeoutMs", () => {
  beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
  afterEach(() => mock.timers.reset());

  it("ends a sweep at 30 seconds by default, reporting the unanswered call failed and still owed, and the next sweep sends it", async () => {
    const { listed, restart, owing } = await owingCalls();
    const [stuck, other] = listed as [string, string];
    const n = new HeldNotifier();
    n.hold.add(stuck);
    const engine = restart(n);
    const sweep = engine.sweepAlerts();
    await tick();
    mock.timers.tick(29_999);
    assert.equal(await soon(sweep), "pending", "not before the default");
    mock.timers.tick(1);
    assert.deepEqual(await soon(sweep), { sent: [other], failed: [stuck] });
    assert.deepEqual(await owing(), [stuck], "still owed");
    // A late answer, either way, neither acknowledges the alert nor throws.
    n.held.get(stuck)!.resolve();
    await tick();
    assert.deepEqual(await owing(), [stuck], "a late resolve records nothing");
    n.hold.delete(stuck);
    assert.deepEqual(await soon(engine.sweepAlerts()), { sent: [stuck], failed: [] }, "the next sweep retries it");
    assert.deepEqual(await owing(), []);
    assert.deepEqual(
      n.told.map((a) => a.callId),
      [stuck, other, stuck],
    );
  });

  it("uses the host's notifyTimeoutMs, for deliverDuressAlerts too, and a late rejection is handled", async () => {
    const { listed, restart, owing } = await owingCalls();
    const [stuck] = listed as [string, string];
    const n = new HeldNotifier();
    n.hold.add(stuck);
    const engine = restart(n, 100);
    const delivery = engine.deliverDuressAlerts(stuck);
    await tick();
    mock.timers.tick(99);
    assert.equal(await soon(delivery), "pending");
    mock.timers.tick(1);
    assert.equal(await soon(delivery), 0, "timed out: nothing acknowledged");
    n.held.get(stuck)!.reject(new Error("late 503"));
    await tick();
    assert.equal((await owing()).includes(stuck), true);
  });

  it("refuses a notifyTimeoutMs that is not a whole number from 100 to 30000", () => {
    for (const notifyTimeoutMs of [99, 30_001, 150.5, Number.NaN, "1000" as unknown as number]) {
      assert.throws(
        () => createTestEngine({ notifyTimeoutMs }),
        (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /notifyTimeoutMs must be an integer from 100 to 30000/.test(e.message),
        String(notifyTimeoutMs),
      );
    }
    for (const notifyTimeoutMs of [100, 30_000]) createTestEngine({ notifyTimeoutMs });
  });
});
