// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// PR #130 review T5, T6, T19: a store, ledger or notifier that never answers holds up only its own work.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, AuditInput, DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine } from "../src/testing/index.ts";
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
const tick = async (n = 10) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
/** Resolves once `ms` of real time pass: the PIN check runs on the thread pool (ADR-29), so a few ticks are not enough to reach its answer. */
const after = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** Ticks until `done` holds, for at most `ms` of real time. */
const until = async (done: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!done() && Date.now() < end) await after(5);
};

/** A ledger whose appends never settle while `stalled`. */
class StalledLedger extends MemoryAuditLedger {
  stalled = false;
  override append(input: AuditInput) {
    return this.stalled ? new Promise<never>(() => undefined) : super.append(input);
  }
}

/** Counters whose notice bookkeeping never settles while `stalled`; the attempt counts still answer. */
class StalledNoticeCounters extends MemoryAttemptCounters {
  stalled = false;
  override recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    return this.stalled && key.factor.startsWith("notice:") ? new Promise<never>(() => undefined) : super.recordFailure(key, at, since);
  }
}

/** A duress notifier that never answers for `hangFor`, and keeps what it was told. */
class HangingNotifier implements DuressNotifier {
  readonly told: DuressAlert[] = [];
  hangFor = new Set<string>();
  notify(a: DuressAlert): Promise<void> {
    this.told.push({ ...a });
    return this.hangFor.has(a.callId) ? new Promise<never>(() => undefined) : Promise.resolve();
  }
}

describe("l2fx-e2: stalls stay local", () => {
  it("T5: a duress entry's alert goes out though its ledger append never settles", async () => {
    const ledger = new StalledLedger();
    const told: DuressAlert[] = [];
    const t = setup({ config: duressConfig(), adapters: { ledger, duressNotifier: { notify: async (a) => void told.push(a) } } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    ledger.stalled = true;
    void t.engine.submitPin(callId, DURESS);
    await until(() => told.length > 0);
    await tick();
    assert.equal(told.length, 1, "the saved alert is sent while the ledger hangs");
    assert.equal(told[0]!.callId, callId);
  });

  it("T6: a notice store that never answers does not hold up the call, its ledger entries or the outbox", async () => {
    const counters = new StalledNoticeCounters();
    const notifier = new FakeNotifier();
    const config = testConfig((c) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 1 }));
    const t = setup({ config, adapters: { notifier, counters } });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    counters.stalled = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stalled = new Promise<"stalled">((r) => (timer = setTimeout(() => r("stalled"), 5000)));
    const answered = await Promise.race([t.engine.submitPin(callId, "0000"), stalled]);
    clearTimeout(timer);
    assert.deepEqual(answered, { matched: false, locked: true });
    assert.ok((await t.ledger.list()).some((e) => e.event === "verification.locked"));
    assert.deepEqual(((await t.sessions.get("ws_test", callId))!.record as { outbox: unknown[] }).outbox, [], "the outbox cleared");
    assert.equal(notifier.notices.length, 0, "no notice without its claim");
    // The claim still comes before the notice: once the store answers, a lock is told once.
    counters.stalled = false;
    assert.deepEqual(await t.engine.submitPin(callId, "1111"), { matched: false, locked: true });
    await tick();
    assert.equal(notifier.notices.length, 1);
  });

  it("T19: a sweep sends a later call's alert while an earlier call's send never settles", async () => {
    const hold: DuressNotifier = { notify: () => Promise.reject(new Error("down")) };
    const counters = new MemoryAttemptCounters();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: hold, counters } });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    const owing: string[] = [];
    for (let i = 0; i < 2; i++) {
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitPin(callId, DURESS);
      owing.push(callId);
    }
    await tick();
    const listed = await t.sessions.listCallsOwingAlerts!("ws_test");
    assert.deepEqual([...listed].sort(), [...owing].sort(), "both calls owe an alert");
    const n = new HangingNotifier();
    n.hangFor.add(listed[0]!);
    const restarted = createTestEngine({ config: t.engine.config, clock: t.clock, adapters: { duressNotifier: n, counters, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    void restarted.engine.sweepAlerts();
    await tick(20);
    assert.deepEqual(n.told.map((a) => a.callId), listed, "the second call was attempted");
    assert.deepEqual(await t.sessions.listCallsOwingAlerts!("ws_test"), [listed[0]], "and its alert acknowledged");
  });
});
