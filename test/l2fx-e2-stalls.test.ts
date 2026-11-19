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
    await tick();
    assert.equal(told.length, 1, "the saved alert is sent while the ledger hangs");
    assert.equal(told[0]!.callId, callId);
  });

});
