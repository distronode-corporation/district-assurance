// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix U7 (PR #130 review, round 3): a clearing that lands between a flag write's check of the
// clearings and the write itself is never undone, for the entry's own write and for its alert's.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { duressFlagKey } from "../src/verify/duress-flag.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const DURESS = "7391";
const flag = duressFlagKey("ws_test", OWNER);
const config = () =>
  testConfig((c: FlowConfig) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    (c.modules.badge!.settings as unknown as { pin: PinSettings }).pin.duress = { refuseScopes: [] };
  });
const tick = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

/** Runs `before` just ahead of the next flag write, and can fail the next flag writes. */
class Racing extends MemoryAttemptCounters {
  before: (() => Promise<void>) | null = null;
  fail = 0;
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    if (key.factor === flag.factor) {
      if (this.fail > 0) {
        this.fail--;
        throw new Error("counters 503");
      }
      const run = this.before;
      this.before = null;
      if (run !== null) await run();
    }
    return super.recordFailure(key, at, since);
  }
}

async function world(): Promise<{ t: TestEngine; counters: Racing; n: FakeDuressNotifier }> {
  const counters = new Racing();
  const n = new FakeDuressNotifier();
  const t = setup({ config: config(), adapters: { duressNotifier: n, counters } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return { t, counters, n };
}

async function call(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return callId;
}

/** Whether the owner's next pass is a duress entry: it alerts. */
async function stillUnderDuress(t: TestEngine, n: FakeDuressNotifier): Promise<boolean> {
  await tick();
  const before = n.told.length;
  const owner = await call(t);
  assert.equal((await t.engine.submitPin(owner, PIN)).matched, true);
  await t.engine.finishVerification(owner);
  await tick();
  return n.told.length > before;
}

describe("U7: a clearing between a flag write's check and the write", () => {
  it("the duress entry's own write: the subject stays cleared, and the entry's alert still goes out", async () => {
    const { t, counters, n } = await world();
    counters.before = () => t.engine.clearDuress(OWNER, "member-7");
    assert.equal((await t.engine.submitPin(await call(t), DURESS)).matched, true);
    await tick();
    assert.equal(n.told.length, 1, "the entry's alert");
    assert.deepEqual(await counters.get(flag, LONG_AGO), []);
    assert.equal(await stillUnderDuress(t, n), false);
  });

  it("the alert's delivery: it sets no flag over the clearing, and the alert still goes out", async () => {
    const { t, counters, n } = await world();
    // The entry's own write and the first delivery's both fail: the alert stays owed.
    counters.fail = 2;
    await assert.rejects(t.engine.submitPin(await call(t), DURESS), /counters 503/);
    await tick();
    assert.equal(n.told.length, 0, "still owed");
    counters.before = () => t.engine.clearDuress(OWNER, "member-7");
    const owing = (await t.sessions.listCallsOwingAlerts!("ws_test"))[0]!;
    assert.equal(await t.engine.deliverDuressAlerts(owing), 1, "the alert itself still goes out");
    assert.deepEqual(await counters.get(flag, LONG_AGO), []);
    assert.equal(await stillUnderDuress(t, n), false);
  });
});
