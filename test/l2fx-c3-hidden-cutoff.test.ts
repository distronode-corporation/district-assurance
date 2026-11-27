// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix U6 (PR #130 review, round 3): a pass not under duress takes off the hidden failures up to
// it, never a later one, and the hidden cleanup costs the same round trips whichever pass it is.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { hiddenCounterKey } from "../src/verify/duress-flag.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const DURESS = "7391";
const hidden = hiddenCounterKey("ws_test", "pin", OWNER);
const config = () =>
  testConfig((c: FlowConfig) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    (c.modules.badge!.settings as unknown as { pin: PinSettings }).pin.duress = { refuseScopes: [] };
  });

/** Records `later` on the hidden counter as the pass's cleanup starts, as another call would. */
class Interleave extends MemoryAttemptCounters {
  later: string | null = null;
  ops: string[] = [];
  override async removeFailure(key: AttemptCounterKey, at: string): Promise<void> {
    const later = this.later;
    if (later !== null && key.factor === "pin" && key.scope === "subject") {
      this.later = null;
      await super.recordFailure(hidden, later, LONG_AGO);
    }
    if (key.factor.startsWith("duress.hidden.")) this.ops.push("write");
    return super.removeFailure(key, at);
  }
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    if (key.factor.startsWith("duress.hidden.")) this.ops.push("read");
    return super.get(key, since);
  }
  override async reset(key: AttemptCounterKey): Promise<void> {
    if (key.factor.startsWith("duress.hidden.")) this.ops.push("write");
    return super.reset(key);
  }
}

async function world(): Promise<{ t: TestEngine; counters: Interleave }> {
  const counters = new Interleave();
  const t = setup({ config: config(), adapters: { duressNotifier: new FakeDuressNotifier(), counters } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return { t, counters };
}

async function call(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return callId;
}

describe("U6: the hidden counter after a pass not under duress", () => {
  it("keeps a hidden failure another call records after the pass", async () => {
    const { t, counters } = await world();
    await t.engine.submitPin(await call(t), "1357");
    const callId = await call(t);
    const later = new Date(t.clock.now().getTime() + 1_000).toISOString();
    counters.later = later;
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.deepEqual(await counters.get(hidden, LONG_AGO), [later], "the earlier wrong guess and the pass's own are gone, the later one stays");
  });

  it("a duress entry and a pass not under duress make the same hidden round trips", async () => {
    const trips = async (pin: string) => {
      const { t, counters } = await world();
      const callId = await call(t);
      counters.ops.length = 0;
      assert.equal((await t.engine.submitPin(callId, pin)).matched, true);
      return counters.ops.join(",");
    };
    assert.equal(await trips(DURESS), await trips(PIN));
  });
});
