// L2 fix T8 (PR #130 review): the hidden counter's cleanup is owed with a saved pass, like the
// visible counters', so a pass whose ledger entry fails still gets it, or the call's next factor does.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { hiddenCounterKey } from "../src/verify/duress-flag.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PIN, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const DURESS = "7391";

const badgeSettings = (c: FlowConfig) => c.modules.badge!.settings as unknown as { pin: PinSettings; factors: string[] };
const duressConfig = (more?: (c: FlowConfig) => void) =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    badgeSettings(c).pin.duress = { refuseScopes: [] };
    more?.(c);
  });

async function duressEngine(config: FlowConfig): Promise<TestEngine> {
  const t = setup({ config, adapters: { duressNotifier: new FakeDuressNotifier() } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return t;
}

async function pinCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return callId;
}

/** The ledger refuses the next `verification.factor` entry, after the pass was saved. */
function ledgerDownOnce(t: TestEngine): void {
  const append = t.ledger.append.bind(t.ledger);
  let down = 1;
  t.ledger.append = async (input) => {
    if (input.event === "verification.factor" && down > 0) {
      down--;
      throw new Error("ledger down");
    }
    return append(input);
  };
}

describe("T8: hidden-counter cleanup is owed with a saved pass", () => {
  it("a normal pass whose ledger entry fails still forgets the hidden failures", async () => {
    const t = await duressEngine(duressConfig());
    await t.engine.submitPin(await pinCall(t), "1357");
    const hidden = hiddenCounterKey("ws_test", "pin", OWNER);
    assert.equal((await t.counters.get(hidden, LONG_AGO)).length, 1);
    const callId = await pinCall(t);
    ledgerDownOnce(t);
    await assert.rejects(t.engine.submitPin(callId, PIN), /ledger down/);
    assert.equal((await t.engine.state(callId)).factors.at(-1)!.passed, true, "the pass was saved");
    assert.deepEqual(await t.counters.get(hidden, LONG_AGO), []);
  });

  it("a duress pass whose ledger entry fails takes off only its own hidden failure", async () => {
    const t = await duressEngine(duressConfig());
    await t.engine.submitPin(await pinCall(t), "1357");
    const hidden = hiddenCounterKey("ws_test", "pin", OWNER);
    const callId = await pinCall(t);
    ledgerDownOnce(t);
    await assert.rejects(t.engine.submitPin(callId, DURESS), /ledger down/);
    assert.equal((await t.counters.get(hidden, LONG_AGO)).length, 1, "the wrong guess stays hidden");
  });

  it("a hidden cleanup that failed is retried before the call's next factor", async () => {
    let fail = true;
    class Flaky extends MemoryAttemptCounters {
      override async reset(key: AttemptCounterKey): Promise<void> {
        if (fail && key.factor.startsWith("duress.hidden.")) {
          fail = false;
          throw new Error("counters down");
        }
        return super.reset(key);
      }
    }
    const counters = new Flaky();
    const t = setup({ config: duressConfig(), adapters: { duressNotifier: new FakeDuressNotifier(), counters } });
    await t.engine.enrolDuressPin(OWNER, DURESS);
    await t.engine.submitPin(await pinCall(t), "1357");
    const hidden = hiddenCounterKey("ws_test", "pin", OWNER);
    const callId = await pinCall(t);
    await assert.rejects(t.engine.submitPin(callId, PIN), /counters down/);
    assert.equal((await counters.get(hidden, LONG_AGO)).length, 2, "still counted");
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.deepEqual(await counters.get(hidden, LONG_AGO), [], "cleaned up before the next factor");
  });
});
