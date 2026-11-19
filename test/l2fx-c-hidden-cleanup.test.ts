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

  it("a cleanup whose claim was not saved runs, hidden counter included, before the call's next factor", async () => {
    const t = await duressEngine(duressConfig());
    await t.engine.submitPin(await pinCall(t), "1357");
    const hidden = hiddenCounterKey("ws_test", "pin", OWNER);
    const callId = await pinCall(t);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    let lose = true;
    t.sessions.compareAndSet = async (workspaceId, id, version, record) => {
      const owed = (record as unknown as { modules: { badge: { forgetOwed?: { claimed?: true } } } }).modules.badge.forgetOwed;
      if (lose && owed?.claimed === true) {
        lose = false;
        throw new Error("store blip");
      }
      return cas(workspaceId, id, version, record);
    };
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    assert.equal((await t.counters.get(hidden, LONG_AGO)).length, 2, "not claimed, so not run");
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.deepEqual(await t.counters.get(hidden, LONG_AGO), [], "run before the next factor");
  });

  it("a claimed cleanup whose hidden reset fails is not run again (at most once, fail closed)", async () => {
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
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await counters.get(hidden, LONG_AGO)).length, 2, "still counted until the window passes");
    assert.equal(((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { forgetOwed?: unknown } } }).modules.badge.forgetOwed, undefined, "and no longer owed");
  });
});
