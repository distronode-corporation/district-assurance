// PR #130 review (CodeRabbit on 07e50ea): a duress alert send owns its claim by token, so a send
// that resumes after another took its alert over neither notifies nor clears the newer claim; and
// the counter preflight before the notify is bounded by `notifyTimeoutMs`, so a read that never
// settles leaves that alert owed, unsent, and the next alert is still tried.
import { strict as assert } from "node:assert";
import { afterEach, beforeEach, describe, it, mock } from "node:test";

import type { AttemptCounters, DuressAlert, DuressNotifier } from "../src/core/adapters.ts";
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

/** Counters whose next `get` is held until the test releases it (or forever), once armed. */
class HeldCounters implements AttemptCounters {
  armed = false;
  release: (() => void) | null = null;
  readonly inner: MemoryAttemptCounters;
  constructor(inner: MemoryAttemptCounters) {
    this.inner = inner;
  }
  async get(...args: Parameters<AttemptCounters["get"]>): Promise<string[]> {
    if (this.armed) {
      this.armed = false;
      await new Promise<void>((resolve) => (this.release = resolve));
    }
    return this.inner.get(...args);
  }
  recordFailure(...args: Parameters<AttemptCounters["recordFailure"]>) {
    return this.inner.recordFailure(...args);
  }
  removeFailure(...args: Parameters<AttemptCounters["removeFailure"]>) {
    return this.inner.removeFailure(...args);
  }
  reset(...args: Parameters<AttemptCounters["reset"]>) {
    return this.inner.reset(...args);
  }
}

/** A call owing `alerts` duress alerts, saved while the notifier was down, and an engine restarted on the same stores. */
async function owing(alerts: number, notifier: DuressNotifier) {
  const counters = new MemoryAttemptCounters();
  const t = setup({ config: duressConfig(), adapters: { duressNotifier: { notify: () => Promise.reject(new Error("down")) }, counters } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  for (let i = 0; i < alerts; i++) await t.engine.submitPin(callId, DURESS);
  await tick();
  const owed = async () => ((await t.sessions.get("ws_test", callId))!.record as unknown as Rec).modules.badge.duressAlerts!.map((a) => a.alertId);
  assert.equal((await owed()).length, alerts);
  const held = new HeldCounters(counters);
  const engine = createTestEngine({ config: t.engine.config, clock: t.clock, adapters: { duressNotifier: notifier, counters: held, sessions: t.sessions, records: t.records, ledger: t.ledger } }).engine;
  return { t, callId, owed, held, engine };
}

describe("l2fx-f: duress alert claims and the bounded preflight", () => {
  it("a send that resumes after another took its alert over does not notify, and leaves the newer claim alone", async () => {
    const told: DuressAlert[] = [];
    let answer: (() => void) | null = null;
    const n: DuressNotifier = {
      notify: (a) => {
        told.push(a);
        return new Promise<void>((resolve) => (answer = resolve));
      },
    };
    const { t, callId, owed, held, engine } = await owing(1, n);
    // A: its counter preflight is held.
    held.armed = true;
    const a = engine.deliverDuressAlerts(callId);
    await tick();
    assert.ok(held.release !== null, "A is in its preflight");
    // A's claim goes stale; B takes the alert over and is held in its notify.
    t.clock.advance(30_000);
    const b = engine.deliverDuressAlerts(callId);
    await tick();
    assert.equal(told.length, 1, "B notified");
    // A resumes: the alert is B's now.
    held.release!();
    assert.equal(await soon(a), 0, "A delivered nothing");
    assert.equal(told.length, 1, "A did not notify");
    // B still holds its claim: a third send leaves the alert to it.
    assert.equal(await soon(engine.deliverDuressAlerts(callId)), 0);
    assert.equal(told.length, 1, "no overlapping send");
    answer!();
    assert.equal(await b, 1);
    assert.deepEqual(await owed(), []);
  });

  describe("under mocked timers", () => {
    beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
    afterEach(() => mock.timers.reset());

    it("leaves an alert owed and unsent when its preflight does not answer in notifyTimeoutMs, and sends the next one", async () => {
      const told: DuressAlert[] = [];
      const n: DuressNotifier = {
        notify: (a) => {
          told.push(a);
          return Promise.resolve();
        },
      };
      const { callId, owed, held, engine } = await owing(2, n);
      const [first, second] = (await owed()) as [string, string];
      // The first alert's counter read never settles.
      held.armed = true;
      const delivery = engine.deliverDuressAlerts(callId);
      await tick();
      assert.ok(held.release !== null, "the first preflight is waiting");
      mock.timers.tick(29_999);
      assert.equal(await soon(delivery), "pending", "not before the bound");
      mock.timers.tick(1);
      assert.equal(await soon(delivery), 1, "the second was sent and acknowledged");
      assert.deepEqual(told.map((x) => x.alertId), [second], "the first was never sent");
      assert.deepEqual(await owed(), [first], "the first stays owed");
    });
  });
});
