// VER-9: the callback factor. The first call is ended, the callback is its own call to the number
// on file, and `callback` counts there only when that line answered and the person keyed the
// confirmation.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import { ConfigError, type FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED, MAX_CALLBACKS_PER_DAY } from "../src/verify/callback.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeCallbackDialer, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig, waitOut } from "./helpers.ts";

const CALLING = "+15555550199";
const NO_NUMBER = "87654321";
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const counter = (factor: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor, scope: "subject", key: SUBJECT });

/** The callback on in Badge, PIN or keypad plus a callback at level 2, and a flow that uses it first. */
function callbackConfig(patch: (config: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
      },
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"], ["keypad_knowledge", "callback"]);
    c.flows = {
      callback: { steps: [{ type: "badge.verify", level: 2, factors: ["pin", "callback", "carrier_identity_match"], scopes: ["payment.request"] }] },
      late: {
        steps: [
          { type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] },
          { type: "badge.verify", level: 2, factors: ["pin", "callback", "carrier_identity_match"], scopes: ["payment.request"] },
        ],
      },
      "no-callback": { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge", "pin"] }] },
    };
    patch(c);
  });
}

function world(options: TestEngineOptions = {}): TestEngine {
  const t = setup({ config: callbackConfig(), ...options });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NO_NUMBER, phoneOnFile: "", knowledge: { dob: DOB }, pin: PIN }));
  return t;
}

/** A first call that keyed the right PIN, from a calling number that is not the one on file. */
async function firstCall(t: TestEngine, input: { flow?: string; account?: string } = {}): Promise<string> {
  const { callId } = await t.engine.startCall(input.flow === undefined ? {} : { flow: input.flow });
  await t.engine.beginVerification(callId, { accountNumber: input.account ?? ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  return callId;
}

async function events(t: TestEngine, callId: string, prefix = "verification.callback"): Promise<Array<{ event: string; detail: unknown }>> {
  return (await t.ledger.list()).filter((e) => e.callId === callId && e.event.startsWith(prefix)).map((e) => ({ event: e.event, detail: e.detail }));
}

/** The callback the dialer placed last, and its call. */
function lastDial(t: TestEngine): { callId: string; ref: string; to: string } {
  return t.dialer.dialed.at(-1)!;
}

async function finishOnCallback(t: TestEngine, callId: string): Promise<number> {
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  await t.engine.checkCarrier(callId);
  return (await t.engine.finishVerification(callId)).level;
}

describe("callback: a pass", () => {
  it("ends the first call, rings the number on file, and records callback on the callback call only", async () => {
    const t = world();
    const first = await firstCall(t);
    assert.equal(await t.engine.requestCallback(first), undefined);
    const firstState = await t.engine.state(first);
    assert.equal(firstState.phase, "ended");
    const dial = lastDial(t);
    assert.deepEqual(t.dialer.dialed, [{ callId: dial.callId, to: PHONE_ON_FILE, locale: "en", ref: "cb_fake_1" }]);
    assert.notEqual(dial.callId, first);
    const before = await t.engine.state(dial.callId);
    assert.deepEqual([before.phase, before.factors, before.level], ["verifying", [], 0], "the subject is chosen, not verified");
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: dial.ref, answered: true, confirmed: true }), { applied: true, callId: dial.callId });
    assert.equal(await finishOnCallback(t, dial.callId), 2);
    assert.equal(await t.engine.authorize(dial.callId, "payment.request"), true);
    assert.deepEqual(await events(t, first), [{ event: "verification.callback_started", detail: { callbackCallId: dial.callId } }]);
    assert.deepEqual(await events(t, dial.callId), [{ event: "verification.callback_finished", detail: { outcome: "passed", requestedOn: first } }]);
    assert.deepEqual(await events(t, dial.callId, "verification.started"), [{ event: "verification.started", detail: { subject: "callback", requestedOn: first } }]);
    assert.deepEqual(await t.counters.get(counter("callback"), "2000-01-01T00:00:00.000Z"), [], "a pass forgets the failure counted before dialing");
    const ledger = JSON.stringify(await t.ledger.list());
    for (const value of ["5555550100", "5555550199", PIN, DOB, SUBJECT]) assert.ok(!ledger.includes(value), `no ${value} in the ledger`);
  });

  it("never gives the first call a level, a factor or a grant", async () => {
    const t = world();
    const first = await firstCall(t);
    await t.engine.requestCallback(first);
    await t.engine.applyCallbackOutcome({ ref: lastDial(t).ref, answered: true, confirmed: true });
    assert.equal(await finishOnCallback(t, lastDial(t).callId), 2);
    const state = await t.engine.state(first);
    assert.deepEqual([state.level, state.grant, state.factors.map((f) => f.kind)], [0, null, ["pin"]]);
    await assert.rejects(t.engine.finishVerification(first), rejects("invalid_transition"));
    assert.equal(await t.engine.authorize(first, "payment.request"), false);
    assert.equal(await t.engine.requestCallback(first), undefined, "asked again: the same answer");
    assert.equal(t.dialer.dialed.length, 1, "and no second ring");
  });

  it("runs the first call's flow again on the callback call, from its first step", async () => {
    const t = world();
    const first = await firstCall(t, { flow: "callback" });
    await t.engine.requestCallback(first);
    assert.equal((await t.engine.flowPosition(first))!.status, "abandoned");
    const { callId, ref } = lastDial(t);
    assert.deepEqual(await t.engine.flowPosition(callId), { flow: "callback", revision: "default", status: "running", index: 0, step: { type: "badge.verify", level: 2, factors: ["pin", "callback", "carrier_identity_match"], scopes: ["payment.request"] } });
    await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true });
    assert.equal(await finishOnCallback(t, callId), 2);
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
  });
});

describe("callback: no pass", () => {
  const cases = [
    { name: "no answer", answered: false, confirmed: false, outcome: "no_answer" },
    { name: "voicemail or an answering machine (no keys)", answered: true, confirmed: false, outcome: "no_confirmation" },
    { name: "no confirmation keyed", answered: true, confirmed: false, outcome: "no_confirmation" },
    { name: "a confirmation reported for a line that did not answer", answered: false, confirmed: true, outcome: "no_answer" },
  ];
  for (const c of cases) {
    it(`${c.name}: callback recorded as failed, the failure stays counted`, async () => {
      const t = world();
      await t.engine.requestCallback(await firstCall(t));
      const { callId, ref } = lastDial(t);
      assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: c.answered, confirmed: c.confirmed }), { applied: true, callId });
      assert.deepEqual((await t.engine.state(callId)).factors.map((f) => [f.kind, f.passed]), [["callback", false]]);
      assert.deepEqual(await events(t, callId), [{ event: "verification.callback_finished", detail: { outcome: c.outcome, requestedOn: "call_1" } }]);
      assert.equal(await finishOnCallback(t, callId), 0);
      assert.equal((await t.counters.get(counter("callback"), "2000-01-01T00:00:00.000Z")).length, 1);
    });
  }

  it("ignores an unknown, repeated or late outcome", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    const { callId, ref } = lastDial(t);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: "cb_unknown", answered: true, confirmed: true }), { applied: false });
    await t.engine.applyCallbackOutcome({ ref, answered: false, confirmed: false });
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: false }, "a callback settles once");
    const t2 = world();
    await t2.engine.requestCallback(await firstCall(t2));
    await t2.engine.endCall(lastDial(t2).callId);
    assert.deepEqual(await t2.engine.applyCallbackOutcome({ ref: lastDial(t2).ref, answered: true, confirmed: true }), { applied: false }, "after the callback call ended");
    assert.equal((await t.engine.state(callId)).factors.length, 1);
  });

  it("voids a callback still ringing when untrusted content enters, or the subject changes", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    const tainted = lastDial(t);
    await t.engine.markUntrusted(tainted.callId, "crm_note");
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: tainted.ref, answered: true, confirmed: true }), { applied: false });
    waitOut(t);
    await t.engine.requestCallback(await firstCall(t));
    const moved = lastDial(t);
    await t.engine.finishVerification(moved.callId);
    await t.engine.beginVerification(moved.callId, { accountNumber: NO_NUMBER });
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: moved.ref, answered: true, confirmed: true }), { applied: false });
  });
});

describe("callback: refused, and the caller hears the same", () => {
  it("refuses without a number on file", async () => {
    const t = world();
    const first = await firstCall(t, { account: NO_NUMBER });
    assert.equal(await t.engine.requestCallback(first), undefined);
    assert.equal((await t.engine.state(first)).phase, "ended");
    assert.deepEqual(t.dialer.dialed, []);
    assert.deepEqual(await events(t, first), [{ event: "verification.callback_finished", detail: { outcome: "refused" } }]);
    assert.equal(await t.engine.requestCallback(first), undefined, "asked again: the same");
    assert.deepEqual(t.dialer.dialed, []);
  });

  it("refuses before a keypad or PIN match, an unknown account included", async () => {
    for (const [account, entry] of [[ACCOUNT, "0000"], ["99999999", PIN]] as const) {
      const t = world();
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: account });
      assert.equal((await t.engine.submitPin(callId, entry)).matched, false);
      assert.equal(await t.engine.requestCallback(callId), undefined);
      assert.equal((await t.engine.state(callId)).phase, "ended");
      assert.deepEqual(t.dialer.dialed, []);
      assert.deepEqual(await events(t, callId), [{ event: "verification.callback_finished", detail: { outcome: "refused" } }]);
    }
  });

  it("refuses a factor that is off, off the flow's step, or past the flow's first step, and outside verification", async () => {
    const off = world({
      config: callbackConfig((c) => {
        (c.modules.badge!.settings as { factors: string[] }).factors = ["pin"];
        c.flows = {};
      }),
    });
    await assert.rejects(off.engine.requestCallback(await firstCall(off)), rejects("precondition_failed", /turned off/));
    const t = world();
    await assert.rejects(t.engine.requestCallback(await firstCall(t, { flow: "no-callback" })), rejects("precondition_failed", /does not use the callback factor/));
    const { callId } = await t.engine.startCall({ flow: "late" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, PIN);
    await assert.rejects(t.engine.requestCallback(callId), rejects("precondition_failed", /first step/));
    const open = (await t.engine.startCall()).callId;
    await assert.rejects(t.engine.requestCallback(open), rejects("invalid_transition"));
    assert.deepEqual(t.dialer.dialed, []);
  });

  it("allows one callback per call: the callback call cannot ask for another", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    const { callId } = lastDial(t);
    await assert.rejects(t.engine.requestCallback(callId), rejects("precondition_failed", /already/));
  });

  it("refuses on a call started while Badge was off", async () => {
    const t = world({
      config: callbackConfig((c) => {
        c.modules.badge = { enabled: false };
        c.flows = {};
      }),
    });
    const { callId } = await t.engine.startCall();
    t.engine.configure(callbackConfig());
    await assert.rejects(t.engine.requestCallback(callId), rejects("module_disabled"));
  });

  it("needs the dialer adapter when the callback is on", () => {
    assert.throws(
      () => world({ adapters: { dialer: undefined } }),
      (e: unknown) => e instanceof ConfigError && e.problems.includes("modules.badge: needs the dialer adapter, which the engine does not have"),
    );
  });
});

describe("callback: limits and lockouts across calls", () => {
  it("locks after a failed callback, and holds a daily limit per subject", async () => {
    const t = world();
    for (let i = 0; i < MAX_CALLBACKS_PER_DAY; i++) {
      await t.engine.requestCallback(await firstCall(t));
      assert.equal(t.dialer.dialed.length, i + 1);
      await t.engine.applyCallbackOutcome({ ref: lastDial(t).ref, answered: false, confirmed: false });
      // Straight away: the wait after the failure holds, on any call.
      const locked = await firstCall(t);
      await t.engine.requestCallback(locked);
      assert.equal(t.dialer.dialed.length, i + 1);
      assert.deepEqual(
        (await events(t, locked, "verification.")).filter((e) => e.event !== "verification.factor" && e.event !== "verification.started").map((e) => e.event),
        ["verification.locked", "verification.callback_finished"],
      );
      waitOut(t);
    }
    const limited = await firstCall(t);
    await t.engine.requestCallback(limited);
    assert.equal(t.dialer.dialed.length, MAX_CALLBACKS_PER_DAY, "the daily limit, even after the waits");
    assert.deepEqual(await events(t, limited), [{ event: "verification.callback_finished", detail: { outcome: "refused" } }]);
    t.clock.advance(24 * 3_600_000);
    await t.engine.requestCallback(await firstCall(t));
    assert.equal(t.dialer.dialed.length, MAX_CALLBACKS_PER_DAY + 1, "a day later");
  });

  it("writes the hard lock a failed callback starts", async () => {
    const t = world({ config: callbackConfig((c) => ((c.modules.badge!.settings as Record<string, unknown>).lockout = { lockAfterFailures: 1 })) });
    await t.engine.requestCallback(await firstCall(t));
    const { callId, ref } = lastDial(t);
    await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: false });
    const locked = (await events(t, callId, "verification.locked"))[0]!;
    assert.deepEqual(locked.detail, { kind: "callback", scope: "subject", hard: true, until: "2026-01-02T00:00:00.000Z" });
    waitOut(t);
    const next = await firstCall(t);
    await t.engine.requestCallback(next);
    assert.equal(t.dialer.dialed.length, 1);
    assert.equal(((await events(t, next, "verification.locked"))[0]!.detail as { hard: boolean }).hard, true);
  });

  it("counts a failure under the subject and the first call's calling number, and the placed callback toward the limit", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    await t.engine.applyCallbackOutcome({ ref: lastDial(t).ref, answered: false, confirmed: false });
    const since = "2000-01-01T00:00:00.000Z";
    const byNumber: AttemptCounterKey = { workspaceId: "ws_test", factor: "callback", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING) };
    assert.deepEqual([(await t.counters.get(counter("callback"), since)).length, (await t.counters.get(byNumber, since)).length], [1, 1]);
    assert.equal((await t.counters.get(counter(CALLBACKS_PLACED), since)).length, 1);
  });

  it("refuses when another request takes the last callback of the day, or locks, in between", async () => {
    for (const factor of [CALLBACKS_PLACED, "callback"]) {
      // A store where another engine records one at the moment this request reads.
      class Racing extends MemoryAttemptCounters {
        armed = false;
        override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
          const seen = await super.get(key, since);
          if (this.armed && key.factor === factor) {
            this.armed = false;
            for (let i = 0; i < MAX_CALLBACKS_PER_DAY; i++) await super.recordFailure(key, "2026-01-01T00:00:00.000Z", since);
          }
          return seen;
        }
      }
      const counters = new Racing();
      const t = world({ adapters: { counters } });
      const first = await firstCall(t);
      counters.armed = true;
      await t.engine.requestCallback(first);
      assert.deepEqual(t.dialer.dialed, [], factor);
      assert.deepEqual((await events(t, first)).at(-1), { event: "verification.callback_finished", detail: { outcome: "refused" } });
    }
  });
});

describe("callback: resuming after a failure", () => {
  it("dials again with the same key after a dialer that placed the call and failed to answer: one ring", async () => {
    const fake = new FakeCallbackDialer();
    let fail = true;
    const dialer: CallbackDialer = {
      async dial(input) {
        const placed = await fake.dial(input);
        if (fail) throw new Error("timeout");
        return placed;
      },
    };
    const t = world({ adapters: { dialer } });
    const first = await firstCall(t);
    // A failed dial answers as a refusal does; asking again resumes it.
    await t.engine.requestCallback(first);
    assert.equal((await t.engine.state(first)).phase, "ended", "the first call is never held");
    fail = false;
    await t.engine.requestCallback(first);
    assert.equal(fake.dialed.length, 1);
    const { callId, ref } = fake.dialed[0]!;
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: true, callId });
  });

  it("never dials a callback that was voided before it rang, or binds one voided while it rang", async () => {
    const fake = new FakeCallbackDialer();
    let engine: TestEngine["engine"] | null = null;
    let mode: "fail" | "taint" | "ok" = "fail";
    const dialer: CallbackDialer = {
      async dial(input) {
        if (mode === "fail") throw new Error("down");
        if (mode === "taint") await engine!.markUntrusted(input.callId, "crm_note");
        return fake.dial(input);
      },
    };
    const t = world({ adapters: { dialer } });
    engine = t.engine;
    const first = await firstCall(t);
    await t.engine.requestCallback(first);
    await t.engine.markUntrusted("call_2", "crm_note");
    mode = "ok";
    await t.engine.requestCallback(first);
    assert.deepEqual(fake.dialed, [], "voided before it rang: never dialed");
    waitOut(t);
    mode = "taint";
    await t.engine.requestCallback(await firstCall(t));
    const dialed: FakeCallbackDialer["dialed"] = fake.dialed;
    assert.equal(dialed.length, 1);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: dialed[0]!.ref, answered: true, confirmed: true }), { applied: false }, "never bound");
  });
});

/** A store that can fail once before or after a write, fail a reset once, or run a step after a read. */
class Faulty extends MemoryAttemptCounters {
  failBefore: ((key: AttemptCounterKey) => boolean) | null = null;
  failAfter: ((key: AttemptCounterKey) => boolean) | null = null;
  failReset = false;
  onGet: (() => Promise<void>) | null = null;

  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    const seen = await super.get(key, since);
    const step = this.onGet;
    this.onGet = null;
    if (step !== null) await step();
    return seen;
  }

  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    if (this.failBefore?.(key) === true) {
      this.failBefore = null;
      throw new Error("store down");
    }
    const failures = await super.recordFailure(key, at, since);
    if (this.failAfter?.(key) === true) {
      this.failAfter = null;
      throw new Error("store down");
    }
    return failures;
  }

  override async reset(key: AttemptCounterKey): Promise<void> {
    if (this.failReset) {
      this.failReset = false;
      throw new Error("store down");
    }
    return super.reset(key);
  }
}

const SINCE = "2000-01-01T00:00:00.000Z";

describe("callback: a request that failed before it was decided", () => {
  const byNumber: AttemptCounterKey = { workspaceId: "ws_test", factor: "callback", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING) };
  const cases: Array<{ name: string; fail: (c: Faulty) => void }> = [
    { name: "nothing counted", fail: (c) => (c.failBefore = (k) => k.factor === CALLBACKS_PLACED) },
    { name: "counted toward the limit only", fail: (c) => (c.failBefore = (k) => k.factor === "callback" && k.scope === "subject") },
    { name: "counted under the subject too", fail: (c) => (c.failBefore = (k) => k.scope === "number") },
    { name: "counted everywhere, not yet written down", fail: (c) => (c.failAfter = (k) => k.scope === "number") },
  ];
  for (const c of cases) {
    it(`${c.name}: a retry decides it, rings once and counts nothing twice`, async () => {
      const counters = new Faulty();
      const t = world({ adapters: { counters } });
      const first = await firstCall(t);
      c.fail(counters);
      await assert.rejects(t.engine.requestCallback(first), /store down/);
      t.clock.advance(1_000);
      await t.engine.requestCallback(first);
      assert.equal(t.dialer.dialed.length, 1);
      const counts = [counter(CALLBACKS_PLACED), counter("callback"), byNumber].map(async (k) => (await counters.get(k, SINCE)).length);
      assert.deepEqual(await Promise.all(counts), [1, 1, 1]);
      assert.deepEqual((await events(t, first)).map((e) => e.event), ["verification.callback_started"]);
      const { ref, callId } = lastDial(t);
      assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: true, callId });
      assert.deepEqual(await counters.get(counter("callback"), SINCE), [], "the pass forgets the failure counted at the reserved time");
    });
  }

  for (const nested of [false, true]) {
    it(`never places one for another subject the call restarted for while it was decided${nested ? ", nor does a retry in between" : ""}`, async () => {
      const counters = new Faulty();
      const t = world({ adapters: { counters } });
      const other = "11223344";
      t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: other, phoneOnFile: "+15555550123", knowledge: { dob: DOB } }));
      const first = await firstCall(t);
      counters.onGet = async () => {
        await t.engine.finishVerification(first);
        await t.engine.beginVerification(first, { accountNumber: other });
        if (nested) await t.engine.requestCallback(first);
      };
      await t.engine.requestCallback(first);
      assert.deepEqual(t.dialer.dialed, []);
      assert.deepEqual(await events(t, first), [{ event: "verification.callback_finished", detail: { outcome: "refused" } }]);
      await t.engine.requestCallback(first);
      assert.deepEqual(t.dialer.dialed, [], "decided: asked again, still refused");
    });
  }

  it("a retry that decides it while the first try is still counting: the placed callback stands, one ring", async () => {
    const counters = new Faulty();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.onGet = () => t.engine.requestCallback(first);
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 1);
    assert.deepEqual((await events(t, first)).map((e) => e.event), ["verification.callback_started"]);
  });
});

describe("callback: a pass whose failure was not yet forgotten", () => {
  it("forgets it on a repeated outcome, which records nothing again", async () => {
    const counters = new Faulty();
    const t = world({ adapters: { counters } });
    await t.engine.requestCallback(await firstCall(t));
    const { ref, callId } = lastDial(t);
    counters.failReset = true;
    await assert.rejects(t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), /store down/);
    assert.equal((await counters.get(counter("callback"), SINCE)).length, 1);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: false });
    assert.deepEqual(await counters.get(counter("callback"), SINCE), []);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: false });
    assert.equal((await t.engine.state(callId)).factors.length, 1, "recorded once");
    assert.equal((await events(t, callId)).length, 1);
    await t.engine.requestCallback(await firstCall(t));
    assert.equal(t.dialer.dialed.length, 2, "nothing stale blocks the next callback");
  });
});
