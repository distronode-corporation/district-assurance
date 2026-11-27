// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Callback dials (VER-9), from the L2 review: a callback voided while the store is read never
// rings (cr-followup, verify-callback-attack.test.ts:243), the carrier check asks about the line
// the dial rang (T11), and a placed callback resumed a day later counts toward the daily limit
// again (T10).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED, MAX_CALLBACKS_PER_DAY } from "../src/verify/callback.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeCallbackDialer, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const NEW_PHONE = "+15555550222";
const DAY = 86_400_000;
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const PLACED: AttemptCounterKey = { workspaceId: "ws_test", factor: CALLBACKS_PLACED, scope: "subject", key: SUBJECT };

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
      },
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });
}
const world = (o: TestEngineOptions = {}): TestEngine => setup({ config: callbackConfig(), ...o });

async function firstCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall({});
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  return callId;
}

const moveNumber = (t: TestEngine, phoneOnFile: string) =>
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile, knowledge: { dob: DOB }, pin: PIN }));

/** A dialer that records every try (its key too), and fails while `failing` is set. */
function recordingDialer() {
  const fake = new FakeCallbackDialer();
  const tries: Array<{ to: string; idempotencyKey: string }> = [];
  const d = {
    failing: false,
    tries,
    fake,
    dialer: {
      async dial(input) {
        tries.push({ to: input.to, idempotencyKey: input.idempotencyKey });
        if (d.failing) throw new Error("telephony down");
        return fake.dial(input);
      },
    } as CallbackDialer,
  };
  return d;
}

const finished = async (t: TestEngine, callId: string) => (await t.ledger.list()).filter((e) => e.event === "verification.callback_finished" && e.callId === callId).map((e) => e.detail);

describe("callback: no window between the status check and the dial", () => {
  it("a callback voided while the store is read never rings, though the number on file is valid", async () => {
    const t = world();
    const asking = await firstCall(t);
    const read = t.records.getSubject.bind(t.records);
    let calls = 0;
    t.records.getSubject = async (w, key) => {
      const subject = await read(w, key);
      // The read at dial time: the callback call is tainted while it waits, and the number is on file.
      if (++calls === 1) await t.engine.markUntrusted("call_2", "crm_note");
      return subject;
    };
    await t.engine.requestCallback(asking);
    assert.equal(calls, 1, "the dial read the store");
    assert.equal(t.dialer.dialed.length, 0, "zero dials");
    assert.deepEqual(await finished(t, "call_2"), [], "voided first: left void, nothing recorded");
  });
});

describe("callback: the carrier check asks about the line rung (T11)", () => {
  it("a number changed before the dial: the dial and the carrier check both use the new one", async () => {
    const t = world();
    t.carrier.set(NEW_PHONE, { identityMatch: "match" });
    const asking = await firstCall(t);
    moveNumber(t, NEW_PHONE);
    await t.engine.requestCallback(asking);
    const { callId, to } = t.dialer.dialed.at(-1)!;
    assert.equal(to, NEW_PHONE);
    // Changed again after the dial: the line rung is still the one checked.
    moveNumber(t, "+15555550333");
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    await t.engine.checkCarrier(callId);
    assert.deepEqual(t.carrier.checked, [NEW_PHONE]);
  });

  it("refuses the carrier check on a callback call before it is dialed", async () => {
    const d = recordingDialer();
    d.failing = true;
    const t = world({ adapters: { dialer: d.dialer } });
    await t.engine.requestCallback(await firstCall(t));
    assert.equal((await t.engine.submitPin("call_2", PIN)).matched, true);
    await assert.rejects(t.engine.checkCarrier("call_2"), rejects("precondition_failed", /once it is dialed/));
    assert.deepEqual(t.carrier.checked, []);
  });

  it("a retry to the same number keeps the key; a changed number gets its own, and is the one checked", async () => {
    const d = recordingDialer();
    d.failing = true;
    const t = world({ adapters: { dialer: d.dialer } });
    const asking = await firstCall(t);
    await t.engine.requestCallback(asking);
    await t.engine.requestCallback(asking);
    moveNumber(t, NEW_PHONE);
    d.failing = false;
    await t.engine.requestCallback(asking);
    assert.deepEqual(d.tries.map((x) => x.to), [PHONE_ON_FILE, PHONE_ON_FILE, NEW_PHONE]);
    assert.equal(d.tries[0]!.idempotencyKey, d.tries[1]!.idempotencyKey, "the same line, the same key");
    assert.notEqual(d.tries[2]!.idempotencyKey, d.tries[0]!.idempotencyKey, "another line, its own key");
    await t.engine.submitPin("call_2", PIN);
    await t.engine.checkCarrier("call_2");
    assert.deepEqual(t.carrier.checked, [NEW_PHONE]);
  });

  it("two tries at once to two numbers: only the dial to the number kept is bound", async () => {
    const fake = new FakeCallbackDialer();
    const held: Array<() => void> = [];
    const reached: string[] = [];
    const dialer: CallbackDialer = {
      dial: (input) =>
        new Promise((resolve) => {
          reached.push(input.to);
          held.push(() => void fake.dial(input).then(resolve));
        }),
    };
    const t = world({ adapters: { dialer } });
    const asking = await firstCall(t);
    const one = t.engine.requestCallback(asking);
    while (held.length < 1) await new Promise((r) => setImmediate(r));
    moveNumber(t, NEW_PHONE);
    const two = t.engine.requestCallback(asking);
    while (held.length < 2) await new Promise((r) => setImmediate(r));
    assert.deepEqual(reached, [PHONE_ON_FILE, NEW_PHONE]);
    held[0]!();
    await one;
    held[1]!();
    await two;
    const [old, kept] = fake.dialed;
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: old!.ref, answered: true, confirmed: true }), { applied: false }, "the old line's dial is not bound");
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: kept!.ref, answered: true, confirmed: true }), { applied: true, callId: "call_2" });
  });
});

describe("callback: a resumed dial counts toward the daily limit again (T10)", () => {
  /** A placed callback whose dial failed, then a day later. */
  async function failedThenADayLater(o: TestEngineOptions = {}) {
    const d = recordingDialer();
    d.failing = true;
    const counters = (o.adapters?.counters as MemoryAttemptCounters | undefined) ?? new MemoryAttemptCounters();
    const t = world({ ...o, adapters: { ...o.adapters, counters, dialer: d.dialer } });
    const asking = await firstCall(t);
    await t.engine.requestCallback(asking);
    assert.equal(d.fake.dialed.length, 0);
    t.clock.advance(DAY);
    d.failing = false;
    return { t, d, asking, counters };
  }

  /** Callbacks placed and passed for the subject, so none leaves a lock. */
  async function placeAndPass(t: TestEngine, d: ReturnType<typeof recordingDialer>, n: number): Promise<void> {
    for (let i = 0; i < n; i++) {
      await t.engine.requestCallback(await firstCall(t));
      await t.engine.applyCallbackOutcome({ ref: d.fake.dialed.at(-1)!.ref, answered: true, confirmed: true });
    }
  }

  it("refused, without ringing, when the subject had the daily limit placed since", async () => {
    const { t, d, asking } = await failedThenADayLater();
    await placeAndPass(t, d, MAX_CALLBACKS_PER_DAY);
    assert.equal(d.fake.dialed.length, MAX_CALLBACKS_PER_DAY);
    await t.engine.requestCallback(asking);
    assert.equal(d.fake.dialed.length, MAX_CALLBACKS_PER_DAY, "no fourth ring in the day");
    assert.deepEqual(await finished(t, "call_2"), [{ outcome: "refused" }]);
    await t.engine.requestCallback(asking);
    assert.equal(d.fake.dialed.length, MAX_CALLBACKS_PER_DAY, "and it stays refused");
  });

  it("dialed and counted again when the subject is under the limit, once, whatever the retries", async () => {
    const { t, d, asking, counters } = await failedThenADayLater();
    d.failing = true;
    await t.engine.requestCallback(asking);
    t.clock.advance(3_600_000);
    d.failing = false;
    await t.engine.requestCallback(asking);
    assert.equal(d.fake.dialed.length, 1);
    assert.equal(d.tries.length, 3);
    assert.equal(new Set(d.tries.map((x) => x.idempotencyKey)).size, 1, "the same line, the same key, across the day");
    assert.equal((await counters.get(PLACED, new Date(t.clock.now().getTime() - DAY + 1).toISOString())).length, 1, "counted once in this day");
    await placeAndPass(t, d, MAX_CALLBACKS_PER_DAY - 1);
    const limited = await firstCall(t);
    await t.engine.requestCallback(limited);
    assert.equal(d.fake.dialed.length, MAX_CALLBACKS_PER_DAY, "the resumed dial took one of the day's");
  });

  it("refused when another request took the last one while it was counted", async () => {
    class Racing extends MemoryAttemptCounters {
      race = false;
      override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
        if (this.race && key.factor === CALLBACKS_PLACED) {
          this.race = false;
          for (let i = 0; i < MAX_CALLBACKS_PER_DAY; i++) await super.recordFailure(key, at, since);
        }
        return super.recordFailure(key, at, since);
      }
    }
    const counters = new Racing();
    const { t, d, asking } = await failedThenADayLater({ adapters: { counters } });
    counters.race = true;
    await t.engine.requestCallback(asking);
    assert.equal(d.fake.dialed.length, 0);
    assert.deepEqual(await finished(t, "call_2"), [{ outcome: "refused" }]);
  });
});
