// Attack tests for the callback factor (VER-9), from a hostile review: the number dialed, races on
// the asking call, outcomes and oracles. Each pins behaviour that holds; four findings were fixed
// (the number is read from the store at dial time, a tainted call is refused, two requests at once
// both resolve, a dial failure answers as a refusal does).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, CallbackDialer } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { CALLBACKS_PLACED } from "../src/verify/callback.ts";
import { FakeCallbackDialer, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";
const NEW_PHONE = "+15555550222";

function callbackConfig(): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: {
        factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "callback"],
        pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
      },
    };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"], ["keypad_knowledge", "callback"]);
  });
}
const world = (o: TestEngineOptions = {}): TestEngine => setup({ config: callbackConfig(), ...o });

async function firstCall(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall({});
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: CALLING });
  assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
  return callId;
}

/** Counters whose read of the daily-limit counter waits on a gate once armed. */
class Gated extends MemoryAttemptCounters {
  armed = false;
  gate: Promise<void> = Promise.resolve();
  release: () => void = () => undefined;
  reached: Promise<void> = Promise.resolve();
  #hit: () => void = () => undefined;
  arm(): void {
    this.armed = true;
    this.gate = new Promise((r) => (this.release = r));
    this.reached = new Promise((r) => (this.#hit = r));
  }
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    if (this.armed && key.factor === CALLBACKS_PLACED) {
      this.armed = false;
      this.#hit();
      await this.gate;
    }
    return super.get(key, since);
  }
}

describe("zz attack: number on file", () => {
  it("dials the number on file in the store when it dials, not the copy taken when verification began", async () => {
    const t = world();
    const first = await firstCall(t);
    // The business updates the number on file (for example after the owner reports a SIM swap).
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB }, pin: PIN }));
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.at(-1)!.to, NEW_PHONE, "the store, not the snapshot");
  });

  it("reads the store again when a failed dial is retried", async () => {
    const fake = new FakeCallbackDialer();
    let fail = true;
    const dialer: CallbackDialer = { async dial(i) { if (fail) throw new Error("telephony down"); return fake.dial(i); } };
    const t = world({ adapters: { dialer } });
    const first = await firstCall(t);
    // A failed dial answers as a refusal does (the oracle below); a retry resumes it.
    await t.engine.requestCallback(first);
    assert.equal(fake.dialed.length, 0);
    t.clock.advance(6 * 3_600_000);
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB }, pin: PIN }));
    fail = false;
    await t.engine.requestCallback(first);
    assert.equal(fake.dialed.at(-1)!.to, NEW_PHONE);
    assert.equal(fake.dialed.length, 1);
  });

  it("never dials when the store no longer has a number on file for the subject", async () => {
    const t = world();
    const first = await firstCall(t);
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: "", knowledge: { dob: DOB }, pin: PIN }));
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 0);
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 0, "a retry does not ring either");
  });

  it("the caller cannot steer the number: calling number is never dialed", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    assert.notEqual(t.dialer.dialed.at(-1)!.to, CALLING);
  });
});

describe("zz attack: races on the asking call", () => {
  it("untrusted content arriving while the request is decided refuses the callback", async () => {
    const counters = new Gated();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.arm();
    const pending = t.engine.requestCallback(first);
    await counters.reached;
    await t.engine.markUntrusted(first, "webhook");
    counters.release();
    await pending;
    assert.equal(t.dialer.dialed.length, 0, "the taint in the window voids the request");
    const finished = (await t.ledger.list()).filter((e) => e.event === "verification.callback_finished" && e.callId === first).map((e) => e.detail);
    assert.deepEqual(finished, [{ outcome: "refused" }], "refused as any refusal is");
  });

  it("a retry after the taint, while the first try is still deciding, is refused too", async () => {
    const counters = new Gated();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.arm();
    const pending = t.engine.requestCallback(first);
    await counters.reached;
    await t.engine.markUntrusted(first, "webhook");
    await t.engine.requestCallback(first);
    counters.release();
    await pending;
    assert.equal(t.dialer.dialed.length, 0);
  });

  it("untrusted content before the request refuses it, silently", async () => {
    const t = world();
    const first = await firstCall(t);
    await t.engine.markUntrusted(first, "webhook");
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 0);
    const finished = (await t.ledger.list()).filter((e) => e.event === "verification.callback_finished").map((e) => e.detail);
    assert.deepEqual(finished, [{ outcome: "refused" }], "the same as any refusal");
  });

  it("endCall in the window: callback still placed, one ring", async () => {
    const counters = new Gated();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.arm();
    const pending = t.engine.requestCallback(first);
    await counters.reached;
    await t.engine.endCall(first);
    counters.release();
    await pending;
    assert.equal(t.dialer.dialed.length, 1);
    assert.equal((await t.engine.state(first)).level, 0);
  });

  it("two concurrent requests on one call: one ring, counted once, and both resolve", { timeout: 10_000 }, async () => {
    const counters = new Gated();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.arm();
    const a = t.engine.requestCallback(first);
    await counters.reached;
    const releaseA = counters.release;
    // The second request reaches its own read of the limit while the first is still held there.
    counters.arm();
    const b = t.engine.requestCallback(first);
    await counters.reached;
    releaseA();
    await a;
    counters.release();
    assert.equal(await b, undefined, "the second ends the call idempotently");
    assert.equal(t.dialer.dialed.length, 1);
    const since = "2000-01-01T00:00:00.000Z";
    const key = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
    const placed = await counters.get({ workspaceId: "ws_test", factor: CALLBACKS_PLACED, scope: "subject", key }, since);
    const failed = await counters.get({ workspaceId: "ws_test", factor: "callback", scope: "subject", key }, since);
    assert.deepEqual([placed.length, failed.length], [1, 1], "counted once");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "call.ended" && e.callId === first).length, 1, "ended once");
  });
});

describe("zz attack: outcomes", () => {
  it("voicemail-shaped outcomes never pass; replays and late outcomes are ignored", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    const { ref, callId } = t.dialer.dialed.at(-1)!;
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: false, confirmed: true }), { applied: true, callId });
    assert.equal((await t.engine.state(callId)).factors.at(-1)!.passed, false);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref, answered: true, confirmed: true }), { applied: false });
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: "cb_forged", answered: true, confirmed: true }), { applied: false });
  });

  it("a ref from one callback cannot pass another call's callback", async () => {
    const t = world();
    await t.engine.requestCallback(await firstCall(t));
    const one = t.dialer.dialed.at(-1)!;
    t.clock.advance(900_000);
    await t.engine.applyCallbackOutcome({ ref: one.ref, answered: true, confirmed: true });
    await t.engine.requestCallback(await firstCall(t));
    const two = t.dialer.dialed.at(-1)!;
    assert.notEqual(one.ref, two.ref);
    assert.deepEqual(await t.engine.applyCallbackOutcome({ ref: one.ref, answered: true, confirmed: true }), { applied: false });
    assert.deepEqual((await t.engine.state(two.callId)).factors, []);
  });

  it("re-requesting on the asking call after the outcome never rings again", async () => {
    const t = world();
    const first = await firstCall(t);
    await t.engine.requestCallback(first);
    await t.engine.applyCallbackOutcome({ ref: t.dialer.dialed.at(-1)!.ref, answered: false, confirmed: false });
    for (let i = 0; i < 5; i++) await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 1);
  });
});

describe("zz attack: oracles", () => {
  it("a telephony error answers as a refusal does, so the result never says whether a number is on file", async () => {
    const attempts: string[] = [];
    const dialer: CallbackDialer = {
      async dial({ to }) {
        attempts.push(to);
        throw new Error("telephony down");
      },
    };
    const t = world({ adapters: { dialer } });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "87654321", phoneOnFile: "", knowledge: { dob: DOB }, pin: PIN }));
    const withNumber = await firstCall(t);
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: "87654321", callingNumber: CALLING });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.equal(await t.engine.requestCallback(withNumber), undefined, "a number on file, the dial failed");
    assert.deepEqual(attempts, [PHONE_ON_FILE], "the account with a number reached the failing dialer once");
    assert.equal(await t.engine.requestCallback(callId), undefined, "no number on file, refused");
    assert.deepEqual(attempts, [PHONE_ON_FILE], "the account without a number never reached the dialer");
  });
});

describe("zz attack: fixes held", () => {
  it("never dials when the subject is gone from the store, nor sets a callback voided while it read", async () => {
    const t = world();
    const first = await firstCall(t);
    t.records.getSubject = async () => null;
    await t.engine.requestCallback(first);
    assert.equal(t.dialer.dialed.length, 0, "no subject on file: no ring");

    const u = world();
    const asking = await firstCall(u);
    const read = u.records.getSubject.bind(u.records);
    let calls = 0;
    u.records.getSubject = async (w, key) => {
      // The read at dial time: the callback call is tainted while it waits, and the number is gone.
      if (++calls === 1) {
        await u.engine.markUntrusted("call_2", "crm_note");
        return null;
      }
      return read(w, key);
    };
    await u.engine.requestCallback(asking);
    assert.equal(u.dialer.dialed.length, 0);
    const finished = (await u.ledger.list()).filter((e) => e.event === "verification.callback_finished" && e.callId === "call_2");
    assert.deepEqual(finished, [], "voided first: left void, nothing recorded");
  });

  it("a retry that refuses it while the first try is still deciding: the refusal stands, no ring", async () => {
    const counters = new Gated();
    const t = world({ adapters: { counters } });
    const first = await firstCall(t);
    counters.arm();
    const pending = t.engine.requestCallback(first);
    await counters.reached;
    // The same subject again: a new epoch, so what was decided for the old one is never placed.
    await t.engine.finishVerification(first);
    await t.engine.beginVerification(first, { accountNumber: ACCOUNT, callingNumber: CALLING });
    await t.engine.requestCallback(first);
    counters.release();
    await pending;
    assert.equal(t.dialer.dialed.length, 0);
  });

  it("still throws an endCall failure that is not a second end, such as the receipt signer's", async () => {
    const t = world({ adapters: { signer: { keyId: "k", algorithm: "ES256", publicJwk: () => ({}), sign: async () => { throw new Error("kms down"); } } } });
    const first = await firstCall(t);
    await assert.rejects(t.engine.requestCallback(first), /kms down/);
  });
});

