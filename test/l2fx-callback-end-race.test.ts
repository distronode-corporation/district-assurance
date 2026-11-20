// Two callback requests on one call that both reach the end of the asking call: the one that ends
// it second is not an error (engine.requestCallback). Held at endCall so both get there for certain.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, PIN, setup, testConfig } from "./helpers.ts";

const callbackConfig = () =>
  testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "callback"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } };
    c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  });

describe("requestCallback: two requests reach the end of the asking call together", () => {
  it("the second completes the receipt before it dials, when the first's signing then fails", async () => {
    const real = generateTestSigner();
    let signs = 0;
    let failFirst!: () => void;
    const t = setup({
      config: callbackConfig(),
      adapters: {
        signer: {
          ...real,
          sign: (bytes) => {
            // The first request's signing is held, then fails; any later one signs.
            if (++signs > 1) return real.sign(bytes);
            return new Promise((_, reject) => (failFirst = () => reject(new Error("kms down"))));
          },
        },
      },
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const endCall = t.engine.endCall.bind(t.engine);
    let arrived = 0;
    let firstHere!: () => void;
    let bothHere!: () => void;
    const first = new Promise<void>((resolve) => (firstHere = resolve));
    const together = new Promise<void>((resolve) => (bothHere = resolve));
    t.engine.endCall = async (id) => {
      ++arrived;
      if (arrived === 1) firstHere();
      if (arrived === 2) bothHere();
      if (arrived <= 2) await together;
      return endCall(id);
    };
    const receiptAtDial: Array<unknown> = [];
    const dial = t.dialer.dial.bind(t.dialer);
    t.dialer.dial = async (...args) => {
      receiptAtDial.push(await t.engine.receipt(callId));
      return dial(...args);
    };
    const a = t.engine.requestCallback(callId);
    await first;
    const b = t.engine.requestCallback(callId);
    // The one that ended second goes on while the other is held signing; then that signing fails.
    const settled = [a, b].map((p) => p.then(() => "ok", (e: Error) => e.message));
    await Promise.race(settled);
    failFirst();
    assert.deepEqual((await Promise.all(settled)).sort(), ["kms down", "ok"]);
    assert.equal(t.dialer.dialed.length, 1, "the line rings once");
    assert.equal(receiptAtDial.length, 1);
    assert.notEqual(receiptAtDial[0], null, "the asking call had its receipt before the callback dialed");
    assert.notEqual(await t.engine.receipt(callId), null);
  });

  it("does not dial when the second's own signing fails too, and both report it", async () => {
    const t = setup({ config: callbackConfig(), adapters: { signer: { ...generateTestSigner(), sign: () => Promise.reject(new Error("kms down")) } } });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const endCall = t.engine.endCall.bind(t.engine);
    let arrived = 0;
    let firstHere!: () => void;
    let bothHere!: () => void;
    const first = new Promise<void>((resolve) => (firstHere = resolve));
    const together = new Promise<void>((resolve) => (bothHere = resolve));
    t.engine.endCall = async (id) => {
      ++arrived;
      if (arrived === 1) firstHere();
      if (arrived === 2) bothHere();
      if (arrived <= 2) await together;
      return endCall(id);
    };
    const a = t.engine.requestCallback(callId);
    await first;
    const results = await Promise.allSettled([a, t.engine.requestCallback(callId)]);
    assert.deepEqual(
      results.map((r) => (r.status === "rejected" ? (r.reason as Error).message : "ok")),
      ["kms down", "kms down"],
    );
    assert.equal(arrived, 3, "the second tried the receipt itself");
    assert.equal(t.dialer.dialed.length, 0, "no callback rings for a call with no receipt");
    assert.equal(await t.engine.receipt(callId), null);
  });

  it("goes ahead when the first stores the receipt between the second's read and its endCall", async () => {
    const real = generateTestSigner();
    let releaseSign!: () => void;
    const signGate = new Promise<void>((r) => (releaseSign = r));
    const t = setup({
      config: callbackConfig(),
      adapters: {
        signer: {
          ...real,
          sign: async (bytes) => {
            await signGate;
            return real.sign(bytes);
          },
        },
      },
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const endCall = t.engine.endCall.bind(t.engine);
    let arrived = 0;
    let firstHere!: () => void;
    let bothHere!: () => void;
    const first = new Promise<void>((resolve) => (firstHere = resolve));
    const together = new Promise<void>((resolve) => (bothHere = resolve));
    t.engine.endCall = async (id) => {
      ++arrived;
      if (arrived === 1) firstHere();
      if (arrived === 2) bothHere();
      if (arrived <= 2) await together;
      if (arrived === 3) {
        // The second request read the receipt as owed; the first now finishes signing and stores it.
        releaseSign();
        while ((await t.engine.receipt(callId)) === null) await new Promise((r) => setImmediate(r));
      }
      return endCall(id);
    };
    const a = t.engine.requestCallback(callId);
    await first;
    const results = await Promise.all([a, t.engine.requestCallback(callId)]);
    assert.deepEqual(results, [undefined, undefined], "neither fails with invalid_transition");
    assert.equal(arrived, 3);
    assert.equal(t.dialer.dialed.length, 1, "the line rings once");
    assert.notEqual(await t.engine.receipt(callId), null);
  });

  it("both resolve, the call ends once, and the line rings once", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "callback"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } };
        c.policy.levels[1]!.anyOf.push(["pin", "callback"]);
      }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: "+15555550199" });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    const endCall = t.engine.endCall.bind(t.engine);
    let arrived = 0;
    let firstHere!: () => void;
    let bothHere!: () => void;
    const first = new Promise<void>((resolve) => (firstHere = resolve));
    const together = new Promise<void>((resolve) => (bothHere = resolve));
    t.engine.endCall = async (id) => {
      if (++arrived === 1) firstHere();
      else bothHere();
      await together;
      return endCall(id);
    };
    // The first is held at the end of the asking call; the second finds its callback placed and,
    // with the call not ended yet, reaches the end too.
    const a = t.engine.requestCallback(callId);
    await first;
    const results = await Promise.all([a, t.engine.requestCallback(callId)]);
    assert.deepEqual(results, [undefined, undefined]);
    // Both reached the end; the one that ended second calls endCall again when the receipt was not yet stored.
    assert.ok(arrived >= 2, "both requests reached the end of the asking call");
    assert.notEqual(await t.engine.receipt(callId), null);
    assert.equal((await t.engine.state(callId)).phase, "ended");
    assert.equal((await t.ledger.list()).filter((e) => e.callId === callId && e.event === "call.ended").length, 1);
    assert.equal(t.dialer.dialed.length, 1);
  });
});
