// Host inputs are read once: a getter (or a host changing the object while the engine waits) can
// never pass a check with one value and have another one used, stored or ledgered.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { signStripePayload, verifyStripeSignature } from "../src/webhooks/stripe.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, wording } from "./helpers.ts";

/** An object whose `key` answers `first` on its first `n` reads and `then` after. */
function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

describe("host inputs are read once", () => {
  it("startCall attaches the flow it named, never one flow's steps under another's name", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.flows = {
          one: { steps: [{ type: "trace.receipt" }] },
          two: { steps: [{ type: "trace.receipt" }, { type: "trace.consent", purpose: "texts" }] },
        };
      }),
    });
    await t.engine.startCall(flipping({}, "flow", "one", "two", 2));
    const started = (await t.ledger.list()).find((e) => e.event === "flow.started")!;
    assert.equal((started.detail as { flow: string }).flow, "one");
    assert.equal((started.detail as { steps: number }).steps, 1);
  });

  it("applyIdentityOutcome ledgers the status that decided the factor, and consumes the session it looked up", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    const sessionId = t.identity.created.at(-1)!.sessionId;
    const outcome = flipping({ sessionId }, "status", "verified", PHONE_ON_FILE);
    assert.equal((await t.engine.applyIdentityOutcome(outcome as never)).applied, true);
    const factor = (await t.ledger.list()).filter((e) => e.event === "verification.factor").at(-1)!;
    assert.deepEqual(factor.detail, { kind: "photo_id", passed: true, status: "verified" });
    assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false);
    const swapped = flipping({ status: "verified" }, "sessionId", sessionId, "vs_other");
    assert.equal((await t.engine.applyIdentityOutcome(swapped as never)).applied, false, "the session was consumed by the first outcome");
  });

  it("recordConsent checks the flow step against the purpose it found a wording for", async () => {
    const t = setup({
      config: testConfig((c) => {
        (c.modules.trace!.settings as { wordings: unknown[] }).wordings.push({ ...wording, purpose: "marketing" });
        c.flows = { consent: { steps: [{ type: "trace.consent", purpose: "texts" }] } };
      }),
    });
    const { callId } = await t.engine.startCall({ flow: "consent" });
    const input = flipping({ answer: "yes" }, "purpose", "marketing", "texts");
    await assert.rejects(t.engine.recordConsent(callId, input as never), rejects("precondition_failed", /asks for consent to texts/));
    assert.equal((await t.ledger.list()).some((e) => e.event === "consent.recorded"), false);
  });

  it("beginVerification uses the subject key it checked, and the account number it checked", async () => {
    const t = setup();
    const keys: string[] = [];
    const get = t.records.getSubject.bind(t.records);
    t.records.getSubject = async (ws, key) => {
      keys.push(key);
      return get(ws, key);
    };
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, flipping({}, "subjectKey", "a".repeat(64), PHONE_ON_FILE) as never);
    assert.deepEqual(keys, ["a".repeat(64)]);
    const second = await t.engine.startCall();
    await t.engine.beginVerification(second.callId, flipping({}, "accountNumber", ACCOUNT, "Jane Doe") as never);
    assert.deepEqual(await t.engine.submitKeypad(second.callId, { dob: DOB }), { matched: true, locked: false }, "the checked account number found the subject");
    const started = (await t.ledger.list()).filter((e) => e.event === "verification.started").map((e) => e.detail);
    assert.deepEqual(started, [{ subject: "host" }, { subject: "account" }]);
  });

  it("verifyStripeSignature parses the header it checked, with the clock it checked", () => {
    const payload = '{"id":"evt_1"}';
    const now = new Date("2026-01-01T00:00:00.000Z");
    const header = signStripePayload(payload, "whsec_test_not_a_secret", Math.floor(now.getTime() / 1000));
    const input = flipping({ payload, secrets: ["whsec_test_not_a_secret"], now }, "header", header, null, 3);
    assert.equal(verifyStripeSignature(input as never).ok, true, "no TypeError from a header that turned null after its checks");
    const lying = flipping({ payload, header, secrets: ["whsec_test_not_a_secret"] }, "now", now, { getTime: () => 0 });
    assert.equal(verifyStripeSignature(lying as never).ok, true, "the clock that was checked is the one used");
  });
});

describe("host values that reach the ledger are checked", () => {
  it("recordConsent refuses an answer other than yes or no before any write", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    const version = (await t.sessions.get("ws_test", callId))!.version;
    for (const answer of ["maybe", "", "YES", PHONE_ON_FILE, null, true, 1, ["yes"], "\ud800", "__proto__"]) {
      await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer } as never), rejects("invalid_input", /answer must be yes or no/), String(answer));
    }
    assert.equal((await t.sessions.get("ws_test", callId))!.version, version, "no write");
    assert.equal((await t.ledger.list()).some((e) => e.event === "consent.recorded"), false);
    assert.equal((await t.engine.recordConsent(callId, { purpose: "texts", answer: "no" })).answer, "no");
  });

  it("applyIdentityOutcome refuses a status other than the provider's three before any lookup or write", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    const sessionId = t.identity.created.at(-1)!.sessionId;
    const entries = (await t.ledger.list()).length;
    for (const status of ["processing", "", "VERIFIED", PHONE_ON_FILE, null, true, 1, "\ud800", "__proto__", "constructor"]) {
      await assert.rejects(t.engine.applyIdentityOutcome({ sessionId, status } as never), rejects("invalid_input", /status must be/), String(status));
    }
    assert.equal((await t.ledger.list()).length, entries, "nothing ledgered");
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "requires_input" }), { applied: true, callId }, "the session was not consumed by a refusal");
  });
});
