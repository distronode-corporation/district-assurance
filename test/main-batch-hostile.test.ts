// Hostile-pass regressions for the main fixes batch (fix-main-batch): Dossier confirmedBy, Stripe signature
// tolerance and clock, and the reference server's bounded webhook event ids.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import { SeenEvents, createReferenceServer } from "../examples/reference-server/src/app.ts";
import type { Engine } from "../src/index.ts";
import { FixedClock, createTestEngine } from "../src/testing/index.ts";
import { signStripePayload, verifyStripeSignature } from "../src/webhooks/stripe.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup } from "./helpers.ts";

const SECRET = "whsec_test_not_a_secret";

async function openIntake() {
  const t = setup();
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.finishVerification(callId);
  await t.engine.startIntake(callId, "repair");
  await t.engine.setIntakeField(callId, "issue", "leak");
  return { t, callId };
}

describe("hostile: confirmIntake confirmedBy", () => {
  it("files the value it checked, not a getter's second answer", async () => {
    const { t, callId } = await openIntake();
    let reads = 0;
    const input = {
      get confirmedBy() {
        reads += 1;
        return reads === 1 ? "voice" : PHONE_ON_FILE;
      },
    };
    const record = await t.engine.confirmIntake(callId, input as never);
    assert.equal(record.confirmedBy, "voice");
    // The call record holds the number on file (Badge's subject); the ledger and the filed record never do.
    const text = JSON.stringify(await t.ledger.list()) + JSON.stringify(record);
    assert.equal(text.includes(PHONE_ON_FILE.slice(2)), false, "the number never lands in the ledger or the record");
  });

  it("files the value it checked when the host changes the input object mid-call", async () => {
    const { t, callId } = await openIntake();
    const input: { confirmedBy: string } = { confirmedBy: "keypad" };
    const pending = t.engine.confirmIntake(callId, input as never);
    input.confirmedBy = `Jane Doe ${DOB}`;
    const record = await pending;
    assert.equal(record.confirmedBy, "keypad");
    assert.equal(JSON.stringify(await t.ledger.list()).includes("Jane Doe"), false);
  });

  it("refuses a Proxy whose read throws, before any write", async () => {
    const { t, callId } = await openIntake();
    const before = (await t.sessions.get("ws_test", callId))!.version;
    const hostile = new Proxy({}, { get: () => { throw new Error("boom"); } });
    await assert.rejects(t.engine.confirmIntake(callId, hostile as never), /boom/);
    for (const confirmedBy of ["__proto__", "constructor", "voice‮", "voice\u0000", new String("voice")]) {
      await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy } as never), rejects("invalid_input"));
    }
    assert.equal((await t.sessions.get("ws_test", callId))!.version, before);
  });

  it("a retry after a lost record write files one record, with the first channel", async () => {
    const { t, callId } = await openIntake();
    const put = t.records.putIntakeRecord.bind(t.records);
    let fail = true;
    t.records.putIntakeRecord = async (r) => {
      if (fail) {
        fail = false;
        throw new Error("store down");
      }
      return put(r);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), /store down/);
    const second = await t.engine.confirmIntake(callId, { confirmedBy: "keypad" });
    assert.equal(second.confirmedBy, "voice", "the reservation keeps the channel the caller confirmed with");
    const confirmed = (await t.ledger.list()).filter((e) => e.event === "intake.confirmed");
    assert.equal(confirmed.length, 1);
  });
});

describe("hostile: verifyStripeSignature", () => {
  const payload = '{"id":"evt_1","type":"checkout.session.completed"}';
  const now = new Date("2026-01-01T00:00:00.000Z");
  const t = Math.floor(now.getTime() / 1000);

  it("checks the tolerance it uses, so a getter cannot pass the check and then widen it", () => {
    let reads = 0;
    const old = signStripePayload(payload, SECRET, t - 365 * 86_400);
    const input = {
      payload,
      header: old,
      secrets: [SECRET],
      now,
      get toleranceSeconds() {
        reads += 1;
        return reads === 1 ? 300 : Number.POSITIVE_INFINITY;
      },
    };
    // Read twice, but the second answer is the one checked: a widened tolerance is refused, never used.
    assert.throws(() => verifyStripeSignature(input), rejects("invalid_input", /toleranceSeconds/));
  });

  it("refuses a Date whose getTime lies, and a clock from a Date subclass at the edges", () => {
    class Liar extends Date {
      override getTime(): number {
        return Number.NaN;
      }
    }
    assert.throws(() => verifyStripeSignature({ payload, header: signStripePayload(payload, SECRET, t), secrets: [SECRET], now: new Liar() }), rejects("invalid_input", /now/));
  });

  it("never accepts a header that re-states t, a 13-digit t, a signed or fractional t, or hostile text", () => {
    const fresh = signStripePayload(payload, SECRET, t);
    const oldSig = signStripePayload(payload, SECRET, t - 365 * 86_400).split(",")[1];
    const v = (header: string) => verifyStripeSignature({ payload, header, secrets: [SECRET], now });
    assert.equal(v(`t=${t},${oldSig}`).ok, false, "a fresh t over an old signature");
    assert.equal(v(`t=${t - 365 * 86_400},${fresh.split(",")[1]},t=${t}`).ok, true, "last t wins and matches its own signature only");
    for (const tt of [`1${"0".repeat(12)}`, `-${t}`, `+${t}`, `${t}.5`, `${t}e0`, "0x10", "Infinity", "NaN", ` ${t}x`]) {
      assert.equal(v(`t=${tt},${fresh.split(",")[1]}`).ok, false, tt);
    }
    for (const header of ["\ud800", "‮", "=".repeat(100_000), ",".repeat(100_000), "t=__proto__,v1=constructor"]) {
      assert.equal(v(header).ok, false);
    }
  });
});

describe("hostile: SeenEvents", () => {
  it("keeps prototype-key ids apart and never answers a forgotten id as seen", () => {
    const clock = new FixedClock();
    const seen = new SeenEvents(clock, 1000, 3);
    for (const id of ["__proto__", "constructor", "toString"]) seen.add(id);
    assert.deepEqual(["__proto__", "constructor", "toString", "hasOwnProperty"].map((id) => seen.has(id)), [true, true, true, false]);
    // A hit moves an id to the recent end without extending its time: it still goes at its ttl.
    const s2 = new SeenEvents(clock, 1000, 10);
    s2.add("a");
    clock.advance(500);
    s2.add("b");
    clock.advance(100);
    assert.equal(s2.has("a"), true);
    clock.advance(400);
    assert.equal(s2.has("a"), false, "forgotten at its own ttl even after a hit");
    assert.equal(s2.has("b"), true);
    assert.ok(s2.size <= 10);
  });

  it("a clock that runs backwards keeps an id, and never holds more than the cap", () => {
    let ms = 10_000;
    const clock = { now: () => new Date(ms) };
    const seen = new SeenEvents(clock, 1000, 2);
    seen.add("a");
    ms = 0;
    assert.equal(seen.has("a"), true);
    for (let i = 0; i < 100; i++) seen.add(`e${i}`);
    assert.equal(seen.size, 2);
  });
});

describe("hostile: reference server webhooks", () => {
  const event = (id: string, sessionId: string) => JSON.stringify({ id, type: "identity.verification_session.verified", data: { object: { id: sessionId } } });

  it("two concurrent deliveries of one event apply its outcome once", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    const sessionId = t.identity.created.at(-1)!.sessionId;
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhooks/stripe/identity`;
    try {
      const body = event("evt_dup", sessionId);
      const headers = { "stripe-signature": signStripePayload(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) };
      const answers = (await Promise.all([1, 2, 3].map(() => fetch(url, { method: "POST", body, headers }).then((r) => r.json())))) as Array<Record<string, unknown>>;
      assert.equal(answers.filter((a) => a.applied === true).length, 1, JSON.stringify(answers));
      const entries = (await t.ledger.list()).filter((e) => e.event.includes("photo") || e.event.includes("identity"));
      const kinds = entries.map((e) => e.event);
      assert.ok(kinds.length > 0);
      assert.equal(new Set(kinds).size, kinds.length, `no entry written twice: ${kinds.join(",")}`);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("an event the engine failed to apply is not remembered, so Stripe's retry applies it", async () => {
    const t = createTestEngine();
    let calls = 0;
    const engine = {
      ...t.engine,
      receiptKeys: () => t.engine.receiptKeys(),
      applyIdentityOutcome: async () => {
        calls += 1;
        if (calls === 1) throw new Error("store down");
        return { applied: true, callId: "call_x" };
      },
    } as unknown as Engine;
    const server = createReferenceServer({ engine, stripeSecrets: { identity: [SECRET], payments: [] }, clock: t.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webhooks/stripe/identity`;
    try {
      const body = event("evt_retry", "vs_1");
      const headers = { "stripe-signature": signStripePayload(body, SECRET, Math.floor(t.clock.now().getTime() / 1000)) };
      const first = await fetch(url, { method: "POST", body, headers });
      assert.deepEqual([first.status, await first.json()], [500, { error: "internal" }], "no detail of the failure leaks");
      assert.deepEqual(await (await fetch(url, { method: "POST", body, headers })).json(), { received: true, applied: true });
      assert.deepEqual(await (await fetch(url, { method: "POST", body, headers })).json(), { received: true, duplicate: true });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
