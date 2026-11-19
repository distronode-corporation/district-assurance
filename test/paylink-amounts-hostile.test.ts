// Hostile-pass regressions for #88 (PAY-2): amounts from code, read back and confirmed before a payment link.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AmountLookup, AmountSource } from "../src/core/runtime.ts";
import { PriceListAmounts } from "../src/pay/amount.ts";
import { testConfig } from "./helpers.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
const byRef = { amountRef: "deposit.standard", description: "Repair deposit", amountSource: "price_list" as const };

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** An AmountSource whose answers the test releases one at a time. */
class HeldAmounts implements AmountSource {
  readonly pending: Array<{ input: AmountLookup; answer: ReturnType<typeof deferred<{ amountMinor: number; currency: string } | null>> }> = [];
  resolve(input: AmountLookup): Promise<{ amountMinor: number; currency: string } | null> {
    const answer = deferred<{ amountMinor: number; currency: string } | null>();
    this.pending.push({ input, answer });
    return answer.promise;
  }
}

async function tick(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

describe("hostile #88: confirmPaymentAmount input", () => {
  it("ledgers the confirmedBy it checked, not a getter's second answer", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    let reads = 0;
    const input = {
      digest: back.digest,
      get confirmedBy() {
        reads += 1;
        return reads === 1 ? "voice" : PHONE_ON_FILE;
      },
    };
    await t.engine.confirmPaymentAmount(callId, input as never);
    const entry = (await t.ledger.list()).find((e) => e.event === "payment.amount_confirmed")!;
    assert.equal((entry.detail as { confirmedBy: string }).confirmedBy, "voice");
    assert.equal(JSON.stringify(await t.ledger.list()).includes(PHONE_ON_FILE.slice(2)), false, "the number never lands in the ledger");
  });

  it("ledgers the confirmedBy it checked when the host changes the object while the update waits", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    const input: { digest: string; confirmedBy: string } = { digest: back.digest, confirmedBy: "keypad" };
    const pending = t.engine.confirmPaymentAmount(callId, input as never);
    input.confirmedBy = `Jane Doe ${DOB}`;
    await pending;
    assert.equal(JSON.stringify(await t.ledger.list()).includes("Jane Doe"), false);
  });

  it("refuses hostile digests and confirmedBy values before any write", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    const version = (await t.sessions.get("ws_test", callId))!.version;
    for (const confirmedBy of ["__proto__", "constructor", "voice‮", "\ud800", new String("voice"), ["voice"]]) {
      await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy } as never), rejects("invalid_input"));
    }
    for (const digest of [back.digest.toUpperCase(), ` ${back.digest}`, `${back.digest}00`, back.digest.slice(0, 63) + "\ud800", "z".repeat(64)]) {
      await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest, confirmedBy: "voice" }), rejects("precondition_failed"));
    }
    assert.equal((await t.sessions.get("ws_test", callId))!.version, version);
  });
});

describe("hostile #88: AmountSource answers", () => {
  function refEngine(amounts: AmountSource) {
    return setup({ adapters: { amounts } });
  }

  it("refuses every bad amount a source can answer, and writes nothing", async () => {
    const answers: unknown[] = [
      { amountMinor: Number.NaN, currency: "cad" },
      { amountMinor: Number.POSITIVE_INFINITY, currency: "cad" },
      { amountMinor: -1, currency: "cad" },
      { amountMinor: 0, currency: "cad" },
      { amountMinor: 1.5, currency: "cad" },
      { amountMinor: "100", currency: "cad" },
      { amountMinor: 1_000_001, currency: "cad" },
      { amountMinor: 100, currency: "CAD" },
      { amountMinor: 100, currency: "‮cad" },
      { amountMinor: 100, currency: "ca\ud800" },
      { amountMinor: 100 },
      5,
      "100 cad",
      [],
    ];
    for (const answer of answers) {
      const t = refEngine({ resolve: async () => answer as never });
      const callId = await verifiedCall(t);
      const entries = (await t.ledger.list()).length;
      await assert.rejects(t.engine.readBackPayment(callId, byRef), (e: unknown) => rejects("invalid_input")(e) || rejects("precondition_failed")(e), JSON.stringify(answer));
      assert.equal((await t.ledger.list()).length, entries, "no read-back entry");
      await assert.rejects(t.engine.requestPayment(callId, byRef), rejects("precondition_failed"));
      assert.equal(t.payments.created.length, 0);
    }
  });

  it("reads a source's answer once, so a getter cannot pass the check and then change the amount", async () => {
    let reads = 0;
    const answer = {
      currency: "cad",
      get amountMinor() {
        reads += 1;
        return reads === 1 ? 100 : 999_999_999;
      },
    };
    const t = refEngine({ resolve: async () => answer });
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, byRef);
    assert.equal(back.amountMinor, 100);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    await t.engine.requestPayment(callId, byRef);
    assert.equal(t.payments.created.at(-1)!.amountMinor, 100);
  });

  it("a source that throws or rejects writes nothing, and prototype-key references find nothing", async () => {
    const t = refEngine({
      resolve: async (input) => {
        if (input.reference === "boom") throw new Error("source down");
        return new PriceListAmounts({ "deposit.standard": { amountMinor: 100, currency: "cad" } }).resolve(input);
      },
    });
    const callId = await verifiedCall(t);
    const entries = (await t.ledger.list()).length;
    await assert.rejects(t.engine.readBackPayment(callId, { ...byRef, amountRef: "boom" }), /source down/);
    for (const amountRef of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      await assert.rejects(t.engine.readBackPayment(callId, { ...byRef, amountRef }), rejects("precondition_failed", /no amount for this reference/), amountRef);
    }
    for (const amountRef of ["", "a".repeat(65), "a b", "a\ud800", "a‮", "../x"]) {
      await assert.rejects(t.engine.readBackPayment(callId, { ...byRef, amountRef }), rejects("invalid_input", /amountRef/), amountRef);
    }
    assert.equal((await t.ledger.list()).length, entries);
  });

  it("never puts the reference or the description in the ledger", async () => {
    const t = refEngine(new PriceListAmounts({ "acct.4111111111111111": { amountMinor: 100, currency: "cad" } }));
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, { ...byRef, amountRef: "acct.4111111111111111", description: "Jane Doe repair" });
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    await t.engine.requestPayment(callId, { ...byRef, amountRef: "acct.4111111111111111", description: "Jane Doe repair" });
    const text = JSON.stringify(await t.ledger.list());
    assert.equal(text.includes("4111111111111111"), false);
    assert.equal(text.includes("Jane Doe"), false);
  });
});

describe("hostile #88: races around the lookup", () => {
  it("reads the request once: a host changing its object while the amount is looked up changes nothing", async () => {
    const held = new HeldAmounts();
    const t = setup({ adapters: { amounts: held } });
    const callId = await verifiedCall(t);
    const input = { ...byRef };
    const pending = t.engine.readBackPayment(callId, input);
    await tick();
    assert.equal(held.pending[0]!.input.reference, "deposit.standard");
    input.amountRef = "deposit.other";
    held.pending[0]!.answer.resolve({ amountMinor: 12500, currency: "cad" });
    const back = await pending;
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    await assert.rejects(t.engine.requestPayment(callId, { ...byRef, amountRef: "deposit.other" }), (e: unknown) => rejects("precondition_failed")(e) || rejects("invalid_input")(e), "the quote is for deposit.standard");
    assert.equal((await t.engine.requestPayment(callId, byRef)).status, "open");
  });

  it("endCall while the amount is looked up leaves no read-back and no link", async () => {
    const held = new HeldAmounts();
    const t = setup({ adapters: { amounts: held } });
    const callId = await verifiedCall(t);
    const pending = t.engine.readBackPayment(callId, byRef);
    await tick();
    await t.engine.endCall(callId);
    held.pending[0]!.answer.resolve({ amountMinor: 100, currency: "cad" });
    // The end drops the grant, so the update refuses before it reads anything else.
    await assert.rejects(pending, (e: unknown) => rejects("scope_denied")(e) || rejects("invalid_transition")(e));
    assert.equal((await t.ledger.list()).some((e) => e.event === "payment.amount_read_back"), false);
  });

  it("a confirmation after endCall, or after untrusted content, is refused", async () => {
    const t = setup();
    const a = await verifiedCall(t);
    const backA = await t.engine.readBackPayment(a, request);
    await t.engine.markUntrusted(a, "transcript");
    const refused = (e: unknown) => rejects("scope_denied")(e) || rejects("precondition_failed")(e);
    await assert.rejects(t.engine.confirmPaymentAmount(a, { digest: backA.digest, confirmedBy: "voice" }), refused);
    await assert.rejects(t.engine.requestPayment(a, request), refused);
    const b = await verifiedCall(t);
    const backB = await t.engine.readBackPayment(b, request);
    await t.engine.endCall(b);
    const entries = (await t.ledger.list()).length;
    await assert.rejects(t.engine.confirmPaymentAmount(b, { digest: backB.digest, confirmedBy: "voice" }), refused);
    assert.equal((await t.ledger.list()).length, entries, "no ledger entry after the end");
  });

  it("two read-backs answered out of order: only the one written last can be confirmed, and the link is for it", async () => {
    const held = new HeldAmounts();
    const t = setup({ adapters: { amounts: held } });
    const callId = await verifiedCall(t);
    const first = t.engine.readBackPayment(callId, byRef);
    const second = t.engine.readBackPayment(callId, byRef);
    await tick();
    held.pending[1]!.answer.resolve({ amountMinor: 200, currency: "cad" });
    const late = await second;
    held.pending[0]!.answer.resolve({ amountMinor: 100, currency: "cad" });
    const early = await first;
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: late.digest, confirmedBy: "voice" }), rejects("precondition_failed"));
    await t.engine.confirmPaymentAmount(callId, { digest: early.digest, confirmedBy: "voice" });
    await t.engine.requestPayment(callId, byRef);
    assert.equal(t.payments.created.at(-1)!.amountMinor, 100);
  });

  it("a confirmation on one engine and a request on a second engine with a lower cap is refused", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    const t2 = setup({
      config: testConfig((c) => (c.modules.paylink = { settings: { maxAmountMinor: 10000 } })),
      adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records },
    });
    await assert.rejects(t2.engine.requestPayment(callId, request), /above the limit/);
    assert.equal(t2.payments.created.length, 0);
  });

  it("a second call in another workspace with the same call id cannot use this call's confirmation", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const back = await t.engine.readBackPayment(callId, request);
    await t.engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "voice" });
    const other = setup({ workspaceId: "ws_other", adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records } });
    await assert.rejects(other.engine.requestPayment(callId, request));
    assert.equal(other.payments.created.length, 0);
  });
});

describe("hostile #88: descriptions", () => {
  it("two descriptions that differ only in a lone surrogate never share a digest", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const outcomes: string[] = [];
    for (const description of ["Deposit \ud800", "Deposit \udc00"]) {
      try {
        outcomes.push((await t.engine.readBackPayment(callId, { ...request, description })).digest);
      } catch (e) {
        assert.ok(rejects("invalid_input", /description/)(e), String(e));
        outcomes.push("refused");
      }
    }
    assert.ok(outcomes[0] === "refused" || outcomes[0] !== outcomes[1], "a stale confirmation would count for a different read-back");
  });

  it("a verified subject's account number stays out of the lookup", async () => {
    const held = new HeldAmounts();
    const t = setup({ adapters: { amounts: held } });
    const callId = await verifiedCall(t);
    const pending = t.engine.readBackPayment(callId, byRef);
    await tick();
    const lookup = held.pending[0]!.input;
    assert.equal(JSON.stringify(lookup).includes(ACCOUNT), false);
    assert.equal(lookup.workspaceId, "ws_test");
    held.pending[0]!.answer.resolve(null);
    await assert.rejects(pending, rejects("precondition_failed"));
  });
});
