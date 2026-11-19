// L1 integration review (PR #129), Paylink, access codes and disputes: each case is a finding from
// the review of the integrated branch, and each test failed before its fix.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput, MessageSender } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAccessCodeStore, accessCodes } from "../src/gate/codes.ts";
import type { DisputeOutcome } from "../src/pay/refunds.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { FakeAccessController, FakeMessageSender, FakePaymentLinks, FixedClock, MemoryCodeStore, generateTestSigner } from "../src/testing/index.ts";
import { parseStripeEvent } from "../src/webhooks/stripe.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

/** A session store that can be told to refuse writes, and to run a hook when a reference is resolved. */
class HookedStore extends MemorySessionStore {
  stopWhen: (() => boolean) | null = null;
  onResolve: (() => void) | null = null;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
    if (this.stopWhen?.() === true) {
      this.stopWhen = null;
      throw new Error("store down");
    }
    return super.compareAndSet(w, c, v, r);
  }
  override async resolveRef(w: string, ref: string) {
    const out = await super.resolveRef(w, ref);
    const run = this.onResolve;
    this.onResolve = null;
    run?.();
    return out;
  }
}

const settled = async (t: ReturnType<typeof setup>) => (await t.ledger.list()).filter((e) => e.event === "payment.settled").map((e) => e.detail);
const linkTexts = (t: ReturnType<typeof setup>) => t.messages.sent.filter((m) => m.purpose === "payment_link");

describe("L1 review: Paylink", () => {
  it("binds a confirmation to one read-back: an identical later read-back has a digest of its own (T9)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const first = await t.engine.readBackPayment(callId, request);
    await t.engine.confirmPaymentAmount(callId, { digest: first.digest, confirmedBy: "keypad" });
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    // A second deposit of the same amount: the caller has not answered it yet.
    const second = await t.engine.readBackPayment(callId, request);
    assert.equal(second.text, first.text);
    assert.notEqual(second.digest, first.digest);
    await assert.rejects(t.engine.confirmPaymentAmount(callId, { digest: first.digest, confirmedBy: "keypad" }), rejects("precondition_failed", /not the amount last read back/), "a late duplicate of the first yes");
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /not confirmed/));
    // A repeat confirmation of the same read-back stays harmless.
    await t.engine.confirmPaymentAmount(callId, { digest: second.digest, confirmedBy: "voice" });
    await t.engine.confirmPaymentAmount(callId, { digest: second.digest, confirmedBy: "voice" });
    assert.equal((await t.engine.requestPayment(callId, request)).paymentId, "pay_2");
  });

  it("never replaces a live send lease: a resume while the text is going out is refused, and one text goes (T10)", { timeout: 10_000 }, async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const inText = new Promise<void>((r) => (entered = r));
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      if (input.purpose === "payment_link") {
        entered();
        await held;
      }
      return send(input);
    };
    const first = t.engine.requestPayment(callId, request);
    await inText;
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /another process is texting/));
    release();
    assert.equal((await first).status, "open");
    assert.equal(linkTexts(t).length, 1, "texted once");
  });

  it("gives a failed sender's lease back so the retry goes at once, and lets it lapse when the release fails (T10)", async () => {
    const sessions = new HookedStore();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const send = t.messages.sendText.bind(t.messages);
    let fail: "text" | "text and release" | null = "text";
    t.messages.sendText = async (input) => {
      if (input.purpose === "payment_link" && fail !== null) {
        if (fail === "text and release") sessions.stopWhen = () => true;
        fail = null;
        throw new Error("carrier down");
      }
      return send(input);
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    fail = "text and release";
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/, "retried at once; the first error is thrown");
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /another process is texting/), "the lease was not given back");
    t.clock.advance(61_000);
    assert.equal((await t.engine.requestPayment(callId, request)).status, "open");
    assert.equal(linkTexts(t).length, 1);
  });

  it("uses one snapshot of a payment outcome, even if the host reuses its object during the lookup (T11)", async () => {
    const sessions = new HookedStore();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    await t.engine.cancelPaymentLink(callId, "pay_1");
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    const outcome = { kind: "completed" as const, linkId: "cs_fake_1", paymentStatus: "paid" as const };
    sessions.onResolve = () => {
      outcome.linkId = "cs_fake_2";
    };
    assert.deepEqual(await t.engine.applyPaymentOutcome(outcome), { applied: true, callId, status: "paid" });
    assert.deepEqual((await settled(t)).at(-1), { paymentId: "pay_1", status: "paid", late: true }, "the link looked up is the one settled");
    assert.equal((await t.engine.state(callId)).phase, "paying", "the second link is still open");
  });

  it("claims a cancel before the provider is asked, so a resume never texts the link being closed (T12)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const send = t.messages.sendText.bind(t.messages);
    let failText = true;
    t.messages.sendText = async (input) => {
      if (input.purpose === "payment_link" && failText) throw new Error("carrier down");
      return send(input);
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    failText = false;
    // Past any lease, so the cancel goes ahead as it did before this fix too.
    t.clock.advance(61_000);
    let resumed: unknown = null;
    const expire = t.payments.expireLink.bind(t.payments);
    let first = true;
    t.payments.expireLink = async (input) => {
      if (first) {
        first = false;
        resumed = await t.engine.requestPayment(callId, request).then(
          () => "texted",
          (e: unknown) => e,
        );
      }
      return expire(input);
    };
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, "pay_1"), { paymentId: "pay_1", status: "expired" });
    assert.ok(rejects("precondition_failed", /closed while its link was created/)(resumed), String(resumed));
    assert.deepEqual(linkTexts(t), [], "the link being closed was never texted");
  });

  it("keeps a close that failed at the provider retryable, with no sender taking over meanwhile (T12)", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    const send = t.messages.sendText.bind(t.messages);
    let failText = true;
    t.messages.sendText = async (input) => {
      if (input.purpose === "payment_link" && failText) throw new Error("carrier down");
      return send(input);
    };
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    failText = false;
    const expire = t.payments.expireLink.bind(t.payments);
    let down = true;
    t.payments.expireLink = async (input) => {
      if (down) throw new Error("provider down");
      return expire(input);
    };
    await assert.rejects(t.engine.cancelPaymentLink(callId, "pay_1"), /provider down/);
    down = false;
    await assert.rejects(t.engine.requestPayment(callId, request), rejects("precondition_failed", /closed while its link was created/));
    assert.deepEqual(linkTexts(t), []);
    assert.deepEqual(await t.engine.cancelPaymentLink(callId, "pay_1"), { paymentId: "pay_1", status: "expired" });
  });
});

describe("L1 review: access codes", () => {
  it("keeps every spent code's ledger entry retryable when an append fails, and the codes never open again (T1)", async () => {
    class FlakyLedger extends MemoryAuditLedger {
      failures = 0;
      override async append(input: AuditInput) {
        if (this.failures > 0) {
          this.failures -= 1;
          throw new Error("ledger down");
        }
        return super.append(input);
      }
    }
    const clock = new FixedClock();
    const texts = new FakeMessageSender();
    const store = new MemoryAccessCodeStore();
    const ledger = new FlakyLedger();
    const accessSigner = generateTestSigner("gate-key-1");
    const codes = accessCodes({ key: "access-code-key-not-a-secret", signer: accessSigner, store, ledger, messages: texts as MessageSender, limits: new MemoryCodeStore(), clock, maxWrongGuesses: 1 });
    const config: FlowConfig = testConfig((c) => {
      c.policy.scopes["entry.open"] = 2;
      c.modules.gate = { settings: { targets: [{ id: "side-door", controller: "keypad", ref: "keypad-1" }] } };
    });
    const t = setup({ clock, config, adapters: { access: { lobby: new FakeAccessController(), keypad: codes.controller }, accessSigner, ledger } });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const issued: string[] = [];
    for (let i = 0; i < 2; i++) {
      const { callId } = await t.engine.startCall({});
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
      assert.equal((await codes.issue(t.engine, callId, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
      issued.push(/door code: (\d{8})/.exec(texts.sent.at(-1)!.body)![1]!);
      clock.advance(61_000);
    }
    const door = { workspaceId: "ws_test", audience: "keypad", target: "keypad-1" };
    const spentEntries = async () => (await ledger.list()).filter((e) => e.event === "access.code_spent").length;
    // One wrong guess spends both codes; the first entry fails to append.
    ledger.failures = 1;
    await assert.rejects(codes.redeem({ ...door, code: "00000000" }), /ledger down/);
    assert.equal(await spentEntries(), 1, "the second code's entry was still appended");
    assert.equal(store.size, 1, "the first is held, spent, until its entry is written");
    // Neither code opens anything, and the next wrong guess writes the entry that failed.
    for (const code of issued) assert.deepEqual(await codes.redeem({ ...door, code }), { ok: false });
    assert.equal(await spentEntries(), 2);
    assert.equal(store.size, 0);
  });
});

describe("L1 review: disputes", () => {
  const dispute = (patch: Partial<DisputeOutcome> = {}): DisputeOutcome => ({ disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: "pi_1", status: "warning_needs_response", amountMinor: 15000, currency: "cad", ...patch });

  async function paidCall() {
    const t = setup({ adapters: { payments: new FakePaymentLinks() } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
    return { t, callId };
  }

  it("never lets a stale inquiry snapshot reopen a closed one, so refunds stay open (T13)", async () => {
    const { t, callId } = await paidCall();
    assert.equal((await t.engine.applyDisputeOutcome(dispute({ status: "warning_closed" }))).applied, true);
    // The older warning_needs_response event arrives after: no time on either, so by its stage.
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute()), { applied: false });
    assert.equal((await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" })).status, "succeeded");
  });

  it("orders dispute events by the provider's time when both carry one, and by stage on a tie (T13)", async () => {
    const { t, callId } = await paidCall();
    const at = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
    assert.equal((await t.engine.applyDisputeOutcome(dispute({ status: "warning_closed", occurredAt: at(20) }))).applied, true);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "warning_under_review", occurredAt: at(10) })), { applied: false }, "older");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "warning_under_review", occurredAt: at(20) })), { applied: false }, "the same second, an earlier stage");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "warning_under_review", occurredAt: at(30) })), { applied: true, callId, status: "warning_under_review" }, "newer, whatever its stage");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "needs_response", occurredAt: at(30) })), { applied: true, callId, status: "needs_response" }, "the same second, a later stage");
    for (const occurredAt of ["yesterday", 7]) {
      await assert.rejects(t.engine.applyDisputeOutcome(dispute({ occurredAt: occurredAt as string })), rejects("invalid_input"), String(occurredAt));
    }
  });

  it("carries a Stripe dispute event's created time, and refuses one that is not Unix seconds (T13)", () => {
    const object = { id: "dp_1", object: "dispute", charge: "ch_1", payment_intent: "pi_1", status: "warning_closed", amount: 15000, currency: "cad" };
    const body = (extra: Record<string, unknown>) => JSON.stringify({ id: "evt_1", type: "charge.dispute.closed", livemode: false, data: { object }, ...extra });
    const parsed = parseStripeEvent(body({ created: 1767225600 }));
    assert.equal(parsed?.kind === "dispute" ? parsed.outcome.occurredAt : null, "2026-01-01T00:00:00.000Z");
    const plain = parseStripeEvent(body({}));
    assert.ok(plain?.kind === "dispute" && !("occurredAt" in plain.outcome), "none without a created time");
    for (const created of [-1, 1.5, "1767225600", null]) assert.equal(parseStripeEvent(body({ created })), null, String(created));
  });
});
