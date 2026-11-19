// L1 integration review (PR #129), round 2: each case is a finding from CodeRabbit's re-review of
// the integrated branch, or one of the design decisions taken on it, and each test failed before
// its fix.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AccessController, AuditInput, CodeStore, MessageSender, UnlockResult } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAccessCodeStore, accessCodes } from "../src/gate/codes.ts";
import type { DisputeOutcome } from "../src/pay/refunds.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { FakeAccessController, FakeMessageSender, FakePaymentLinks, FixedClock, MemoryCodeStore, SequentialIds, generateTestSigner } from "../src/testing/index.ts";
import { parseStripeEvent } from "../src/webhooks/stripe.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, confirmAmount, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

/** A ledger that can be told to refuse the next appends. */
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

/** A door controller that can withdraw a grant, and records each request to. */
class RevocableDoor extends FakeAccessController {
  readonly revoked: Array<{ grantId: string; callId: string; idempotencyKey: string }> = [];
  failRevoke = false;
  async revoke(input: Parameters<NonNullable<AccessController["revoke"]>>[0]): Promise<void> {
    if (this.failRevoke) throw new Error("door offline");
    this.revoked.push({ grantId: input.grant.grantId, callId: input.callId, idempotencyKey: input.idempotencyKey });
  }
}

const doors = [
  { id: "front-door", controller: "lobby", ref: "door-1" },
  { id: "side-door", controller: "keypad", ref: "keypad-1" },
  { id: "back-door", controller: "keypad", ref: "keypad-2" },
];

function codesWorld(options: { limits?: CodeStore; ids?: { next(prefix: string): string }; lobby?: AccessController; maxWrongGuesses?: number } = {}) {
  const clock = new FixedClock();
  const texts = new FakeMessageSender();
  const store = new MemoryAccessCodeStore();
  const ledger = new FlakyLedger();
  const accessSigner = generateTestSigner("gate-key-1");
  const codes = accessCodes({
    key: "access-code-key-not-a-secret",
    signer: accessSigner,
    store,
    ledger,
    messages: texts as MessageSender,
    limits: options.limits ?? new MemoryCodeStore(),
    clock,
    maxWrongGuesses: options.maxWrongGuesses ?? 1,
  });
  const lobby = options.lobby ?? new FakeAccessController();
  const config: FlowConfig = testConfig((c) => {
    c.policy.scopes["entry.open"] = 2;
    c.modules.gate = { settings: { targets: structuredClone(doors) } };
  });
  const t = setup({ clock, config, ...(options.ids === undefined ? {} : { ids: options.ids }), adapters: { access: { lobby, keypad: codes.controller }, accessSigner, ledger } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const call = async () => {
    const { callId } = await t.engine.startCall({});
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    return callId;
  };
  const lastCode = () => /door code: (\d{8})/.exec(texts.sent.at(-1)!.body)![1]!;
  const events = async (name: string) => (await ledger.list()).filter((e) => e.event === name);
  return { ...t, clock, texts, store, ledger, codes, lobby, call, lastCode, events };
}

const keypad = (ref: string) => ({ workspaceId: "ws_test", audience: "keypad", target: ref });

describe("L1 review round 2: access codes", () => {
  it("refuses to issue a code for a target a live door controller works, before anything is reserved", async () => {
    const w = codesWorld();
    const callId = await w.call();
    await assert.rejects(w.codes.issue(w.engine, callId, { target: "front-door" }), rejects("invalid_input", /not worked by that controller/));
    assert.equal((w.lobby as FakeAccessController).received.length, 0, "the lobby door was never asked");
    assert.deepEqual(await w.engine.accessGrants(callId), []);
    assert.equal((await w.codes.issue(w.engine, callId, { target: "side-door" })).status, "delivered");
  });

  it("settles a limiter that fails before the text as refused, so the call can end", async () => {
    const limits = new MemoryCodeStore();
    limits.take = async () => {
      throw new Error("limits store down");
    };
    const w = codesWorld({ limits });
    const callId = await w.call();
    assert.equal((await w.codes.issue(w.engine, callId, { target: "side-door" })).status, "refused");
    assert.deepEqual((await w.events("access.refused")).map((e) => e.detail.reason), ["send_limit_unavailable"]);
    assert.equal(w.texts.sent.length, 0);
    await w.engine.endCall(callId);
    assert.equal((await w.engine.state(callId)).phase, "ended");
  });

  it("keeps two calls' codes apart when they share a grant id: their spent entries and their revokes", async () => {
    const seq = new SequentialIds();
    const w = codesWorld({ ids: { next: (prefix) => (prefix === "acc" ? "acc_1" : seq.next(prefix)) } });
    const first = await w.call();
    assert.equal((await w.codes.issue(w.engine, first, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    w.clock.advance(61_000);
    const second = await w.call();
    assert.equal((await w.codes.issue(w.engine, second, { target: "back-door", lifetimeSeconds: 600 })).status, "delivered");
    const backCode = w.lastCode();
    // A wrong guess at the side door spends the first call's code only.
    assert.deepEqual(await w.codes.redeem({ ...keypad("keypad-1"), code: "00000000" }), { ok: false });
    assert.equal((await w.codes.redeem({ ...keypad("keypad-2"), code: backCode })).ok, true, "the other call's code still opens its door");
    // Two calls' codes at one door, spent together: two entries, one per call.
    w.clock.advance(61_000);
    const third = await w.call();
    assert.equal((await w.codes.issue(w.engine, third, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    w.clock.advance(61_000);
    const fourth = await w.call();
    assert.equal((await w.codes.issue(w.engine, fourth, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    await w.codes.redeem({ ...keypad("keypad-1"), code: "00000000" });
    assert.deepEqual((await w.events("access.code_spent")).map((e) => e.callId), [first, third, fourth]);
    // A host's revoke for one call leaves another call's code under the same grant id.
    w.clock.advance(61_000);
    const fifth = await w.call();
    await w.codes.issue(w.engine, fifth, { target: "back-door", lifetimeSeconds: 600 });
    const fifthCode = w.lastCode();
    w.clock.advance(61_000);
    const sixth = await w.call();
    await w.codes.issue(w.engine, sixth, { target: "side-door", lifetimeSeconds: 600 });
    await w.codes.revoke("ws_test", "acc_1", sixth);
    assert.equal((await w.codes.redeem({ ...keypad("keypad-2"), code: fifthCode })).ok, true);
  });

  it("writes a spent code's entry that failed when the call ends, and on the engine's sweep, with no further wrong guess", async () => {
    const w = codesWorld();
    const callId = await w.call();
    await w.codes.issue(w.engine, callId, { target: "side-door", lifetimeSeconds: 600 });
    w.ledger.failures = 1;
    await assert.rejects(w.codes.redeem({ ...keypad("keypad-1"), code: "00000000" }), /ledger down/);
    assert.equal(w.store.size, 1, "held, spent");
    // The end of the call writes it, before the receipt's head.
    await w.engine.endCall(callId);
    assert.deepEqual((await w.events("access.code_spent")).map((e) => e.callId), [callId]);
    assert.equal(w.store.size, 0);
    // A code spent after its call ended: the sweep writes it, and says when it could not.
    w.clock.advance(61_000);
    const next = await w.call();
    assert.equal((await w.codes.issue(w.engine, next, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    await w.engine.endCall(next);
    w.ledger.failures = 1;
    await assert.rejects(w.codes.redeem({ ...keypad("keypad-1"), code: "00000000" }), /ledger down/);
    w.ledger.failures = 1;
    assert.deepEqual(await w.engine.sweepAccess(), { failed: ["keypad"] });
    assert.deepEqual(await w.engine.sweepAccess(), { failed: [] });
    assert.deepEqual((await w.events("access.code_spent")).map((e) => e.callId), [callId, next]);
    assert.equal(w.store.size, 0);
    // A flush that fails at the end of a call never stops the end.
    w.clock.advance(61_000);
    const third = await w.call();
    assert.equal((await w.codes.issue(w.engine, third, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    w.ledger.failures = 1;
    await assert.rejects(w.codes.redeem({ ...keypad("keypad-1"), code: "00000000" }), /ledger down/);
    const flush = w.codes.controller.flush!;
    w.codes.controller.flush = async () => {
      throw new Error("store down");
    };
    await w.engine.endCall(third);
    assert.equal((await w.engine.state(third)).phase, "ended");
    w.codes.controller.flush = flush;
    assert.deepEqual(await w.engine.sweepAccess(), { failed: [] });
    // An engine without access controllers (Gate off) sweeps nothing, and ends its calls as before.
    const plain = setup({ config: testConfig((c) => void delete (c.modules as Record<string, unknown>).gate), adapters: { access: undefined } as never });
    assert.deepEqual(await plain.engine.sweepAccess(), { failed: [] });
    const id = await verifiedCall(plain);
    await plain.engine.endCall(id);
    assert.equal((await plain.engine.state(id)).phase, "ended");
  });

  it("takes a texted code back when the call is tainted, so it opens nothing", async () => {
    const w = codesWorld();
    const callId = await w.call();
    assert.equal((await w.codes.issue(w.engine, callId, { target: "side-door", lifetimeSeconds: 600 })).status, "delivered");
    const code = w.lastCode();
    await w.engine.markUntrusted(callId, "webhook_reply");
    assert.deepEqual((await w.events("access.tainted")).map((e) => [e.detail.status, e.detail.revocable]), [["delivered", true]]);
    assert.deepEqual((await w.events("access.revoked")).map((e) => e.detail.outcome), ["revoked"]);
    assert.deepEqual(await w.codes.redeem({ ...keypad("keypad-1"), code }), { ok: false });
  });

  it("never texts a code to a call tainted while the code was being stored", async () => {
    const limits = new MemoryCodeStore();
    const w = codesWorld({ limits });
    const take = limits.take.bind(limits);
    let callId = "";
    limits.take = async (input) => {
      await w.engine.markUntrusted(callId, "webhook_reply");
      return take(input);
    };
    callId = await w.call();
    assert.equal((await w.codes.issue(w.engine, callId, { target: "side-door" })).status, "refused");
    assert.deepEqual((await w.events("access.refused")).map((e) => e.detail.reason), ["not_authorized"]);
    assert.equal(w.texts.sent.length, 0);
    assert.equal(w.store.size, 0);
  });
});

describe("L1 review round 2: a taint while a grant is in flight (T3)", () => {
  /** A grant held at its door until released, with a taint landing meanwhile. */
  async function taintInFlight(lobby: FakeAccessController) {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let entered!: () => void;
    const atDoor = new Promise<void>((r) => (entered = r));
    const unlock = lobby.unlock.bind(lobby);
    lobby.unlock = async (input): Promise<UnlockResult> => {
      entered();
      await held;
      return unlock(input);
    };
    const w = codesWorld({ lobby });
    const callId = await w.call();
    const granted = w.engine.grantAccess(callId, { target: "front-door" });
    await atDoor;
    await w.engine.markUntrusted(callId, "webhook_reply");
    release();
    assert.equal((await granted).status, "delivered", "a grant already on its way is not pulled back");
    return { w, callId };
  }

  it("ledgers the taint against the grant and asks a controller that can to withdraw it, once", async () => {
    const door = new RevocableDoor();
    const { w, callId } = await taintInFlight(door);
    assert.deepEqual((await w.events("access.tainted")).map((e) => [e.detail.grantId, e.detail.status, e.detail.revocable]), [["acc_1", "reserved", true]]);
    assert.deepEqual(door.revoked, [{ grantId: "acc_1", callId, idempotencyKey: JSON.stringify(["ws_test", callId, "acc_1", "revoke"]) }]);
    assert.deepEqual((await w.events("access.revoked")).map((e) => e.detail), [{ grantId: "acc_1", outcome: "revoked" }]);
    // A revoke that fails is recorded as failed; the taint stands.
    const failing = new RevocableDoor();
    failing.failRevoke = true;
    const second = await taintInFlight(failing);
    assert.deepEqual((await second.w.events("access.revoked")).map((e) => e.detail.outcome), ["failed"]);
    assert.equal(await second.w.engine.authorize(second.callId, "entry.open"), false);
  });

  it("ledgers the taint against the grant when the controller cannot withdraw it, and asks nothing", async () => {
    const { w } = await taintInFlight(new FakeAccessController());
    assert.deepEqual((await w.events("access.tainted")).map((e) => [e.detail.status, e.detail.revocable]), [["reserved", false]]);
    assert.deepEqual(await w.events("access.revoked"), []);
    // A grant no longer live (expired, refused or failed) is not written down with a later taint.
    const callId = await w.call();
    w.clock.advance(3_600_000);
    await w.engine.markUntrusted(callId, "webhook_reply");
    assert.equal((await w.events("access.tainted")).length, 1);
    // Nor on a call without Gate.
    const plain = setup();
    const id = await verifiedCall(plain);
    await plain.engine.markUntrusted(id, "webhook_reply");
    assert.deepEqual((await plain.ledger.list()).filter((e) => e.event === "access.tainted"), []);
  });
});

/** A session store that runs a hook on each write, and one after a reference is bound. */
class WatchedStore extends MemorySessionStore {
  onWrite: ((record: JsonValue) => void) | null = null;
  afterBind: (() => void) | null = null;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
    this.onWrite?.(r);
    return super.compareAndSet(w, c, v, r);
  }
  override async bindRef(w: string, ref: string, callId: string) {
    const out = await super.bindRef(w, ref, callId);
    this.afterBind?.();
    return out;
  }
}

describe("L1 review round 2: Paylink", () => {
  it("checks a saved step's mode against this engine's payments adapter, and keeps the read-back", async () => {
    const sessions = new MemorySessionStore();
    const pay = { type: "paylink.request", amountMinor: 5000, currency: "cad", description: "Deposit", amountSource: "price_list" };
    const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
    const config = (step: Record<string, unknown>) =>
      testConfig((c) => {
        c.modules.paylink = { settings: { mode: "platform", connectedAccountId: "acct_business_1" } as never };
        c.flows = { deposit: { steps: [verify as never, step as never] } };
      });
    const a = setup({ config: config({ ...pay, mode: "connect" }), adapters: { sessions } });
    const b = setup({ config: config(pay), adapters: { sessions, payments: new FakePaymentLinks({ modes: ["platform"] }) } });
    a.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await a.engine.startCall({ flow: "deposit" });
    await a.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await a.engine.submitKeypad(callId, { dob: DOB });
    await a.engine.checkCarrier(callId);
    await a.engine.finishVerification(callId);
    await confirmAmount(a.engine, callId);
    await assert.rejects(b.engine.requestPayment(callId), rejects("invalid_input", /does not take connect payments/));
    assert.deepEqual(b.payments.created, [], "no link under a mode this adapter does not have");
    // The confirmed read-back is still there: the engine that has connect sends it.
    assert.equal((await a.engine.requestPayment(callId)).status, "open");
    assert.equal(a.payments.created[0]!.mode, "connect");
  });

  async function slowRenewal(answer: "expired" | "not_open") {
    const sessions = new WatchedStore();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    if (answer === "not_open") t.payments.expireLink = async () => ({ state: "not_open" });
    // The renewal is the first write after the reference is bound: the link's life runs out during it.
    sessions.afterBind = () => {
      sessions.afterBind = null;
      sessions.onWrite = () => {
        sessions.onWrite = null;
        t.clock.advance(31 * 60_000);
      };
    };
    const refused = await t.engine.requestPayment(callId, request).then(
      () => null,
      (e: unknown) => e,
    );
    return { t, callId, refused };
  }

  it("checks the link's life again after the lease is renewed, and never texts a link about to die", async () => {
    const { t, callId, refused } = await slowRenewal("expired");
    assert.ok(rejects("precondition_failed", /could not be texted in time and was expired; request a new payment/)(refused), String(refused));
    assert.deepEqual(t.messages.sent.filter((m) => m.purpose === "payment_link"), []);
    assert.notEqual((await t.engine.state(callId)).phase, "paying", "settled expired: a new payment may follow");
  });

  it("tells the host to wait for the provider's outcome when the late link is no longer open there", async () => {
    const { t, callId, refused } = await slowRenewal("not_open");
    assert.ok(rejects("precondition_failed", /no longer open; wait for its outcome/)(refused), String(refused));
    assert.equal((await t.engine.state(callId)).phase, "paying", "the payment waits for its webhook");
    assert.deepEqual(t.messages.sent.filter((m) => m.purpose === "payment_link"), []);
  });
});

describe("L1 review round 2: refunds and disputes", () => {
  async function paidCall() {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, request);
    await t.engine.requestPayment(callId, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid", paymentIntentId: "pi_1" });
    return { t, callId };
  }

  it("gives a numbered refund's saved result back when the host lost the answer, and never refunds twice", async () => {
    const { t, callId } = await paidCall();
    const refund = (patch: Record<string, unknown> = {}) => t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer", amountMinor: 5000, sequence: 1, ...patch });
    const first = await refund();
    // The host's answer was lost after the commit: the same request again.
    assert.deepEqual(await refund(), first);
    assert.equal(t.payments.refunds.length, 1, "refunded once");
    // The second refund is a new number, with a key of its own.
    assert.equal((await refund({ sequence: 2 })).refundedMinor, 10000);
    assert.equal(t.payments.refunds.length, 2);
    await assert.rejects(refund({ sequence: 1, amountMinor: 4000 }), rejects("invalid_input", /another amount/));
    await assert.rejects(refund({ sequence: 4 }), rejects("invalid_input", /next refund of this payment is number 3/));
    for (const sequence of [0, 1.5, "1"]) await assert.rejects(refund({ sequence }), rejects("invalid_input", /sequence/), String(sequence));
  });

  it("resumes a numbered refund whose provider answer was lost with the same key, and refunds once", async () => {
    const { t, callId } = await paidCall();
    const keys: string[] = [];
    const real = t.payments.refund.bind(t.payments);
    let lose = true;
    t.payments.refund = async (input) => {
      keys.push(input.idempotencyKey);
      const answer = await real(input);
      if (lose) throw new Error("answer lost");
      return answer;
    };
    const refund = (sequence: number) => t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer", amountMinor: 5000, sequence });
    await assert.rejects(refund(1), /answer lost/);
    await assert.rejects(refund(2), rejects("precondition_failed", /refund number 1 of this payment is still being sent/));
    lose = false;
    assert.equal((await refund(1)).status, "succeeded");
    assert.deepEqual(keys, [JSON.stringify(["ws_test", callId, "pay_1", "refund", "1"]), JSON.stringify(["ws_test", callId, "pay_1", "refund", "1"])]);
    assert.equal(t.payments.refunds.length, 1, "refunded once");
  });

  it("moves a dispute's time on for a newer snapshot that changes nothing, so an older one cannot reopen it", async () => {
    const { t, callId } = await paidCall();
    const at = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
    const dispute = (patch: Partial<DisputeOutcome>): DisputeOutcome => ({ disputeId: "dp_1", chargeId: "ch_1", paymentIntentId: "pi_1", status: "warning_closed", amountMinor: 15000, currency: "cad", ...patch });
    assert.equal((await t.engine.applyDisputeOutcome(dispute({ occurredAt: at(10) }))).applied, true);
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ occurredAt: at(30) })), { applied: false }, "nothing changed, no entry");
    assert.deepEqual(await t.engine.applyDisputeOutcome(dispute({ status: "warning_needs_response", occurredAt: at(20) })), { applied: false }, "older than t30");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.disputed").length, 1);
    assert.equal((await t.engine.refundPayment({ callId, paymentId: "pay_1", reason: "requested_by_customer" })).status, "succeeded");
  });

  it("refuses a dispute event whose created time is past what a Date can hold, without throwing", () => {
    const object = { id: "dp_1", object: "dispute", charge: "ch_1", payment_intent: "pi_1", status: "warning_closed", amount: 15000, currency: "cad" };
    const body = (created: number) => JSON.stringify({ id: "evt_1", type: "charge.dispute.closed", livemode: false, created, data: { object } });
    assert.equal(parseStripeEvent(body(8_640_000_000_001)), null);
    assert.equal(parseStripeEvent(body(8_640_000_000_000))?.kind, "dispute", "the last second a Date holds");
  });
});
