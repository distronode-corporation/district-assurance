// Risk-based step-up (VER-13): the policy's rules raise a scope's minimum for a large amount, after
// hours in the business's time zone, or on a signal the host raised, and only ever raise it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import type { StepUpRule } from "../src/core/policy.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const RULES: StepUpRule[] = [
  { name: "large_payment", scope: "payment.request", level: 3, amountOverMinor: { cad: 50000 } },
  { name: "after_hours", scope: "payment.request", level: 3, localTime: { from: "18:00", to: "08:00" } },
  { name: "caller_flagged", scope: "payment.request", level: 3, signal: "caller_flagged" },
  { name: "intake_flagged", scope: "intake.file", level: 2, signal: "intake_flagged" },
];

const pay = { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" } as const;
const payment = (amountMinor: number, currency = "cad") => ({ amountMinor, currency, description: "Repair", amountSource: "price_list" as const });

function stepUpConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.timeZone = "America/Toronto";
    c.policy.stepUp = structuredClone(RULES);
    c.flows = {
      deposit: {
        steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] }, pay, { type: "trace.receipt" }],
      },
    };
    patch(c);
  });
}

/** Moves the test clock to an instant (the fixed clock only moves forward). */
function at(t: TestEngine, iso: string): void {
  t.clock.advance(Date.parse(iso) - t.clock.now().getTime());
}

/** A test engine at 10:00 in Toronto (15:00 UTC), inside business hours. */
function stepUpSetup(config = stepUpConfig()): TestEngine {
  const t = setup({ config });
  at(t, "2026-01-01T15:00:00Z");
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return t;
}

/** A call verified to level 2 by keypad and a carrier match, outside any flow, or in `flow`. */
async function level2Call(t: TestEngine, flow?: string): Promise<string> {
  const { callId } = await t.engine.startCall(flow === undefined ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

async function entries(t: TestEngine, event: string) {
  return (await t.ledger.list()).filter((e) => e.event === event).map((e) => e.detail);
}

describe("step-up on the amount", () => {
  it("raises payment.request for an amount over the threshold, and only then", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 50000, currency: "cad" }), true, "at the threshold is not over it");
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 50001, currency: "cad" }), false);
    await assert.rejects(t.engine.requestPayment(callId, payment(50001)), rejects("scope_denied", /step-up rule\(s\) large_payment/));
    assert.equal(t.payments.created.length, 0);
    await t.engine.requestPayment(callId, payment(50000));
    assert.equal(t.payments.created[0]!.amountMinor, 50000);
    // The rule is on the ledger by name, once, and never with the amount.
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
  });

  it("lets a level 3 grant through, and records the rule that raised the minimum", async () => {
    const t = stepUpSetup();
    const callId = await verifiedCall(t);
    await t.engine.requestPayment(callId, payment(90000));
    assert.equal(t.payments.created[0]!.amountMinor, 90000);
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 90000, currency: "cad" }), true);
    assert.equal((await entries(t, "policy.step_up")).length, 1, "a rule is written once per call");
  });

  it("counts a currency the rule does not list, or an amount not given, as over", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "usd" }), false);
    assert.equal(await t.engine.authorize(callId, "payment.request"), false, "outside a flow, no amount counts as over");
    // A host passing something that is not an amount gets a refusal, never a TypeError or a coerced string.
    for (const bad of [null, "100", { amountMinor: "100", currency: "cad" }, { amountMinor: 100, currency: 1 }]) {
      assert.equal(await t.engine.authorize(callId, "payment.request", bad as never), false, JSON.stringify(bad));
    }
    await assert.rejects(t.engine.requestPayment(callId, payment(100, "usd")), rejects("scope_denied", /large_payment/));
    // The authorize read wrote the rule once; a scope with no rule writes nothing.
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
    assert.equal(await t.engine.authorize(callId, "status.read"), true);
    await t.engine.endCall(callId);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 1, currency: "cad" }), false);
  });
});

describe("step-up on the time of day", () => {
  /** Whether a call verified to level 2 at `iso` may request a small payment then. */
  async function smallPaymentAt(iso: string): Promise<boolean> {
    const t = stepUpSetup();
    at(t, iso);
    const callId = await level2Call(t);
    return t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" });
  }

  it("follows the business's time zone, not UTC, across the evening and the morning", async () => {
    // 22:30 UTC is after hours in UTC, but 17:30 in Toronto: business hours.
    assert.equal(await smallPaymentAt("2026-01-01T22:30:00Z"), true);
    // 23:30 UTC is 18:30 in Toronto: after hours.
    assert.equal(await smallPaymentAt("2026-01-01T23:30:00Z"), false);
    // 02:00 UTC on the 2nd is 21:00 on the 1st in Toronto: still after hours, across the date line.
    assert.equal(await smallPaymentAt("2026-01-02T02:00:00Z"), false);
    // 12:59 UTC is 07:59 in Toronto, the last minute of the window; 13:00 UTC is 08:00, open again.
    assert.equal(await smallPaymentAt("2026-01-02T12:59:00Z"), false);
    assert.equal(await smallPaymentAt("2026-01-02T13:00:00Z"), true);
    // In summer Toronto is UTC-4: 22:30 UTC is 18:30 there.
    assert.equal(await smallPaymentAt("2026-07-01T22:30:00Z"), false);
  });

  it("applies to a grant issued before the window opened", async () => {
    const t = stepUpSetup();
    at(t, "2026-01-01T22:55:00Z");
    const callId = await level2Call(t);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), true);
    t.clock.advance(6 * 60_000);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), false);
    await assert.rejects(t.engine.requestPayment(callId, payment(100)), rejects("scope_denied", /after_hours/));
  });
});

describe("step-up on a host signal", () => {
  it("raises a scope once the host's code raises the signal, for a grant already issued", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), true);
    await t.engine.raiseSignal(callId, "caller_flagged");
    await t.engine.raiseSignal(callId, "caller_flagged");
    assert.deepEqual(await entries(t, "signal.raised"), [{ signal: "caller_flagged" }], "raised once");
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), false);
    await assert.rejects(t.engine.requestPayment(callId, payment(100)), rejects("scope_denied", /caller_flagged/));
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "caller_flagged", scope: "payment.request", level: 3 }]);
  });

  it("is never cleared: not by verifying again, not by a new subject", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal(await t.engine.authorize(callId, "intake.file"), true);
    await t.engine.raiseSignal(callId, "intake_flagged");
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("scope_denied"));
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal(await t.engine.authorize(callId, "intake.file"), false, "level 1 no longer files once the signal is up");
  });

  it("records the rule when it is why an intake is refused", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    await t.engine.raiseSignal(callId, "intake_flagged");
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("scope_denied", /intake_flagged/));
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "intake_flagged", scope: "intake.file", level: 2 }], "on the ledger without an authorize call");
  });

  it("refuses to file an intake opened before the signal, naming the rule", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.raiseSignal(callId, "intake_flagged");
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice" }), rejects("scope_denied", /intake_flagged/));
    assert.equal((await t.ledger.list()).some((e) => e.event === "intake.confirmed"), false);
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "intake_flagged", scope: "intake.file", level: 2 }]);
  });

  for (const [name, interrupt, why] of [
    ["a signal is raised", (t: TestEngine, callId: string) => t.engine.raiseSignal(callId, "caller_flagged"), /caller_flagged/],
    ["the call is tainted", (t: TestEngine, callId: string) => t.engine.markUntrusted(callId, "crm note"), /does not cover payment.request$/],
  ] as const) {
    it(`never texts a payment link when ${name} while the link is being created`, async () => {
      const t = stepUpSetup();
      const callId = await level2Call(t);
      const create = t.payments.createLink.bind(t.payments);
      let release: () => void = () => undefined;
      const held = new Promise<void>((resolve) => (release = resolve));
      let calls = 0;
      t.payments.createLink = async (input) => {
        calls++;
        await held;
        return create(input);
      };
      const pending = t.engine.requestPayment(callId, payment(100));
      while (calls === 0) await new Promise((resolve) => setImmediate(resolve));
      await interrupt(t, callId);
      release();
      await assert.rejects(pending, rejects("scope_denied", why));
      assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 0, "no link texted");
      assert.deepEqual(await entries(t, "payment.link_sent"), []);
      assert.equal(t.payments.created.length, 1, "the link exists, and its id is kept for a resume");
    });
  }

  it("refuses a signal no rule uses, and a signal on an ended call", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    await assert.rejects(t.engine.raiseSignal(callId, "not_a_rule"), rejects("invalid_input", /no step-up rule uses that signal/));
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.raiseSignal(callId, "caller_flagged"), rejects("invalid_transition"));
    const plain = setup();
    const other = await verifiedCall(plain);
    await assert.rejects(plain.engine.raiseSignal(other, "caller_flagged"), rejects("invalid_input"));
  });
});

describe("step-up in a flow", () => {
  it("fails a payment step that the time of day raised above the flow's verification, naming the rule", async () => {
    const t = stepUpSetup();
    at(t, "2026-01-01T22:55:00Z");
    const callId = await level2Call(t, "deposit");
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "paylink.request");
    assert.equal(await t.engine.authorize(callId, "payment.request"), true, "the step's own amount is the default");
    t.clock.advance(6 * 60_000);
    await assert.rejects(t.engine.requestPayment(callId), rejects("scope_denied", /after_hours/));
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.deepEqual((await entries(t, "flow.failed")).at(-1), { flow: "deposit", step: 1, type: "paylink.request", rules: ["after_hours"] });
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "after_hours", scope: "payment.request", level: 3 }]);
    assert.equal(t.payments.created.length, 0);
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /has failed/));
  });

  it("fails the step on entry when a signal raised during verification lifts its scope", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.raiseSignal(callId, "caller_flagged");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    const position = await t.engine.flowPosition(callId);
    assert.deepEqual([position!.status, position!.index], ["failed", 1]);
    assert.deepEqual((await entries(t, "flow.failed")).at(-1)!.rules, ["caller_flagged"]);
  });

  it("fails the current step when a signal is raised on it", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t, "deposit");
    await t.engine.raiseSignal(callId, "caller_flagged");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.deepEqual((await entries(t, "flow.failed")).at(-1), { flow: "deposit", step: 1, type: "paylink.request", rules: ["caller_flagged"] });
  });

  it("passes a step whose verification reaches the raised level", async () => {
    const t = stepUpSetup(
      stepUpConfig((c) => {
        c.flows.deposit!.steps = [{ type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"], scopes: ["payment.request"] }, { ...pay, amountMinor: 90000 }];
      }),
    );
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
    await t.engine.finishVerification(callId);
    await t.engine.requestPayment(callId);
    assert.equal(t.payments.created[0]!.amountMinor, 90000);
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
  });

  it("validateConfig refuses a flow whose step amount is sure to trigger an amount rule above its verification", async () => {
    const t = stepUpSetup();
    const big = stepUpConfig((c) => {
      c.flows.deposit!.steps[1] = { ...pay, amountMinor: 50001 };
      c.flows.usd = { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"] }, { ...pay, currency: "usd" }] };
      c.flows.small = { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"] }, { ...pay, amountMinor: 50000 }] };
      c.flows.high = { steps: [{ type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"] }, { ...pay, amountMinor: 90000 }] };
    });
    assert.deepEqual(validateConfig(big, t.engine.registry), [
      "flows.deposit.steps[1] (paylink.request): its amount triggers the step-up rule large_payment, which raises payment.request to level 3, but the flow has verified to level 2 at this point",
      "flows.usd.steps[1] (paylink.request): its amount triggers the step-up rule large_payment, which raises payment.request to level 3, but the flow has verified to level 2 at this point",
    ]);
  });

  it("holds an outside module's step to its raised minimum, and fails the flow on it", async () => {
    const lookup: AssuranceModule = {
      manifest: {
        name: "loyalty",
        version: "1",
        summary: "Looks up the caller's loyalty tier.",
        provides: { factors: [], steps: ["loyalty.greet", "loyalty.lookup"], outcomes: [] },
        scopes: { grants: [], needs: { "loyalty.lookup": "status.read" } },
        adapters: [],
      },
      validateSettings: () => [],
      requiredAdapters: () => [],
      validateStep: () => [],
      initCall: () => ({ greeted: false, tier: null }),
      enterStep: () => null,
      stepStatus: (step, view) => {
        const slice = view.slice as { greeted: boolean; tier: string | null };
        return (step.type === "loyalty.greet" ? slice.greeted : slice.tier !== null) ? "complete" : "pending";
      },
    };
    const config = stepUpConfig((c) => {
      c.policy.stepUp!.push({ name: "status_after_hours", scope: "status.read", level: 2, localTime: { from: "18:00", to: "08:00" } });
      c.modules.loyalty = {};
      c.flows = { lookup: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "loyalty.greet" }, { type: "loyalty.lookup" }] } };
    });
    const t = setup({ config, modules: [lookup] });
    at(t, "2026-01-01T22:58:00Z");
    const { callId } = await t.engine.startCall({ flow: "lookup" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    // A step that needs no scope is not held to one.
    await t.engine.updateModule(callId, "loyalty", () => ({ greeted: true, tier: null }));
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "loyalty.lookup");
    assert.deepEqual(await t.engine.updateModule(callId, "loyalty", (slice) => slice), { greeted: true, tier: null });
    t.clock.advance(3 * 60_000);
    await assert.rejects(
      t.engine.updateModule(callId, "loyalty", () => ({ greeted: true, tier: "gold" })),
      rejects("scope_denied", /status_after_hours/),
    );
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.deepEqual((await entries(t, "flow.failed")).at(-1)!.rules, ["status_after_hours"]);
  });
});

describe("step-up on stored calls and ordinary denials", () => {
  it("loads a call stored before step-up rules existed with no signals and no rules applied", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const legacy = structuredClone(stored.record) as Record<string, unknown>;
    delete legacy.signals;
    delete legacy.stepUps;
    assert.ok((await t.sessions.compareAndSet("ws_test", callId, stored.version, legacy as never)).ok);
    await t.engine.flushLedger(callId);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 50001, currency: "cad" }), false);
    await t.engine.raiseSignal(callId, "intake_flagged");
    assert.deepEqual(await entries(t, "signal.raised"), [{ signal: "intake_flagged" }]);
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
  });

  it("keeps a rule's first step-up on the ledger when the grant is refused without it too", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.requestPayment(callId, payment(90000)), rejects("scope_denied", /step-up rule\(s\) large_payment also apply/));
    assert.equal(t.payments.created.length, 0);
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "large_payment", scope: "payment.request", level: 3 }]);
    // A denial no rule affects still throws at once, naming no rule.
    await assert.rejects(t.engine.requestPayment(callId, payment(100)), rejects("scope_denied", /^the grant does not cover payment\.request$/));
  });
});

describe("step-up: the amount is read once", () => {
  it("judges the amount it type-checked, never a smaller one swapped in after the check", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    let reads = 0;
    const amount = {
      currency: "cad",
      get amountMinor() {
        reads += 1;
        return reads === 1 ? 90000 : 100;
      },
    };
    assert.equal(await t.engine.authorize(callId, "payment.request", amount), false, "90,000 is over the 50,000 rule");
  });
});
