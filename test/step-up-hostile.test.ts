// Hostile-pass regressions for #107 (VER-13, risk-based step-up): every attack held.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { StepUpRule } from "../src/core/policy.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, confirmAmount, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

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


describe("hostile #107: step-up", () => {
  it("U1: a signal raised while the payment link is being created stops the text, and the rule is ledgered by name only", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    const create = t.payments.createLink.bind(t.payments);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    t.payments.createLink = async (input) => {
      await held;
      return create(input);
    };
    await confirmAmount(t.engine, callId, payment(15000));
    const asked = t.engine.requestPayment(callId, payment(15000));
    await new Promise((resolve) => setImmediate(resolve));
    await t.engine.raiseSignal(callId, "caller_flagged");
    release();
    await assert.rejects(asked, rejects("scope_denied"));
    assert.equal(t.messages.sent.length, 0, "no link texted");
    const ledger = JSON.stringify(await t.ledger.list());
    assert.deepEqual(await entries(t, "policy.step_up"), [{ rule: "caller_flagged", scope: "payment.request", level: 3 }]);
    assert.equal(ledger.includes("50000"), false, "no threshold in the ledger");
  });

  it("U2: a grant issued before a signal is held to the raised minimum, on another engine too, and the signal outlives a new verification", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), true);
    const other = setup({ config: stepUpConfig(), adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records } });
    await other.engine.raiseSignal(callId, "caller_flagged");
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), false);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, reset: true } as never);
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), false, "the signal is never cleared");
  });

  it("U3: signals the policy does not use, of any shape, are refused and change nothing", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    for (const signal of ["unknown", "", "CALLER_FLAGGED", "caller_flagged ", "__proto__", "constructor", "caller_flagged\uD800", 1, null, ["caller_flagged"], { toString: () => "caller_flagged" }]) {
      await assert.rejects(t.engine.raiseSignal(callId, signal as string), rejects("invalid_input"), String(signal));
    }
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), true);
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.raiseSignal(callId, "caller_flagged"), rejects("invalid_transition"));
  });

  it("U4: after hours holds at the local midnight and the window edges, across the DST change", async () => {
    for (const [iso, over] of [
      ["2026-01-01T22:59:00Z", false], // 17:59 local
      ["2026-01-01T23:00:00Z", true], // 18:00
      ["2026-01-02T05:00:00Z", true], // 00:00
      ["2026-01-02T12:59:00Z", true], // 07:59
      ["2026-01-02T13:00:00Z", false], // 08:00
      ["2026-03-08T07:30:00Z", true], // 03:30 EDT, just after the clocks go forward
      ["2026-11-01T05:30:00Z", true], // 01:30 EDT, before the clocks go back
      ["2026-11-01T06:30:00Z", true], // 01:30 EST, the repeated hour
    ] as const) {
      const t = setup({ config: stepUpConfig() });
      at(t, iso);
      t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
      const callId = await level2Call(t);
      assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), !over, iso);
    }
  });

  it("U5: amounts the host passes in odd shapes count as over the threshold", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t);
    for (const amount of [{ amountMinor: Number.NaN, currency: "cad" }, { amountMinor: Infinity, currency: "cad" }, { amountMinor: "100", currency: "cad" }, { amountMinor: 100, currency: "CAD" }, { amountMinor: 100 }, null, "100", []]) {
      assert.equal(await t.engine.authorize(callId, "payment.request", amount as never), false, JSON.stringify(amount));
    }
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: -1, currency: "cad" }), true, "a negative amount is under (requestPayment refuses it on its own)");
  });

  it("U5b: in a flow, an explicit null amount is unknown (over every amount rule), never the step's amount", async () => {
    const t = stepUpSetup();
    const callId = await level2Call(t, "deposit");
    // The current step moves 15000, under the 50000 rule: left out, the step's amount is judged.
    assert.equal(await t.engine.authorize(callId, "payment.request"), true, "omitted: the step's amount");
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 100, currency: "cad" }), true, "a known amount under the rule");
    assert.equal(await t.engine.authorize(callId, "payment.request", { amountMinor: 60000, currency: "cad" }), false, "a known amount over the rule");
    assert.equal(await t.engine.authorize(callId, "payment.request", null as never), false, "null from an untyped host: an unknown amount");
  });
});
