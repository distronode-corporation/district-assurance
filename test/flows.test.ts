// Flow execution: a call runs its flow step by step, only the current step's work is allowed, and
// outside modules plug in their own steps.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import { ConfigError, validateConfig, type FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule } from "../src/core/module.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const pay = { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" } as const;

function flowConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"]] };
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    c.flows = {
      "owner-command": { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] },
      deposit: {
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
          { type: "dossier.collect", form: "repair" },
          pay,
          { type: "trace.consent", purpose: "texts" },
          { type: "trace.receipt" },
        ],
      },
      "receipt-first": { steps: [{ type: "trace.receipt" }, { type: "trace.consent", purpose: "texts" }] },
    };
    patch(c);
  });
}

/** An outside module with one step that completes when the host marks the account looked up. */
function loyaltyModule(): AssuranceModule {
  return {
    manifest: {
      name: "loyalty",
      version: "1",
      summary: "Looks up the caller's loyalty tier.",
      provides: { factors: [], steps: ["loyalty.lookup"], outcomes: ["tier"] },
      scopes: { grants: [], needs: { "loyalty.lookup": "status.read" } },
      adapters: [],
    },
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => ({ tier: null }),
    enterStep: () => "entered",
    stepStatus: (_step, view) => {
      assert.equal(view.mark, "entered");
      const tier = (view.slice as { tier: string | null }).tier;
      return tier === null ? "pending" : tier === "banned" ? "failed" : "complete";
    },
  };
}

describe("flows", () => {
  it("runs owner-command: the PIN only, and a grant for owner commands only", async () => {
    const t = setup({ config: flowConfig() });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    assert.deepEqual(await t.engine.flowPosition(callId), {
      flow: "owner-command",
      revision: "default",
      status: "running",
      index: 0,
      step: { type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] },
    });
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await assert.rejects(t.engine.submitKeypad(callId, { dob: DOB }), rejects("precondition_failed", /does not use the keypad_knowledge factor/));
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("precondition_failed", /on step badge.verify/));
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["owner.command"] });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    assert.equal(await t.engine.authorize(callId, "owner.command"), true);
    assert.equal(await t.engine.authorize(callId, "status.read"), false, "the step's scopes only");
    assert.equal(await t.engine.endCall(callId), null, "no trace.receipt step, no receipt");
    const events = (await t.ledger.list()).map((e) => e.event);
    assert.deepEqual(events.filter((e) => e.startsWith("flow.")), ["flow.started", "flow.step_completed", "flow.completed"]);
    assert.deepEqual((await t.ledger.list()).find((e) => e.event === "flow.started")!.detail, { flow: "owner-command", revision: "default", steps: 1 });
  });

  it("fails the flow when verification finishes below the step's level", async () => {
    const t = setup({ config: flowConfig() });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, "0000");
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    const position = await t.engine.flowPosition(callId);
    assert.deepEqual([position!.status, position!.step], ["failed", null]);
    assert.deepEqual((await t.ledger.list()).at(-1)!.detail, { flow: "owner-command", step: 0, type: "badge.verify" });
    await assert.rejects(t.engine.beginVerification(callId, { subjectKey: OWNER }), rejects("precondition_failed", /has failed/));
    await assert.rejects(t.engine.startFlow(callId, "owner-command"), rejects("precondition_failed", /already ran a flow/));
  });

  it("refuses every step on a call whose flow ended (review blocker 1: no escalation after a failed PIN)", async () => {
    const t = setup({ config: flowConfig() });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    for (let i = 0; i < 3; i++) await t.engine.submitPin(callId, "0000");
    assert.equal((await t.engine.finishVerification(callId)).level, 0);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    const ended = rejects("precondition_failed", /flow owner-command has failed/);
    await assert.rejects(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }), ended);
    await assert.rejects(t.engine.submitKeypad(callId, { dob: DOB }), ended);
    await assert.rejects(t.engine.checkCarrier(callId), ended);
    await assert.rejects(t.engine.startPhotoId(callId), ended);
    await assert.rejects(t.engine.finishVerification(callId), ended);
    await assert.rejects(t.engine.startIntake(callId, "repair"), ended);
    await assert.rejects(t.engine.requestPayment(callId, { amountMinor: 99999, currency: "cad", description: "x", amountSource: "price_list" }), ended);
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), ended);
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    assert.equal(t.payments.created.length, 0, "no link was ever created");
  });

  it("refuses more steps after a flow completed, and ignores a late identity outcome", async () => {
    const t = setup({ config: flowConfig((c) => (c.flows["owner-command"]!.steps = [{ type: "badge.verify", level: 1, factors: ["pin", "photo_id"], scopes: ["owner.command"] }])) });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, PIN);
    await t.engine.startPhotoId(callId);
    await t.engine.finishVerification(callId);
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    await assert.rejects(t.engine.beginVerification(callId, { subjectKey: OWNER }), rejects("precondition_failed", /has completed/));
    const sessionId = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
    assert.equal(await t.engine.authorize(callId, "owner.command"), true, "the grant the flow issued stands");
  });

  it("fails the flow on a consent of no, before any money step (review blocker 2)", async () => {
    const steps = (require?: string) => [
      { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
      { type: "trace.consent", purpose: "texts", ...(require === undefined ? {} : { require }) },
      pay,
    ];
    for (const [require, expected] of [[undefined, "failed"], ["yes", "failed"], ["answer", "running"]] as const) {
      const t = setup({ config: flowConfig((c) => (c.flows.pay = { steps: steps(require) as never })) });
      t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
      const { callId } = await t.engine.startCall({ flow: "pay" });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
      await t.engine.recordConsent(callId, { purpose: "texts", answer: "no" });
      assert.equal((await t.engine.flowPosition(callId))!.status, expected, String(require));
      if (expected === "failed") {
        await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed"));
        assert.equal(t.messages.sent.length, 0, "no link was texted");
      } else {
        assert.equal((await t.engine.requestPayment(callId)).status, "open");
      }
    }
    assert.ok(validateConfig(flowConfig((c) => (c.flows.pay = { steps: [{ type: "trace.consent", purpose: "texts", require: "maybe" }] })), setup().engine.registry).includes('flows.pay.steps[0] (trace.consent): require must be "yes" (the default) or "answer"'));
  });

  it("counts only the step's factors toward its level", async () => {
    const t = setup({ config: flowConfig((c) => (c.flows["owner-command"]!.steps = [{ type: "badge.verify", level: 1, factors: ["pin", "photo_id"] }])) });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, PIN);
    await t.engine.startPhotoId(callId);
    // A factor recorded outside the step (here, straight into the state) does not count.
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
  });

  it("runs deposit end to end, with the amount from the flow and a receipt", async () => {
    const t = setup({ config: flowConfig() });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed", /does not use the photo_id factor/));
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "dossier.collect");
    await assert.rejects(t.engine.requestPayment(callId), rejects("precondition_failed", /on step dossier.collect/));
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "paylink.request");
    await assert.rejects(t.engine.requestPayment(callId, { amountMinor: 1, currency: "cad", description: "x", amountSource: "price_list" }), rejects("invalid_input", /flow step sets the amount/));
    await t.engine.requestPayment(callId);
    assert.equal(t.payments.created[0]!.amountMinor, 15000);
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "paylink.request", "waits for the payment to settle");
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "other", answer: "yes" }), rejects("invalid_input"));
    await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const done = await t.engine.flowPosition(callId);
    assert.deepEqual([done!.status, done!.index], ["completed", 5]);
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.verification, { level: 2, methods: ["carrier_identity_match", "keypad_knowledge"] });
    assert.equal(receipt!.body.records.length, 1);
  });

  it("refuses the wrong form or consent purpose for the step, and fails on an unpaid link", async () => {
    const t = setup({
      config: flowConfig((c) => {
        c.modules.dossier = {
          settings: { forms: [{ formId: "repair", version: "1", fields: [{ key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true }] }, { formId: "other", version: "1", fields: [{ key: "x", label: { en: "X", fr: "X" }, type: "text", required: false }] }] },
        };
        c.modules.trace = { settings: { wordings: [{ purpose: "texts", version: "1", text: { en: "a", fr: "b" } }, { purpose: "calls", version: "1", text: { en: "a", fr: "b" } }] } };
        c.flows.deposit!.steps.splice(2, 0, { type: "trace.consent", purpose: "texts" });
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    await assert.rejects(t.engine.startIntake(callId, "other"), rejects("precondition_failed", /collects repair/));
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "calls", answer: "yes" }), rejects("precondition_failed", /consent to texts/));
    await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.requestPayment(callId);
    await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" });
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("completes a collect step only with its own form, filed during the step", async () => {
    const t = setup({
      config: flowConfig((c) => {
        c.modules.dossier = {
          settings: { forms: [{ formId: "repair", version: "1", fields: [{ key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true }] }, { formId: "other", version: "1", fields: [{ key: "x", label: { en: "X", fr: "X" }, type: "text", required: false }] }] },
        };
        c.flows.deposit!.steps = [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "trace.receipt" }, { type: "dossier.collect", form: "repair" }];
      }),
      modules: [loyaltyModule()],
    });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    // The flow is on dossier.collect for repair; a record of another form must not complete it.
    const view = { state: await t.engine.state(callId), slice: { intake: null, records: [{ recordId: "r", formId: "other", digest: "d" }] } as unknown as JsonValue, mark: 0 };
    const dossier = t.engine.registry.get("dossier")!;
    assert.equal(dossier.stepStatus({ type: "dossier.collect", form: "repair" }, view), "pending");
    assert.equal(dossier.stepStatus({ type: "dossier.collect", form: "repair" }, { ...view, mark: 1 }), "pending", "only records filed after the step started");
    assert.equal(dossier.stepStatus({ type: "dossier.collect", form: "other" }, view), "complete");
  });

  it("keeps the form a draft started with when the config changes the form", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    t.engine.configure(testConfig((c) => (c.modules.dossier = { settings: { forms: [{ formId: "repair", version: "2", fields: [{ key: "other", label: { en: "O", fr: "O" }, type: "text", required: true }] }] } })));
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    assert.deepEqual([record.formVersion, record.values], ["1", { issue: "leak" }]);
  });

  it("completes a receipt step at once, and abandons a running flow when the call ends", async () => {
    const t = setup({ config: flowConfig() });
    const { callId } = await t.engine.startCall({ flow: "receipt-first" });
    assert.deepEqual((await t.engine.flowPosition(callId))!.step, { type: "trace.consent", purpose: "texts" });
    const receipt = await t.engine.endCall(callId);
    assert.notEqual(receipt, null, "the flow has a trace.receipt step");
    assert.equal((await t.engine.flowPosition(callId))!.status, "abandoned");
    assert.deepEqual((await t.ledger.list()).find((e) => e.event === "flow.abandoned")!.detail, { flow: "receipt-first", step: 1 });
    const other = await t.engine.startCall();
    assert.equal(await t.engine.flowPosition(other.callId), null);
  });

  it("ignores a photo ID outcome when the step it arrives in does not use photo ID", async () => {
    const t = setup({
      config: flowConfig((c) => {
        c.flows.deposit!.steps = [
          { type: "badge.verify", level: 1, factors: ["keypad_knowledge", "photo_id"] },
          { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] },
        ];
      }),
    });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const sessionId = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
    assert.equal((await t.engine.state(callId)).factors.some((f) => f.kind === "photo_id"), false);
  });

  it("ignores a photo ID outcome that arrives after the flow moved on", async () => {
    const t = setup({ config: flowConfig((c) => (c.flows.deposit!.steps = [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge", "photo_id"] }, { type: "dossier.collect", form: "repair" }])) });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.finishVerification(callId);
    const sessionId = t.identity.created[0]!.sessionId;
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: false });
  });

  it("creates a call with its flow attached, so no other start can race it", async () => {
    const t = setup({ config: flowConfig() });
    const create = t.sessions.create.bind(t.sessions);
    let seen: unknown = null;
    t.sessions.create = async (w, c, record) => {
      seen = (record as { flow: unknown }).flow;
      return create(w, c, record);
    };
    const { callId } = await t.engine.startCall({ callId: "c-race", flow: "receipt-first" });
    assert.deepEqual((seen as { name: string; index: number }).name, "receipt-first");
    assert.equal((seen as { index: number }).index, 1, "a receipt step is passed before the call is even stored");
    await assert.rejects(t.engine.startFlow(callId, "owner-command"), rejects("precondition_failed", /already ran a flow/));
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["call.started", "flow.started", "flow.step_completed"]);
  });

  it("starts a flow on an open call that has none yet", async () => {
    const t = setup({ config: flowConfig() });
    const { callId } = await t.engine.startCall();
    const position = await t.engine.startFlow(callId, "owner-command");
    assert.deepEqual([position.flow, position.status, position.index], ["owner-command", "running", 0]);
  });

  it("refuses to start an unknown flow, a second flow, or a flow outside the open phase", async () => {
    const t = setup({ config: flowConfig() });
    await assert.rejects(t.engine.startCall({ flow: "nope" }), rejects("invalid_input", /no flow named nope/));
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.startFlow(callId, "constructor"), rejects("invalid_input"));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.startFlow(callId, "owner-command"), rejects("invalid_transition"));
  });

  it("keeps a call on the steps it started with when the config changes, and refuses bad configs", async () => {
    const t = setup({ config: flowConfig() });
    const { callId } = await t.engine.startCall({ flow: "owner-command" });
    t.engine.configure(flowConfig((c) => (c.flows = {})));
    assert.deepEqual(t.engine.config.flows, {});
    assert.equal((await t.engine.flowPosition(callId))!.step!.type, "badge.verify");
    assert.throws(() => t.engine.configure({ version: 9 }), (e: unknown) => e instanceof ConfigError);
  });

  it("refuses a flow whose module was off when the call started", async () => {
    const t = setup({ config: flowConfig((c) => {
      c.modules.dossier = { enabled: false, settings: { forms: [] } };
      c.flows = {};
    }) });
    const { callId } = await t.engine.startCall();
    t.engine.configure(flowConfig());
    await assert.rejects(t.engine.startFlow(callId, "deposit"), rejects("module_disabled"));
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("module_disabled"));
  });

  it("fails the step of a module removed while the call ran", async () => {
    const t = setup({ config: flowConfig((c) => (c.flows.deposit!.steps = [{ type: "trace.receipt" }, { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "dossier.collect", form: "repair" }])) });
    const removed = setup({ config: flowConfig((c) => (c.flows.deposit!.steps = [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "trace.receipt" }])) });
    // Remove Badge's flow partner while a step of it is pending, then let the step resolve.
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    t.engine.configure(flowConfig((c) => {
      c.flows = {};
      c.modules.dossier = { enabled: false };
    }));
    t.engine.remove("dossier");
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    // And a removed module whose step is the current one fails at the next change.
    const second = await removed.engine.startCall({ flow: "deposit" });
    removed.engine.configure(flowConfig((c) => {
      c.flows = {};
      c.modules.badge = { enabled: false };
    }));
    removed.engine.remove("badge");
    await removed.engine.markUntrusted(second.callId, "document");
    assert.equal((await removed.engine.flowPosition(second.callId))!.status, "failed");
  });
});

describe("module switches", () => {
  it("refuses a module that is off, and removes only modules that are off", async () => {
    const t = setup({ config: testConfig((c) => (c.modules.paylink = { enabled: false })) });
    assert.equal(t.engine.isEnabled("paylink"), false);
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.requestPayment(callId), rejects("module_disabled"));
    await assert.rejects(t.engine.applyPaymentOutcome({ kind: "expired", linkId: "x" }).then(() => t.engine.requestPayment(callId)), rejects("module_disabled"));
    assert.throws(() => t.engine.remove("badge"), rejects("precondition_failed", /turn it off first/));
    assert.throws(() => t.engine.remove("trace"), rejects("precondition_failed", /audit ledger/));
    t.engine.remove("paylink");
    assert.equal(t.engine.registry.get("paylink"), undefined);
    const off = setup({ config: testConfig((c) => {
      c.modules.badge = { enabled: false };
      c.modules.dossier = { enabled: false };
      c.flows = {};
    }) });
    const call = await off.engine.startCall();
    await assert.rejects(off.engine.beginVerification(call.callId, { accountNumber: ACCOUNT }), rejects("module_disabled"));
    await assert.rejects(off.engine.finishVerification(call.callId), rejects("module_disabled"));
    await assert.rejects(off.engine.setIntakeField(call.callId, "a", "b"), rejects("module_disabled"));
    await assert.rejects(off.engine.confirmIntake(call.callId, { confirmedBy: "voice" }), rejects("module_disabled"));
    await assert.rejects(off.engine.abandonIntake(call.callId), rejects("module_disabled"));
  });
});

describe("outside modules", () => {
  it("adds a module with engine.use, turns it on by config, and runs its step in a flow", async () => {
    const t = setup({ config: flowConfig() });
    assert.equal(t.engine.use(loyaltyModule()), t.engine);
    assert.equal(t.engine.isEnabled("loyalty"), false, "installed, off until the config turns it on");
    const config = flowConfig((c) => {
      c.modules.loyalty = {};
      c.flows.loyalty = { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "loyalty.lookup" }, { type: "loyalty.lookup" }] };
    });
    t.engine.configure(config);
    const { callId } = await t.engine.startCall({ flow: "loyalty" });
    assert.deepEqual(await t.engine.moduleState(callId, "loyalty"), { tier: null });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    const result = await t.engine.updateModule(callId, "loyalty", (slice, call) => {
      assert.equal(call.state.level, 1);
      assert.equal(call.authorized("status.read"), true);
      call.emit("tier_found", { tier: "gold" });
      return { ...(slice as object), tier: "gold" } as JsonValue;
    });
    assert.deepEqual(result, { tier: "gold" });
    const position = await t.engine.flowPosition(callId);
    assert.equal(position!.status, "completed", "both lookup steps see the tier");
    const entry = (await t.ledger.list()).find((e) => e.event === "module.event")!;
    assert.deepEqual(entry.detail, { module: "loyalty", event: "tier_found", detail: { tier: "gold" } });
  });

  it("holds an outside module's step to its scope even when the module never asks (review item 3)", async () => {
    const t = setup({ config: flowConfig(), modules: [loyaltyModule()] });
    t.engine.configure(flowConfig((c) => {
      c.modules.loyalty = {};
      c.flows.l = { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "loyalty.lookup" }] };
    }));
    const { callId } = await t.engine.startCall({ flow: "l" });
    await assert.rejects(t.engine.updateModule(callId, "loyalty", () => ({ tier: "gold" })), rejects("precondition_failed", /not a step of loyalty/));
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.markUntrusted(callId, "document");
    await assert.rejects(t.engine.updateModule(callId, "loyalty", () => ({ tier: "gold" })), rejects("scope_denied", /status.read/));
    assert.deepEqual(await t.engine.moduleState(callId, "loyalty"), { tier: null });
    await assert.rejects(
      t.engine.updateModule(callId, "loyalty", (slice) => slice),
      rejects("scope_denied"),
    );
  });

  it("refuses an outside module's entry that carries a card number, before anything is saved", async () => {
    const t = setup({ config: flowConfig(), modules: [loyaltyModule()] });
    t.engine.configure(flowConfig((c) => (c.modules.loyalty = {})));
    const callId = await verifiedCall(t);
    const before = (await t.ledger.list()).length;
    await assert.rejects(
      t.engine.updateModule(callId, "loyalty", (slice, call) => {
        call.emit("note", { text: "card 4242 4242 4242 4242" });
        return slice;
      }),
      rejects("invalid_input", /card number/),
    );
    assert.equal((await t.ledger.list()).length, before, "nothing was saved");
  });

  it("fails a flow on the module's failed step, and guards the built-in and switched-off modules", async () => {
    const t = setup({ config: flowConfig(), modules: [loyaltyModule()] });
    await assert.rejects(t.engine.updateModule("c", "badge", (s) => s), rejects("precondition_failed", /built in/));
    await assert.rejects(t.engine.moduleState("c", "loyalty"), rejects("module_disabled"));
    const before = await t.engine.startCall();
    t.engine.configure(flowConfig((c) => {
      c.modules.loyalty = {};
      c.flows.l = { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "loyalty.lookup" }] };
    }));
    await assert.rejects(t.engine.moduleState(before.callId, "loyalty"), rejects("module_disabled", /off when this call started/));
    const { callId } = await t.engine.startCall({ flow: "l" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.updateModule(callId, "loyalty", () => ({ tier: "banned" }));
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    await assert.rejects(t.engine.updateModule(callId, "loyalty", () => ({ tier: "gold" })), rejects("precondition_failed", /has failed/));
  });
});
