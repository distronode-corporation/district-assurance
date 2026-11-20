// Overlapping retries and mid-call changes (CodeRabbit's third pass on PR 3): each case is one
// process racing another, or a config changing under a call.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, confirmAmount, DOB, PHONE_ON_FILE, heard, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

class FlakyLedger extends MemoryAuditLedger {
  failures = 0;
  override async append(input: AuditInput) {
    if (this.failures > 0) {
      this.failures--;
      throw new Error("ledger down");
    }
    return super.append(input);
  }
}

describe("flows attached to a running call", () => {
  it("refuses a flow whose step the call cannot run with what it kept", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    t.engine.configure(
      testConfig((c) => {
        const repair = (c.modules.dossier!.settings as { forms: unknown[] }).forms[0];
        c.modules.dossier = { settings: { forms: [repair, { formId: "warranty", version: "1", fields: [{ key: "x", label: { en: "X", fr: "X" }, type: "text", required: true }] }] } as never };
        c.modules.trace = { settings: { wordings: [{ purpose: "marketing", version: "1", text: { en: "a", fr: "b" } }] } };
        c.flows = {
          w: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "dossier.collect", form: "warranty" }] },
          m: { steps: [{ type: "trace.consent", purpose: "marketing" }] },
          r: { steps: [{ type: "trace.receipt" }, { type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "dossier.collect", form: "repair" }] },
        };
      }),
    );
    await assert.rejects(t.engine.startFlow(callId, "w"), rejects("precondition_failed", /no form warranty/));
    await assert.rejects(t.engine.startFlow(callId, "m"), rejects("precondition_failed", /no wording for marketing/));
    assert.equal(await t.engine.flowPosition(callId), null, "nothing was saved");
    assert.equal((await t.engine.startFlow(callId, "r")).step!.type, "badge.verify", "the call's own form still runs");
  });

  it("refuses a flow whose outside module was turned off while the call was read", async () => {
    const loyalty = { manifest: { name: "loyalty", version: "1", summary: "x", provides: { factors: [], steps: ["loyalty.lookup"], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] }, validateSettings: () => [], requiredAdapters: () => [], validateStep: () => [], initCall: () => ({}), enterStep: () => null, stepStatus: () => "pending" as const };
    const t = setup({ modules: [loyalty] });
    t.engine.configure(testConfig((c) => {
      c.modules.loyalty = {};
      c.flows = { l: { steps: [{ type: "loyalty.lookup" }] } };
    }));
    const { callId } = await t.engine.startCall();
    const get = t.sessions.get.bind(t.sessions);
    let once = true;
    t.sessions.get = async (w, c) => {
      if (once) {
        once = false;
        t.engine.configure(testConfig((x) => (x.modules.loyalty = { enabled: false })));
      }
      return get(w, c);
    };
    await assert.rejects(t.engine.startFlow(callId, "l"), rejects("module_disabled", /loyalty module is turned off/));
    assert.equal(await t.engine.flowPosition(callId), null);
  });

  it("refuses a flow whose module was removed while the call was read", async () => {
    const t = setup({ config: testConfig((c) => (c.flows = { p: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"] }, { type: "dossier.collect", form: "repair" }] } })) });
    const { callId } = await t.engine.startCall();
    const get = t.sessions.get.bind(t.sessions);
    let once = true;
    t.sessions.get = async (w, c) => {
      if (once) {
        once = false;
        t.engine.configure(testConfig((x) => (x.modules.dossier = { enabled: false })));
        t.engine.remove("dossier");
      }
      return get(w, c);
    };
    await assert.rejects(t.engine.startFlow(callId, "p"), rejects("module_disabled", /no installed module provides dossier.collect/));
  });
});

describe("overlapping retries", () => {
  it("publishes one receipt and keeps one ledger head when two endCall retries overlap", async () => {
    const signer = generateTestSigner();
    let fail = true;
    const flaky = { keyId: signer.keyId, algorithm: signer.algorithm, publicJwk: () => signer.publicJwk(), sign: async (p: Uint8Array) => {
      if (fail) throw new Error("kms down");
      return signer.sign(p);
    } };
    const t = setup({ adapters: { signer: flaky } });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.endCall(callId), /kms down/);
    fail = false;
    const [a, b] = await Promise.all([t.engine.endCall(callId), t.engine.endCall(callId)]);
    assert.deepEqual(a, b, "both retries get the stored receipt");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "receipt.issued").length, 1);
  });

  it("records a payment link's delivery once when two resumes overlap", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    const request = { amountMinor: 100, currency: "cad", description: "x", amountSource: "price_list" as const };
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await confirmAmount(t.engine, callId, request);
    await assert.rejects(t.engine.requestPayment(callId, request), /carrier down/);
    t.messages.sendText = send;
    // One resume takes the text; the other finds its lease live and is refused, never sending a
    // second text over it (L1 review, T10).
    const [a, b] = await Promise.allSettled([t.engine.requestPayment(callId, request), t.engine.requestPayment(callId, request)]);
    assert.equal(a.status, "fulfilled");
    assert.ok(b.status === "rejected" && rejects("precondition_failed", /another process is texting/)(b.reason));
    assert.equal(t.messages.sent.filter((m) => m.purpose === "payment_link").length, 1, "texted once");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "payment.link_sent").length, 1);
  });

  it("returns the filed record to a confirmation retried after its ledger entry failed", async () => {
    const ledger = new FlakyLedger();
    const t = setup({ adapters: { ledger } });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    ledger.failures = 1;
    const readBack = await heard(t, callId);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /ledger down/);
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack });
    assert.equal(record.recordId, "rec_1");
    assert.equal((await ledger.list()).filter((e) => e.event === "intake.confirmed").length, 1, "appended once, by the retry");
    assert.deepEqual((await t.engine.state(callId)).recordIds, ["rec_1"]);
  });

  it("refuses to end a call while a record is being filed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    let ended: unknown = null;
    t.records.putIntakeRecord = async (record) => {
      ended = await t.engine.endCall(callId).catch((e: unknown) => e);
      return put(record);
    };
    await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    assert.ok(rejects("precondition_failed", /being filed/)(ended));
    const receipt = await t.engine.endCall(callId);
    assert.deepEqual(receipt!.body.records.map((r) => r.recordId), ["rec_1"]);
  });

  it("keeps the filing guard when Dossier is removed while a record is being filed", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    let ended: unknown = null;
    t.records.putIntakeRecord = async (record) => {
      t.engine.configure(testConfig((c) => (c.modules.dossier = { enabled: false })));
      t.engine.remove("dossier");
      ended = await t.engine.endCall(callId).catch((e: unknown) => e);
      return put(record);
    };
    await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    assert.ok(rejects("precondition_failed", /being filed/)(ended));
    assert.deepEqual((await t.engine.endCall(callId))!.body.records.map((r) => r.recordId), ["rec_1"]);
  });

  it("queues a copy of an outside module's detail, checked as queued", async () => {
    const t = setup();
    const loyalty = { manifest: { name: "loyalty", version: "1", summary: "x", provides: { factors: [], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] }, validateSettings: () => [], requiredAdapters: () => [], validateStep: () => [], initCall: () => ({}), enterStep: () => null, stepStatus: () => "pending" as const };
    t.engine.use(loyalty);
    t.engine.configure(testConfig((c) => (c.modules.loyalty = {})));
    const { callId } = await t.engine.startCall();
    await t.engine.updateModule(callId, "loyalty", (slice, view) => {
      const detail = { note: "ok" };
      view.emit("noted", detail);
      detail.note = "4242 4242 4242 4242";
      return slice;
    });
    await t.engine.markUntrusted(callId, "x");
    const entries = await t.ledger.list();
    assert.deepEqual(entries.find((e) => e.event === "module.event")!.detail, { module: "loyalty", event: "noted", detail: { note: "ok" } });
    assert.equal(entries.at(-1)!.event, "session.tainted", "later writes go on");
  });

  it("scopes provider idempotency keys to the workspace", async () => {
    const a = setup();
    const b = setup({ workspaceId: "ws_other", adapters: { payments: a.payments, messages: a.messages, identity: a.identity } });
    b.records.putSubject("ws_other", (await a.records.getSubject("ws_test", (await import("../src/verify/knowledge.ts")).subjectKeyFor("test-knowledge-key-not-a-secret", ACCOUNT)))!);
    for (const t of [a, b]) {
      t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
      const { callId } = await t.engine.startCall({ callId: "c1" });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
      await confirmAmount(t.engine, callId, { amountMinor: t === a ? 100 : 200, currency: "cad", description: "x", amountSource: "price_list" });
      await t.engine.requestPayment(callId, { amountMinor: t === a ? 100 : 200, currency: "cad", description: "x", amountSource: "price_list" });
    }
    assert.deepEqual(a.payments.created.map((p) => p.amountMinor), [100, 200], "two links, one per workspace");
  });
});
