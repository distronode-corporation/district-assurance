import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { MemoryAuditLedger, GENESIS_HASH } from "../src/prove/ledger.ts";
import { verifyReceipt, type SignedReceipt } from "../src/prove/receipt.ts";
import {
  entryWorkspace,
  monthlyReport,
  reportCsv,
  reportPayload,
  reportRows,
  signReportCsv,
  signReportJson,
  verifyReport,
  type MonthlyReport,
  type SignedReport,
} from "../src/prove/report.ts";
import { generateTestSigner } from "../src/testing/fakes.ts";
import { createTestEngine, TEST_KNOWLEDGE_KEY, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const DAY = 24 * 60 * 60 * 1000;
const request = { amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" as const };

/** A call that pays (or not) one link: verified to level 3, a link, an outcome, then the end. */
async function payingCall(t: TestEngine, amount: { amountMinor: number; currency: string }, outcome: "paid" | "failed" | "expired" | null): Promise<void> {
  const callId = await verifiedCall(t);
  await t.engine.requestPayment(callId, { ...request, ...amount });
  const linkId = t.payments.created.at(-1)!.linkId;
  if (outcome === "paid") await t.engine.applyPaymentOutcome({ kind: "completed", linkId, paymentStatus: "paid" });
  if (outcome === "failed") await t.engine.applyPaymentOutcome({ kind: "async_failed", linkId });
  await t.engine.endCall(callId);
  if (outcome === "expired") await t.engine.applyPaymentOutcome({ kind: "expired", linkId });
}

/** A call whose keypad entry is wrong: one failed factor, a verification at level 0. */
async function refusedCall(t: TestEngine): Promise<void> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: "19990101" });
  await t.engine.finishVerification(callId);
  await t.engine.endCall(callId);
}

function emptyReport(patch: Partial<MonthlyReport> = {}): MonthlyReport {
  return {
    v: 1,
    document: "monthly_report",
    workspaceId: "ws_test",
    month: "2026-01",
    timeZone: "UTC",
    ledger: { seq: 0, hash: GENESIS_HASH },
    calls: { started: 0, ended: 0 },
    verifications: { byLevel: { "0": 0, "1": 0, "2": 0, "3": 0 }, failedFactors: 0 },
    payments: {
      sent: { count: 0, totals: {} },
      paid: { count: 0, totals: {} },
      failed: { count: 0, totals: {} },
      expired: { count: 0, totals: {} },
      unmatched: 0,
    },
    consents: {},
    lockouts: 0,
    access: { issued: 0, refused: 0, revoked: 0 },
    unattributed: 0,
    ...patch,
  };
}

const entry = (eventId: string | undefined, event: string, at: string, detail: AuditInput["detail"] = {}): AuditInput => ({
  ...(eventId === undefined ? {} : { eventId }),
  callId: "c1",
  actor: "code",
  event: event as AuditInput["event"],
  at,
  detail,
});

describe("monthly report", () => {
  it("counts a month of fixed-clock calls, with totals by currency", async () => {
    const t = setup();
    const first = await verifiedCall(t);
    await t.engine.recordConsent(first, { purpose: "texts", answer: "yes" });
    await t.engine.requestPayment(first, request);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: "cs_fake_1", paymentStatus: "paid" });
    await t.engine.endCall(first);
    t.clock.advance(DAY);
    await payingCall(t, { amountMinor: 2500, currency: "cad" }, "failed");
    t.clock.advance(DAY);
    await payingCall(t, { amountMinor: 150, currency: "jpy" }, "expired");
    t.clock.advance(DAY);
    await payingCall(t, { amountMinor: 900, currency: "jpy" }, null);
    await refusedCall(t);
    const second = (await t.engine.startCall()).callId;
    await t.engine.recordConsent(second, { purpose: "texts", answer: "no" });
    await t.engine.endCall(second);

    const report = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const head = await t.ledger.head();
    assert.deepEqual(
      report,
      emptyReport({
        ledger: head,
        calls: { started: 6, ended: 6 },
        verifications: { byLevel: { "0": 1, "1": 0, "2": 0, "3": 4 }, failedFactors: 1 },
        payments: {
          sent: { count: 4, totals: { cad: 17500, jpy: 1050 } },
          paid: { count: 1, totals: { cad: 15000 } },
          failed: { count: 1, totals: { cad: 2500 } },
          expired: { count: 1, totals: { jpy: 150 } },
          unmatched: 0,
        },
        consents: { texts: { yes: 1, no: 1 } },
      }),
    );
    assert.equal(report.timeZone, "UTC", "UTC by default");
  });

  it("carries no personal values: no call ids, subjects, numbers or links", async () => {
    const t = setup();
    await payingCall(t, { amountMinor: 15000, currency: "cad" }, "paid");
    const report = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const text = JSON.stringify(report) + reportCsv(report);
    for (const value of ["call_", "pay_", "cs_fake", ACCOUNT, DOB, PHONE_ON_FILE, "https:", "grant_"]) assert.equal(text.includes(value), false, value);
  });

  it("reports a month with no calls as zeros, and an empty ledger the same", async () => {
    const t = setup();
    await payingCall(t, { amountMinor: 15000, currency: "cad" }, "paid");
    const head = await t.ledger.head();
    assert.deepEqual(await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-02" }), emptyReport({ month: "2026-02", ledger: head }));
    assert.deepEqual(await monthlyReport({ ledger: new MemoryAuditLedger(), workspaceId: "ws_test", month: "2026-01" }), emptyReport());
  });

  it("reads the month in the host's time zone, and takes an amount from a link sent the month before", async () => {
    // 2026-02-01T03:00Z is still January in Toronto (UTC-5), and already February in UTC.
    const t = createTestEngine({ config: testConfig() });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    t.clock.advance(31 * DAY + 3 * 60 * 60 * 1000);
    await payingCall(t, { amountMinor: 15000, currency: "cad" }, null);
    t.clock.advance(3 * 60 * 60 * 1000);
    await t.engine.applyPaymentOutcome({ kind: "expired", linkId: "cs_fake_1" });

    const toronto = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01", timeZone: "America/Toronto" });
    assert.deepEqual([toronto.calls.started, toronto.payments.sent, toronto.payments.expired.count], [1, { count: 1, totals: { cad: 15000 } }, 0]);
    const torontoFeb = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-02", timeZone: "America/Toronto" });
    assert.deepEqual([torontoFeb.calls.started, torontoFeb.payments.sent.count, torontoFeb.payments.expired], [0, 0, { count: 1, totals: { cad: 15000 } }]);
    const utcJan = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    assert.equal(utcJan.calls.started, 0);
    const utcFeb = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-02", timeZone: "UTC" });
    assert.deepEqual([utcFeb.calls.started, utcFeb.payments.expired.count], [1, 1]);
  });

  it("picks entries by the workspace in their eventId on a shared ledger", async () => {
    const ledger = new MemoryAuditLedger();
    const engines = ["ws_a", "ws_b"].map((workspaceId) => {
      const t = createTestEngine({ config: testConfig(), workspaceId, adapters: { ledger } });
      t.records.putSubject(workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
      return t;
    });
    const [a, b] = engines as [TestEngine, TestEngine];
    // Both engines count ids from 1, so their calls and payments have the same ids.
    await payingCall(a, { amountMinor: 15000, currency: "cad" }, "paid");
    await payingCall(b, { amountMinor: 700, currency: "usd" }, "paid");
    await refusedCall(b);
    await ledger.append(entry(undefined, "call.started", "2026-01-01T00:00:00.000Z"));

    const reportA = await monthlyReport({ ledger, workspaceId: "ws_a", month: "2026-01" });
    const reportB = await monthlyReport({ ledger, workspaceId: "ws_b", month: "2026-01" });
    assert.deepEqual([reportA.calls.started, reportA.payments.paid, reportA.verifications.byLevel], [1, { count: 1, totals: { cad: 15000 } }, { "0": 0, "1": 0, "2": 0, "3": 1 }]);
    assert.deepEqual([reportB.calls.started, reportB.payments.paid, reportB.verifications.byLevel], [2, { count: 1, totals: { usd: 700 } }, { "0": 1, "1": 0, "2": 0, "3": 1 }]);
    assert.deepEqual([reportA.unattributed, reportB.unattributed], [1, 1], "reported, never counted");
    const none = await monthlyReport({ ledger, workspaceId: "ws_c", month: "2026-01" });
    assert.deepEqual(none, emptyReport({ workspaceId: "ws_c", ledger: await ledger.head(), unattributed: 1 }));
  });

  it("reports an entry without a workspace as unattributed, only in its month", async () => {
    const ledger = new MemoryAuditLedger();
    const jan = "2026-01-15T00:00:00.000Z";
    for (const eventId of [undefined, "not json", '{"workspace":"ws_test"}', "[1, 2]", '["", "c1", 1, 0]']) await ledger.append(entry(eventId, "call.started", jan));
    await ledger.append(entry(undefined, "call.started", "2026-02-15T00:00:00.000Z"));
    const report = await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
    assert.deepEqual([report.calls.started, report.unattributed], [0, 5]);
    assert.equal(entryWorkspace({ eventId: '["ws_test","c1",1,0]' }), "ws_test");
    assert.equal(entryWorkspace({}), null);
  });

  it("counts lockouts and access grants once those events exist, and an unmatched settlement apart", async () => {
    const ledger = new MemoryAuditLedger();
    const at = "2026-01-10T12:00:00.000Z";
    let n = 0;
    const add = (event: string, detail: AuditInput["detail"] = {}) => ledger.append(entry(JSON.stringify(["ws_test", "c1", 1, n++]), event, at, detail));
    await add("verification.locked", { scope: "subject", kind: "pin" });
    await add("verification.locked", { scope: "number", kind: "pin" });
    // The names Gate (GAT-1) writes; `gate.*` names are nobody's and count nowhere.
    for (const event of ["access.issued", "access.issued", "access.refused", "access.revoked", "access.delivered", "gate.granted"]) await add(event);
    await add("payment.settled", { paymentId: "pay_9", status: "paid" });
    // A link that is known, with a settlement status that is not a tally (a property name included).
    await add("payment.link_sent", { paymentId: "pay_1", amountMinor: 500, currency: "cad" });
    for (const status of ["sent", "unmatched", "canceled"]) await add("payment.settled", { paymentId: "pay_1", status });
    await add("verification.finished", { level: 4, methods: [], discounted: false });
    await add("verification.factor", { kind: "pin", passed: true });
    await add("intake.started", { formId: "repair", version: "1" });
    const report = await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
    assert.equal(report.lockouts, 2);
    assert.deepEqual(report.access, { issued: 2, refused: 1, revoked: 1 });
    assert.equal(report.payments.unmatched, 4);
    assert.deepEqual(report.payments.sent, { count: 1, totals: { cad: 500 } }, "a settlement never counts as sent");
    assert.equal(report.payments.paid.count, 0);
    assert.equal(report.verifications.byLevel["4"], 1);
    assert.equal(report.verifications.failedFactors, 0);
  });

  it("refuses a bad workspace, month, time zone or entry time", async () => {
    const ledger = new MemoryAuditLedger();
    const input = { ledger, workspaceId: "ws_test", month: "2026-01" };
    await assert.rejects(monthlyReport({ ...input, workspaceId: "" }), rejects("invalid_input", /workspaceId/));
    await assert.rejects(monthlyReport({ ...input, workspaceId: 7 as unknown as string }), rejects("invalid_input", /workspaceId/));
    for (const month of ["2026-1", "2026-13", "2026-00", "202601", "2026-01-01"]) await assert.rejects(monthlyReport({ ...input, month }), rejects("invalid_input", /YYYY-MM/), month);
    await assert.rejects(monthlyReport({ ...input, timeZone: "Mars/Olympus" }), rejects("invalid_input", /time zone/));
    await ledger.append(entry(undefined, "call.started", "yesterday"));
    await assert.rejects(monthlyReport(input), rejects("invalid_input", /valid time/));
  });

  it("refuses an entry time that Date.parse would roll into another date, or not in UTC", async () => {
    for (const at of ["2026-02-30T12:00:00.000Z", "2026-01-31T24:00:00.000Z", "2026-01-15T00:00:00.000+05:00", "2026-01-15", "2026-13-01T00:00:00.000Z"]) {
      const ledger = new MemoryAuditLedger();
      await ledger.append(entry(undefined, "call.started", at));
      await assert.rejects(monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" }), rejects("invalid_input", /valid time/), at);
    }
    const ledger = new MemoryAuditLedger();
    await ledger.append(entry(undefined, "call.started", "2026-01-31T23:59:59Z"));
    assert.equal((await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" })).unattributed, 1);
  });

  it("counts a consent purpose named like an Object property as any other", async () => {
    const ledger = new MemoryAuditLedger();
    const at = "2026-01-10T12:00:00.000Z";
    let n = 0;
    for (const [purpose, answer] of [["constructor", "yes"], ["constructor", "no"], ["__proto__", "yes"], ["toString", "no"], ["texts", "yes"]] as const) {
      await ledger.append(entry(JSON.stringify(["ws_test", "c1", 1, n++]), "consent.recorded", at, { purpose, answer }));
    }
    const report = await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
    assert.equal(Object.getPrototypeOf(report.consents), Object.prototype);
    assert.deepEqual(Object.keys(report.consents), ["__proto__", "constructor", "texts", "toString"]);
    assert.deepEqual(report.consents.constructor, { yes: 1, no: 1 });
    assert.deepEqual(Object.getOwnPropertyDescriptor(report.consents, "__proto__")?.value, { yes: 1, no: 0 });
    assert.deepEqual(report.consents.toString, { yes: 0, no: 1 });
    assert.ok(reportCsv(report).includes("consents.constructor.no,1\r\n"));
  });
});

describe("monthly report CSV", () => {
  it("lists every metric as a row, in a fixed order", async () => {
    const t = setup();
    await payingCall(t, { amountMinor: 15000, currency: "cad" }, "paid");
    const report = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const csv = reportCsv(report);
    assert.equal(csv.endsWith("\r\n"), true);
    const lines = csv.split("\r\n").slice(0, -1);
    assert.equal(lines[0], "metric,value");
    assert.equal(lines.length, reportRows(report).length + 1);
    for (const line of ["workspace,ws_test", "month,2026-01", "time_zone,UTC", "calls.started,1", "verifications.level_3,1", "payments.sent.count,1", "payments.sent.total.cad,15000", "payments.paid.total.cad,15000", "unattributed,0"]) {
      assert.ok(lines.includes(line), line);
    }
    const consented = reportRows(emptyReport({ consents: { texts: { yes: 2, no: 1 } } }));
    assert.deepEqual(consented.filter(([m]) => m.startsWith("consents.")), [["consents.texts.yes", 2], ["consents.texts.no", 1]]);
  });

  it("quotes fields with commas, quotes or line breaks, and neutralises formulas", () => {
    const csv = reportCsv(emptyReport({ workspaceId: 'ws "a", b\nc', timeZone: "=cmd()" }));
    assert.ok(csv.includes('workspace,"ws ""a"", b\nc"'));
    assert.ok(csv.includes("time_zone,'=cmd()"));
    assert.ok(reportCsv(emptyReport({ workspaceId: "-1,2" })).includes(`workspace,"'-1,2"`));
  });
});

describe("signed monthly reports", () => {
  it("signs the JSON and the CSV with the receipt signer, and verifies with the public key only", async () => {
    const signer = generateTestSigner("k1");
    const t = setup({ adapters: { signer } });
    await payingCall(t, { amountMinor: 15000, currency: "cad" }, "paid");
    const report = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const keys = t.engine.receiptKeys();
    const json = await signReportJson(signer, report);
    const csv = await signReportCsv(signer, report);
    assert.deepEqual([json.document, json.alg, json.kid, csv.document, csv.csv], ["monthly_report.json", "ES256", "k1", "monthly_report.csv", reportCsv(report)]);
    assert.equal(verifyReport(json, keys), true);
    assert.equal(verifyReport(csv, keys), true);
    assert.equal(new TextDecoder().decode(reportPayload("monthly_report.csv", "x")), "district-assurance signed document v1\nmonthly_report.csv\nx");
  });

  it("fails on any change, a swapped document type, a wrong key or a malformed signature", async () => {
    const signer = generateTestSigner("k1");
    const report = emptyReport({ calls: { started: 3, ended: 3 } });
    const json = await signReportJson(signer, report);
    const csv = await signReportCsv(signer, report);
    const keys = [signer.publicJwk()];
    assert.equal(verifyReport({ ...json, report: { ...report, calls: { started: 4, ended: 3 } } }, keys), false);
    assert.equal(verifyReport({ ...csv, csv: csv.csv.replace("calls.started,3", "calls.started,4") }, keys), false);
    assert.equal(verifyReport({ ...csv, document: "monthly_report.json", report } as SignedReport, keys), false, "a CSV signature is not a JSON one");
    assert.equal(verifyReport({ ...json, document: "monthly_report.csv", csv: canonicalJson(report) } as SignedReport, keys), false, "nor the other way");
    assert.equal(verifyReport({ ...json, document: "monthly_report.pdf" } as unknown as SignedReport, keys), false);
    assert.equal(verifyReport({ ...csv, csv: 7 } as unknown as SignedReport, keys), false);
    assert.equal(verifyReport({ ...json, report: { ...report, extra: undefined } as unknown as MonthlyReport }, keys), false, "never throws");
    assert.equal(verifyReport(json, [generateTestSigner("k1").publicJwk()]), false);
    assert.equal(verifyReport({ ...json, kid: "k2" }, keys), false);
    assert.equal(verifyReport({ ...json, alg: "HS256" as "ES256" }, keys), false);
    assert.equal(verifyReport({ ...json, signature: json.signature.slice(4) }, keys), false);
    assert.equal(verifyReport(null as unknown as SignedReport, keys), false);
    assert.equal(verifyReport(undefined as unknown as SignedReport, keys), false);
    assert.equal(verifyReport(json, null as unknown as typeof keys), false);
    assert.equal(verifyReport(json, [null] as unknown as typeof keys), false);
  });

  it("signs and returns one detached snapshot of the report", async () => {
    const signer = generateTestSigner("k1");
    const keys = [signer.publicJwk()];
    const report = emptyReport({ calls: { started: 3, ended: 3 } });
    const pending = signReportJson(signer, report);
    report.calls.started = 9;
    const json = await pending;
    assert.equal(json.report.calls.started, 3);
    assert.notEqual(json.report, report);
    assert.equal(verifyReport(json, keys), true);
  });

  it("never verifies as a receipt, and a receipt never verifies as a report", async () => {
    const signer = generateTestSigner("k1");
    const t = setup({ adapters: { signer } });
    const callId = await verifiedCall(t);
    const receipt = (await t.engine.endCall(callId))!;
    const keys = t.engine.receiptKeys();
    assert.equal(verifyReceipt(receipt, keys), true);
    const report = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const json = await signReportJson(signer, report);
    const csv = await signReportCsv(signer, report);
    for (const signed of [json, csv]) {
      const body = signed.document === "monthly_report.json" ? signed.report : signed.csv;
      const asReceipt = { body, alg: signed.alg, kid: signed.kid, signature: signed.signature } as unknown as SignedReceipt;
      assert.equal(verifyReceipt(asReceipt, keys), false, signed.document);
    }
    const asReport = { document: "monthly_report.json", report: receipt.body, alg: receipt.alg, kid: receipt.kid, signature: receipt.signature } as unknown as SignedReport;
    assert.equal(verifyReport(asReport, keys), false);
  });
});
