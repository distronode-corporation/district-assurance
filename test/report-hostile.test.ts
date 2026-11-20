// Hostile-pass regressions for #106 (PRV-8): the monthly report per business.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { monthlyReport, reportCsv, signReportCsv, signReportJson, verifyReport } from "../src/prove/report.ts";
import { generateTestSigner } from "../src/testing/fakes.ts";

const AT = "2026-01-15T12:00:00.000Z";
let n = 0;
const entry = (event: string, detail: AuditInput["detail"], workspace = "ws_test"): AuditInput => ({
  eventId: JSON.stringify([workspace, "call_1", 1, n++]),
  callId: "call_1",
  actor: "system",
  event: event as AuditInput["event"],
  at: AT,
  detail,
});

describe("hostile #106: entries whose detail does not read", () => {
  it("one odd entry in the workspace never stops its report from being built and signed", async () => {
    const odd: AuditInput[] = [
      entry("consent.recorded", { purpose: "texts", answer: "maybe" }),
      entry("consent.recorded", { purpose: "texts", answer: "not_recorded" }),
      entry("consent.recorded", { purpose: 7, answer: "yes" } as never),
      entry("payment.link_sent", { paymentId: "pay_1", amountMinor: "100" as never, currency: "cad" }),
      entry("payment.link_sent", { paymentId: "pay_2", amountMinor: 100, currency: "__proto__" }),
      entry("verification.finished", { level: "constructor" }),
      entry("verification.finished", { level: 1.5 }),
    ];
    for (const bad of odd) {
      const ledger = new MemoryAuditLedger();
      await ledger.append(entry("consent.recorded", { purpose: "texts", answer: "yes" }));
      await ledger.append(bad);
      const report = await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
      const signer = generateTestSigner();
      const json = await signReportJson(signer, report);
      assert.equal(verifyReport(json, [signer.publicJwk()]), true, JSON.stringify(bad.detail));
      assert.equal(verifyReport(await signReportCsv(signer, report), [signer.publicJwk()]), true);
      assert.equal(reportCsv(report).includes("NaN"), false);
      assert.deepEqual(report.consents.texts, { yes: 1, no: 0 }, "the good entry still counts");
      assert.equal(report.malformed.count, 1, "the odd one is counted apart");
      assert.deepEqual(Object.keys(report.verifications.byLevel), ["0", "1", "2", "3"]);
    }
  });
});

describe("hostile #106: what holds", () => {
  it("another workspace's entries, and one claiming ours from a malformed id, never count", async () => {
    const ledger = new MemoryAuditLedger();
    await ledger.append(entry("call.started", {}, "ws_other"));
    await ledger.append({ ...entry("call.started", {}), eventId: '["ws_test"' });
    await ledger.append({ ...entry("call.started", {}), eventId: JSON.stringify([["ws_test"], 1]) });
    const report = await monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
    assert.equal(report.calls.started, 0);
    assert.equal(report.unattributed, 2);
  });


  it("verifyReport never throws on hostile input", () => {
    for (const bad of [null, {}, { alg: "ES256", kid: "k", document: "monthly_report.json", report: { a: Number.NaN }, signature: "x" }, { alg: "ES256", kid: "k", document: "monthly_report.csv", csv: 7 }]) {
      assert.equal(verifyReport(bad as never, [generateTestSigner("k").publicJwk() as never]), false);
    }
  });
});

describe("hostile #106: the month is a string", () => {
  it("refuses a month that only reads as one, before the ledger is read", async () => {
    const ledger = new MemoryAuditLedger();
    let lists = 0;
    const list = ledger.list.bind(ledger);
    ledger.list = async () => (lists++, list());
    for (const month of [["2026-01"], { toString: () => "2026-01" }, new String("2026-01"), 202601]) {
      await assert.rejects(monthlyReport({ ledger, workspaceId: "ws_test", month } as never), (e: unknown) => e instanceof Error && /month must be YYYY-MM/.test(e.message), String(month));
    }
    assert.equal(lists, 0);
  });
});
