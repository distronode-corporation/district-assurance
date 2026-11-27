// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for the monthly report (PRV-8, PR #133 review): totals past
// Number.MAX_SAFE_INTEGER are refused, never rounded and signed, and a link or a settlement without
// a payment id never matches another.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput } from "../src/core/adapters.ts";
import { EngineError } from "../src/core/errors.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { monthlyReport, signReportCsv, signReportJson, type MonthlyReport } from "../src/prove/report.ts";
import { generateTestSigner } from "../src/testing/fakes.ts";

const AT = "2026-01-15T12:00:00.000Z";
let n = 0;
const entry = (event: string, detail: AuditInput["detail"], callId = "call_1"): AuditInput => ({
  eventId: JSON.stringify(["ws_test", callId, 1, n++]),
  callId,
  actor: "system",
  event: event as AuditInput["event"],
  at: AT,
  detail,
});

async function reportOf(inputs: AuditInput[]): Promise<MonthlyReport> {
  const ledger = new MemoryAuditLedger();
  for (const input of inputs) await ledger.append(input);
  return monthlyReport({ ledger, workspaceId: "ws_test", month: "2026-01" });
}

const unsafeTotal = (e: unknown): boolean => e instanceof EngineError && e.code === "precondition_failed" && /not a safe integer/.test(e.message);

describe("hostile: report totals past Number.MAX_SAFE_INTEGER", () => {
  it("T1: two safe link amounts whose sum is not safe refuse the report instead of rounding it", async () => {
    const big = Number.MAX_SAFE_INTEGER;
    await assert.rejects(
      reportOf([
        entry("payment.link_sent", { paymentId: "pay_1", amountMinor: big, currency: "cad" }),
        entry("payment.link_sent", { paymentId: "pay_2", amountMinor: 2, currency: "cad" }, "call_2"),
      ]),
      unsafeTotal,
    );
  });

  it("T2: a settled tally past the limit is refused too", async () => {
    const big = Number.MAX_SAFE_INTEGER;
    // Sent in December, so only the January settlements are summed.
    const sent = (paymentId: string, callId: string, amountMinor: number) => ({ ...entry("payment.link_sent", { paymentId, amountMinor, currency: "cad" }, callId), at: "2025-12-15T12:00:00.000Z" });
    await assert.rejects(
      reportOf([
        sent("pay_1", "call_1", big),
        sent("pay_2", "call_2", 1),
        entry("payment.settled", { paymentId: "pay_1", status: "paid" }, "call_1"),
        entry("payment.settled", { paymentId: "pay_2", status: "paid" }, "call_2"),
      ]),
      unsafeTotal,
    );
  });

  it("T3: a total that reaches exactly Number.MAX_SAFE_INTEGER is kept, and ordinary totals are unchanged", async () => {
    const report = await reportOf([
      entry("payment.link_sent", { paymentId: "pay_1", amountMinor: Number.MAX_SAFE_INTEGER - 5, currency: "cad" }),
      entry("payment.link_sent", { paymentId: "pay_2", amountMinor: 5, currency: "cad" }, "call_2"),
      entry("payment.link_sent", { paymentId: "pay_3", amountMinor: 1250, currency: "usd" }, "call_3"),
      entry("payment.link_sent", { paymentId: "pay_4", amountMinor: 750, currency: "usd" }, "call_4"),
    ]);
    assert.deepEqual(report.payments.sent, { count: 4, totals: { cad: Number.MAX_SAFE_INTEGER, usd: 2000 } });
  });

  it("T4: a report handed to the signers with a total that is not a safe integer is refused, JSON and CSV", async () => {
    const report = await reportOf([entry("payment.link_sent", { paymentId: "pay_1", amountMinor: 100, currency: "cad" })]);
    const signer = generateTestSigner();
    for (const total of [2 ** 53, 1.5, -1, Number.NaN]) {
      const bad = { ...report, payments: { ...report.payments, paid: { count: 1, totals: { cad: total } } } };
      await assert.rejects(signReportJson(signer, bad), unsafeTotal, String(total));
      await assert.rejects(signReportCsv(signer, bad), unsafeTotal, String(total));
    }
  });
});

describe("hostile: payment ids that do not identify a payment", () => {
  it("P1: a link and a settlement that both omit paymentId never match; the link is malformed, the settlement unmatched", async () => {
    const report = await reportOf([entry("payment.link_sent", { amountMinor: 100, currency: "cad" }), entry("payment.settled", { status: "paid" })]);
    assert.deepEqual(report.payments.paid, { count: 0, totals: {} });
    assert.deepEqual(report.payments.sent, { count: 0, totals: {} });
    assert.equal(report.payments.unmatched, 1);
    assert.deepEqual(report.malformed, { count: 1, firstSeq: 1 });
  });

  it("P2: a link whose paymentId is empty, a number or null is malformed, and a settlement with the same id stays unmatched", async () => {
    for (const paymentId of ["", 7, null, ["pay_1"]] as never[]) {
      const report = await reportOf([entry("payment.link_sent", { paymentId, amountMinor: 100, currency: "cad" }), entry("payment.settled", { paymentId, status: "paid" })]);
      assert.equal(report.payments.paid.count, 0, JSON.stringify(paymentId));
      assert.equal(report.payments.unmatched, 1, JSON.stringify(paymentId));
      assert.equal(report.malformed.count, 1, JSON.stringify(paymentId));
    }
  });

  it("P3: a link and a settlement with the same string paymentId still match", async () => {
    const report = await reportOf([entry("payment.link_sent", { paymentId: "pay_1", amountMinor: 100, currency: "cad" }), entry("payment.settled", { paymentId: "pay_1", status: "paid" })]);
    assert.deepEqual(report.payments.paid, { count: 1, totals: { cad: 100 } });
    assert.equal(report.payments.unmatched, 0);
    assert.equal(report.malformed.count, 0);
  });
});
