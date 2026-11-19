// The monthly report per business: what one workspace's line verified, refused, collected and
// opened in a calendar month, built from the audit ledger. Counts and totals only: no call ids, no
// subjects, no values. Signed with the receipt signer, but the signed bytes start with a domain
// line naming the document type, so a report can never verify as a receipt (whose signed bytes
// are canonical JSON and start with "{"), and a JSON report never as a CSV one.
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

import type { AuditEntry, AuditLedger, ReceiptSigner } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { GENESIS_HASH } from "./ledger.ts";

/** Counts and totals in minor units, by lower-case ISO 4217 currency. */
export interface PaymentTally {
  count: number;
  totals: Record<string, number>;
}

export interface MonthlyReport {
  v: 1;
  document: "monthly_report";
  workspaceId: string;
  /** `YYYY-MM`, in `timeZone`. */
  month: string;
  /** The IANA time zone the month is read in. */
  timeZone: string;
  /** The last ledger entry read: the report covers the ledger up to and including it. */
  ledger: { seq: number; hash: string };
  calls: { started: number; ended: number };
  verifications: {
    /** Finished verifications by the level reached; level 0 is a verification that reached none. */
    byLevel: Record<string, number>;
    /** Factor attempts judged and failed. */
    failedFactors: number;
  };
  payments: {
    sent: PaymentTally;
    paid: PaymentTally;
    failed: PaymentTally;
    expired: PaymentTally;
    /** Settlements in the month whose link the ledger does not show: counted nowhere else. */
    unmatched: number;
  };
  /** Consent answers by purpose. */
  consents: Record<string, { yes: number; no: number }>;
  /** `verification.locked` entries (VER-1), once Badge writes them. */
  lockouts: number;
  /** `gate.granted`, `gate.refused` and `gate.revoked` entries (GAT-1), once Gate writes them. */
  access: { granted: number; refused: number; revoked: number };
  /** Entries in the month with no workspace in their `eventId`: reported here, never counted above. */
  unattributed: number;
}

const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
/** A ledger time as the engine writes it (`Date.prototype.toISOString`), always in UTC. */
const LEDGER_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

/** The workspace an entry belongs to: the first element of its `eventId` tuple, or null. */
export function entryWorkspace(entry: Pick<AuditEntry, "eventId">): string | null {
  if (entry.eventId === undefined) return null;
  try {
    const tuple: unknown = JSON.parse(entry.eventId);
    return Array.isArray(tuple) && typeof tuple[0] === "string" && tuple[0] !== "" ? tuple[0] : null;
  } catch {
    return null;
  }
}

function monthReader(timeZone: string): (at: string) => string {
  let format: Intl.DateTimeFormat;
  try {
    format = new Intl.DateTimeFormat("en-US", { timeZone, calendar: "gregory", numberingSystem: "latn", year: "numeric", month: "2-digit" });
  } catch {
    throw new EngineError("invalid_input", "timeZone must be an IANA time zone");
  }
  return (at) => {
    // Date.parse rolls an impossible date (Feb 30, hour 24) into the next one, so the UTC date of
    // the parsed instant must be the date written.
    const ms = typeof at === "string" && LEDGER_TIME.test(at) ? Date.parse(at) : Number.NaN;
    if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== at.slice(0, 10)) throw new EngineError("invalid_input", "a ledger entry has no valid time");
    const parts = format.formatToParts(ms);
    const part = (type: "year" | "month"): string => parts.find((p) => p.type === type)!.value;
    return `${part("year").padStart(4, "0")}-${part("month")}`;
  };
}

function tally(): PaymentTally {
  return { count: 0, totals: {} };
}

function add(t: PaymentTally, link: { amountMinor: number; currency: string }): void {
  t.count++;
  t.totals[link.currency] = (t.totals[link.currency] ?? 0) + link.amountMinor;
}

/** Sorts an object's keys, so the JSON and the CSV list them in one order. */
function sorted<T>(record: Record<string, T>): Record<string, T> {
  return Object.fromEntries(Object.keys(record).sort().map((k) => [k, record[k]!]));
}

/**
 * Builds a workspace's report for a month from the ledger. `month` is `YYYY-MM` in `timeZone`
 * (UTC by default). Every entry is read: a payment settled in the month may have been sent in an
 * earlier one, and its amount is taken from its `payment.link_sent` entry.
 */
export async function monthlyReport(input: { ledger: AuditLedger; workspaceId: string; month: string; timeZone?: string }): Promise<MonthlyReport> {
  if (typeof input.workspaceId !== "string" || input.workspaceId === "") throw new EngineError("invalid_input", "workspaceId is empty");
  if (!MONTH.test(input.month)) throw new EngineError("invalid_input", "month must be YYYY-MM");
  const timeZone = input.timeZone ?? "UTC";
  const monthOf = monthReader(timeZone);
  const entries = await input.ledger.list();
  const last = entries.at(-1);
  const report: MonthlyReport = {
    v: 1,
    document: "monthly_report",
    workspaceId: input.workspaceId,
    month: input.month,
    timeZone,
    ledger: { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS_HASH },
    calls: { started: 0, ended: 0 },
    verifications: { byLevel: { "0": 0, "1": 0, "2": 0, "3": 0 }, failedFactors: 0 },
    payments: { sent: tally(), paid: tally(), failed: tally(), expired: tally(), unmatched: 0 },
    consents: {},
    lockouts: 0,
    access: { granted: 0, refused: 0, revoked: 0 },
    unattributed: 0,
  };
  // Payment ids are unique per call, so links are keyed by call and payment.
  // Consent counters live in a map until the end, so a purpose such as `constructor` or
  // `__proto__` is counted like any other and never reaches an inherited property.
  const consents = new Map<string, { yes: number; no: number }>();
  const links = new Map<string, { amountMinor: number; currency: string }>();
  const linkKey = (entry: AuditEntry): string => JSON.stringify([entry.callId, entry.detail.paymentId]);
  for (const entry of entries) {
    const workspace = entryWorkspace(entry);
    const inMonth = monthOf(entry.at) === input.month;
    if (workspace === null) {
      if (inMonth) report.unattributed++;
      continue;
    }
    if (workspace !== input.workspaceId) continue;
    // Events other packages will add (VER-1, GAT-1) are matched by name.
    const name: string = entry.event;
    const d = entry.detail;
    if (name === "payment.link_sent") links.set(linkKey(entry), { amountMinor: d.amountMinor as number, currency: d.currency as string });
    if (!inMonth) continue;
    switch (name) {
      case "call.started":
        report.calls.started++;
        break;
      case "call.ended":
        report.calls.ended++;
        break;
      case "verification.finished": {
        const level = String(d.level);
        report.verifications.byLevel[level] = (report.verifications.byLevel[level] ?? 0) + 1;
        break;
      }
      case "verification.factor":
        if (d.passed === false) report.verifications.failedFactors++;
        break;
      case "payment.link_sent":
        add(report.payments.sent, links.get(linkKey(entry))!);
        break;
      case "payment.settled": {
        const link = links.get(linkKey(entry));
        if (link === undefined) report.payments.unmatched++;
        else add(report.payments[d.status as "paid" | "failed" | "expired"], link);
        break;
      }
      case "consent.recorded": {
        const purpose = d.purpose as string;
        const counts = consents.get(purpose) ?? { yes: 0, no: 0 };
        counts[d.answer as "yes" | "no"]++;
        consents.set(purpose, counts);
        break;
      }
      case "verification.locked":
        report.lockouts++;
        break;
      case "gate.granted":
        report.access.granted++;
        break;
      case "gate.refused":
        report.access.refused++;
        break;
      case "gate.revoked":
        report.access.revoked++;
        break;
    }
  }
  report.verifications.byLevel = sorted(report.verifications.byLevel);
  for (const t of [report.payments.sent, report.payments.paid, report.payments.failed, report.payments.expired]) t.totals = sorted(t.totals);
  report.consents = Object.fromEntries([...consents.keys()].sort().map((k) => [k, consents.get(k)!]));
  return report;
}

// ---- CSV -----------------------------------------------------------------------------------

/** One field, quoted when it holds a comma, a quote or a line break; a leading formula character is neutralised. */
function csvField(value: string | number): string {
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** The report as `metric,value` rows, in a fixed order. */
export function reportRows(report: MonthlyReport): Array<[string, string | number]> {
  const rows: Array<[string, string | number]> = [
    ["document", report.document],
    ["workspace", report.workspaceId],
    ["month", report.month],
    ["time_zone", report.timeZone],
    ["ledger.seq", report.ledger.seq],
    ["ledger.hash", report.ledger.hash],
    ["calls.started", report.calls.started],
    ["calls.ended", report.calls.ended],
  ];
  for (const [level, n] of Object.entries(report.verifications.byLevel)) rows.push([`verifications.level_${level}`, n]);
  rows.push(["verifications.failed_factors", report.verifications.failedFactors]);
  for (const status of ["sent", "paid", "failed", "expired"] as const) {
    const t = report.payments[status];
    rows.push([`payments.${status}.count`, t.count]);
    for (const [currency, total] of Object.entries(t.totals)) rows.push([`payments.${status}.total.${currency}`, total]);
  }
  rows.push(["payments.unmatched", report.payments.unmatched]);
  for (const [purpose, c] of Object.entries(report.consents)) rows.push([`consents.${purpose}.yes`, c.yes], [`consents.${purpose}.no`, c.no]);
  rows.push(
    ["lockouts", report.lockouts],
    ["access.granted", report.access.granted],
    ["access.refused", report.access.refused],
    ["access.revoked", report.access.revoked],
    ["unattributed", report.unattributed],
  );
  return rows;
}

/** RFC 4180 CSV with a `metric,value` header and CRLF line ends. */
export function reportCsv(report: MonthlyReport): string {
  return [["metric", "value"] as const, ...reportRows(report)].map((row) => row.map(csvField).join(",")).join("\r\n") + "\r\n";
}

// ---- signing -------------------------------------------------------------------------------

export type ReportDocument = "monthly_report.json" | "monthly_report.csv";

interface SignedParts {
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature over `reportPayload(document, content)`. */
  signature: string;
}

export interface SignedReportJson extends SignedParts {
  document: "monthly_report.json";
  report: MonthlyReport;
}

export interface SignedReportCsv extends SignedParts {
  document: "monthly_report.csv";
  csv: string;
}

export type SignedReport = SignedReportJson | SignedReportCsv;

/** The first line of every signed report: what signed it, and that it is not a receipt. */
export const REPORT_DOMAIN = "district-assurance signed document v1";

/** The exact bytes that are signed: the domain line, the document type line, then the content. */
export function reportPayload(document: ReportDocument, content: string): Uint8Array {
  return new TextEncoder().encode(`${REPORT_DOMAIN}\n${document}\n${content}`);
}

async function signed(signer: ReceiptSigner, document: ReportDocument, content: string): Promise<SignedParts> {
  const signature = await signer.sign(reportPayload(document, content));
  return { alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
}

/** Signs the JSON report (for a PDF template) with the receipt signer. */
export async function signReportJson(signer: ReceiptSigner, report: MonthlyReport): Promise<SignedReportJson> {
  // A detached copy of exactly what is signed, so a change to the caller's object while the signer
  // runs cannot break the envelope.
  const content = canonicalJson(report);
  const snapshot = JSON.parse(content) as MonthlyReport;
  return { document: "monthly_report.json", report: snapshot, ...(await signed(signer, "monthly_report.json", content)) };
}

/** Signs the CSV of a report with the receipt signer. */
export async function signReportCsv(signer: ReceiptSigner, report: MonthlyReport): Promise<SignedReportCsv> {
  const csv = reportCsv(report);
  return { document: "monthly_report.csv", csv, ...(await signed(signer, "monthly_report.csv", csv)) };
}

/**
 * Checks a signed report against a key set. False for an unknown document type or `kid`, a wrong
 * algorithm, a malformed signature or any change to the content. Never throws on bad input.
 */
export function verifyReport(signedReport: SignedReport, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  try {
    if (signedReport.alg !== "ES256") return false;
    const jwk = keys.find((k) => k.kid === signedReport.kid);
    if (jwk === undefined) return false;
    let payload: Uint8Array;
    if (signedReport.document === "monthly_report.json") payload = reportPayload(signedReport.document, canonicalJson(signedReport.report));
    else if (signedReport.document === "monthly_report.csv" && typeof signedReport.csv === "string") payload = reportPayload(signedReport.document, signedReport.csv);
    else return false;
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(signedReport.signature, "base64url");
    if (signature.length !== 64) return false;
    return verify("sha256", payload, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}
