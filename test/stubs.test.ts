// Every planned-but-unbuilt entry point throws NotImplementedError naming its roadmap issue.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { NotImplementedError } from "../src/core/errors.ts";
import { buildReadBack, createUploadLink, deliverRecord } from "../src/file/later.ts";
import { cancelPaymentLink, chargeSavedCard, startKeypadCardCapture } from "../src/pay/later.ts";
import { revokeConsent } from "../src/prove/consent.ts";
import { exportLedger } from "../src/prove/later.ts";
import { checkTextCode, normaliseSpokenAnswer, recordSubjectFailure, returningCallerPin, sendTextCode } from "../src/verify/later.ts";
import { verifySinchSignature, verifyTelnyxSignature, verifyTwilioSignature } from "../src/webhooks/carrier.ts";

const form = { formId: "f", version: "1", fields: [] };
const hook = { url: "https://example.test/", headers: {}, body: "", now: new Date(0) };

const STUBS: Array<[string, () => unknown]> = [
  ["VER-1", () => recordSubjectFailure({ workspaceId: "w", subjectKey: "s" })],
  ["VER-2", () => sendTextCode({ callId: "c" })],
  ["VER-2", () => checkTextCode({ callId: "c", code: "1" })],
  ["VER-3", () => normaliseSpokenAnswer({ field: "postal", transcript: "", locale: "en" })],
  ["VER-6", () => returningCallerPin({ subjectKey: "s" })],
  ["FIL-1", () => buildReadBack(form, {}, "fr")],
  ["FIL-3", () => deliverRecord({ workspaceId: "w", recordId: "r" })],
  ["FIL-5", () => createUploadLink({ callId: "c", recordId: "r" })],
  ["PAY-3", () => cancelPaymentLink({ callId: "c", paymentId: "p" })],
  ["PAY-4", () => chargeSavedCard({ callId: "c", paymentId: "p" })],
  ["PAY-6", () => startKeypadCardCapture({ callId: "c", paymentId: "p" })],
  ["PRV-3", () => revokeConsent({ consentId: "x", via: "call" })],
  ["PRV-4", () => exportLedger({ fromSeq: 1 })],
  ["SRV-1", () => verifyTwilioSignature(hook)],
  ["SRV-1", () => verifyTelnyxSignature(hook)],
  ["SRV-1", () => verifySinchSignature(hook)],
];

describe("planned entry points", () => {
  const roadmap = readFileSync(new URL("../ROADMAP.md", import.meta.url), "utf8");

  for (const [issue, call] of STUBS) {
    it(`${issue}: throws NotImplementedError, and the issue is in ROADMAP.md`, () => {
      assert.throws(call, (e: unknown) => e instanceof NotImplementedError && e.issue === issue);
      assert.ok(roadmap.includes(`**${issue}**`), `${issue} is missing from ROADMAP.md`);
    });
  }
});
