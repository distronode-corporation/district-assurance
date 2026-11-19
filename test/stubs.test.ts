// Every planned-but-unbuilt entry point throws NotImplementedError naming its roadmap issue.
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { NotImplementedError } from "../src/core/errors.ts";
import { buildReadBack, createUploadLink, deliverRecord } from "../src/file/later.ts";
import { cancelPaymentLink, chargeSavedCard, startKeypadCardCapture } from "../src/pay/later.ts";
import { revokeConsent } from "../src/prove/consent.ts";
import { exportLedger } from "../src/prove/later.ts";
import { gateModule } from "../src/gate/later.ts";
import { createTestEngine } from "../src/testing/index.ts";
import { enrolPin, normaliseSpokenAnswer } from "../src/verify/later.ts";
import { verifyTelnyxSignature, verifyTwilioSignature } from "../src/webhooks/carrier.ts";

const form = { formId: "f", version: "1", fields: [] };
const hook = { url: "https://example.test/", headers: {}, body: "", now: new Date(0) };

const STUBS: Array<[string, () => unknown]> = [
  ["VER-3", () => normaliseSpokenAnswer({ field: "postal", transcript: "", locale: "en" })],
  ["VER-6", () => enrolPin({ callId: "c" })],
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
  ["GAT-1", () => gateModule()],
  ["MOD-3", () => createTestEngine().engine.useFactor({ kind: "x_factor", summary: "x", maxAttemptsPerCall: 1, adapters: [], judge: async () => false })],
];

/** Planned work a validator refuses by id (so a config can never reach it mid-call). */
const REFUSED_BY_VALIDATORS = ["VER-3", "FIL-2", "PAY-7"];

/** One `new NotImplementedError(<string literal>, "<ID>")`, whatever the quotes, commas or escapes in the first argument. */
const STUB_CALL = /new NotImplementedError\(\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)\s*,\s*["'`]([A-Z]{3}-\d+)["'`]\s*\)/g;

function stubIds(text: string): string[] {
  const ids = [...text.matchAll(STUB_CALL)].map((m) => m[1]!);
  // A call the pattern cannot read (a variable as an argument) must not slip past.
  assert.equal(ids.length, text.split("new NotImplementedError(").length - 1, "every NotImplementedError takes two string literals");
  return ids;
}

/** Every `NotImplementedError("...", "ID")` in src/, so a new stub cannot skip this file. */
function stubIdsInSource(dir: URL): string[] {
  const ids: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) ids.push(...stubIdsInSource(new URL(`${entry.name}/`, dir)));
    else if (entry.name.endsWith(".ts")) ids.push(...stubIds(readFileSync(new URL(entry.name, dir), "utf8")));
  }
  return ids;
}

describe("the stub scanner", () => {
  it("reads ids after commas, escaped quotes and any quote style", () => {
    const src = [
      'new NotImplementedError("simple", "VER-1")',
      'new NotImplementedError("Pending, see roadmap", "VER-99")',
      "new NotImplementedError('it\\'s, later', 'PAY-7')",
      'new NotImplementedError(`a "b", c`, `GAT-2`)',
      'new NotImplementedError("say \\"x\\", y", "FIL-3")',
    ].join("\n");
    assert.deepEqual(stubIds(src), ["VER-1", "VER-99", "PAY-7", "GAT-2", "FIL-3"]);
    assert.throws(() => stubIds("new NotImplementedError(name, id)"), /two string literals/);
  });
});

describe("planned entry points", () => {
  const roadmap = readFileSync(new URL("../ROADMAP.md", import.meta.url), "utf8");
  const issues = readFileSync(new URL("../ISSUES.md", import.meta.url), "utf8");

  it("every NotImplementedError in src/ is listed here", () => {
    const listed = new Set(STUBS.map(([id]) => id));
    for (const id of stubIdsInSource(new URL("../src/", import.meta.url))) assert.ok(listed.has(id), `${id} is thrown in src/ but not tested here`);
  });

  for (const id of REFUSED_BY_VALIDATORS) {
    it(`${id}: refused by a validator, and in ROADMAP.md`, () => {
      assert.ok(roadmap.includes(`**${id}**`), `${id} is missing from ROADMAP.md`);
    });
  }

  it("every issue in ISSUES.md is in ROADMAP.md, written out once", () => {
    const ids = [...issues.matchAll(/^### ([A-Z]{3}-\d+):/gm)].map((m) => m[1]!);
    assert.ok(ids.length > 0);
    for (const id of ids) assert.ok(roadmap.includes(`**${id}**`), `${id} is in ISSUES.md but not in ROADMAP.md`);
    assert.equal(new Set(ids).size, ids.length, "an issue is written out twice");
  });

  for (const [issue, call] of STUBS) {
    it(`${issue}: throws NotImplementedError, and the issue is in ROADMAP.md`, () => {
      assert.throws(call, (e: unknown) => e instanceof NotImplementedError && e.issue === issue);
      assert.ok(roadmap.includes(`**${issue}**`), `${issue} is missing from ROADMAP.md`);
    });
  }
});
