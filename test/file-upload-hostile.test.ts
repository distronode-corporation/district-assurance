// Hostile pass on #87 (FIL-5 documents by text), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { DocumentScanner, IntakeRecord } from "../src/core/adapters.ts";
import { MemoryDocumentStore, acceptUpload, createUploadLink, openUploadLink } from "../src/file/upload.ts";
import { FixedClock, MemoryRecordStore, SequentialIds } from "../src/testing/index.ts";
import { rejects } from "./helpers.ts";

const WS = "ws_test";
const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);

function world() {
  const clock = new FixedClock();
  const records = new MemoryRecordStore();
  const documents = new MemoryDocumentStore();
  const scanner: DocumentScanner = { scan: async () => ({ clean: true }) };
  const record: IntakeRecord = { recordId: "rec_1", workspaceId: WS, callId: "call_1", formId: "repair", formVersion: "1", values: { issue: "Leak" }, digest: "0".repeat(64), confirmedBy: "voice", confirmedAt: "2026-01-01T00:00:00.000Z" };
  void records.putIntakeRecord(record);
  const context = { workspaceId: WS, documents, clock, records, scanner, ids: new SequentialIds() };
  return { documents, context };
}

describe("#87 hostile: what a host passes", () => {
  it("F1 a call id or record id that is not a string is refused, never coerced into the record it names", async () => {
    const w = world();
    for (const input of [{ callId: "call_1", recordId: ["rec_1"] }, { callId: ["call_1"], recordId: "rec_1" }, { callId: "call_1", recordId: { toString: () => "rec_1" } }, { callId: "call_1", recordId: 7 }]) {
      await assert.rejects(createUploadLink(input as never, w.context), rejects("invalid_input"), JSON.stringify(input));
    }
    assert.deepEqual(w.documents.links(), [], "no link stored");
  });

  it("F2 a token that is not a string is not a usable link, never a TypeError", async () => {
    const w = world();
    const { token } = await createUploadLink({ callId: "call_1", recordId: "rec_1" }, w.context);
    for (const bad of [[token], { toString: () => token }, 12, null]) {
      assert.equal(await openUploadLink(bad as never, w.context), null, String(bad));
      assert.deepEqual(await acceptUpload({ token: bad as never, contentType: "image/jpeg", bytes: JPEG }, w.context), { ok: false, reason: "link_not_usable" });
    }
    assert.equal((await acceptUpload({ token, contentType: "image/jpeg", bytes: JPEG }, w.context)).ok, true, "the real token still works once");
  });

  it("F3 another workspace never finds a link, even on a shared store", async () => {
    const w = world();
    const { token } = await createUploadLink({ callId: "call_1", recordId: "rec_1" }, w.context);
    const other = { ...w.context, workspaceId: "ws_other" };
    assert.equal(await openUploadLink(token, other), null);
    assert.deepEqual(await acceptUpload({ token, contentType: "image/jpeg", bytes: JPEG }, other), { ok: false, reason: "link_not_usable" });
  });
});
