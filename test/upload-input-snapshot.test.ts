// Upload inputs are read once: a getter (or a host changing the object while the engine waits)
// can never pass a check with one value and have another one copied, bound or stored.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeRecord } from "../src/core/adapters.ts";
import { MemoryDocumentStore, acceptUpload, createUploadLink } from "../src/file/upload.ts";
import { FixedClock, MemoryRecordStore, SequentialIds } from "../src/testing/index.ts";
import { rejects } from "./helpers.ts";

const WS = "ws_test";
const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

function record(recordId: string, callId: string): IntakeRecord {
  return { recordId, workspaceId: WS, callId, subjectKey: null, formId: "repair", formVersion: "1", values: { issue: "Leak" }, digest: "0".repeat(64), confirmedBy: "voice", confirmedAt: "2026-01-01T00:00:00.000Z" };
}

function world() {
  const records = new MemoryRecordStore();
  void records.putIntakeRecord(record("rec_1", "call_1"));
  void records.putIntakeRecord(record("rec_other", "call_other"));
  void records.confirmIntakeRecord(WS, "rec_1");
  void records.confirmIntakeRecord(WS, "rec_other");
  const documents = new MemoryDocumentStore();
  const context = { workspaceId: WS, documents, clock: new FixedClock(), records, scanner: { scan: async () => ({ clean: true }) }, ids: new SequentialIds() };
  return { documents, context };
}

describe("uploads: inputs are read once", () => {
  it("binds a link to the record it checked against the call, never another call's record", async () => {
    const w = world();
    await createUploadLink(flipping({ callId: "call_1" }, "recordId", "rec_1", "rec_other", 2) as never, w.context);
    await createUploadLink(flipping({ recordId: "rec_1" }, "callId", "call_1", "call_other", 2) as never, w.context);
    assert.deepEqual(
      w.documents.links().map((l) => [l.callId, l.recordId]),
      [
        ["call_1", "rec_1"],
        ["call_1", "rec_1"],
      ],
    );
    await assert.rejects(createUploadLink(flipping({ callId: "call_1" }, "recordId", "rec_other", "rec_1", 2) as never, w.context), rejects("precondition_failed"));
  });

  it("copies and stores the bytes and type it checked", async () => {
    const w = world();
    const { token } = await createUploadLink({ callId: "call_1", recordId: "rec_1" }, w.context);
    const huge = new Uint8Array(64 * 1024 * 1024);
    const answer = await acceptUpload(flipping({ token, contentType: "image/jpeg" }, "bytes", JPEG, huge, 2) as never, w.context);
    assert.equal(answer.ok, true);
    assert.equal(answer.ok && answer.document.size, JPEG.length);
    const second = await createUploadLink({ callId: "call_1", recordId: "rec_1" }, w.context);
    const typed = await acceptUpload(flipping({ token: second.token, bytes: JPEG }, "contentType", "image/jpeg", 42) as never, w.context);
    assert.equal(typed.ok, true, "no TypeError from a type that changed after its check");
  });
});
