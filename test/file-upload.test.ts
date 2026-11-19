// Documents by text (FIL-5): single-use upload links bound to a call and a record, with an expiry,
// allowed types and a size cap, a scanning hook, and only the token's hash in the store.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { DocumentScanner, DocumentStore, IntakeRecord } from "../src/core/adapters.ts";
import { sha256Hex } from "../src/core/hash.ts";
import {
  DEFAULT_UPLOAD_MAX_BYTES,
  DOCUMENT_TYPES,
  MemoryDocumentStore,
  UPLOAD_LINK_TTL_SECONDS,
  UPLOAD_MAX_BYTES_LIMIT,
  acceptUpload,
  createUploadLink,
  isDocumentType,
  openUploadLink,
} from "../src/file/upload.ts";
import { FixedClock, MemoryRecordStore, SequentialIds } from "../src/testing/index.ts";
import { rejects, setup, verifiedCall } from "./helpers.ts";

const WS = "ws_test";
const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]);
const PDF = new TextEncoder().encode("%PDF-1.7\n%fake\n");

function intakeRecord(recordId: string, callId: string): IntakeRecord {
  return { recordId, workspaceId: WS, callId, formId: "repair", formVersion: "1", values: { issue: "Leak" }, digest: "0".repeat(64), confirmedBy: "voice", confirmedAt: "2026-01-01T00:00:00.000Z" };
}

class FakeScanner implements DocumentScanner {
  readonly scanned: string[] = [];
  clean = true;

  async scan(input: { documentId: string }): Promise<{ clean: boolean }> {
    this.scanned.push(input.documentId);
    return { clean: this.clean };
  }
}

function world() {
  const clock = new FixedClock();
  const records = new MemoryRecordStore();
  const documents = new MemoryDocumentStore();
  const scanner = new FakeScanner();
  void records.putIntakeRecord(intakeRecord("rec_1", "call_1"));
  const context = { workspaceId: WS, documents, clock, records, scanner, ids: new SequentialIds() };
  const link = (input: Partial<Parameters<typeof createUploadLink>[0]> = {}) => createUploadLink({ callId: "call_1", recordId: "rec_1", ...input }, context);
  const upload = (token: string, bytes: Uint8Array = JPEG, contentType = "image/jpeg") => acceptUpload({ token, contentType, bytes }, context);
  return { clock, records, documents, scanner, context, link, upload };
}

describe("createUploadLink", () => {
  it("returns a capability token with a 30-minute expiry, and stores only its hash, bound to the call and record", async () => {
    const w = world();
    const link = await w.link({ locale: "fr" });
    assert.match(link.token, /^upl_[A-Za-z0-9_-]{43}$/);
    assert.equal(link.expiresAt, new Date(w.clock.now().getTime() + 30 * 60 * 1000).toISOString());
    assert.equal(UPLOAD_LINK_TTL_SECONDS, 1800);
    assert.deepEqual(link.allowedTypes, [...DOCUMENT_TYPES]);
    assert.equal(link.maxBytes, DEFAULT_UPLOAD_MAX_BYTES);
    const stored = w.documents.links();
    assert.deepEqual(stored, [
      {
        workspaceId: WS,
        tokenHash: sha256Hex(link.token),
        callId: "call_1",
        recordId: "rec_1",
        locale: "fr",
        allowedTypes: [...DOCUMENT_TYPES],
        maxBytes: DEFAULT_UPLOAD_MAX_BYTES,
        createdAt: w.clock.now().toISOString(),
        expiresAt: link.expiresAt,
        usedAt: null,
      },
    ]);
    assert.ok(!JSON.stringify(stored).includes(link.token.slice(4)), "the token itself is never stored");
    assert.notEqual((await w.link()).token, link.token, "every link has its own token");
  });

  it("takes a record the engine confirmed on the call", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Broken window");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice" });
    const documents = new MemoryDocumentStore();
    const context = { workspaceId: t.engine.workspaceId, documents, clock: t.clock, records: t.records, ids: t.ids, scanner: new FakeScanner() };
    const link = await createUploadLink({ callId, recordId: record.recordId, allowedTypes: ["application/pdf"], maxBytes: 100 }, context);
    const result = await acceptUpload({ token: link.token, contentType: "application/pdf", bytes: PDF }, context);
    assert.ok(result.ok);
    assert.equal(result.document.recordId, record.recordId);
    assert.equal(result.document.callId, callId);
  });

  it("refuses a record that is not the call's, or that does not exist", async () => {
    const w = world();
    await w.records.putIntakeRecord(intakeRecord("rec_other", "call_2"));
    await assert.rejects(w.link({ recordId: "rec_other" }), rejects("precondition_failed", /not a confirmed record of this call/));
    await assert.rejects(w.link({ recordId: "rec_404" }), rejects("precondition_failed", /not a confirmed record of this call/));
    await assert.rejects(w.link({ callId: "call_2" }), rejects("precondition_failed"));
    assert.deepEqual(w.documents.links(), []);
  });

  it("refuses bad input, every problem at once", async () => {
    const w = world();
    await assert.rejects(w.link({ callId: "" }), rejects("invalid_input", /callId and recordId are required/));
    await assert.rejects(w.link({ recordId: "" }), rejects("invalid_input", /callId and recordId are required/));
    await assert.rejects(w.link({ locale: "de" as "en" }), rejects("invalid_input", /locale is en or fr/));
    for (const allowedTypes of [[], ["image/gif"], ["image/png", "image/png"]]) {
      await assert.rejects(w.link({ allowedTypes: allowedTypes as never }), rejects("invalid_input", /allowedTypes is a non-empty list/));
    }
    for (const maxBytes of [0, 1.5, UPLOAD_MAX_BYTES_LIMIT + 1]) {
      await assert.rejects(w.link({ maxBytes }), rejects("invalid_input", /maxBytes is an integer from 1 to 26214400/));
    }
    await assert.rejects(w.link({ callId: "", locale: "x" as "en", maxBytes: 0 }), rejects("invalid_input", /required; locale .*; maxBytes/));
    assert.ok(await w.link({ maxBytes: UPLOAD_MAX_BYTES_LIMIT }));
  });

  it("refuses when the store already has the token's hash", async () => {
    const w = world();
    const documents: DocumentStore = { ...w.documents, putUploadLink: async () => false } as unknown as DocumentStore;
    await assert.rejects(createUploadLink({ callId: "call_1", recordId: "rec_1" }, { ...w.context, documents }), rejects("conflict"));
  });
});

describe("acceptUpload", () => {
  it("stores one document and spends the link: single use", async () => {
    const w = world();
    const { token } = await w.link();
    assert.deepEqual(await openUploadLink(token, w.context), { locale: "en", allowedTypes: [...DOCUMENT_TYPES], maxBytes: DEFAULT_UPLOAD_MAX_BYTES, expiresAt: (await w.documents.links())[0]!.expiresAt });
    const result = await w.upload(token, JPEG, "IMAGE/JPEG; name=x.jpg");
    assert.deepEqual(result, {
      ok: true,
      document: { documentId: "doc_1", workspaceId: WS, callId: "call_1", recordId: "rec_1", contentType: "image/jpeg", size: JPEG.length, digest: sha256Hex(JPEG), receivedAt: w.clock.now().toISOString() },
    });
    assert.deepEqual(w.scanner.scanned, ["doc_1"]);
    assert.deepEqual(w.documents.documents().map((d) => [d.document.documentId, [...d.bytes]]), [["doc_1", [...JPEG]]]);
    assert.equal(w.documents.links()[0]!.usedAt, w.clock.now().toISOString());

    assert.deepEqual(await w.upload(token), { ok: false, reason: "link_not_usable" });
    assert.equal(await openUploadLink(token, w.context), null);
    assert.equal(w.documents.documents().length, 1);
  });

  it("lets only one of two uploads at once through", async () => {
    const w = world();
    const { token } = await w.link();
    const results = await Promise.all([w.upload(token), w.upload(token, PNG, "image/png")]);
    assert.deepEqual(results.map((r) => r.ok).sort(), [false, true]);
    assert.ok(results.some((r) => !r.ok && r.reason === "link_not_usable"));
    assert.equal(w.documents.documents().length, 1);
    assert.equal(w.scanner.scanned.length, 1);
  });

  it("refuses an expired link, from 30 minutes on", async () => {
    const w = world();
    const { token } = await w.link();
    w.clock.advance(UPLOAD_LINK_TTL_SECONDS * 1000 - 1);
    assert.notEqual(await openUploadLink(token, w.context), null);
    w.clock.advance(1);
    assert.equal(await openUploadLink(token, w.context), null);
    assert.deepEqual(await w.upload(token), { ok: false, reason: "link_not_usable" });
    assert.equal(w.documents.links()[0]!.usedAt, null);
    assert.deepEqual(w.scanner.scanned, []);
  });

  it("refuses an unknown or malformed token, and one from another workspace, the same way", async () => {
    const w = world();
    const { token } = await w.link();
    for (const bad of ["", "upl_short", `upl_${"A".repeat(43)}`, `${token}x`, token.toUpperCase()]) {
      assert.deepEqual(await w.upload(bad), { ok: false, reason: "link_not_usable" }, bad);
      assert.equal(await openUploadLink(bad, w.context), null);
    }
    assert.deepEqual(await acceptUpload({ token, contentType: "image/jpeg", bytes: JPEG }, { ...w.context, workspaceId: "ws_other" }), { ok: false, reason: "link_not_usable" });
  });

  it("refuses a type the link does not allow, without spending it", async () => {
    const w = world();
    const { token } = await w.link({ allowedTypes: ["image/jpeg", "image/png"] });
    assert.deepEqual(await w.upload(token, PDF, "application/pdf"), { ok: false, reason: "type_not_allowed" });
    assert.deepEqual(await w.upload(token, JPEG, "image/gif"), { ok: false, reason: "type_not_allowed" });
    assert.deepEqual(await w.upload(token, JPEG, "text/html"), { ok: false, reason: "type_not_allowed" });
    assert.deepEqual(await w.upload(token, PNG, "image/jpeg"), { ok: false, reason: "content_mismatch" }, "the bytes must be what the type says");
    assert.deepEqual(await w.upload(token, new TextEncoder().encode("<html>"), "image/png"), { ok: false, reason: "content_mismatch" });
    assert.deepEqual(w.scanner.scanned, []);
    assert.equal(w.documents.links()[0]!.usedAt, null);
    assert.equal((await w.upload(token, PNG, "image/png")).ok, true);
  });

  it("refuses an empty file and one over the size cap, without spending the link", async () => {
    const w = world();
    const { token } = await w.link({ maxBytes: JPEG.length });
    assert.deepEqual(await w.upload(token, new Uint8Array(0)), { ok: false, reason: "empty" });
    const big = new Uint8Array(JPEG.length + 1);
    big.set(JPEG);
    assert.deepEqual(await w.upload(token, big), { ok: false, reason: "too_large" });
    assert.equal(w.documents.links()[0]!.usedAt, null);
    assert.equal((await w.upload(token, JPEG)).ok, true, "exactly the cap is accepted");
  });

  it("refuses what the scanner does not pass, and the link is spent", async () => {
    const w = world();
    const { token } = await w.link();
    w.scanner.clean = false;
    assert.deepEqual(await w.upload(token), { ok: false, reason: "scan_refused" });
    assert.deepEqual(w.documents.documents(), []);
    w.scanner.clean = true;
    assert.deepEqual(await w.upload(token), { ok: false, reason: "link_not_usable" });
  });
});

describe("MemoryDocumentStore", () => {
  it("keeps the first link per token hash, claims once, and copies in and out", async () => {
    const store = new MemoryDocumentStore();
    const link = { workspaceId: WS, tokenHash: "a".repeat(64), callId: "c", recordId: "r", locale: "en" as const, allowedTypes: ["image/png" as const], maxBytes: 1, createdAt: "t", expiresAt: "t", usedAt: null };
    assert.equal(await store.putUploadLink(link), true);
    assert.equal(await store.putUploadLink({ ...link, callId: "other" }), false);
    link.allowedTypes.push("image/jpeg" as never);
    assert.deepEqual((await store.getUploadLink(WS, link.tokenHash))!.allowedTypes, ["image/png"]);
    assert.equal(await store.getUploadLink("ws_other", link.tokenHash), null);
    assert.equal(await store.claimUploadLink("ws_other", link.tokenHash, "u"), false);
    assert.equal(await store.claimUploadLink(WS, link.tokenHash, "u"), true);
    assert.equal(await store.claimUploadLink(WS, link.tokenHash, "v"), false);
    assert.equal((await store.getUploadLink(WS, link.tokenHash))!.usedAt, "u");
    const bytes = Uint8Array.from([1]);
    await store.putDocument({ documentId: "d", workspaceId: WS, callId: "c", recordId: "r", contentType: "image/png", size: 1, digest: "d", receivedAt: "t" }, bytes);
    bytes[0] = 9;
    store.documents()[0]!.bytes[0] = 7;
    assert.deepEqual([...store.documents()[0]!.bytes], [1]);
  });

  it("knows the document types", () => {
    assert.ok(DOCUMENT_TYPES.every(isDocumentType));
    assert.equal(isDocumentType("image/gif"), false);
    assert.equal(isDocumentType(1), false);
  });
});
