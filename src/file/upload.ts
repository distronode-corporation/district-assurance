// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Documents by text: a single-use link the caller opens on their phone to add a photo or a PDF to
// a record they confirmed. The link carries a capability token of 256 random bits; only its
// SHA-256 is stored, so a copy of the store never yields a working link. A link is bound to one
// call and one record, expires after 30 minutes, takes the types and the size it was made for,
// and is spent by the first upload that passes those checks, whatever happens to it after.
import { randomBytes } from "node:crypto";

import type { DocumentRecord, DocumentScanner, DocumentStore, DocumentType, RecordStore, UploadLinkRecord } from "../core/adapters.ts";
import type { Clock, IdGenerator } from "../core/clock.ts";
import { EngineError } from "../core/errors.ts";
import { sha256Hex } from "../core/hash.ts";
import { SUPPORTED_LOCALES, isSupportedLocale, type Locale } from "../core/runtime.ts";

export const DOCUMENT_TYPES: readonly DocumentType[] = ["image/jpeg", "image/png", "application/pdf"];
export const UPLOAD_LINK_TTL_SECONDS = 1800;
export const DEFAULT_UPLOAD_MAX_BYTES = 10 * 1024 * 1024;
export const UPLOAD_MAX_BYTES_LIMIT = 25 * 1024 * 1024;

/** `upl_` and 32 random bytes in base64url. */
const TOKEN = /^upl_[A-Za-z0-9_-]{43}$/;

/** The leading bytes each type must start with, so a declared type is never taken on trust. */
const SIGNATURES: Readonly<Record<DocumentType, readonly number[]>> = {
  "image/jpeg": [0xff, 0xd8, 0xff],
  "image/png": [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  "application/pdf": [0x25, 0x50, 0x44, 0x46, 0x2d],
};

export interface UploadContext {
  workspaceId: string;
  documents: DocumentStore;
  clock: Clock;
}

export interface UploadLinkInput {
  callId: string;
  /** A confirmed intake record of this call. */
  recordId: string;
  /** The upload page's language. Default `en`. */
  locale?: Locale;
  /** Default every type in `DOCUMENT_TYPES`. */
  allowedTypes?: readonly DocumentType[];
  /** 1 to `UPLOAD_MAX_BYTES_LIMIT`. Default `DEFAULT_UPLOAD_MAX_BYTES`. */
  maxBytes?: number;
}

export interface UploadLink {
  /** The capability. Goes into the link and nowhere else: never a log, an event or a ledger entry. */
  token: string;
  expiresAt: string;
  allowedTypes: DocumentType[];
  maxBytes: number;
}

/** What the upload page needs to know about a usable link. */
export interface OpenUploadLink {
  locale: Locale;
  allowedTypes: DocumentType[];
  maxBytes: number;
  expiresAt: string;
}

/**
 * Why an upload was refused. `link_not_usable` covers an unknown, malformed, used and expired
 * token alike. The type, size and content refusals leave the link usable; `scan_refused` (the
 * scanner did not pass it) and `scan_failed` (the scanner threw) spend it.
 */
export type UploadRefusal = "link_not_usable" | "type_not_allowed" | "empty" | "too_large" | "content_mismatch" | "scan_refused" | "scan_failed";

export type UploadResult = { ok: true; document: DocumentRecord } | { ok: false; reason: UploadRefusal };

export function isDocumentType(value: unknown): value is DocumentType {
  return DOCUMENT_TYPES.includes(value as DocumentType);
}

/**
 * Creates a link for one confirmed record of one call and returns its token. Refuses
 * (`invalid_input`) bad types, a bad size cap or a bad locale, and (`precondition_failed`) a record
 * the store does not have or that another call confirmed.
 */
export async function createUploadLink(input: UploadLinkInput, context: UploadContext & { records: RecordStore }): Promise<UploadLink> {
  // Read once: the record checked against the call is the one the link is bound to.
  const { callId, recordId } = input;
  const locale = input.locale ?? "en";
  const allowedTypes = [...(input.allowedTypes ?? DOCUMENT_TYPES)];
  const maxBytes = input.maxBytes ?? DEFAULT_UPLOAD_MAX_BYTES;
  const problems: string[] = [];
  // Strings only: a record store keyed by text finds a record for ["rec_1"] too, and the link would
  // then be bound to an array.
  if (typeof callId !== "string" || typeof recordId !== "string" || callId === "" || recordId === "") problems.push("callId and recordId are required");
  if (!isSupportedLocale(locale)) problems.push(`locale is one of ${SUPPORTED_LOCALES.join(", ")}`);
  if (allowedTypes.length === 0 || !allowedTypes.every(isDocumentType) || new Set(allowedTypes).size !== allowedTypes.length) {
    problems.push(`allowedTypes is a non-empty list of distinct types from ${DOCUMENT_TYPES.join(", ")}`);
  }
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > UPLOAD_MAX_BYTES_LIMIT) problems.push(`maxBytes is an integer from 1 to ${UPLOAD_MAX_BYTES_LIMIT}`);
  if (problems.length > 0) throw new EngineError("invalid_input", `upload link: ${problems.join("; ")}`);

  const record = await context.records.getIntakeRecord(context.workspaceId, recordId);
  if (record === null || record.callId !== callId || !(await context.records.isIntakeRecordConfirmed(context.workspaceId, recordId))) {
    throw new EngineError("precondition_failed", "upload link: the record is not a confirmed record of this call");
  }

  const token = `upl_${randomBytes(32).toString("base64url")}`;
  const now = context.clock.now();
  const expiresAt = new Date(now.getTime() + UPLOAD_LINK_TTL_SECONDS * 1000).toISOString();
  const stored = await context.documents.putUploadLink({
    workspaceId: context.workspaceId,
    tokenHash: sha256Hex(token),
    callId,
    recordId,
    locale,
    allowedTypes,
    maxBytes,
    createdAt: now.toISOString(),
    expiresAt,
    usedAt: null,
  });
  if (!stored) throw new EngineError("conflict", "upload link: the store already has this token");
  return { token, expiresAt, allowedTypes, maxBytes };
}

/** The link behind a token, while it is unused and unexpired; null otherwise, for any reason. */
export async function openUploadLink(token: string, context: UploadContext): Promise<OpenUploadLink | null> {
  const link = await usableLink(token, context);
  return link === null ? null : { locale: link.locale, allowedTypes: [...link.allowedTypes], maxBytes: link.maxBytes, expiresAt: link.expiresAt };
}

/**
 * Takes one upload on a token. The declared type, the size and the leading bytes are checked
 * first, and a refusal there leaves the link usable. Then the link is claimed, which spends it,
 * and only the one claim that won goes on to the scanner and the store. The bytes are copied
 * before the first await, so a later write to the caller's array cannot change what was checked;
 * a body over `UPLOAD_MAX_BYTES_LIMIT` is refused before it is copied, so a huge body is never held
 * twice. Bytes that are not a `Uint8Array`, or a content type that is not a string, are a host's
 * bug (`invalid_input`).
 */
export async function acceptUpload(
  input: { token: string; contentType: string; bytes: Uint8Array },
  context: UploadContext & { ids: IdGenerator; scanner: DocumentScanner },
): Promise<UploadResult> {
  // Read once: the bytes and type checked are the ones copied, scanned and stored.
  const { token, contentType: declared, bytes: given } = input;
  if (!(given instanceof Uint8Array) || typeof declared !== "string") {
    throw new EngineError("invalid_input", "upload: bytes must be a Uint8Array and contentType a string");
  }
  if (given.length > UPLOAD_MAX_BYTES_LIMIT) return { ok: false, reason: "too_large" };
  const bytes = Uint8Array.prototype.slice.call(given);
  const link = await usableLink(token, context);
  if (link === null) return { ok: false, reason: "link_not_usable" };
  const contentType = declared.split(";")[0]!.trim().toLowerCase();
  if (!isDocumentType(contentType) || !link.allowedTypes.includes(contentType)) return { ok: false, reason: "type_not_allowed" };
  if (bytes.length === 0) return { ok: false, reason: "empty" };
  if (bytes.length > link.maxBytes) return { ok: false, reason: "too_large" };
  if (!SIGNATURES[contentType].every((byte, i) => bytes[i] === byte)) return { ok: false, reason: "content_mismatch" };

  const now = context.clock.now().toISOString();
  if (!(await context.documents.claimUploadLink(context.workspaceId, link.tokenHash, now))) return { ok: false, reason: "link_not_usable" };
  const documentId = context.ids.next("doc");
  let scan: { clean: boolean };
  try {
    scan = await context.scanner.scan({ workspaceId: context.workspaceId, documentId, contentType, bytes });
  } catch {
    // The scanner's error is the host's to log; the caller only learns the document was not taken.
    return { ok: false, reason: "scan_failed" };
  }
  if (scan?.clean !== true) return { ok: false, reason: "scan_refused" };
  const document: DocumentRecord = {
    documentId,
    workspaceId: context.workspaceId,
    callId: link.callId,
    recordId: link.recordId,
    contentType,
    size: bytes.length,
    digest: sha256Hex(bytes),
    receivedAt: now,
  };
  await context.documents.putDocument(document, bytes);
  return { ok: true, document };
}

async function usableLink(token: string, context: UploadContext): Promise<UploadLinkRecord | null> {
  // A string only: a regex test turns an array into its text, which would pass, and hashing it throws.
  if (typeof token !== "string" || !TOKEN.test(token)) return null;
  const link = await context.documents.getUploadLink(context.workspaceId, sha256Hex(token));
  if (link === null) return null;
  const now = context.clock.now();
  if (!(now.getTime() < Date.parse(link.expiresAt))) {
    // An expired link is read once more at most: reading it purges it, and every other expired link.
    await context.documents.purgeExpiredUploadLinks(context.workspaceId, now.toISOString());
    return null;
  }
  return link.usedAt === null ? link : null;
}

/** Removes the workspace's expired upload links, for a host's periodic sweep. Returns how many. */
export async function sweepUploadLinks(context: UploadContext): Promise<number> {
  return context.documents.purgeExpiredUploadLinks(context.workspaceId, context.clock.now().toISOString());
}

const tupleKey = (workspaceId: string, id: string): string => JSON.stringify([workspaceId, id]);

/**
 * The in-memory document store: the reference `DocumentStore`, for tests and the demo. Links and
 * documents are copied in and out, and a link is spent only through `claimUploadLink`.
 */
export class MemoryDocumentStore implements DocumentStore {
  readonly #links = new Map<string, UploadLinkRecord>();
  readonly #documents: Array<{ document: DocumentRecord; bytes: Uint8Array }> = [];

  async putUploadLink(link: UploadLinkRecord): Promise<boolean> {
    const key = tupleKey(link.workspaceId, link.tokenHash);
    if (this.#links.has(key)) return false;
    this.#links.set(key, structuredClone(link));
    return true;
  }

  async getUploadLink(workspaceId: string, tokenHash: string): Promise<UploadLinkRecord | null> {
    const link = this.#links.get(tupleKey(workspaceId, tokenHash));
    return link === undefined ? null : structuredClone(link);
  }

  async claimUploadLink(workspaceId: string, tokenHash: string, usedAt: string): Promise<boolean> {
    const link = this.#links.get(tupleKey(workspaceId, tokenHash));
    if (link === undefined || link.usedAt !== null || !(Date.parse(usedAt) < Date.parse(link.expiresAt))) return false;
    link.usedAt = usedAt;
    return true;
  }

  async purgeExpiredUploadLinks(workspaceId: string, now: string): Promise<number> {
    let purged = 0;
    for (const [key, link] of this.#links) {
      if (link.workspaceId === workspaceId && !(Date.parse(now) < Date.parse(link.expiresAt))) {
        this.#links.delete(key);
        purged++;
      }
    }
    return purged;
  }

  async putDocument(document: DocumentRecord, bytes: Uint8Array): Promise<void> {
    this.#documents.push({ document: structuredClone(document), bytes: Uint8Array.from(bytes) });
  }

  /** Every stored link, copied: what a breach of this store would expose. */
  links(): UploadLinkRecord[] {
    return [...this.#links.values()].map((link) => structuredClone(link));
  }

  /** Every stored document with its bytes, copied. */
  documents(): Array<{ document: DocumentRecord; bytes: Uint8Array }> {
    return this.#documents.map(({ document, bytes }) => ({ document: structuredClone(document), bytes: Uint8Array.from(bytes) }));
  }
}
