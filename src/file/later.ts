// File pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";
import type { Locale } from "../core/runtime.ts";
import type { FieldValue, IntakeForm } from "./intake.ts";

/** The read-back line, built by code in English or French, that the caller confirms. */
export function buildReadBack(_form: IntakeForm, _values: Readonly<Record<string, FieldValue>>, _locale: Locale): never {
  throw new NotImplementedError("buildReadBack", "FIL-1");
}

/** Encrypts a sensitive field value before storage, with the host's key. */
export interface FieldCipher {
  encrypt(plain: string, context: { workspaceId: string; recordId: string; field: string }): Promise<string>;
}

/** Delivers a confirmed record (signed webhook, email) with retries and an idempotency key. */
export function deliverRecord(_input: { workspaceId: string; recordId: string }): never {
  throw new NotImplementedError("deliverRecord", "FIL-3");
}

/** A single-use upload link for a photo or PDF, attached to the record. */
export function createUploadLink(_input: { callId: string; recordId: string }): never {
  throw new NotImplementedError("createUploadLink", "FIL-5");
}
