// File pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";
import type { FieldValue, IntakeForm } from "./intake.ts";

/** The read-back line, built by code in English or French, that the caller confirms. */
export function buildReadBack(_form: IntakeForm, _values: Readonly<Record<string, FieldValue>>, _locale: "en" | "fr"): never {
  throw new NotImplementedError("buildReadBack", "FIL-1");
}

/** Delivers a confirmed record (signed webhook, email) with retries and an idempotency key. */
export function deliverRecord(_input: { workspaceId: string; recordId: string }): never {
  throw new NotImplementedError("deliverRecord", "FIL-3");
}

/** A single-use upload link for a photo or PDF, attached to the record. */
export function createUploadLink(_input: { callId: string; recordId: string }): never {
  throw new NotImplementedError("createUploadLink", "FIL-5");
}
