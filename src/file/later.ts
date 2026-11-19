// File pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** Delivers a confirmed record (signed webhook, email) with retries and an idempotency key. */
export function deliverRecord(_input: { workspaceId: string; recordId: string }): never {
  throw new NotImplementedError("deliverRecord", "FIL-3");
}

/** A single-use upload link for a photo or PDF, attached to the record. */
export function createUploadLink(_input: { callId: string; recordId: string }): never {
  throw new NotImplementedError("createUploadLink", "FIL-5");
}
