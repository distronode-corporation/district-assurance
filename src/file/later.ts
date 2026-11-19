// File pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** A single-use upload link for a photo or PDF, attached to the record. */
export function createUploadLink(_input: { callId: string; recordId: string }): never {
  throw new NotImplementedError("createUploadLink", "FIL-5");
}
