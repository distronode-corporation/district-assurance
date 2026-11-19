// Verify pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/**
 * Sends a one-time code by text to the number on file, only after the keypad checks matched, with
 * limits per subject and per calling number and a country allow-list for destinations.
 */
export function sendTextCode(_input: { callId: string }): never {
  throw new NotImplementedError("sendTextCode", "VER-2");
}

/** Checks a keyed one-time code: single use, short-lived, bound to the call. */
export function checkTextCode(_input: { callId: string; code: string }): never {
  throw new NotImplementedError("checkTextCode", "VER-2");
}
