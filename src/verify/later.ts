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

/** Failure counters and lockout per subject and per calling number, across calls. */
export function recordSubjectFailure(_input: { workspaceId: string; subjectKey: string }): never {
  throw new NotImplementedError("recordSubjectFailure", "VER-1");
}

/** Normalises a spoken answer (a postal code, a name) for an exact comparison. Never fuzzy. */
export function normaliseSpokenAnswer(_input: { field: string; transcript: string; locale: "en" | "fr" }): never {
  throw new NotImplementedError("normaliseSpokenAnswer", "VER-3");
}
