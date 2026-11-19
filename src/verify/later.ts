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

/**
 * Lets a caller who verified to level 2 or above on this call choose a PIN, stored as the keyed
 * hash the PIN factor compares against. Checking a PIN is built (the `pin` factor); enrolment is not.
 */
export function enrolPin(_input: { callId: string }): never {
  throw new NotImplementedError("enrolPin", "VER-6");
}
