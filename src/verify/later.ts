// Verify pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** Failure counters and lockout per subject and per calling number, across calls. */
export function recordSubjectFailure(_input: { workspaceId: string; subjectKey: string }): never {
  throw new NotImplementedError("recordSubjectFailure", "VER-1");
}

/** Normalises a spoken answer (a postal code, a name) for an exact comparison. Never fuzzy. */
export function normaliseSpokenAnswer(_input: { field: string; transcript: string; locale: "en" | "fr" }): never {
  throw new NotImplementedError("normaliseSpokenAnswer", "VER-3");
}

/**
 * Lets a caller who verified to level 2 or above on this call choose a PIN, stored as the keyed
 * hash the PIN factor compares against. Checking a PIN is built (the `pin` factor); enrolment is not.
 */
export function enrolPin(_input: { callId: string }): never {
  throw new NotImplementedError("enrolPin", "VER-6");
}
