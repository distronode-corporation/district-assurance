// The carrier Lookup answers read as the engine's carrier signals: Twilio Lookup v2's `sim_swap` and
// `identity_match` fields and Telnyx Number Lookup's `portability`. Pure: the host fetches the
// answer with its own credentials, rate limits and country policy (ADR-30) and hands the fields here.
import type { CarrierSignalReport } from "../core/policy.ts";

/** Why a field is not an answer: not the shape the vendor documents, or the vendor reported an error for it. */
export type CarrierFieldFailure = { reason: "bad_response" } | { reason: "feature_unavailable"; code?: string };

const HOUR_MS = 3_600_000;
/** A date and time with a zone, as Twilio writes `last_sim_swap_date`. */
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/;
const UNCHECKED: CarrierSignalReport = { checked: false, simSwapChecked: false, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A fresh report that says nothing is known. */
export function uncheckedReport(): CarrierSignalReport {
  return { ...UNCHECKED };
}

/** Whole hours from `at` to now, never negative. Rounded down, so a change is never reported older than it is. */
function hoursSince(at: number, now: Date): number {
  return Math.max(0, Math.floor((now.getTime() - at) / HOUR_MS));
}

/** An ISO 8601 duration such as `PT15282H33M44S` or `P3DT4H`, in whole hours, or null. */
export function durationHours(value: string): number | null {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(value);
  if (m === null || value === "P" || value.endsWith("T")) return null;
  const [, d, h, min, s] = m;
  const hours = Number(d ?? 0) * 24 + Number(h ?? 0) + Number(min ?? 0) / 60 + Number(s ?? 0) / 3600;
  // A period too long for a number is not an answer: Infinity hours would trust a texted code on a
  // SIM swap of any age.
  return Number.isFinite(hours) ? Math.floor(hours) : null;
}

/**
 * Hours since the last SIM change, from Twilio Lookup v2's `sim_swap` field: from its date (ISO 8601
 * only), but when Twilio says it changed within the period it looked at, never older than that period
 * (0 without a date that fits it); else, when Twilio says it did not, the period's length as a lower
 * bound. Anything else is not an answer.
 */
export function twilioSimSwapHours(field: unknown, now: Date): number | CarrierFieldFailure {
  if (!isObject(field)) return { reason: "bad_response" };
  if (field.error_code !== null && field.error_code !== undefined) return { reason: "feature_unavailable", code: String(field.error_code) };
  const last = field.last_sim_swap;
  if (!isObject(last)) return { reason: "bad_response" };
  // Only an ISO 8601 time is a date: Date.parse also reads "1" or "Jan 1" as a year long ago.
  const at = typeof last.last_sim_swap_date === "string" && ISO_TIME.test(last.last_sim_swap_date) ? Date.parse(last.last_sim_swap_date) : Number.NaN;
  const dated = Number.isNaN(at) ? null : hoursSince(at, now);
  const period = typeof last.swapped_period === "string" ? durationHours(last.swapped_period) : null;
  if (last.swapped_in_period === true) return dated !== null && period !== null && dated <= period ? dated : 0;
  if (dated !== null) return dated;
  if (last.swapped_in_period === false && period !== null) return period;
  return { reason: "bad_response" };
}

/** Twilio Lookup v2's `identity_match`: a match at `minScore` (1 to 100) or more of its 0 to 100 summary score. */
export function twilioIdentityMatch(field: unknown, minScore: number): "match" | "no_match" | CarrierFieldFailure {
  if (typeof minScore !== "number" || !(minScore >= 1 && minScore <= 100)) throw new TypeError("minScore must be from 1 to 100");
  if (!isObject(field)) return { reason: "bad_response" };
  if (field.error_code !== null && field.error_code !== undefined) return { reason: "feature_unavailable", code: String(field.error_code) };
  const score = field.summary_score;
  if (typeof score !== "number" || !(score >= 0 && score <= 100)) return { reason: "bad_response" };
  return score >= minScore ? "match" : "no_match";
}

/**
 * Hours since the last port, from Telnyx Number Lookup's `portability`; null when not ported.
 * Telnyx gives a date without a time or a zone, so the hours run from the last moment that date
 * ends anywhere (noon UTC the next day), so a port is never reported older than it can be. A port
 * without a readable date is a port just now (0).
 */
export function telnyxPortHours(field: unknown, now: Date): number | null | CarrierFieldFailure {
  if (!isObject(field)) return { reason: "bad_response" };
  const status = typeof field.ported_status === "string" ? field.ported_status.toUpperCase() : "";
  if (status === "N") return null;
  if (status !== "Y") return { reason: "feature_unavailable" };
  const date = typeof field.ported_date === "string" ? field.ported_date : "";
  const dayOnly = /^\d{4}-\d{2}-\d{2}$/.test(date);
  const at = dayOnly ? Date.parse(`${date}T00:00:00Z`) + 36 * HOUR_MS : ISO_TIME.test(date) ? Date.parse(date) : Number.NaN;
  return Number.isNaN(at) ? 0 : hoursSince(at, now);
}

/** Whether a parse answered: a number of hours or null (none), never a failure. */
export function isCarrierAnswer<T>(value: T | CarrierFieldFailure): value is T {
  return !isObject(value);
}
