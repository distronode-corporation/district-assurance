// Carrier signal adapters for the reference server (VER-4): Twilio Lookup v2 (SIM Swap and Identity
// Match) and Telnyx Number Lookup (porting status and date, and the carrier). They call the vendors'
// REST APIs with fetch (no SDK dependency), with credentials read from the environment by
// `twilioLookupFromEnv` and `telnyxLookupFromEnv`.
//
// Fail closed: a bad number, a country the account may not look up, a timeout, a network error, an
// HTTP error, a feature the account is not approved for, or an answer this code cannot read all
// give `checked: false` with nothing known. `check` never throws into the call. `onUnavailable`
// hears why, with the vendor's status and error code, never the number, a name or a credential.
import type { CarrierSignalReport, CarrierSignals, Clock } from "../../../src/index.ts";
import { systemClock } from "../../../src/index.ts";

export type CarrierVendor = "twilio" | "telnyx";

/** Why a lookup gave no answer. Says how it failed, never what was looked up. */
export type CarrierLookupFailureReason =
  | "invalid_number"
  | "unsupported_country"
  | "identity_on_file"
  | "timeout"
  | "network"
  | "http_status"
  | "bad_response"
  | "feature_unavailable";

export interface CarrierLookupFailure {
  vendor: CarrierVendor;
  reason: CarrierLookupFailureReason;
  /** The HTTP status, when there was one. */
  status?: number;
  /** The vendor's error code, when it gave one (for example a feature the account is not approved for). */
  code?: string;
}

export interface CarrierAdapterOptions {
  /** ISO 3166 alpha-2 codes the account may look up; an answer for any other country is not used. */
  countries: readonly string[];
  /** The API origin. Tests point it at a local fake server. */
  baseUrl?: string;
  /** Per lookup, connection and body included: a whole number from 1 to 60000. Default 3000. */
  timeoutMs?: number;
  clock?: Clock;
  /**
   * Hears each lookup that gave no answer, for the host's logs and metrics. Its errors, thrown or
   * rejected, are ignored, and the report is not held back waiting for it.
   */
  onUnavailable?: (failure: CarrierLookupFailure) => void | Promise<void>;
}

/** What the business has on file for the subject, for Twilio Identity Match. Sent to Twilio, kept nowhere. */
export interface IdentityOnFile {
  firstName?: string;
  lastName?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  /** ISO 3166 alpha-2. */
  addressCountryCode?: string;
  nationalId?: string;
  /** YYYYMMDD. */
  dateOfBirth?: string;
}

export interface TwilioLookupOptions extends CarrierAdapterOptions {
  /**
   * The identity on file for a number on file, or null when there is none. Without it, or when it
   * answers null, Identity Match is not asked and is reported `unavailable`.
   */
  identityFor?: (phoneNumber: string) => Promise<IdentityOnFile | null>;
  /** Twilio's `summary_score` (0 to 100) at or above which the identity is a match. Default 80. */
  identityMinScore?: number;
}

/** Basic auth for Twilio: an API key and its secret, or the account SID and auth token. */
export interface TwilioCredentials {
  username: string;
  password: string;
}

/** The carrier Telnyx names for a number, for the host's own use. Not part of the report. */
export interface TelnyxCarrier {
  name: string | null;
  /** For example `mobile`, `fixed line`, `voip`. */
  type: string | null;
}

type Env = Readonly<Record<string, string | undefined>>;
type Json = Record<string, unknown>;
type Fetched = { ok: true; body: Json } | { ok: false; failure: Omit<CarrierLookupFailure, "vendor"> };

const UNCHECKED: CarrierSignalReport = { checked: false, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" };
const E164 = /^\+[1-9]\d{6,14}$/;
const HOUR_MS = 3_600_000;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_TIMEOUT_MS = 60_000;

/** A fresh report that says nothing is known. */
export function uncheckedReport(): CarrierSignalReport {
  return { ...UNCHECKED };
}

const isObject = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);

/** Whole hours from `at` to now, never negative. Rounded down, so a change is never reported older than it is. */
function hoursSince(at: number, now: Date): number {
  return Math.max(0, Math.floor((now.getTime() - at) / HOUR_MS));
}

/** An ISO 8601 duration such as `PT15282H33M44S` or `P3DT4H`, in hours, or null. */
export function durationHours(value: string): number | null {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(value);
  if (m === null || value === "P" || value.endsWith("T")) return null;
  const [, d, h, min, s] = m;
  const hours = Number(d ?? 0) * 24 + Number(h ?? 0) + Number(min ?? 0) / 60 + Number(s ?? 0) / 3600;
  return Math.floor(hours);
}

function countryList(raw: string | undefined, fallback: readonly string[]): string[] {
  const list = (raw ?? "")
    .split(",")
    .map((c) => c.trim().toUpperCase())
    .filter((c) => c !== "");
  return list.length > 0 ? list : [...fallback];
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The API origin without a trailing slash. Credentials go to it, so it must be https, or plain
 * http only on a loopback host (a local fake server). Anything else throws when the adapter is
 * built, before any credential is used.
 */
function safeBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("carrier adapter baseUrl is not a valid URL");
  }
  const loopback = LOOPBACK_HOSTS.has(url.hostname) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("carrier adapter baseUrl must be https, or http only on a loopback host");
  }
  return raw.replace(/\/+$/, "");
}

abstract class LookupAdapter implements CarrierSignals {
  protected abstract readonly vendor: CarrierVendor;
  protected readonly baseUrl: string;
  protected readonly clock: Clock;
  readonly #countries: ReadonlySet<string>;
  readonly #timeoutMs: number;
  readonly #onUnavailable: ((failure: CarrierLookupFailure) => void | Promise<void>) | undefined;

  constructor(options: CarrierAdapterOptions, defaultBaseUrl: string) {
    this.baseUrl = safeBaseUrl(options.baseUrl ?? defaultBaseUrl);
    this.clock = options.clock ?? systemClock;
    this.#countries = new Set(options.countries.map((c) => c.toUpperCase()));
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // AbortSignal.timeout throws on anything else, and it runs inside check, so refuse it here.
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(`carrier adapter timeoutMs must be a whole number from 1 to ${MAX_TIMEOUT_MS}`);
    }
    this.#timeoutMs = timeoutMs;
    this.#onUnavailable = options.onUnavailable;
  }

  abstract check(input: { phoneNumber: string }): Promise<CarrierSignalReport>;

  /** Reports a failure to the host's listener and answers that nothing is known. */
  protected unavailable(failure: Omit<CarrierLookupFailure, "vendor">): CarrierSignalReport {
    try {
      const result: unknown = this.#onUnavailable?.({ vendor: this.vendor, ...failure });
      if (result instanceof Promise) result.catch(() => undefined);
    } catch {
      // A listener's error never reaches the call.
    }
    return uncheckedReport();
  }

  /** E.164, and a string: RegExp.test would coerce anything else, and a Symbol makes it throw. */
  protected validNumber(phoneNumber: unknown): boolean {
    return typeof phoneNumber === "string" && E164.test(phoneNumber);
  }

  protected countryAllowed(country: unknown): boolean {
    return typeof country === "string" && this.#countries.has(country.toUpperCase());
  }

  /** One GET with a deadline over the whole exchange. Never throws. */
  protected async getJson(url: string, headers: Record<string, string>, errorCode: (body: unknown) => string | undefined): Promise<Fetched> {
    const signal = AbortSignal.timeout(this.#timeoutMs);
    let status: number;
    let text: string;
    try {
      const res = await fetch(url, { method: "GET", headers: { accept: "application/json", ...headers }, signal, redirect: "error" });
      status = res.status;
      text = await res.text();
    } catch (err) {
      return { ok: false, failure: { reason: (err as Error).name === "TimeoutError" ? "timeout" : "network" } };
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    if (status < 200 || status > 299) {
      const code = errorCode(body);
      return { ok: false, failure: code === undefined ? { reason: "http_status", status } : { reason: "http_status", status, code } };
    }
    if (!isObject(body)) return { ok: false, failure: { reason: "bad_response", status } };
    return { ok: true, body };
  }
}

const TWILIO_IDENTITY_PARAMS: ReadonlyArray<[keyof IdentityOnFile, string]> = [
  ["firstName", "FirstName"],
  ["lastName", "LastName"],
  ["addressLine1", "AddressLine1"],
  ["addressLine2", "AddressLine2"],
  ["city", "City"],
  ["state", "State"],
  ["postalCode", "PostalCode"],
  ["addressCountryCode", "AddressCountryCode"],
  ["nationalId", "NationalId"],
  ["dateOfBirth", "DateOfBirth"],
];

/**
 * Twilio Lookup v2 with the `sim_swap` field, and `identity_match` when the host gives the identity
 * on file. `checked` is true only when every field asked for answered; a SIM Swap that did not
 * answer makes the whole report unknown, so a texted code is never trusted on half an answer.
 */
export class TwilioLookupSignals extends LookupAdapter {
  protected readonly vendor = "twilio";
  readonly #authorization: string;
  readonly #identityFor: ((phoneNumber: string) => Promise<IdentityOnFile | null>) | undefined;
  readonly #minScore: number;

  constructor(credentials: TwilioCredentials, options: TwilioLookupOptions) {
    super(options, "https://lookups.twilio.com");
    this.#authorization = `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64")}`;
    this.#identityFor = options.identityFor;
    this.#minScore = options.identityMinScore ?? 80;
  }

  async check(input: { phoneNumber: string }): Promise<CarrierSignalReport> {
    if (!this.validNumber(input.phoneNumber)) return this.unavailable({ reason: "invalid_number" });
    let identity: IdentityOnFile | null = null;
    try {
      identity = this.#identityFor === undefined ? null : await this.#identityFor(input.phoneNumber);
    } catch {
      return this.unavailable({ reason: "identity_on_file" });
    }
    const params = new URLSearchParams({ Fields: identity === null ? "sim_swap" : "sim_swap,identity_match" });
    for (const [key, param] of TWILIO_IDENTITY_PARAMS) {
      const value = identity?.[key];
      if (value !== undefined && value !== "") params.set(param, value);
    }
    const url = `${this.baseUrl}/v2/PhoneNumbers/${encodeURIComponent(input.phoneNumber)}?${params.toString()}`;
    const fetched = await this.getJson(url, { authorization: this.#authorization }, (body) =>
      isObject(body) && (typeof body.code === "number" || typeof body.code === "string") ? String(body.code) : undefined,
    );
    if (!fetched.ok) return this.unavailable(fetched.failure);
    const body = fetched.body;
    if (body.valid === false) return this.unavailable({ reason: "invalid_number" });
    if (!this.countryAllowed(body.country_code)) return this.unavailable({ reason: "unsupported_country" });

    const swap = this.#simSwapHours(body.sim_swap);
    if (typeof swap !== "number" && swap !== null) return this.unavailable(swap);
    let identityMatch: CarrierSignalReport["identityMatch"] = "unavailable";
    if (identity !== null) {
      const matched = this.#identityMatch(body.identity_match);
      if (typeof matched !== "string") return this.unavailable(matched);
      identityMatch = matched;
    }
    return { checked: true, lastSimSwapHoursAgo: swap, lastPortHoursAgo: null, identityMatch };
  }

  /**
   * Hours since the last SIM change: from its date; else 0 when Twilio says it changed within the
   * period it looked at; else, when Twilio says it did not, the length of that period as a lower
   * bound (the change is at least that old). `swapped_period` is the window Twilio looked at, never
   * the age of a change. Anything else is not an answer.
   */
  #simSwapHours(field: unknown): number | null | Omit<CarrierLookupFailure, "vendor"> {
    if (!isObject(field)) return { reason: "bad_response" };
    if (field.error_code !== null && field.error_code !== undefined) return { reason: "feature_unavailable", code: String(field.error_code) };
    const last = field.last_sim_swap;
    if (!isObject(last)) return { reason: "bad_response" };
    if (typeof last.last_sim_swap_date === "string") {
      const at = Date.parse(last.last_sim_swap_date);
      if (!Number.isNaN(at)) return hoursSince(at, this.clock.now());
    }
    if (last.swapped_in_period === true) return 0;
    if (last.swapped_in_period === false && typeof last.swapped_period === "string") {
      const hours = durationHours(last.swapped_period);
      if (hours !== null) return hours;
    }
    return { reason: "bad_response" };
  }

  #identityMatch(field: unknown): CarrierSignalReport["identityMatch"] | Omit<CarrierLookupFailure, "vendor"> {
    if (!isObject(field)) return { reason: "bad_response" };
    if (field.error_code !== null && field.error_code !== undefined) return { reason: "feature_unavailable", code: String(field.error_code) };
    const score = field.summary_score;
    if (typeof score !== "number" || !Number.isFinite(score)) return { reason: "bad_response" };
    return score >= this.#minScore ? "match" : "no_match";
  }
}

/**
 * Telnyx Number Lookup (`type=carrier`): porting status and date, and the carrier. Telnyx reports
 * no SIM change and no identity match, so those are always null and `unavailable`.
 */
export class TelnyxNumberLookupSignals extends LookupAdapter {
  protected readonly vendor = "telnyx";
  readonly #authorization: string;

  constructor(apiKey: string, options: CarrierAdapterOptions) {
    super(options, "https://api.telnyx.com");
    this.#authorization = `Bearer ${apiKey}`;
  }

  async check(input: { phoneNumber: string }): Promise<CarrierSignalReport> {
    return (await this.lookup(input)).report;
  }

  /** The report, plus the carrier Telnyx named (null when the lookup gave no answer or no carrier). */
  async lookup(input: { phoneNumber: string }): Promise<{ report: CarrierSignalReport; carrier: TelnyxCarrier | null }> {
    if (!this.validNumber(input.phoneNumber)) return { report: this.unavailable({ reason: "invalid_number" }), carrier: null };
    const url = `${this.baseUrl}/v2/number_lookup/${encodeURIComponent(input.phoneNumber)}?type=carrier`;
    const fetched = await this.getJson(url, { authorization: this.#authorization }, (body) => {
      const first = isObject(body) && Array.isArray(body.errors) ? (body.errors[0] as unknown) : undefined;
      return isObject(first) && (typeof first.code === "string" || typeof first.code === "number") ? String(first.code) : undefined;
    });
    if (!fetched.ok) return { report: this.unavailable(fetched.failure), carrier: null };
    const data = fetched.body.data;
    if (!isObject(data)) return { report: this.unavailable({ reason: "bad_response" }), carrier: null };
    if (!this.countryAllowed(data.country_code)) return { report: this.unavailable({ reason: "unsupported_country" }), carrier: null };
    const port = this.#portHours(data.portability);
    if (typeof port !== "number" && port !== null) return { report: this.unavailable(port), carrier: null };
    return {
      report: { checked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: port, identityMatch: "unavailable" },
      carrier: carrierOf(data.carrier),
    };
  }

  /**
   * Hours since the last port. Telnyx gives a date without a time, so the hours run from the end of
   * that day (a port is never reported older than it can be), and a port without a date is 0.
   */
  #portHours(field: unknown): number | null | Omit<CarrierLookupFailure, "vendor"> {
    if (!isObject(field)) return { reason: "bad_response" };
    const status = typeof field.ported_status === "string" ? field.ported_status.toUpperCase() : "";
    if (status === "N") return null;
    if (status !== "Y") return { reason: "feature_unavailable" };
    const date = typeof field.ported_date === "string" ? field.ported_date : "";
    const dayOnly = /^\d{4}-\d{2}-\d{2}$/.test(date);
    const at = dayOnly ? Date.parse(`${date}T00:00:00Z`) + 24 * HOUR_MS : Date.parse(date);
    return Number.isNaN(at) ? 0 : hoursSince(at, this.clock.now());
  }
}

function carrierOf(field: unknown): TelnyxCarrier | null {
  if (!isObject(field) || (field.error_code !== null && field.error_code !== undefined)) return null;
  const name = typeof field.name === "string" && field.name !== "" ? field.name : null;
  const type = typeof field.type === "string" && field.type !== "" ? field.type : null;
  return name === null && type === null ? null : { name, type };
}

/**
 * Twilio Lookup from the environment, or null when its credentials are not set:
 * `TWILIO_API_KEY` and `TWILIO_API_SECRET` (preferred), else `TWILIO_ACCOUNT_SID` and
 * `TWILIO_AUTH_TOKEN`; `TWILIO_LOOKUP_COUNTRIES` (comma separated, default `US`).
 */
export function twilioLookupFromEnv(env: Env = process.env, options: Omit<TwilioLookupOptions, "countries"> = {}): TwilioLookupSignals | null {
  const apiKey = env.TWILIO_API_KEY ?? "";
  const credentials =
    apiKey !== ""
      ? { username: apiKey, password: env.TWILIO_API_SECRET ?? "" }
      : { username: env.TWILIO_ACCOUNT_SID ?? "", password: env.TWILIO_AUTH_TOKEN ?? "" };
  if (credentials.username === "" || credentials.password === "") return null;
  return new TwilioLookupSignals(credentials, { ...options, countries: countryList(env.TWILIO_LOOKUP_COUNTRIES, ["US"]) });
}

/**
 * Telnyx Number Lookup from the environment, or null when `TELNYX_API_KEY` is not set;
 * `TELNYX_LOOKUP_COUNTRIES` (comma separated, default `US`).
 */
export function telnyxLookupFromEnv(env: Env = process.env, options: Omit<CarrierAdapterOptions, "countries"> = {}): TelnyxNumberLookupSignals | null {
  const apiKey = env.TELNYX_API_KEY ?? "";
  if (apiKey === "") return null;
  return new TelnyxNumberLookupSignals(apiKey, { ...options, countries: countryList(env.TELNYX_LOOKUP_COUNTRIES, ["US"]) });
}
