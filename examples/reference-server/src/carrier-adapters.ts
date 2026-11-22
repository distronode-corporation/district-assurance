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
import { isCarrierAnswer, telnyxPortHours, twilioIdentityMatch, twilioSimSwapHours, uncheckedReport } from "../../../src/carrier/index.ts";

// The parsers moved into the package (district-assurance/carrier); re-exported for the reference server's callers.
export { durationHours, uncheckedReport } from "../../../src/carrier/index.ts";

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
  /** Twilio's `summary_score` (0 to 100) at or above which the identity is a match: 1 to 100, default 80. */
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

const E164 = /^\+[1-9]\d{6,14}$/;
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_TIMEOUT_MS = 60_000;


/** `work`, or a rejection when `signal` aborts first. The listener goes when either settles. */
function beforeDeadline<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason as Error);
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(work).then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

const isObject = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);

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

  /** The deadline for one lookup, started before anything it waits on. */
  protected deadline(): AbortSignal {
    return AbortSignal.timeout(this.#timeoutMs);
  }

  /** One GET under the lookup's deadline, connection and body included. Never throws. */
  protected async getJson(
    url: string,
    headers: Record<string, string>,
    errorCode: (body: unknown) => string | undefined,
    signal: AbortSignal,
  ): Promise<Fetched> {
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
    const minScore = options.identityMinScore ?? 80;
    // 0 or less would call a score of 0 a match, and a match is a factor that is not knowledge.
    if (typeof minScore !== "number" || !(minScore >= 1 && minScore <= 100)) {
      throw new Error("carrier adapter identityMinScore must be from 1 to 100");
    }
    this.#minScore = minScore;
  }

  async check(input: { phoneNumber: string }): Promise<CarrierSignalReport> {
    if (!this.validNumber(input.phoneNumber)) return this.unavailable({ reason: "invalid_number" });
    // The identity on file counts against the deadline: one that never answers is a timeout, and
    // the vendor is not asked.
    const signal = this.deadline();
    let identity: IdentityOnFile | null = null;
    try {
      identity = this.#identityFor === undefined ? null : await beforeDeadline(this.#identityFor(input.phoneNumber), signal);
    } catch {
      return this.unavailable({ reason: signal.aborted ? "timeout" : "identity_on_file" });
    }
    const params = new URLSearchParams({ Fields: identity === null ? "sim_swap" : "sim_swap,identity_match" });
    for (const [key, param] of TWILIO_IDENTITY_PARAMS) {
      const value = identity?.[key];
      if (value !== undefined && value !== "") params.set(param, value);
    }
    const url = `${this.baseUrl}/v2/PhoneNumbers/${encodeURIComponent(input.phoneNumber)}?${params.toString()}`;
    const fetched = await this.getJson(
      url,
      { authorization: this.#authorization },
      (body) => (isObject(body) && (typeof body.code === "number" || typeof body.code === "string") ? String(body.code) : undefined),
      signal,
    );
    if (!fetched.ok) return this.unavailable(fetched.failure);
    const body = fetched.body;
    if (body.valid === false) return this.unavailable({ reason: "invalid_number" });
    if (!this.countryAllowed(body.country_code)) return this.unavailable({ reason: "unsupported_country" });

    const swap = twilioSimSwapHours(body.sim_swap, this.clock.now());
    if (!isCarrierAnswer(swap)) return this.unavailable(swap);
    let identityMatch: CarrierSignalReport["identityMatch"] = "unavailable";
    if (identity !== null) {
      const matched = twilioIdentityMatch(body.identity_match, this.#minScore);
      if (!isCarrierAnswer(matched)) return this.unavailable(matched);
      identityMatch = matched;
    }
    return { checked: true, simSwapChecked: true, lastSimSwapHoursAgo: swap, lastPortHoursAgo: null, identityMatch };
  }
}

/**
 * Telnyx Number Lookup (`type=carrier`): porting status and date, and the carrier. Telnyx reports
 * no SIM change and no identity match, so `simSwapChecked` is false (a texted code never counts on
 * this report alone), the SIM swap hours null and the identity match `unavailable`.
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
    const fetched = await this.getJson(
      url,
      { authorization: this.#authorization },
      (body) => {
        const first = isObject(body) && Array.isArray(body.errors) ? (body.errors[0] as unknown) : undefined;
        return isObject(first) && (typeof first.code === "string" || typeof first.code === "number") ? String(first.code) : undefined;
      },
      this.deadline(),
    );
    if (!fetched.ok) return { report: this.unavailable(fetched.failure), carrier: null };
    const data = fetched.body.data;
    if (!isObject(data)) return { report: this.unavailable({ reason: "bad_response" }), carrier: null };
    if (!this.countryAllowed(data.country_code)) return { report: this.unavailable({ reason: "unsupported_country" }), carrier: null };
    const port = telnyxPortHours(data.portability, this.clock.now());
    if (typeof port !== "number" && port !== null) return { report: this.unavailable(port), carrier: null };
    return {
      report: { checked: true, simSwapChecked: false, lastSimSwapHoursAgo: null, lastPortHoursAgo: port, identityMatch: "unavailable" },
      carrier: carrierOf(data.carrier),
    };
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
