// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment (platform-mode payments on the account
// endpoint, connect-mode payments on the Connect endpoint, each with its own signing secret),
// serves receipts by capability link with a small receipt page, serves the receipt key set, runs a
// sample receiver for signed record deliveries, checks the signatures of the carrier webhooks
// (Twilio, Telnyx), and, with `uploads`, serves the single-use document upload page in English and
// French (FIL-5). With `ui`, it also serves the demo's browser UI and the routes that run the
// scripted demo one step at a time. With `securityTxt`, it serves the host's own
// `/.well-known/security.txt` (RFC 9116). Each route that reads a body has its own body limit,
// every request has deadlines, each remote address has a rate limit, and each answered request can
// be logged as one structured entry that never holds a body or a header. Still not hardened for
// production; ROADMAP.md, "Reference server", lists what else that takes.
import { STATUS_CODES, createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIPv6, type Socket } from "node:net";
import { performance } from "node:perf_hooks";

import {
  acceptUpload,
  DELIVERY_SIGNATURE_HEADER,
  EngineError,
  formatAmount,
  newReceiptLinkToken,
  openUploadLink,
  parseStripeEvent,
  randomIds,
  receiptLinkTokenHash,
  sha256Hex,
  systemClock,
  verifyReceipt,
  verifyStripeSignature,
  verifyTelnyxSignature,
  verifyTwilioSignature,
  type Clock,
  type DocumentScanner,
  type DocumentStore,
  type DocumentType,
  type Engine,
  type IdGenerator,
  type RecordDeliveryBody,
  type SignedReceipt,
  type UploadRefusal,
  type UploadResult,
} from "../../../src/index.ts";
import type { DemoRuns, RunAnswer } from "./demo-runs.ts";
import { UI_HEADERS, loadStaticFiles, type StaticFile } from "./static.ts";

export interface ReferenceServerOptions {
  engine: Engine;
  /**
   * Signing secrets per Stripe endpoint. Empty means the endpoint refuses everything. `connect` is
   * the Connect endpoint ("Events from: Connected accounts"), which has its own secret.
   */
  stripeSecrets: { identity: readonly string[]; payments: readonly string[]; connect?: readonly string[] };
  /** Carrier webhook keys. A carrier left out, or given no key, refuses everything. */
  carriers?: {
    /**
     * The account's auth tokens, and the public origin Twilio calls (`https://voice.example.test`):
     * Twilio signs the full URL, which a server behind a proxy cannot see.
     */
    twilio?: { authTokens: readonly string[]; publicOrigin: string };
    /** The account's Ed25519 public keys, base64, as the Telnyx portal shows them. */
    telnyx?: { publicKeys: readonly string[] };
  };
  clock: Clock;
  /**
   * The sample receiver of record deliveries (`POST /webhooks/records`): the signing secrets it
   * accepts, and what it does with a record. Without secrets it refuses everything. The receiver
   * awaits `onRecord` and records the key only once it succeeds; when it throws or rejects, the
   * answer is 500 and the sender's retry applies the record again.
   */
  records?: {
    secrets: readonly string[];
    onRecord?: (delivery: RecordDeliveryBody) => void | Promise<void>;
    /**
     * Told of each duplicate, before it is answered: `pending` while the first delivery's
     * `onRecord` still runs (the duplicate waits for it), `received` once it has succeeded.
     */
    onDuplicate?: (idempotencyKey: string, state: "pending" | "received") => void;
  };
  /**
   * Body limits in bytes, per route that reads a body. Defaults in `DEFAULT_BODY_LIMITS`. An upload
   * (`/u/:token`) has none here: its limit is its own link's size cap plus the multipart overhead.
   */
  bodyLimits?: Partial<BodyLimits>;
  /**
   * Milliseconds to receive a whole request, headers and body, and, counted from the end of the
   * headers, to answer it. A request not all received in time gets `408 request_timeout` and the
   * connection is closed; a request not answered in time gets `503 timeout` (a body still arriving
   * gets whichever comes first). Default 10 seconds.
   */
  timeoutMs?: number;
  /**
   * Requests per remote address per window, for at most `addresses` addresses at once. Default
   * 300 a minute, 10,000 addresses. The window is counted on `clock`, the system clock by default,
   * never on the server's `clock`: the demo's server runs on a fixed clock, where a window that
   * filled up would never end.
   */
  rateLimit?: { requests: number; windowMs: number; addresses?: number; clock?: Clock };
  /**
   * Called once per answered request, after the answer is written, including the refusals of
   * requests node:http could not read. Absent means no logs. If it throws, or answers a promise
   * that rejects, the entry is dropped.
   */
  log?: (entry: RequestLog) => void;
  /** How long and how many Stripe event ids are remembered (`SeenEvents`). Defaults: 4 days, 10,000. */
  seenEvents?: { ttlMs?: number; max?: number };
  /** The demo's runs: serves the browser UI and the `/demo/*` routes. Off when absent. */
  ui?: DemoRuns;
  /** The receipt links the host issued. Absent: `/r/:token` answers 404 for every token. */
  receiptLinks?: ReceiptLinks;
  /** Document uploads by single-use link: serves `/u/:token`. Off when absent. */
  uploads?: {
    documents: DocumentStore;
    scanner: DocumentScanner;
    ids?: IdGenerator;
    /**
     * How many upload outcomes are kept at once, each until its link would have expired, so a
     * retry after a lost answer gets the outcome. Default 10,000. When it is full, a new upload is
     * refused (503, `retry-after`) before it spends its link; a kept outcome is never dropped early.
     */
    keptMax?: number;
  };
  /** The host's own security.txt. No route when absent: there is no default. */
  securityTxt?: SecurityTxtSettings;
  /** Where start-up warnings go. Default `console.warn`. */
  warn?: (message: string) => void;
}

/** The routes that read a body, upload aside (its link sets its limit). Every other route answers without reading one. */
export interface BodyLimits {
  stripeIdentity: number;
  stripePayments: number;
  stripeConnect: number;
  /** `POST /webhooks/records`, the sample receiver of record deliveries. */
  records: number;
  twilio: number;
  telnyx: number;
  /** `POST /demo/runs` and `POST /demo/runs/:runId/next`, whose bodies are a flow name or nothing. */
  demo: number;
}

export const DEFAULT_BODY_LIMITS: Readonly<BodyLimits> = {
  stripeIdentity: 64 * 1024,
  stripePayments: 64 * 1024,
  stripeConnect: 64 * 1024,
  records: 64 * 1024,
  twilio: 64 * 1024,
  telnyx: 64 * 1024,
  demo: 1024,
};

const BODY_LIMIT_NAMES = Object.keys(DEFAULT_BODY_LIMITS) as ReadonlyArray<keyof BodyLimits>;

/**
 * One answered request. It names the route by its pattern, never the path as sent, so the ids and
 * tokens a path can carry stay out of the log, and it holds no header, no query string and no body.
 */
export interface RequestLog {
  /** From the server's clock, ISO 8601. */
  time: string;
  /** The caller the rate limit counts: the socket's IPv4 address, or its IPv6 /64 (`rateLimitKey`). */
  address: string;
  /** `unknown` when the request was refused before its headers were read. */
  method: string;
  /** `/r/:token`, `/u/:token`, `/demo/runs/:runId/next` and so on; `unmatched` when no route matched. */
  route: string;
  status: number;
  /** A refusal's error code, as in its JSON answer. */
  error?: string;
  /** Wall time spent answering, in whole milliseconds. */
  ms: number;
}

/** A `log` sink of JSON lines, and the switch that stops it for good. */
export interface JsonLinesLog {
  (entry: RequestLog): void;
  /** Writes nothing more: for a stream that has failed (`guardLogStream` in main.ts). */
  stop(): void;
}

/** The stream a `JsonLinesLog` writes to: `write` answers false while its buffer is full. */
export interface LogStream {
  write(chunk: string): boolean;
  once(event: "drain", listener: () => void): unknown;
}

/**
 * A `log` that writes each entry as one line of JSON on `stream`, never holding more than the
 * stream's own buffer: while the stream is backpressured each new entry is dropped and counted,
 * and on `drain` one line says how many were (`{"warning":"log_entries_dropped","dropped":n}`).
 * A request never waits on it.
 */
export function jsonLinesLog(stream: LogStream): JsonLinesLog {
  let stopped = false;
  let blocked = false;
  let dropped = 0;
  const put = (line: string): void => {
    if (stream.write(line)) return;
    blocked = true;
    stream.once("drain", () => {
      blocked = false;
      if (dropped === 0 || stopped) return;
      const count = dropped;
      dropped = 0;
      put(`${JSON.stringify({ warning: "log_entries_dropped", dropped: count })}\n`);
    });
  };
  const log = (entry: RequestLog): void => {
    if (stopped) return;
    if (blocked) {
      dropped += 1;
      return;
    }
    put(`${JSON.stringify(entry)}\n`);
  };
  return Object.assign(log, {
    stop: () => {
      stopped = true;
    },
  });
}

/** The `log` of `npm run serve`: JSON lines on standard output, bounded as `jsonLinesLog` says. */
export const logJsonLines: JsonLinesLog = jsonLinesLog(process.stdout);

/**
 * The host's security.txt (RFC 9116). A security.txt speaks only for the domain it is served
 * from, so these are the host's own contacts and policy, never this project's.
 */
export interface SecurityTxtSettings {
  /** One or more ways to reach the host's security team: `mailto:`, `tel:` or `https:` URIs. */
  contact: readonly string[];
  /** When the file stops being valid: after the server starts, and at most a year later. */
  expires: Date;
  /** The host's disclosure policy, an `https:` URL. */
  policy?: string;
  /** Where the host publishes this file, an `https:` URL. */
  canonical?: string;
}

/**
 * Links to receipts by capability token. A call id is not a secret, so a receipt is served only
 * to whoever holds a token issued for it. Only the token's hash is kept, so this map (or a
 * database in its place) never holds a working link. In memory: links end with the process.
 */
export class ReceiptLinks {
  readonly #calls = new Map<string, string>();

  /** A new token for the receipt of `callId`, for the host to send once as `/r/<token>`. Not kept. */
  issue(callId: string): string {
    const { token, hash } = newReceiptLinkToken();
    this.#calls.set(hash, callId);
    return token;
  }

  /** The call a token was issued for; null for an unknown or malformed token alike. */
  callFor(token: string): string | null {
    const hash = receiptLinkTokenHash(token);
    return hash === null ? null : (this.#calls.get(hash) ?? null);
  }
}

type Json = Record<string, unknown>;
/** A page in HTML, already escaped: a receipt page, or an upload page (`upload`: it posts a form back here). */
interface Page {
  status?: number;
  upload?: true;
  /** Headers on top of the page's own: the `retry-after` of an upload still running. */
  headers?: Readonly<Record<string, string>>;
  html: string;
}
/** A plain text answer: the security.txt. */
type TextAnswer = { text: string };
type Answer = [number, Json] | StaticFile | Page | TextAnswer;

/** On the security.txt answer: plain text, never sniffed as anything else, never framed. */
const TEXT_HEADERS = {
  "content-type": "text/plain; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
};

const DAY_MS = 24 * 60 * 60 * 1000;
const WARN_MS = 30 * DAY_MS;

/**
 * This project's own reporting addresses (SECURITY.md). A host that copies one into its settings
 * would send reports about its deployment to this project, so they are refused.
 */
const PROJECT_ADDRESSES: readonly RegExp[] = [
  // The mailbox with or without a plus tag, which reaches it too; never a longer domain that starts the same.
  /(?<![\w.+-])opensource(?:\+[^@\s]*)?@distronode\.com(?![\w-]|\.[\w-])/i,
  // The repository however its path is spelled: doubled slashes, a .git suffix, any page under it.
  /github\.com\/+distronode-corporation\/+district-assurance(?:\.git)?(?![\w.-])/i,
];

/**
 * A URI of an allowed scheme, on one line of printable ASCII, so it can never add a field of its
 * own. A web URI must be written `https://` (RFC 9116): the URL parser repairs forms such as
 * `https:example.org`, but the file carries the value as written, so those are refused.
 */
function checkUri(field: string, value: string, schemes: readonly string[]): void {
  let scheme = "";
  try {
    scheme = new URL(value).protocol;
  } catch {
    // Not a URI: refused below.
  }
  const malformedWeb = scheme === "https:" && !/^https:\/\/[^/]/i.test(value);
  // A phone number is a global number (RFC 3966): `+`, then digits and visual separators with at
  // least one digit. A local number, a parameter or an escape is refused, so `tel:` alone is too.
  const malformedTel = scheme === "tel:" && !/^tel:\+[-.()0-9]*[0-9][-.()0-9]*$/i.test(value);
  if (!/^[\x21-\x7e]+$/.test(value) || !schemes.includes(scheme) || malformedWeb || malformedTel) {
    throw new Error(`securityTxt: ${field} must be a ${schemes.join(" or ")} URI on one line`);
  }
  if (PROJECT_ADDRESSES.some((p) => p.test(decodeURIComponentSafe(value)))) {
    throw new Error(`securityTxt: ${field} is this project's address; a security.txt names the host's own contacts`);
  }
}

/** The value with percent escapes decoded where they decode, so an escaped `@` is still seen. */
function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * The security.txt body, checked once when the server is created. Settings that cannot make a
 * valid file are refused, so a server never starts with an expired or a far-future file (RFC 9116
 * advises at most a year); one that expires within 30 days starts with a warning.
 */
export function securityTxt(settings: SecurityTxtSettings, now: Date, warn: (message: string) => void): string {
  // Read once: the contacts, links and expiry checked are the ones written into the file.
  const contacts = [...settings.contact];
  const { policy, canonical, expires: expiresAt } = settings;
  if (contacts.length === 0) throw new Error("securityTxt: at least one contact is required");
  for (const contact of contacts) checkUri("contact", contact, ["mailto:", "tel:", "https:"]);
  if (policy !== undefined) checkUri("policy", policy, ["https:"]);
  if (canonical !== undefined) checkUri("canonical", canonical, ["https:"]);
  const expires = expiresAt.getTime();
  const yearAhead = new Date(now);
  yearAhead.setUTCFullYear(yearAhead.getUTCFullYear() + 1);
  if (Number.isNaN(expires) || expires <= now.getTime()) throw new Error("securityTxt: expires must be in the future");
  if (expires > yearAhead.getTime()) throw new Error("securityTxt: expires must be at most a year ahead");
  // Whole seconds drop the `.000`; any other milliseconds stay, so the file never advertises an
  // expiry earlier than the one the route enforces.
  const stamp = expiresAt.toISOString().replace(/\.000Z$/, "Z");
  if (expires - now.getTime() <= WARN_MS) warn(expiryWarning(expiresAt));
  const lines = contacts.map((c) => `Contact: ${c}`);
  lines.push(`Expires: ${stamp}`);
  if (policy !== undefined) lines.push(`Policy: ${policy}`);
  if (canonical !== undefined) lines.push(`Canonical: ${canonical}`);
  return lines.join("\n") + "\n";
}

function expiryWarning(expires: Date): string {
  return `security.txt expires at ${expires.toISOString().replace(/\.000Z$/, "Z")}: renew it before then`;
}

/** On every JSON answer: never sniffed as anything else, never framed, never cached. */
const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
};

/**
 * On the receipt page: no script, style or form, never framed or cached, never indexed, and no
 * Referer, so the link's token never leaves in a header when the page is left.
 */
const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-robots-tag": "noindex, nofollow",
  "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

/** The same for the upload page, whose form posts back here only. */
const UPLOAD_PAGE_HEADERS = { ...PAGE_HEADERS, "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" };

/** Room for the multipart framing around the file, on top of the link's size cap. */
const MULTIPART_OVERHEAD_BYTES = 16 * 1024;

/**
 * With the UI on, the server answers this machine's own names on its own port only, on every
 * route: a page on another name (DNS rebinding) or another port gets nothing, not the UI, not the
 * receipts, and not the webhooks that accept the demo's published secret.
 */
function isLocalHost(host: string, port: number): boolean {
  const h = host.toLowerCase();
  return h === `127.0.0.1:${port}` || h === `localhost:${port}` || h === `[::1]:${port}`;
}

/** Stripe retries an undelivered event for up to 3 days, re-signed each time; ids are kept a day longer. */
export const SEEN_EVENT_TTL_MS = 4 * 24 * 60 * 60 * 1000;
export const SEEN_EVENT_MAX = 10_000;

/**
 * The webhook event ids applied recently, so a retried delivery is answered as a duplicate. Bounded
 * two ways, so a stream of distinct signed events cannot grow it without end: an id is forgotten
 * after `ttlMs` (longer than Stripe's retry window), and past `max` ids the least recently seen goes
 * first. A forgotten id that comes back is applied again, which the engine answers once anyway.
 */
export class SeenEvents {
  readonly #ttlMs: number;
  readonly #max: number;
  readonly #clock: Clock;
  /** Id to the time it is forgotten, least recently seen first (a Map keeps insertion order). */
  readonly #ids = new Map<string, number>();

  constructor(clock: Clock, ttlMs = SEEN_EVENT_TTL_MS, max = SEEN_EVENT_MAX) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new TypeError("SeenEvents: ttlMs must be an integer of 1 or more");
    if (!Number.isSafeInteger(max) || max < 1) throw new TypeError("SeenEvents: max must be an integer of 1 or more");
    this.#clock = clock;
    this.#ttlMs = ttlMs;
    this.#max = max;
  }

  get size(): number {
    return this.#ids.size;
  }

  /** Whether the id was seen and not yet forgotten; a hit counts as a use, for the cap. */
  has(id: string): boolean {
    const now = this.#clock.now().getTime();
    this.#expire(now);
    const until = this.#ids.get(id);
    if (until === undefined) return false;
    this.#ids.delete(id);
    if (until <= now) return false;
    this.#ids.set(id, until);
    return true;
  }

  add(id: string): void {
    const now = this.#clock.now().getTime();
    this.#ids.delete(id);
    this.#ids.set(id, now + this.#ttlMs);
    while (this.#ids.size > this.#max) this.#ids.delete(this.#ids.keys().next().value!);
  }

  /** Forgets expired ids from the least recently seen end, until the first one still in time. */
  #expire(now: number): void {
    for (const [id, until] of this.#ids) {
      if (until > now) return;
      this.#ids.delete(id);
    }
  }
}

class HttpError extends Error {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  constructor(status: number, message: string, headers: Readonly<Record<string, string>> = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

/**
 * A fixed window per remote address, on its own clock (the system clock unless the host gives
 * one). The address is the socket's: the server never reads `X-Forwarded-For`, which any client
 * can set, so behind a proxy every caller shares the proxy's address and the proxy has to do its
 * own limiting.
 */
class RateLimit {
  readonly #requests: number;
  readonly #windowMs: number;
  readonly #addresses: number;
  readonly #clock: Clock;
  readonly #windows = new Map<string, { start: number; count: number }>();

  constructor(requests: number, windowMs: number, addresses: number, clock: Clock) {
    this.#requests = requests;
    this.#windowMs = windowMs;
    this.#addresses = addresses;
    this.#clock = clock;
  }

  /** Counts a request, and throws a 429 with `retry-after` in seconds once the address is over. */
  take(address: string): void {
    const now = this.#clock.now().getTime();
    let window = this.#windows.get(address);
    if (window === undefined || now - window.start >= this.#windowMs) {
      // Deleted and set again, so the map stays in order of each window's start.
      this.#windows.delete(address);
      if (this.#windows.size >= this.#addresses) this.#forget(now);
      window = { start: now, count: 0 };
      this.#windows.set(address, window);
    }
    window.count += 1;
    if (window.count > this.#requests) {
      throw new HttpError(429, "rate_limited", { "retry-after": String(Math.ceil((window.start + this.#windowMs - now) / 1000)) });
    }
  }

  /** Drops every ended window, and then the oldest if none had ended. */
  #forget(now: number): void {
    for (const [address, window] of this.#windows) {
      if (now - window.start >= this.#windowMs) this.#windows.delete(address);
    }
    if (this.#windows.size >= this.#addresses) this.#windows.delete(this.#windows.keys().next().value!);
  }
}

/** What routing learns about a request, for its log entry. */
interface Seen {
  route: string;
}

/**
 * A limit, checked when the server is created: anything but a whole number from 1 would switch it
 * off (0 or NaN compare false, a 0 window starts afresh on every request) or refuse everything.
 */
function wholeFrom1(name: string, value: number, max = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new RangeError(`${name} must be a whole number from 1 to ${max}`);
  return value;
}

/** The longest setTimeout can wait; past it, the 503 deadline would fire at once. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

export function createReferenceServer(options: ReferenceServerOptions): Server {
  const processed = new SeenEvents(options.clock, options.seenEvents?.ttlMs, options.seenEvents?.max);
  const receivedRecords = new Set<string>();
  /** Deliveries whose `onRecord` is still running; a concurrent duplicate waits on the same one. */
  const pendingRecords = new Map<string, Promise<void>>();
  const limits: BodyLimits = { ...DEFAULT_BODY_LIMITS, ...options.bodyLimits };
  for (const name of BODY_LIMIT_NAMES) wholeFrom1(`bodyLimits.${name}`, limits[name]);
  const timeoutMs = wholeFrom1("timeoutMs", options.timeoutMs ?? 10_000, MAX_TIMEOUT_MS);
  const rate = options.rateLimit ?? { requests: 300, windowMs: 60_000 };
  const rateLimit = new RateLimit(
    wholeFrom1("rateLimit.requests", rate.requests),
    wholeFrom1("rateLimit.windowMs", rate.windowMs),
    wholeFrom1("rateLimit.addresses", rate.addresses ?? 10_000),
    rate.clock ?? systemClock,
  );
  const files = options.ui === undefined ? new Map<string, StaticFile>() : loadStaticFiles();
  const security = options.securityTxt;
  const sink = options.warn ?? console.warn;
  // A sink that throws, or answers a promise that rejects, loses its warning, never the request.
  const warn = (message: string): void => {
    try {
      const told: unknown = sink(message);
      Promise.resolve(told).catch(() => undefined);
    } catch {
      // Nowhere else to report it.
    }
  };
  const startedAt = options.clock.now();
  // The expiry the route enforces is read with the one the file was built from, from one copy.
  const securityCopy = security === undefined ? undefined : { ...security, contact: [...security.contact], expires: new Date(security.expires.getTime()) };
  const securityFile = securityCopy === undefined ? null : { text: securityTxt(securityCopy, startedAt, warn), expires: securityCopy.expires.getTime() };
  // A server that runs into the last 30 days, or past the expiry, says so once each, on the first
  // request for the file after it happens: the start-up check alone would never see it.
  let warnedSoon = securityFile !== null && securityFile.expires - startedAt.getTime() <= WARN_MS;
  let warnedExpired = false;
  const securityRequested = (now: number): boolean => {
    const file = securityFile!;
    // Each flag is set before its warning, so a sink that fails is not told again on every request.
    if (now >= file.expires) {
      if (!warnedExpired) {
        warnedExpired = true;
        warn(`security.txt expired at ${securityCopy!.expires.toISOString()}: it is no longer served; renew it`);
      }
      return false;
    }
    if (!warnedSoon && file.expires - now <= WARN_MS) {
      warnedSoon = true;
      warn(expiryWarning(securityCopy!.expires));
    }
    return true;
  };

  const STRIPE_LIMITS = { identity: "stripeIdentity", payments: "stripePayments", connect: "stripeConnect" } as const;

  async function stripeWebhook(req: IncomingMessage, route: "identity" | "payments" | "connect"): Promise<[number, Json]> {
    // The bytes as received: checked before anything decodes or parses them, so a body under a bad
    // signature is never read, and two invalid UTF-8 bodies that decode alike never share one.
    const payload = await readBytes(req, limits[STRIPE_LIMITS[route]]);
    const header = req.headers["stripe-signature"];
    const check = verifyStripeSignature({
      payload,
      header: Array.isArray(header) ? header[0] : header,
      secrets: options.stripeSecrets[route] ?? [],
      now: options.clock.now(),
    });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    const event = parseStripeEvent(payload.toString("utf8"));
    if (event === null) return [400, { error: "malformed_event" }];
    // Only an event this endpoint handles is applied and remembered: one that reached the wrong
    // endpoint (an unfiltered listener) is acknowledged and left for its own endpoint.
    let apply: (() => Promise<{ applied: boolean; unbound?: true }>) | null = null;
    if (route === "identity" && event.kind === "identity") {
      const outcome = event.outcome;
      apply = async () => ({ applied: (await options.engine.applyIdentityOutcome(outcome)).applied });
    }
    // The endpoint fixes the mode: Connect events always name a connected account, account events never do.
    if (event.kind === "payment" && (route === "connect" ? event.outcome.account !== undefined : route === "payments" && event.outcome.account === undefined)) {
      const outcome = event.outcome;
      apply = () => options.engine.applyPaymentOutcome(outcome);
    }
    // Disputes of platform payments come to the platform's own endpoint; a connect payment's are the business's.
    if (route === "payments" && event.kind === "dispute") {
      if (processed.has(event.eventId)) return [200, { received: true, duplicate: true }];
      const result = await options.engine.applyDisputeOutcome(event.outcome);
      // A dispute for a payment not bound yet (its own event still on its way) is not acknowledged,
      // so Stripe delivers it again; it is never remembered as processed.
      if (!result.applied && result.unbound === true) return [503, { received: true, applied: false, retry: true }];
      processed.add(event.eventId);
      return [200, { received: true, applied: result.applied }];
    }
    if (apply === null) return [200, { received: true, applied: false, handled: false }];
    if (processed.has(event.eventId)) return [200, { received: true, duplicate: true }];
    const result = await apply();
    // A payment event for a link no call holds yet (its reference still being bound) is not
    // acknowledged either, so Stripe delivers it again once it is; never remembered as processed.
    if (result.unbound === true) return [503, { received: true, applied: false, retry: true }];
    processed.add(event.eventId);
    return [200, { received: true, applied: result.applied }];
  }

  async function linkedReceipt(token: string): Promise<SignedReceipt | null> {
    const callId = options.receiptLinks?.callFor(token) ?? null;
    if (callId === null) return null;
    try {
      return await options.engine.receipt(callId);
    } catch (error) {
      if (error instanceof EngineError && error.code === "unknown_call") return null;
      throw error;
    }
  }

  /**
   * A sample receiver for `deliverRecord`, as a business's own system would run it: the signature
   * first (the same scheme as Stripe's, so the same check), then the body, then each idempotency
   * key once. The key is read from the signed body, not from the unsigned header. A duplicate
   * answers 200, so the sender stops retrying. The key counts as received only after `onRecord`
   * succeeds, so a failed handler answers 500 and the retry is applied, not skipped.
   */
  async function recordWebhook(req: IncomingMessage): Promise<[number, Json]> {
    // The bytes as received, verified before they are decoded or parsed (as `stripeWebhook` does).
    const payload = await readBytes(req, limits.records);
    const header = req.headers[DELIVERY_SIGNATURE_HEADER];
    const check = verifyStripeSignature({
      payload,
      header: Array.isArray(header) ? header[0] : header,
      secrets: options.records?.secrets ?? [],
      now: options.clock.now(),
    });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    const delivery = parseRecordDelivery(payload.toString("utf8"));
    if (delivery === null) return [400, { error: "malformed_delivery" }];
    const key = delivery.idempotencyKey;
    if (receivedRecords.has(key)) {
      options.records?.onDuplicate?.(key, "received");
      return [200, { received: true, duplicate: true }];
    }
    const pending = pendingRecords.get(key);
    if (pending !== undefined) {
      options.records?.onDuplicate?.(key, "pending");
      await pending;
      return [200, { received: true, duplicate: true }];
    }
    const handler = options.records?.onRecord;
    const applying = (async () => {
      await handler?.(delivery);
    })();
    pendingRecords.set(key, applying);
    try {
      await applying;
    } finally {
      pendingRecords.delete(key);
    }
    receivedRecords.add(key);
    return [200, { received: true, recordId: delivery.record.recordId }];
  }

  /**
   * A carrier webhook: the signature is checked, and nothing else yet. The engine takes no carrier
   * event today (call handling is the host's), so a verified request is acknowledged and dropped.
   */
  async function carrierWebhook(req: IncomingMessage, carrier: "twilio" | "telnyx"): Promise<[number, Json]> {
    // The bytes as received, never decoded first: a decoder with replacement reads two different
    // invalid UTF-8 bodies the same, and both would verify under one signature.
    const payload = await readBytes(req, limits[carrier]);
    const header = (name: string) => {
      const value = req.headers[name];
      return typeof value === "string" ? value : undefined;
    };
    const twilio = options.carriers?.twilio;
    const check =
      carrier === "twilio"
        ? verifyTwilioSignature({
            url: `${twilio?.publicOrigin ?? ""}${req.url!}`,
            payload,
            header: header("x-twilio-signature"),
            authTokens: twilio?.authTokens ?? [],
          })
        : verifyTelnyxSignature({
            payload,
            signatureHeader: header("telnyx-signature-ed25519"),
            timestampHeader: header("telnyx-timestamp"),
            publicKeys: options.carriers?.telnyx?.publicKeys ?? [],
            now: options.clock.now(),
          });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    return [200, { received: true }];
  }

  async function demoRoute(req: IncomingMessage, runs: DemoRuns, path: string, method: string, seen: Seen): Promise<Answer> {
    const host = req.headers.host!;
    const file = files.get(path);
    if (file !== undefined) {
      seen.route = path;
      if (method !== "GET") throw new HttpError(405, "method_not_allowed");
      return file;
    }
    const answer = (a: RunAnswer): [number, Json] => (a.ok ? [200, a.view as unknown as Json] : [a.status, { error: a.error }]);
    if (path === "/demo/flows") {
      seen.route = path;
      if (method !== "GET") throw new HttpError(405, "method_not_allowed");
      return [200, { flows: runs.flows() }];
    }
    const run = /^\/demo\/runs(?:\/(run_[A-Za-z0-9-]{1,64})(\/next)?)?$/.exec(path);
    if (run !== null) {
      const [, runId, next] = run;
      seen.route = runId === undefined ? "/demo/runs" : next === undefined ? "/demo/runs/:runId" : "/demo/runs/:runId/next";
      const post = runId === undefined || next !== undefined;
      if (method !== (post ? "POST" : "GET")) throw new HttpError(405, "method_not_allowed");
      if (!post) return answer(await runs.view(runId as string));
      // A page on another origin can send a simple POST without asking; it cannot send JSON
      // without a preflight this server never answers, nor forge its Origin.
      if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw new HttpError(415, "json_required");
      const origin = req.headers.origin;
      if (origin !== undefined && origin !== `http://${host}`) throw new HttpError(403, "cross_origin");
      const body = await readBody(req, limits.demo);
      if (runId !== undefined) return answer(await runs.step(runId));
      let flow: unknown;
      try {
        flow = (JSON.parse(body) as { flow?: unknown } | null)?.flow;
      } catch {
        throw new HttpError(400, "malformed_json");
      }
      if (typeof flow !== "string" || !runs.hasFlow(flow)) throw new HttpError(400, "unknown_flow");
      return [201, (await runs.start(flow)) as unknown as Json];
    }
    return [404, { error: "not_found" }];
  }

  async function uploadRoute(
    req: IncomingMessage,
    uploads: NonNullable<ReferenceServerOptions["uploads"]>,
    token: string,
    method: string,
    lang: PageLocale | undefined,
  ): Promise<Page> {
    const context = { workspaceId: options.engine.workspaceId, documents: uploads.documents, clock: options.clock };
    if (method === "POST") {
      const kept = keptUpload(sha256Hex(token));
      if (kept !== undefined) return keptUploadPage(kept, lang ?? kept.locale);
    }
    const link = await openUploadLink(token, context);
    if (link === null) return uploadPage(410, lang ?? "en", "link_not_usable", null);
    // The upload page is in English and French: a Spanish link (#122) gets the English page.
    const locale: PageLocale = lang ?? (Object.hasOwn(PAGE_TEXT, link.locale) ? (link.locale as PageLocale) : "en");
    if (method === "GET") return uploadPage(200, locale, null, link);
    let body: Buffer;
    try {
      body = await readBytes(req, link.maxBytes + MULTIPART_OVERHEAD_BYTES);
    } catch (error) {
      if (error instanceof HttpError && error.status === 413) return uploadPage(413, locale, "too_large", link);
      throw error;
    }
    const file = filePart(body, req.headers["content-type"] ?? "");
    if (file === null) return uploadPage(400, locale, "empty", link);
    // Checked again: another upload on this link may have started while this body arrived.
    const key = sha256Hex(token);
    const started = keptUpload(key);
    if (started !== undefined) return keptUploadPage(started, lang ?? started.locale);
    const kept: KeptUpload = { expires: Date.parse(link.expiresAt), locale, result: null };
    // No room: refused before the link is claimed, so it is left unspent and nothing is scanned.
    const full = keepUpload(key, kept);
    if (full !== null) return { ...uploadPage(503, locale, "busy", link), headers: { "retry-after": String(full) } };
    let result: UploadResult;
    try {
      result = await acceptUpload({ token, contentType: file.contentType, bytes: file.bytes }, { ...context, ids: uploads.ids ?? randomIds, scanner: uploads.scanner });
    } catch (error) {
      forgetUpload(key, kept);
      throw error;
    }
    // Kept only when this upload spent the link: it was stored, or the scanner refused or failed it.
    // Kept even when the deadline has answered already, so the client's retry learns the outcome.
    if (result.ok || result.reason === "scan_refused" || result.reason === "scan_failed") kept.result = result;
    else forgetUpload(key, kept);
    return uploadResultPage(result, locale, link);
  }

  /**
   * The outcome of each upload that spent its link, by the token's hash, until the link would have
   * expired: an upload can outlast the deadline after its link is spent, and the client's retry
   * with the same link then gets that outcome, not "link used". `result` is null while the upload
   * still runs. At most `keptMax` at once.
   */
  const keptMax = options.uploads === undefined ? KEPT_UPLOADS_MAX : wholeFrom1("uploads.keptMax", options.uploads.keptMax ?? KEPT_UPLOADS_MAX);
  const keptUploads = new Map<string, KeptUpload>();

  function keptUpload(key: string): KeptUpload | undefined {
    const kept = keptUploads.get(key);
    if (kept === undefined || options.clock.now().getTime() < kept.expires) return kept;
    keptUploads.delete(key);
    return undefined;
  }

  /**
   * Keeps `kept`, after dropping the expired outcomes when the store is full. Never drops one still
   * in time (its upload may be running, or its retry still to come): when none has expired, keeps
   * nothing and answers the whole seconds until the first one does.
   */
  function keepUpload(key: string, kept: KeptUpload): number | null {
    if (keptUploads.size >= keptMax) {
      const now = options.clock.now().getTime();
      let first = Number.POSITIVE_INFINITY;
      for (const [k, v] of keptUploads) {
        if (now >= v.expires) keptUploads.delete(k);
        else first = Math.min(first, v.expires);
      }
      if (keptUploads.size >= keptMax) return Math.max(1, Math.ceil((first - now) / 1000));
    }
    keptUploads.set(key, kept);
    return null;
  }

  function forgetUpload(key: string, kept: KeptUpload): void {
    if (keptUploads.get(key) === kept) keptUploads.delete(key);
  }

  /** A kept outcome; while the first upload still runs, a 503 to try again, and no second scan. */
  function keptUploadPage(kept: KeptUpload, locale: PageLocale): Page {
    if (kept.result !== null) return uploadResultPage(kept.result, locale, null);
    return { ...uploadPage(503, locale, "in_progress", null), headers: { "retry-after": String(Math.ceil(timeoutMs / 1000)) } };
  }

  async function route(req: IncomingMessage, seen: Seen): Promise<Answer> {
    // First, so a flood is refused before any other work.
    rateLimit.take(addressOf(req));
    if (options.ui !== undefined && !isLocalHost(req.headers.host ?? "", req.socket.localPort!)) throw new HttpError(403, "host_not_allowed");
    // Prefixed, so a path that starts with `//` stays a path instead of naming a host.
    const url = parseUrl(req.url!);
    const path = url.pathname;
    const method = req.method ?? "GET";
    const expect = (m: string) => {
      if (method !== m) throw new HttpError(405, "method_not_allowed");
    };
    if (path === "/healthz") {
      seen.route = path;
      expect("GET");
      return [200, { ok: true }];
    }
    if (path === "/.well-known/receipt-keys.json") {
      seen.route = path;
      expect("GET");
      return [200, { keys: options.engine.receiptKeys() }];
    }
    // The host's own file only, and none once it has expired while the server kept running.
    if (path === "/.well-known/security.txt" && securityFile !== null && securityRequested(options.clock.now().getTime())) {
      seen.route = path;
      expect("GET");
      return { text: securityFile.text };
    }
    const stripe = /^\/webhooks\/stripe\/(identity|payments|connect)$/.exec(path);
    if (stripe !== null) {
      seen.route = path;
      expect("POST");
      return stripeWebhook(req, stripe[1] as "identity" | "payments" | "connect");
    }
    if (path === "/webhooks/records") {
      seen.route = path;
      expect("POST");
      return recordWebhook(req);
    }
    const carrier = /^\/webhooks\/(twilio|telnyx)$/.exec(path);
    if (carrier !== null) {
      seen.route = path;
      expect("POST");
      return carrierWebhook(req, carrier[1] as "twilio" | "telnyx");
    }
    // `/r/<token>` is the page, `/r/<token>.json` the signed receipt itself. An unknown token, a
    // malformed one and a call without a receipt all answer the same 404.
    const link = /^\/r\/([A-Za-z0-9_-]{1,64})(\.json)?$/.exec(path);
    if (link !== null) {
      const [, token, json] = link as unknown as [string, string, string | undefined];
      seen.route = json === undefined ? "/r/:token" : "/r/:token.json";
      expect("GET");
      const found = await linkedReceipt(token);
      if (found === null) return [404, { error: "not_found" }];
      if (json !== undefined) return [200, found as unknown as Json];
      return { html: receiptPage(found, options.engine.receiptKeys(), token, pageLocale(url, req.headers["accept-language"])) };
    }
    const upload = /^\/u\/([^/]*)$/.exec(path);
    if (options.uploads !== undefined && upload !== null) {
      seen.route = "/u/:token";
      if (method !== "GET" && method !== "POST") throw new HttpError(405, "method_not_allowed");
      const lang = url.searchParams.get("lang");
      return uploadRoute(req, options.uploads, upload[1]!, method, lang === "en" || lang === "fr" ? lang : undefined);
    }
    if (options.ui !== undefined && (files.has(path) || path.startsWith("/demo/"))) return demoRoute(req, options.ui, path, method, seen);
    return [404, { error: "not_found" }];
  }

  /** The request each socket is answering, so a client error on it is answered and logged once. */
  const inFlight = new WeakMap<Socket, Exchange>();
  /**
   * The answers on each socket not yet sent in full. node:http sends pipelined answers in order,
   * but a refusal written straight to the socket would overtake them, and be read as theirs.
   */
  const unsent = new WeakMap<Socket, Set<ServerResponse>>();
  /** Sockets whose client error waits for earlier answers; a repeat of that error is not answered again. */
  const refusing = new WeakSet<Socket>();

  /** Logs one answered request. A `log` that throws loses its entry, never the server. */
  function record(exchange: Exchange, address: string, status: number, error: string | undefined): void {
    try {
      // An async sink answers a promise: a rejected one is caught too, never an unhandled rejection.
      const written: unknown = options.log?.({
        time: options.clock.now().toISOString(),
        address,
        method: exchange.method,
        route: exchange.seen.route,
        status,
        ...(error === undefined ? {} : { error }),
        ms: Math.round(performance.now() - exchange.started),
      });
      Promise.resolve(written).catch(() => undefined);
    } catch {
      // The answer is already written, and a failing log sink has nowhere to report to.
    }
  }

  /** Writes an answer; the status and error code it wrote, for the log. */
  function write(res: ServerResponse, answer: Answer): [number, string | undefined] {
    if ("html" in answer) {
      const status = answer.status ?? 200;
      res.writeHead(status, { ...(answer.upload === true ? UPLOAD_PAGE_HEADERS : PAGE_HEADERS), ...answer.headers });
      res.end(answer.html);
      return [status, undefined];
    }
    if (Array.isArray(answer)) {
      const [status, body] = answer;
      res.writeHead(status, JSON_HEADERS);
      res.end(JSON.stringify(body));
      return [status, typeof body.error === "string" ? body.error : undefined];
    }
    if ("text" in answer) {
      res.writeHead(200, TEXT_HEADERS);
      res.end(answer.text);
      return [200, undefined];
    }
    res.writeHead(200, { ...UI_HEADERS, "content-type": answer.contentType });
    res.end(answer.body);
    return [200, undefined];
  }

  // node:http enforces the receive deadline itself, checking open connections at this interval.
  const timeouts = { requestTimeout: timeoutMs, headersTimeout: timeoutMs, connectionsCheckingInterval: Math.min(timeoutMs, 1000) };
  const server = createServer(timeouts, (req: IncomingMessage, res: ServerResponse) => {
    const exchange: Exchange = { started: performance.now(), method: req.method ?? "GET", seen: { route: "unmatched" }, done: false, req, res };
    const socket = req.socket;
    inFlight.set(socket, exchange);
    const pending = unsent.get(socket) ?? new Set<ServerResponse>();
    unsent.set(socket, pending);
    pending.add(res);
    let timer: NodeJS.Timeout | undefined;
    // Kept while its body is unread, so node:http timing that body out after the answer is not
    // answered and logged a second time; forgotten once the socket can carry the next request.
    res.on("close", () => {
      pending.delete(res);
      // Closed before its answer was sent (the client reset or left): abandoned, so neither the
      // handler nor the deadline answers or logs it later.
      if (!res.writableFinished && !exchange.done) {
        exchange.done = true;
        clearTimeout(timer);
      }
      if (req.complete && inFlight.get(socket) === exchange) inFlight.delete(socket);
    });
    const deadline = new Promise<Answer>((resolve) => {
      timer = setTimeout(() => resolve([503, { error: "timeout" }]), timeoutMs);
    });
    const routed = route(req, exchange.seen).catch((error: unknown): Answer => {
      if (!(error instanceof HttpError)) return [500, { error: "internal" }];
      for (const [name, value] of Object.entries(error.headers)) res.setHeader(name, value);
      return [error.status, { error: error.message }];
    });
    void Promise.race([routed, deadline]).then((answer) => {
      clearTimeout(timer);
      // Already answered and logged in `clientError`, when node:http gave up on the request.
      if (exchange.done) return;
      exchange.done = true;
      const [status, error] = write(res, answer);
      record(exchange, addressOf(req), status, error);
    });
  });

  // node:http's own refusals (headers or body too slow, headers too large, a malformed request)
  // reach this instead of the listener. Answered as node:http would, but in JSON, and logged.
  server.on("clientError", (err: NodeJS.ErrnoException, socket: Socket) => {
    // Already waiting to refuse this socket: node:http reports the same error again on more data.
    if (refusing.has(socket)) return;
    const held = inFlight.get(socket);
    inFlight.delete(socket);
    // A request received in full is over, even before its stream says so: an error after it is the
    // next request's (one the client sent right behind a body drained after its answer), answered too.
    const exchange = held?.req!.complete === true ? undefined : held;
    // Answers to earlier requests not yet sent go first: each is sent, or its socket closes, within
    // the deadline. Then the refusal, which the client reads as the failed request's own.
    const earlier = [...(unsent.get(socket) ?? [])].filter((res) => res !== exchange?.res);
    if (err.code === "ECONNRESET" || earlier.length === 0) {
      refuse(err, socket, exchange);
      return;
    }
    refusing.add(socket);
    socket.pause();
    void Promise.all(earlier.map((res) => new Promise((resolve) => res.once("close", resolve)))).then(() => refuse(err, socket, exchange));
  });

  /** Answers a client error as node:http would, but in JSON, logs it, and closes the socket. */
  function refuse(err: NodeJS.ErrnoException, socket: Socket, exchange: Exchange | undefined): void {
    // A reset socket takes no answer, and one whose answer is already written cannot take another.
    if (err.code !== "ECONNRESET" && socket.writable && exchange?.done !== true) {
      const [status, code] = CLIENT_ERRORS[err.code ?? ""] ?? [400, "bad_request"];
      const body = JSON.stringify({ error: code });
      const headers = { ...JSON_HEADERS, "content-length": String(Buffer.byteLength(body)), connection: "close" };
      const head = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`);
      socket.write(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\n${head.join("")}\r\n${body}`);
      const answered = exchange ?? { started: performance.now(), method: "unknown", seen: { route: "unmatched" }, done: false, req: null, res: null };
      answered.done = true;
      record(answered, rateLimitKey(socket.remoteAddress ?? "unknown"), status, code);
    }
    socket.destroy(err);
  }
  return server;
}

/** One request, from the listener to its answer. */
interface Exchange {
  started: number;
  method: string;
  seen: Seen;
  /** Answered, by the listener or by `clientError`. */
  done: boolean;
  /** The request; null for one node:http refused before its headers were read. */
  req: IncomingMessage | null;
  /** Its answer; null as `req` is. */
  res: ServerResponse | null;
}

/** node:http's client error codes and the answer each gets; any other is `400 bad_request`. */
const CLIENT_ERRORS: Readonly<Record<string, readonly [number, string]>> = {
  ERR_HTTP_REQUEST_TIMEOUT: [408, "request_timeout"],
  HPE_HEADER_OVERFLOW: [431, "headers_too_large"],
  HPE_CHUNK_EXTENSIONS_OVERFLOW: [413, "body_too_large"],
};

function addressOf(req: IncomingMessage): string {
  return rateLimitKey(req.socket.remoteAddress ?? "unknown");
}

/**
 * The caller the rate limit counts, and logs, for a socket address. An IPv6 address counts by its
 * /64 (`2001:db8:1:2::/64`), since one subscriber usually holds a whole /64 and could otherwise
 * rotate through it; an IPv4-mapped one (`::ffff:192.0.2.1`, as a server on `::` sees IPv4) as its
 * IPv4 address. Anything else is counted as given.
 */
export function rateLimitKey(address: string): string {
  const plain = address.split("%")[0]!.toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(plain);
  if (mapped !== null) return mapped[1]!;
  if (!isIPv6(plain)) return address;
  // An embedded IPv4 address is the last two groups, which the /64 never reaches.
  const groups = (part: string) => (part === "" ? [] : part.split(":")).flatMap((g) => (g.includes(".") ? ["0", "0"] : [g]));
  const [head, tail] = plain.split("::") as [string, string | undefined];
  const left = groups(head);
  const all = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - groups(tail).length).fill("0"), ...groups(tail)];
  return `${all.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

/** The request target as a URL; a target that is not a path (an absolute URL, garbage) is a 400. */
function parseUrl(target: string): URL {
  if (!target.startsWith("/")) throw new HttpError(400, "bad_request");
  return new URL(`http://x${target}`);
}

/** `?lang=en` or `?lang=fr` first, then French when the browser asks for it first, else English. */
function pageLocale(url: URL, acceptLanguage: string | undefined): PageLocale {
  const lang = url.searchParams.get("lang");
  if (lang === "en" || lang === "fr") return lang;
  return /^\s*fr(?:-|;|,|\s|$)/i.test(acceptLanguage ?? "") ? "fr" : "en";
}

export /** The receipt page is in English and French; a Spanish reader gets the English page (#122 adds no page text). */
type PageLocale = keyof typeof PAGE_TEXT;

export const PAGE_TEXT = {
  en: {
    title: "Call receipt",
    valid: (kid: string) => `Signature valid: signed with key ${kid}, and not one byte has changed since.`,
    invalid: "Signature not valid: do not rely on this receipt.",
    receipt: "Receipt",
    started: "Call started",
    ended: "Call ended",
    identity: "Identity check",
    level: (level: number, methods: string) => (level === 0 ? "not verified" : `level ${level}, by ${methods}`),
    records: "Records filed",
    fingerprint: "fingerprint",
    payments: "Payments",
    consents: "Consents",
    none: "none",
    ledger: "Audit ledger",
    head: (seq: number, hash: string) => `entry ${seq}, hash ${hash}`,
    json: "The signed receipt (JSON)",
    keys: "The public keys",
    other: ["fr", "Français"],
    methods: {
      keypad_knowledge: "answers keyed on the phone",
      pin: "PIN",
      carrier_identity_match: "the carrier's match on the number on file",
      photo_id: "photo ID and selfie",
      text_code: "texted code",
      spoken_knowledge: "spoken answers",
    } as Record<string, string>,
    status: { open: "open", paid: "paid", failed: "failed", expired: "expired" } as Record<string, string>,
    answer: { yes: "yes", no: "no", not_recorded: "not recorded" },
  },
  fr: {
    title: "Reçu d'appel",
    valid: (kid: string) => `Signature valide : signé avec la clé ${kid}, et pas un octet n'a changé depuis.`,
    invalid: "Signature non valide : ne vous fiez pas à ce reçu.",
    receipt: "Reçu",
    started: "Début de l'appel",
    ended: "Fin de l'appel",
    identity: "Vérification d'identité",
    level: (level: number, methods: string) => (level === 0 ? "non vérifiée" : `niveau ${level}, par ${methods}`),
    records: "Formulaires déposés",
    fingerprint: "empreinte",
    payments: "Paiements",
    consents: "Consentements",
    none: "aucun",
    ledger: "Registre d'audit",
    head: (seq: number, hash: string) => `entrée ${seq}, empreinte ${hash}`,
    json: "Le reçu signé (JSON)",
    keys: "Les clés publiques",
    other: ["en", "English"],
    methods: {
      keypad_knowledge: "réponses saisies au clavier",
      pin: "NIP",
      carrier_identity_match: "la correspondance de l'opérateur pour le numéro au dossier",
      photo_id: "pièce d'identité avec photo et égoportrait",
      text_code: "code reçu par texto",
      spoken_knowledge: "réponses de vive voix",
    } as Record<string, string>,
    status: { open: "en cours", paid: "payé", failed: "échoué", expired: "expiré" } as Record<string, string>,
    answer: { yes: "oui", no: "non", not_recorded: "non enregistrée" },
  },
} as const;

/** A word from a page table by its own key, else the key itself: `constructor` is a name, never Object's. */
function word(table: Readonly<Record<string, string>>, key: string): string {
  return Object.hasOwn(table, key) ? table[key]! : key;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * The receipt page: what the receipt says, in the reader's language, and whether its signature
 * holds against the server's own key set. Plain HTML, every value escaped; the receipt holds no
 * value the caller keyed, so neither does the page.
 */
function receiptPage(receipt: SignedReceipt, keys: Parameters<typeof verifyReceipt>[1], token: string, locale: PageLocale): string {
  const t = PAGE_TEXT[locale];
  const b = receipt.body;
  const list = (items: string[]) => (items.length === 0 ? t.none : items.join("; "));
  const methods = b.verification.methods.map((m) => word(t.methods, m)).join(", ");
  const rows: Array<[string, string]> = [
    [t.receipt, b.receiptId],
    [t.started, b.startedAt],
    [t.ended, b.endedAt],
    [t.identity, t.level(b.verification.level, methods)],
    [t.records, list(b.records.map((r) => `${r.formId}, ${t.fingerprint} ${r.digest}`))],
    [t.payments, list(b.payments.map((p) => `${formatAmount(locale, p.amountMinor, p.currency)}, ${word(t.status, p.status)}`))],
    [t.consents, list(b.consents.map((c) => `${c.purpose}: ${word(t.answer, c.answer)}`))],
    [t.ledger, t.head(b.ledger.seq, b.ledger.hash)],
  ];
  const valid = verifyReceipt(receipt, keys);
  const [otherLang, otherName] = t.other;
  return [
    "<!doctype html>",
    `<html lang="${locale}">`,
    '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer">',
    `<title>${escapeHtml(t.title)}</title></head>`,
    "<body><main>",
    `<h1>${escapeHtml(t.title)}</h1>`,
    `<p><strong>${escapeHtml(valid ? t.valid(receipt.kid) : t.invalid)}</strong></p>`,
    "<dl>",
    ...rows.map(([term, value]) => `<dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd>`),
    "</dl>",
    `<p><a href="${escapeHtml(token)}.json">${escapeHtml(t.json)}</a> | <a href="/.well-known/receipt-keys.json">${escapeHtml(t.keys)}</a> | ` +
      `<a href="?lang=${otherLang}" hreflang="${otherLang}" lang="${otherLang}">${escapeHtml(otherName)}</a></p>`,
    "</main></body></html>",
    "",
  ].join("\n");
}

/** A verified delivery body, or null when it is not one. */
function parseRecordDelivery(payload: string): RecordDeliveryBody | null {
  let body: unknown;
  try {
    body = JSON.parse(payload);
  } catch {
    return null;
  }
  if (typeof body !== "object" || body === null) return null;
  const { v, type, idempotencyKey, destinationId, record } = body as Record<string, unknown>;
  if (v !== 1 || type !== "record.confirmed" || typeof idempotencyKey !== "string" || typeof destinationId !== "string") return null;
  if (typeof record !== "object" || record === null || typeof (record as { recordId?: unknown }).recordId !== "string") return null;
  return body as RecordDeliveryBody;
}

async function readBody(req: IncomingMessage, max: number): Promise<string> {
  return (await readBytes(req, max)).toString("utf8");
}

/** The body, refused with a 413 as soon as its declared or received size passes `max`. */
function readBytes(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    if (Number(req.headers["content-length"] ?? 0) > max) {
      // Refused before a byte is buffered; drained so the 413 can still be written.
      req.resume();
      reject(new HttpError(413, "body_too_large"));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > max) {
        // Stop buffering, drain the rest so the 413 can still be written.
        req.off("data", onData);
        req.resume();
        reject(new HttpError(413, "body_too_large"));
        return;
      }
      chunks.push(chunk);
    };
    req.on("data", onData);
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** An upload that spent its link: its outcome, null while it runs, kept until the link's expiry. */
interface KeptUpload {
  expires: number;
  locale: PageLocale;
  result: UploadResult | null;
}

/** Kept outcomes at once by default; a link lives 30 minutes, so this is a rate of uploads, not a total. */
const KEPT_UPLOADS_MAX = 10_000;

/** The page for an upload's result: a spent link shows no form. */
function uploadResultPage(result: UploadResult, locale: PageLocale, link: { allowedTypes: DocumentType[]; maxBytes: number } | null): Page {
  if (result.ok) return uploadPage(201, locale, "received", null, result.document.documentId);
  const spent = result.reason === "link_not_usable" || result.reason === "scan_refused" || result.reason === "scan_failed";
  return uploadPage(REFUSAL_STATUS[result.reason], locale, result.reason, spent ? null : link);
}

const REFUSAL_STATUS: Readonly<Record<UploadRefusal, number>> = {
  link_not_usable: 410,
  type_not_allowed: 415,
  content_mismatch: 415,
  empty: 400,
  too_large: 413,
  scan_refused: 422,
  scan_failed: 503,
};

type PageMessage = UploadRefusal | "received" | "in_progress" | "busy";

const UPLOAD_TEXT = {
  en: {
    title: "Add a document",
    intro: "Choose a photo or a PDF to add to your file. This link works once.",
    accepted: "Accepted:",
    upTo: "up to",
    send: "Send",
    other: ["fr", "Français"],
    units: ["MB", "KB"],
    reference: "Reference:",
    messages: {
      received: "Thank you. Your document was received. You can close this page.",
      in_progress: "Your document is still being checked. Try again in a moment.",
      busy: "We cannot take your document right now. Try again later.",
      link_not_usable: "This link has expired or was already used. Ask for a new one.",
      type_not_allowed: "This type of file is not accepted here.",
      content_mismatch: "This type of file is not accepted here.",
      empty: "Choose a file first.",
      too_large: "This file is too large.",
      scan_refused: "This file could not be accepted. Ask for a new link.",
      scan_failed: "This file could not be checked right now. Ask for a new link.",
    },
  },
  fr: {
    title: "Ajouter un document",
    intro: "Choisissez une photo ou un PDF à ajouter à votre dossier. Ce lien ne fonctionne qu'une fois.",
    accepted: "Acceptés :",
    upTo: "jusqu'à",
    send: "Envoyer",
    other: ["en", "English"],
    units: ["Mo", "Ko"],
    reference: "Référence :",
    messages: {
      received: "Merci. Votre document a bien été reçu. Vous pouvez fermer cette page.",
      in_progress: "Votre document est encore en cours de vérification. Réessayez dans un instant.",
      busy: "Nous ne pouvons pas recevoir votre document pour le moment. Réessayez plus tard.",
      link_not_usable: "Ce lien a expiré ou a déjà été utilisé. Demandez-en un nouveau.",
      type_not_allowed: "Ce type de fichier n'est pas accepté ici.",
      content_mismatch: "Ce type de fichier n'est pas accepté ici.",
      empty: "Choisissez d'abord un fichier.",
      too_large: "Ce fichier est trop volumineux.",
      scan_refused: "Ce fichier n'a pas pu être accepté. Demandez un nouveau lien.",
      scan_failed: "Ce fichier n'a pas pu être vérifié pour le moment. Demandez un nouveau lien.",
    },
  },
} as const;

const TYPE_LABELS: Readonly<Record<DocumentType, string>> = { "image/jpeg": "JPEG", "image/png": "PNG", "application/pdf": "PDF" };

/**
 * The upload page: plain HTML, no script, a form that posts the file back to the same address.
 * Every string on it is the code's own; nothing from the request or the store is written into it
 * except the link's types and size cap, which come from a fixed list and a number, and the id the
 * server gave a document it received, escaped.
 */
function uploadPage(
  status: number,
  locale: PageLocale,
  message: PageMessage | null,
  link: { allowedTypes: DocumentType[]; maxBytes: number } | null,
  documentId?: string,
): Page {
  const text = UPLOAD_TEXT[locale];
  const [otherLang, otherName] = text.other;
  let form = "";
  if (link !== null) {
    const mib = 1024 * 1024;
    const size = link.maxBytes >= mib ? `${Math.floor(link.maxBytes / mib)} ${text.units[0]}` : `${Math.ceil(link.maxBytes / 1024)} ${text.units[1]}`;
    form = [
      `<p>${text.intro}</p>`,
      `<p>${text.accepted} ${link.allowedTypes.map((t) => TYPE_LABELS[t]).join(", ")}, ${text.upTo} ${size}.</p>`,
      `<form method="post" enctype="multipart/form-data">`,
      `<input type="file" name="file" accept="${link.allowedTypes.join(",")}" required>`,
      `<button type="submit">${text.send}</button>`,
      `</form>`,
    ].join("\n");
  }
  const html = [
    "<!doctype html>",
    `<html lang="${locale}">`,
    `<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${text.title}</title></head>`,
    "<body>",
    `<h1>${text.title}</h1>`,
    message === null ? "" : `<p role="status">${text.messages[message]}</p>`,
    documentId === undefined ? "" : `<p>${text.reference} ${escapeHtml(documentId)}</p>`,
    form,
    `<p><a href="?lang=${otherLang}" lang="${otherLang}">${otherName}</a></p>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
  return { status, html, upload: true };
}

/**
 * The part named `file` of a multipart/form-data body, with its declared type; null when the body
 * is not multipart or has no such part. Minimal on purpose: one boundary, CRLF line ends.
 */
function filePart(body: Buffer, contentType: string): { contentType: string; bytes: Buffer } | null {
  const found = /^multipart\/form-data\s*;.*?\bboundary=(?:"([^"]{1,70})"|([^\s;"]{1,70}))/i.exec(contentType);
  if (found === null) return null;
  const boundary = found[1] ?? found[2];
  const delimiter = Buffer.from(`--${boundary}`);
  const next = Buffer.from(`\r\n--${boundary}`);
  let start = body.indexOf(delimiter);
  while (start !== -1) {
    const headersStart = start + delimiter.length + 2;
    const headersEnd = body.indexOf("\r\n\r\n", headersStart);
    if (headersEnd === -1) return null;
    const end = body.indexOf(next, headersEnd + 4);
    if (end === -1) return null;
    const headers = body.subarray(headersStart, headersEnd).toString("latin1");
    if (/^content-disposition:[^\r\n]*;\s*name="file"/im.test(headers)) {
      return { contentType: /^content-type:[ \t]*([^\r\n]*)/im.exec(headers)?.[1] ?? "", bytes: body.subarray(headersEnd + 4, end) };
    }
    start = end + 2;
  }
  return null;
}
