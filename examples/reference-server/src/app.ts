// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment (platform-mode payments on the account
// endpoint, connect-mode payments on the Connect endpoint, each with its own signing secret),
// serves receipts by capability link with a small receipt page, serves the receipt key set, runs a
// sample receiver for signed record deliveries, answers 501 on the carrier webhooks that are not
// built yet, and, with `uploads`, serves the single-use document upload page in English and French
// (FIL-5). With `ui`, it also serves the demo's browser UI and the routes that run the
// scripted demo one step at a time. Not hardened for production; ROADMAP.md, "Reference server",
// lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

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
  verifyReceipt,
  verifyStripeSignature,
  type Clock,
  type DocumentScanner,
  type DocumentStore,
  type DocumentType,
  type Engine,
  type IdGenerator,
  type RecordDeliveryBody,
  type SignedReceipt,
  type UploadRefusal,
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
  /** Default 64 KiB. */
  maxBodyBytes?: number;
  /** How long and how many Stripe event ids are remembered (`SeenEvents`). Defaults: 4 days, 10,000. */
  seenEvents?: { ttlMs?: number; max?: number };
  /** The demo's runs: serves the browser UI and the `/demo/*` routes. Off when absent. */
  ui?: DemoRuns;
  /** The receipt links the host issued. Absent: `/r/:token` answers 404 for every token. */
  receiptLinks?: ReceiptLinks;
  /** Document uploads by single-use link: serves `/u/:token`. Off when absent. */
  uploads?: { documents: DocumentStore; scanner: DocumentScanner; ids?: IdGenerator };
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
  html: string;
}
type Answer = [number, Json] | StaticFile | Page;

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
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createReferenceServer(options: ReferenceServerOptions): Server {
  const processed = new SeenEvents(options.clock, options.seenEvents?.ttlMs, options.seenEvents?.max);
  const receivedRecords = new Set<string>();
  /** Deliveries whose `onRecord` is still running; a concurrent duplicate waits on the same one. */
  const pendingRecords = new Map<string, Promise<void>>();
  const maxBody = options.maxBodyBytes ?? 64 * 1024;
  const files = options.ui === undefined ? new Map<string, StaticFile>() : loadStaticFiles();

  async function stripeWebhook(req: IncomingMessage, route: "identity" | "payments" | "connect"): Promise<[number, Json]> {
    const payload = await readBody(req, maxBody);
    const header = req.headers["stripe-signature"];
    const check = verifyStripeSignature({
      payload,
      header: Array.isArray(header) ? header[0] : header,
      secrets: options.stripeSecrets[route] ?? [],
      now: options.clock.now(),
    });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    const event = parseStripeEvent(payload);
    if (event === null) return [400, { error: "malformed_event" }];
    // Only an event this endpoint handles is applied and remembered: one that reached the wrong
    // endpoint (an unfiltered listener) is acknowledged and left for its own endpoint.
    let apply: (() => Promise<boolean>) | null = null;
    if (route === "identity" && event.kind === "identity") {
      const outcome = event.outcome;
      apply = async () => (await options.engine.applyIdentityOutcome(outcome)).applied;
    }
    // The endpoint fixes the mode: Connect events always name a connected account, account events never do.
    if (event.kind === "payment" && (route === "connect" ? event.outcome.account !== undefined : route === "payments" && event.outcome.account === undefined)) {
      const outcome = event.outcome;
      apply = async () => (await options.engine.applyPaymentOutcome(outcome)).applied;
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
    const applied = await apply();
    processed.add(event.eventId);
    return [200, { received: true, applied }];
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
    const payload = await readBody(req, maxBody);
    const header = req.headers[DELIVERY_SIGNATURE_HEADER];
    const check = verifyStripeSignature({
      payload,
      header: Array.isArray(header) ? header[0] : header,
      secrets: options.records?.secrets ?? [],
      now: options.clock.now(),
    });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    const delivery = parseRecordDelivery(payload);
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

  async function demoRoute(req: IncomingMessage, runs: DemoRuns, path: string, method: string): Promise<Answer> {
    const host = req.headers.host!;
    const file = files.get(path);
    if (file !== undefined) {
      if (method !== "GET") throw new HttpError(405, "method_not_allowed");
      return file;
    }
    const answer = (a: RunAnswer): [number, Json] => (a.ok ? [200, a.view as unknown as Json] : [a.status, { error: a.error }]);
    if (path === "/demo/flows") {
      if (method !== "GET") throw new HttpError(405, "method_not_allowed");
      return [200, { flows: runs.flows() }];
    }
    const run = /^\/demo\/runs(?:\/(run_[A-Za-z0-9-]{1,64})(\/next)?)?$/.exec(path);
    if (run !== null) {
      const [, runId, next] = run;
      const post = runId === undefined || next !== undefined;
      if (method !== (post ? "POST" : "GET")) throw new HttpError(405, "method_not_allowed");
      if (!post) return answer(await runs.view(runId as string));
      // A page on another origin can send a simple POST without asking; it cannot send JSON
      // without a preflight this server never answers, nor forge its Origin.
      if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw new HttpError(415, "json_required");
      const origin = req.headers.origin;
      if (origin !== undefined && origin !== `http://${host}`) throw new HttpError(403, "cross_origin");
      const body = await readBody(req, maxBody);
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
    lang: "en" | "fr" | undefined,
  ): Promise<Page> {
    const context = { workspaceId: options.engine.workspaceId, documents: uploads.documents, clock: options.clock };
    const link = await openUploadLink(token, context);
    if (link === null) return uploadPage(410, lang ?? "en", "link_not_usable", null);
    const locale = lang ?? link.locale;
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
    const result = await acceptUpload({ token, contentType: file.contentType, bytes: file.bytes }, { ...context, ids: uploads.ids ?? randomIds, scanner: uploads.scanner });
    if (result.ok) return uploadPage(201, locale, "received", null);
    const spent = result.reason === "link_not_usable" || result.reason === "scan_refused" || result.reason === "scan_failed";
    return uploadPage(REFUSAL_STATUS[result.reason], locale, result.reason, spent ? null : link);
  }

  async function route(req: IncomingMessage): Promise<Answer> {
    if (options.ui !== undefined && !isLocalHost(req.headers.host ?? "", req.socket.localPort!)) throw new HttpError(403, "host_not_allowed");
    // Prefixed, so a path that starts with `//` stays a path instead of naming a host.
    const url = parseUrl(req.url!);
    const path = url.pathname;
    const method = req.method ?? "GET";
    const expect = (m: string) => {
      if (method !== m) throw new HttpError(405, "method_not_allowed");
    };
    if (path === "/healthz") {
      expect("GET");
      return [200, { ok: true }];
    }
    if (path === "/.well-known/receipt-keys.json") {
      expect("GET");
      return [200, { keys: options.engine.receiptKeys() }];
    }
    const stripe = /^\/webhooks\/stripe\/(identity|payments|connect)$/.exec(path);
    if (stripe !== null) {
      expect("POST");
      return stripeWebhook(req, stripe[1] as "identity" | "payments" | "connect");
    }
    if (path === "/webhooks/records") {
      expect("POST");
      return recordWebhook(req);
    }
    const carrier = /^\/webhooks\/(twilio|telnyx)$/.exec(path);
    if (carrier !== null) {
      expect("POST");
      return [501, { error: "not_implemented", issue: "SRV-1", carrier: carrier[1] }];
    }
    // `/r/<token>` is the page, `/r/<token>.json` the signed receipt itself. An unknown token, a
    // malformed one and a call without a receipt all answer the same 404.
    const link = /^\/r\/([A-Za-z0-9_-]{1,64})(\.json)?$/.exec(path);
    if (link !== null) {
      expect("GET");
      const [, token, json] = link as unknown as [string, string, string | undefined];
      const found = await linkedReceipt(token);
      if (found === null) return [404, { error: "not_found" }];
      if (json !== undefined) return [200, found as unknown as Json];
      return { html: receiptPage(found, options.engine.receiptKeys(), token, pageLocale(url, req.headers["accept-language"])) };
    }
    const upload = /^\/u\/([^/]*)$/.exec(path);
    if (options.uploads !== undefined && upload !== null) {
      if (method !== "GET" && method !== "POST") throw new HttpError(405, "method_not_allowed");
      const lang = parseUrl(req.url!).searchParams.get("lang");
      return uploadRoute(req, options.uploads, upload[1]!, method, lang === "en" || lang === "fr" ? lang : undefined);
    }
    if (options.ui !== undefined && (files.has(path) || path.startsWith("/demo/"))) return demoRoute(req, options.ui, path, method);
    return [404, { error: "not_found" }];
  }

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    route(req)
      .catch((error: unknown): Answer => (error instanceof HttpError ? [error.status, { error: error.message }] : [500, { error: "internal" }]))
      .then((answer) => {
        if ("html" in answer) {
          res.writeHead(answer.status ?? 200, answer.upload === true ? UPLOAD_PAGE_HEADERS : PAGE_HEADERS);
          res.end(answer.html);
          return;
        }
        if (Array.isArray(answer)) {
          res.writeHead(answer[0], JSON_HEADERS);
          res.end(JSON.stringify(answer[1]));
          return;
        }
        res.writeHead(200, { ...UI_HEADERS, "content-type": answer.contentType });
        res.end(answer.body);
      });
  });
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

function readBytes(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
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

const REFUSAL_STATUS: Readonly<Record<UploadRefusal, number>> = {
  link_not_usable: 410,
  type_not_allowed: 415,
  content_mismatch: 415,
  empty: 400,
  too_large: 413,
  scan_refused: 422,
  scan_failed: 503,
};

type PageMessage = UploadRefusal | "received";

const UPLOAD_TEXT = {
  en: {
    title: "Add a document",
    intro: "Choose a photo or a PDF to add to your file. This link works once.",
    accepted: "Accepted:",
    upTo: "up to",
    send: "Send",
    other: ["fr", "Français"],
    units: ["MB", "KB"],
    messages: {
      received: "Thank you. Your document was received. You can close this page.",
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
    messages: {
      received: "Merci. Votre document a bien été reçu. Vous pouvez fermer cette page.",
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
 * except the link's types and size cap, which come from a fixed list and a number.
 */
function uploadPage(status: number, locale: PageLocale, message: PageMessage | null, link: { allowedTypes: DocumentType[]; maxBytes: number } | null): Page {
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
