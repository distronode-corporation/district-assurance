// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts by capability link with a
// small receipt page, serves the receipt key set, and answers 501 on the carrier webhooks that
// are not built yet. With `ui`, it also serves the demo's browser UI and the routes that run the
// scripted demo one step at a time. Not hardened for production; ROADMAP.md, "Reference server",
// lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  EngineError,
  formatAmount,
  newReceiptLinkToken,
  parseStripeEvent,
  receiptLinkTokenHash,
  verifyReceipt,
  verifyStripeSignature,
  type Clock,
  type Engine,
  type Locale,
  type SignedReceipt,
} from "../../../src/index.ts";
import type { DemoRuns, RunAnswer } from "./demo-runs.ts";
import { isDemoFlow } from "./script.ts";
import { UI_HEADERS, loadStaticFiles, type StaticFile } from "./static.ts";

export interface ReferenceServerOptions {
  engine: Engine;
  /** Signing secrets per Stripe endpoint. Empty means the endpoint refuses everything. */
  stripeSecrets: { identity: readonly string[]; payments: readonly string[] };
  clock: Clock;
  /** Default 64 KiB. */
  maxBodyBytes?: number;
  /** The demo's runs: serves the browser UI and the `/demo/*` routes. Off when absent. */
  ui?: DemoRuns;
  /** The receipt links the host issued. Absent: `/r/:token` answers 404 for every token. */
  receiptLinks?: ReceiptLinks;
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
/** A receipt page, in HTML, already escaped. */
interface Page {
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

/**
 * With the UI on, the server answers this machine's own names on its own port only, on every
 * route: a page on another name (DNS rebinding) or another port gets nothing, not the UI, not the
 * receipts, and not the webhooks that accept the demo's published secret.
 */
function isLocalHost(host: string, port: number): boolean {
  const h = host.toLowerCase();
  return h === `127.0.0.1:${port}` || h === `localhost:${port}` || h === `[::1]:${port}`;
}

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createReferenceServer(options: ReferenceServerOptions): Server {
  const processed = new Set<string>();
  const maxBody = options.maxBodyBytes ?? 64 * 1024;
  const files = options.ui === undefined ? new Map<string, StaticFile>() : loadStaticFiles();

  async function stripeWebhook(req: IncomingMessage, route: "identity" | "payments"): Promise<[number, Json]> {
    const payload = await readBody(req, maxBody);
    const header = req.headers["stripe-signature"];
    const check = verifyStripeSignature({
      payload,
      header: Array.isArray(header) ? header[0] : header,
      secrets: options.stripeSecrets[route],
      now: options.clock.now(),
    });
    if (!check.ok) return [400, { error: "signature", reason: check.reason }];
    const event = parseStripeEvent(payload);
    if (event === null) return [400, { error: "malformed_event" }];
    if (processed.has(event.eventId)) return [200, { received: true, duplicate: true }];
    let applied = false;
    if (route === "identity" && event.kind === "identity") applied = (await options.engine.applyIdentityOutcome(event.outcome)).applied;
    if (route === "payments" && event.kind === "payment") applied = (await options.engine.applyPaymentOutcome(event.outcome)).applied;
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
      if (!isDemoFlow(flow)) throw new HttpError(400, "unknown_flow");
      return [201, (await runs.start(flow)) as unknown as Json];
    }
    return [404, { error: "not_found" }];
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
    if (path === "/webhooks/stripe/identity" || path === "/webhooks/stripe/payments") {
      expect("POST");
      return stripeWebhook(req, path.endsWith("identity") ? "identity" : "payments");
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
    if (options.ui !== undefined && (files.has(path) || path.startsWith("/demo/"))) return demoRoute(req, options.ui, path, method);
    return [404, { error: "not_found" }];
  }

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    route(req)
      .catch((error: unknown): Answer => (error instanceof HttpError ? [error.status, { error: error.message }] : [500, { error: "internal" }]))
      .then((answer) => {
        if (Array.isArray(answer)) {
          res.writeHead(answer[0], JSON_HEADERS);
          res.end(JSON.stringify(answer[1]));
          return;
        }
        if ("html" in answer) {
          res.writeHead(200, PAGE_HEADERS);
          res.end(answer.html);
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
function pageLocale(url: URL, acceptLanguage: string | undefined): Locale {
  const lang = url.searchParams.get("lang");
  if (lang === "en" || lang === "fr") return lang;
  return /^\s*fr(?:-|;|,|\s|$)/i.test(acceptLanguage ?? "") ? "fr" : "en";
}

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
    answer: { yes: "yes", no: "no" },
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
    answer: { yes: "oui", no: "non" },
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
function receiptPage(receipt: SignedReceipt, keys: Parameters<typeof verifyReceipt>[1], token: string, locale: Locale): string {
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

function readBody(req: IncomingMessage, max: number): Promise<string> {
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
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
