// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts and the receipt key set,
// and answers 501 on the carrier webhooks that are not built yet. With `securityTxt`, it serves the
// host's own `/.well-known/security.txt` (RFC 9116). With `ui`, it also serves the demo's browser
// UI and the routes that run the scripted demo one step at a time. Not hardened
// for production; ROADMAP.md, "Reference server", lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { EngineError, parseStripeEvent, verifyStripeSignature, type Clock, type Engine } from "../../../src/index.ts";
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
  /** The host's own security.txt. No route when absent: there is no default. */
  securityTxt?: SecurityTxtSettings;
  /** Where start-up warnings go. Default `console.warn`. */
  warn?: (message: string) => void;
}

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

type Json = Record<string, unknown>;
/** A plain text answer: the security.txt. */
type TextAnswer = { text: string };
type Answer = [number, Json] | StaticFile | TextAnswer;

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
  if (!/^[\x21-\x7e]+$/.test(value) || !schemes.includes(scheme) || malformedWeb) {
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
  const security = options.securityTxt;
  const warn = options.warn ?? console.warn;
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
    if (now >= file.expires) {
      if (!warnedExpired) warn(`security.txt expired at ${securityCopy!.expires.toISOString()}: it is no longer served; renew it`);
      warnedExpired = true;
      return false;
    }
    if (!warnedSoon && file.expires - now <= WARN_MS) {
      warn(expiryWarning(securityCopy!.expires));
      warnedSoon = true;
    }
    return true;
  };

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
    const path = parseUrl(req.url!).pathname;
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
    // The host's own file only, and none once it has expired while the server kept running.
    if (path === "/.well-known/security.txt" && securityFile !== null && securityRequested(options.clock.now().getTime())) {
      expect("GET");
      return { text: securityFile.text };
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
    const receipt = /^\/receipts\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (receipt !== null) {
      expect("GET");
      try {
        const found = await options.engine.receipt(receipt[1]!);
        return found === null ? [404, { error: "not_found" }] : [200, found as unknown as Json];
      } catch (error) {
        if (error instanceof EngineError && error.code === "unknown_call") return [404, { error: "not_found" }];
        throw error;
      }
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
        if ("text" in answer) {
          res.writeHead(200, TEXT_HEADERS);
          res.end(answer.text);
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
