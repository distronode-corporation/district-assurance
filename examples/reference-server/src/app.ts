// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts and the receipt key set,
// and answers 501 on the carrier webhooks that are not built yet. With `ui`, it also serves the
// demo's browser UI and the routes that run the scripted demo one step at a time. Each route has
// its own body limit, every request has deadlines, each remote address has a rate limit, and each
// answered request can be logged as one structured entry that never holds a body or a header.
// Still not hardened for production; ROADMAP.md, "Reference server", lists what else that takes.
import { STATUS_CODES, createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIPv6, type Socket } from "node:net";
import { performance } from "node:perf_hooks";

import { EngineError, parseStripeEvent, systemClock, verifyStripeSignature, type Clock, type Engine } from "../../../src/index.ts";
import type { DemoRuns, RunAnswer } from "./demo-runs.ts";
import { isDemoFlow } from "./script.ts";
import { UI_HEADERS, loadStaticFiles, type StaticFile } from "./static.ts";

export interface ReferenceServerOptions {
  engine: Engine;
  /** Signing secrets per Stripe endpoint. Empty means the endpoint refuses everything. */
  stripeSecrets: { identity: readonly string[]; payments: readonly string[] };
  clock: Clock;
  /** Body limits in bytes, per route that reads a body. Defaults in `DEFAULT_BODY_LIMITS`. */
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
  /** The demo's runs: serves the browser UI and the `/demo/*` routes. Off when absent. */
  ui?: DemoRuns;
}

/** The routes that read a body. Every other route answers without reading one. */
export interface BodyLimits {
  stripeIdentity: number;
  stripePayments: number;
  /** `POST /demo/runs` and `POST /demo/runs/:runId/next`, whose bodies are a flow name or nothing. */
  demo: number;
}

export const DEFAULT_BODY_LIMITS: Readonly<BodyLimits> = { stripeIdentity: 64 * 1024, stripePayments: 64 * 1024, demo: 1024 };

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
  /** `/receipts/:callId`, `/demo/runs/:runId/next` and so on; `unmatched` when no route matched. */
  route: string;
  status: number;
  /** A refusal's error code, as in its answer. */
  error?: string;
  /** Wall time spent answering, in whole milliseconds. */
  ms: number;
}

/** A `log` that writes each entry as one line of JSON on standard output. */
export function logJsonLines(entry: RequestLog): void {
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

type Json = Record<string, unknown>;
type Answer = [number, Json] | StaticFile;

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
  const processed = new Set<string>();
  const limits: BodyLimits = { ...DEFAULT_BODY_LIMITS, ...options.bodyLimits };
  for (const name of ["stripeIdentity", "stripePayments", "demo"] as const) wholeFrom1(`bodyLimits.${name}`, limits[name]);
  const timeoutMs = wholeFrom1("timeoutMs", options.timeoutMs ?? 10_000, MAX_TIMEOUT_MS);
  const rate = options.rateLimit ?? { requests: 300, windowMs: 60_000 };
  const rateLimit = new RateLimit(
    wholeFrom1("rateLimit.requests", rate.requests),
    wholeFrom1("rateLimit.windowMs", rate.windowMs),
    wholeFrom1("rateLimit.addresses", rate.addresses ?? 10_000),
    rate.clock ?? systemClock,
  );
  const files = options.ui === undefined ? new Map<string, StaticFile>() : loadStaticFiles();

  async function stripeWebhook(req: IncomingMessage, route: "identity" | "payments"): Promise<[number, Json]> {
    const payload = await readBody(req, route === "identity" ? limits.stripeIdentity : limits.stripePayments);
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
      if (!isDemoFlow(flow)) throw new HttpError(400, "unknown_flow");
      return [201, (await runs.start(flow)) as unknown as Json];
    }
    return [404, { error: "not_found" }];
  }

  async function route(req: IncomingMessage, seen: Seen): Promise<Answer> {
    // First, so a flood is refused before any other work.
    rateLimit.take(addressOf(req));
    if (options.ui !== undefined && !isLocalHost(req.headers.host ?? "", req.socket.localPort!)) throw new HttpError(403, "host_not_allowed");
    // Prefixed, so a path that starts with `//` stays a path instead of naming a host.
    const path = parseUrl(req.url!).pathname;
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
    if (path === "/webhooks/stripe/identity" || path === "/webhooks/stripe/payments") {
      seen.route = path;
      expect("POST");
      return stripeWebhook(req, path.endsWith("identity") ? "identity" : "payments");
    }
    const carrier = /^\/webhooks\/(twilio|telnyx)$/.exec(path);
    if (carrier !== null) {
      seen.route = path;
      expect("POST");
      return [501, { error: "not_implemented", issue: "SRV-1", carrier: carrier[1] }];
    }
    const receipt = /^\/receipts\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (receipt !== null) {
      seen.route = "/receipts/:callId";
      expect("GET");
      try {
        const found = await options.engine.receipt(receipt[1]!);
        return found === null ? [404, { error: "not_found" }] : [200, found as unknown as Json];
      } catch (error) {
        if (error instanceof EngineError && error.code === "unknown_call") return [404, { error: "not_found" }];
        throw error;
      }
    }
    if (options.ui !== undefined && (files.has(path) || path.startsWith("/demo/"))) return demoRoute(req, options.ui, path, method, seen);
    return [404, { error: "not_found" }];
  }

  /** The request each socket is answering, so a client error on it is answered and logged once. */
  const inFlight = new WeakMap<Socket, Exchange>();

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

  // node:http enforces the receive deadline itself, checking open connections at this interval.
  const timeouts = { requestTimeout: timeoutMs, headersTimeout: timeoutMs, connectionsCheckingInterval: Math.min(timeoutMs, 1000) };
  const server = createServer(timeouts, (req: IncomingMessage, res: ServerResponse) => {
    const exchange: Exchange = { started: performance.now(), method: req.method ?? "GET", seen: { route: "unmatched" }, done: false, req };
    const socket = req.socket;
    inFlight.set(socket, exchange);
    // Kept while its body is unread, so node:http timing that body out after the answer is not
    // answered and logged a second time; forgotten once the socket can carry the next request.
    res.on("close", () => {
      if (req.complete && inFlight.get(socket) === exchange) inFlight.delete(socket);
    });
    let timer: NodeJS.Timeout | undefined;
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
      let status = 200;
      let error: string | undefined;
      if (Array.isArray(answer)) {
        [status] = answer;
        if (typeof answer[1].error === "string") error = answer[1].error;
        res.writeHead(status, JSON_HEADERS);
        res.end(JSON.stringify(answer[1]));
      } else {
        res.writeHead(status, { ...UI_HEADERS, "content-type": answer.contentType });
        res.end(answer.body);
      }
      record(exchange, addressOf(req), status, error);
    });
  });

  // node:http's own refusals (headers or body too slow, headers too large, a malformed request)
  // reach this instead of the listener. Answered as node:http would, but in JSON, and logged.
  server.on("clientError", (err: NodeJS.ErrnoException, socket: Socket) => {
    const held = inFlight.get(socket);
    inFlight.delete(socket);
    // A request received in full is over, even before its stream says so: an error after it is the
    // next request's (one the client sent right behind a body drained after its answer), answered too.
    const exchange = held?.req!.complete === true ? undefined : held;
    // A reset socket takes no answer, and one whose answer is already written cannot take another.
    if (err.code !== "ECONNRESET" && socket.writable && exchange?.done !== true) {
      const [status, code] = CLIENT_ERRORS[err.code ?? ""] ?? [400, "bad_request"];
      const body = JSON.stringify({ error: code });
      const headers = { ...JSON_HEADERS, "content-length": String(Buffer.byteLength(body)), connection: "close" };
      const head = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`);
      socket.write(`HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\n${head.join("")}\r\n${body}`);
      const answered = exchange ?? { started: performance.now(), method: "unknown", seen: { route: "unmatched" }, done: false, req: null };
      answered.done = true;
      record(answered, rateLimitKey(socket.remoteAddress ?? "unknown"), status, code);
    }
    socket.destroy(err);
  });
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

/** The body as text, refused with a 413 as soon as its declared or received size passes `max`. */
function readBody(req: IncomingMessage, max: number): Promise<string> {
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
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
