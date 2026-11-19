// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts and the receipt key set,
// runs a sample receiver for signed record deliveries, and answers 501 on the carrier webhooks that are not built yet. With `ui`, it also serves the
// demo's browser UI and the routes that run the scripted demo one step at a time. Not hardened
// for production; ROADMAP.md, "Reference server", lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  DELIVERY_SIGNATURE_HEADER,
  EngineError,
  parseStripeEvent,
  verifyStripeSignature,
  type Clock,
  type Engine,
  type RecordDeliveryBody,
} from "../../../src/index.ts";
import type { DemoRuns, RunAnswer } from "./demo-runs.ts";
import { isDemoFlow } from "./script.ts";
import { UI_HEADERS, loadStaticFiles, type StaticFile } from "./static.ts";

export interface ReferenceServerOptions {
  engine: Engine;
  /** Signing secrets per Stripe endpoint. Empty means the endpoint refuses everything. */
  stripeSecrets: { identity: readonly string[]; payments: readonly string[] };
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
  /** The demo's runs: serves the browser UI and the `/demo/*` routes. Off when absent. */
  ui?: DemoRuns;
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
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function createReferenceServer(options: ReferenceServerOptions): Server {
  const processed = new Set<string>();
  const receivedRecords = new Set<string>();
  /** Deliveries whose `onRecord` is still running; a concurrent duplicate waits on the same one. */
  const pendingRecords = new Map<string, Promise<void>>();
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
    if (path === "/webhooks/stripe/identity" || path === "/webhooks/stripe/payments") {
      expect("POST");
      return stripeWebhook(req, path.endsWith("identity") ? "identity" : "payments");
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
