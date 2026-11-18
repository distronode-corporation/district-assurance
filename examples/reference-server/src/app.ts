// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts and the receipt key set,
// and answers 501 on the carrier webhooks that are not built yet. Not hardened for production;
// ROADMAP.md, "Reference server", lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { EngineError, parseStripeEvent, verifyStripeSignature, type Clock, type Engine } from "../../../src/index.ts";

export interface ReferenceServerOptions {
  engine: Engine;
  /** Signing secrets per Stripe endpoint. Empty means the endpoint refuses everything. */
  stripeSecrets: { identity: readonly string[]; payments: readonly string[] };
  clock: Clock;
  /** Default 64 KiB. */
  maxBodyBytes?: number;
}

type Json = Record<string, unknown>;

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

  async function route(req: IncomingMessage): Promise<[number, Json]> {
    const url = new URL(req.url ?? "/", "http://localhost");
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
    const carrier = /^\/webhooks\/(twilio|telnyx|sinch)$/.exec(path);
    if (carrier !== null) {
      expect("POST");
      return [501, { error: "not_implemented", issue: "SRV-1", carrier: carrier[1] }];
    }
    const receipt = /^\/receipts\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (receipt !== null) {
      expect("GET");
      try {
        const found = options.engine.receipt(receipt[1]!);
        return found === null ? [404, { error: "not_found" }] : [200, found as unknown as Json];
      } catch (error) {
        if (error instanceof EngineError && error.code === "unknown_call") return [404, { error: "not_found" }];
        throw error;
      }
    }
    return [404, { error: "not_found" }];
  }

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    route(req)
      .catch((error: unknown): [number, Json] => (error instanceof HttpError ? [error.status, { error: error.message }] : [500, { error: "internal" }]))
      .then(([status, body]) => {
        res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify(body));
      });
  });
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
