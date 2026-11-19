// The reference server: a small node:http server around one Engine. It receives the Stripe
// webhooks that finish a photo ID check and a payment, serves receipts and the receipt key set,
// answers 501 on the carrier webhooks that are not built yet, and, with `uploads`, serves the
// single-use document upload page in English and French (FIL-5). With `ui`, it also serves the
// demo's browser UI and the routes that run the scripted demo one step at a time. Not hardened
// for production; ROADMAP.md, "Reference server", lists what that takes.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  EngineError,
  acceptUpload,
  openUploadLink,
  parseStripeEvent,
  randomIds,
  verifyStripeSignature,
  type Clock,
  type DocumentScanner,
  type DocumentStore,
  type DocumentType,
  type Engine,
  type IdGenerator,
  type UploadRefusal,
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
  /** Document uploads by single-use link: serves `/u/:token`. Off when absent. */
  uploads?: { documents: DocumentStore; scanner: DocumentScanner; ids?: IdGenerator };
}

type Json = Record<string, unknown>;
interface Page {
  status: number;
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
 * On the upload page: no script, no style, no framing, forms posted back here only, and no
 * referrer, so the token in the address never leaves in a header.
 */
const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

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
          res.writeHead(answer.status, PAGE_HEADERS);
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
function uploadPage(status: number, locale: "en" | "fr", message: PageMessage | null, link: { allowedTypes: DocumentType[]; maxBytes: number } | null): Page {
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
  return { status, html };
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
