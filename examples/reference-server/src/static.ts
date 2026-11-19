// The browser UI's files: a fixed allow-list, read once when the server is created. A request path
// is only ever a key into this map, so it never reaches the file system: no traversal, no
// directory listing, nothing outside the list.
import { readFileSync } from "node:fs";

export interface StaticFile {
  contentType: string;
  body: Buffer;
}

/** URL path to file name under `public/`, and its content type. */
export const STATIC_FILES: Readonly<Record<string, readonly [file: string, contentType: string]>> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/receipt-check.js": ["receipt-check.js", "text/javascript; charset=utf-8"],
};

/**
 * The page's policy: scripts, styles and requests from this origin only, no inline script or
 * style, no framing, no forms posted anywhere, no plugins.
 */
export const UI_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Headers on every UI file. */
export const UI_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy": UI_CSP,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "cache-control": "no-store",
};

export function loadStaticFiles(dir: URL = new URL("../public/", import.meta.url)): ReadonlyMap<string, StaticFile> {
  const files = new Map<string, StaticFile>();
  for (const [path, [file, contentType]] of Object.entries(STATIC_FILES)) {
    files.set(path, { contentType, body: readFileSync(new URL(file, dir)) });
  }
  return files;
}
