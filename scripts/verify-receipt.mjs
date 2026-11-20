#!/usr/bin/env node
// Checks a District Assurance receipt against a key set, without this package: Node 24.2 or later
// and nothing else. SPEC.md, section 12, describes the format; this file repeats only what a
// verifier needs (canonical JSON and ES256 over it), so it can be copied out on its own.
//
//   node verify-receipt.mjs <receipt.json | -> <keys.json | https://host/.well-known/receipt-keys.json>
//
// Prints `valid`, or `valid, signed with a retired key (retired <time>)` for a receipt issued
// before its key was retired, and exits 0; or `invalid: <reason>` and exits 1 (a receipt signed by
// a retired key at or after its retirement is invalid). Exits 2 when it cannot run the check at all (a missing argument, an unreadable file, a key set it cannot fetch). A key set URL
// must be https, or http on this machine (127.0.0.1, localhost, [::1]): a key set fetched in the
// clear could be swapped for one that makes a forged receipt look valid.
import { createPublicKey, verify } from "node:crypto";
import { createReadStream } from "node:fs";

const MAX_BYTES = 1024 * 1024;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

class Usage extends Error {}

/** A JSON string, refusing a lone surrogate as RFC 8785 (section 3.2.2.2) does. */
function jsonString(value) {
  if (!value.isWellFormed()) throw new TypeError("lone surrogate");
  return JSON.stringify(value);
}

/** RFC 8785 canonical JSON for plain JSON values: sorted keys, no whitespace, JSON.stringify scalars. */
function canonicalJson(value) {
  if (typeof value === "string") return jsonString(value);
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("not JSON");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${jsonString(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("not JSON");
}

/** An ISO 8601 UTC time as the engine writes it. */
function isUtcTime(value) {
  if (typeof value !== "string") return false;
  const ms = Date.parse(value);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === value;
}

/**
 * The reason a receipt fails against the keys, or null when it verifies. A retired key (one with
 * `retiredAt`) verifies only a receipt issued before its retirement; `retired` receives when.
 */
function check(receipt, keys, retired = { at: null }) {
  if (receipt === null || typeof receipt !== "object" || receipt.body === null || typeof receipt.body !== "object") return "not a receipt";
  if (receipt.body.v !== 1) return "an unknown receipt version";
  if (receipt.alg !== "ES256") return "an algorithm other than ES256";
  if (typeof receipt.kid !== "string" || typeof receipt.signature !== "string") return "not a receipt";
  const jwk = keys.find((k) => k !== null && typeof k === "object" && k.kid === receipt.kid);
  if (jwk === undefined) return `no key with kid ${shown(receipt.kid)} in the key set`;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.d !== undefined) return "the key is not a public P-256 key";
  if (jwk.retiredAt !== undefined) {
    if (!isUtcTime(jwk.retiredAt)) return "the key's retiredAt is not an ISO 8601 UTC time";
    if (!isUtcTime(receipt.body.issuedAt) || Date.parse(receipt.body.issuedAt) >= Date.parse(jwk.retiredAt)) {
      return `signed with a key retired at ${jwk.retiredAt}, at or after its retirement`;
    }
    retired.at = jwk.retiredAt;
  }
  let key;
  try {
    key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
  } catch {
    return "the key is not a public P-256 key";
  }
  // Strict base64url: 64 bytes are exactly 86 characters, without padding.
  if (!/^[A-Za-z0-9_-]{85}[AQgw]$/.test(receipt.signature)) return "a malformed signature";
  let payload;
  try {
    payload = new TextEncoder().encode(canonicalJson(receipt.body));
  } catch {
    // The engine signs only what canonicalJson accepts, so no key signed this body.
    return "a body that is not canonical JSON (a lone surrogate)";
  }
  const signature = Buffer.from(receipt.signature, "base64url");
  return verify("sha256", payload, { key, dsaEncoding: "ieee-p1363" }, signature) ? null : "the signature does not match the body";
}

/**
 * The characters a terminal acts on or that reorder or hide text, as code point ranges: C0, DEL
 * and C1 controls (escape sequences, the 8-bit CSI U+009B), the Arabic letter mark, the zero-width
 * characters and bidi marks (U+200B to U+200F), U+2028, U+2029 and the bidi embeddings and
 * overrides (to U+202E), the invisible format characters and bidi isolates (U+2060 to U+206F), and
 * U+FEFF. The same table as the simulator's terminalSafe (src/cli/simulate.ts); keep the two identical.
 */
const TERMINAL_UNSAFE_RANGES = [
  [0x00, 0x1f],
  [0x7f, 0x9f],
  [0x61c, 0x61c],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0xfeff, 0xfeff],
];

/**
 * A value from the receipt as the terminal may show it: JSON, with every character of the table
 * above that JSON leaves as it is written as a `\u` escape too, so no text can move the cursor, or
 * reorder or hide the verdict it is printed in.
 */
function shown(value) {
  let out = "";
  for (const c of JSON.stringify(value)) {
    const n = c.codePointAt(0);
    out += TERMINAL_UNSAFE_RANGES.some(([lo, hi]) => n >= lo && n <= hi) ? `\\u${n.toString(16).padStart(4, "0")}` : c;
  }
  return out;
}

function parse(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Usage(`${what} is not JSON`);
  }
}

/** Reads a file or standard input, stopping as soon as it passes 1 MiB (a pipe or device may never end). */
async function readSource(source, what) {
  try {
    const chunks = [];
    let total = 0;
    for await (const chunk of source === "-" ? process.stdin : createReadStream(source)) {
      total += chunk.byteLength;
      if (total > MAX_BYTES) throw new Usage(`${what} is larger than 1 MiB`);
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  } catch (error) {
    if (error instanceof Usage) throw error;
    throw new Usage(`cannot read ${what} from ${source}`);
  }
}

async function fetchKeySet(source) {
  let url;
  try {
    url = new URL(source);
  } catch {
    throw new Usage("the key set URL is not a URL");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new Usage("a key set URL must be https (or http on 127.0.0.1, localhost or [::1])");
  }
  let response;
  try {
    // No redirects: a redirect could leave https.
    response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(10_000), headers: { accept: "application/json" } });
  } catch {
    throw new Usage(`cannot fetch the key set from ${url.href}`);
  }
  if (!response.ok) throw new Usage(`the key set URL answered ${response.status}`);
  // Counted in UTF-8 bytes while reading (not string length), so an oversized answer is never held
  // in full; leaving the loop early cancels the rest of the body.
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of response.body ?? []) {
      total += chunk.byteLength;
      if (total > MAX_BYTES) throw new Usage("the key set is larger than 1 MiB");
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof Usage) throw error;
    throw new Usage(`cannot fetch the key set from ${url.href}`);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main(args) {
  if (args.length !== 2) throw new Usage("usage: node verify-receipt.mjs <receipt.json | -> <keys.json | https://.../receipt-keys.json>");
  const [receiptSource, keysSource] = args;
  const receipt = parse(await readSource(receiptSource, "the receipt"), "the receipt");
  const isUrl = /^https?:\/\//i.test(keysSource);
  const keySet = parse(isUrl ? await fetchKeySet(keysSource) : await readSource(keysSource, "the key set"), "the key set");
  // A JWK set (`{"keys": [...]}`, what the reference server serves) or a bare list of keys.
  const keys = Array.isArray(keySet) ? keySet : keySet?.keys;
  if (!Array.isArray(keys)) throw new Usage('the key set must be {"keys": [...]} or a list of keys');
  const retired = { at: null };
  const reason = check(receipt, keys, retired);
  return { reason, retiredAt: retired.at };
}

if (import.meta.main) {
  try {
    const { reason, retiredAt } = await main(process.argv.slice(2));
    const valid = retiredAt === null ? "valid\n" : `valid, signed with a retired key (retired ${retiredAt})\n`;
    process.stdout.write(reason === null ? valid : `invalid: ${reason}\n`);
    process.exitCode = reason === null ? 0 : 1;
  } catch (error) {
    process.stderr.write(`verify-receipt: ${error instanceof Usage ? error.message : "unexpected error"}\n`);
    process.exitCode = 2;
  }
}
