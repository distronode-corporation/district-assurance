// The page's own checks, with nothing but Web Crypto: a receipt's ES256 signature against the
// public key set, and a ledger entry's hash. No DOM here, so the same module runs in Node's test
// suite against receipts the engine signed (test/reference-ui.test.ts).
//
// canonicalJson mirrors src/core/canonical.ts (RFC 8785 for the values the engine produces): keys
// sorted by UTF-16 code units, no whitespace, strings and numbers as JSON.stringify writes them,
// and a string or key holding a lone surrogate refused (RFC 8785, section 3.2.2.2).

/**
 * @param {string} value
 * @returns {string}
 */
function jsonString(value) {
  if (!value.isWellFormed()) throw new TypeError("canonicalJson: lone surrogate");
  return JSON.stringify(value);
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return jsonString(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("canonicalJson: non-finite number");
      return JSON.stringify(value);
    case "object":
      if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
      return `{${Object.keys(value)
        .sort()
        .map((key) => `${jsonString(key)}:${canonicalJson(/** @type {Record<string, unknown>} */ (value)[key])}`)
        .join(",")}}`;
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
  }
}

/**
 * @param {string} text base64url, no padding
 * @returns {Uint8Array}
 */
export function base64urlToBytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new TypeError("not base64url");
  const base64 = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * @param {string} text
 * @returns {Promise<string>} the SHA-256 of the UTF-8 bytes, in lower-case hex
 */
export async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Checks a signed receipt against a key set, as `verifyReceipt` in src/prove/receipt.ts does.
 * Never throws: every failure is a reason.
 *
 * @param {{ body: unknown, alg: string, kid: string, signature: string }} receipt
 * @param {ReadonlyArray<{ kid?: string, kty?: string, crv?: string, x?: string, y?: string }>} keys
 * A key with `retiredAt` verifies only a receipt issued before it was retired: such a receipt is
 * `valid_retired_key`, with the time, and one issued at or after it is `retired_key_after`.
 *
 * @returns {Promise<{ ok: boolean, reason: "valid" | "valid_retired_key" | "wrong_alg" | "unknown_kid" | "bad_key" | "retired_key_after" | "malformed_signature" | "malformed_body" | "signature_mismatch", retiredAt?: string }>}
 */
export async function checkReceipt(receipt, keys) {
  if (receipt.alg !== "ES256") return { ok: false, reason: "wrong_alg" };
  const jwk = keys.find((k) => k.kid === receipt.kid);
  if (jwk === undefined) return { ok: false, reason: "unknown_kid" };
  /** @type {string | null} */
  let retiredAt = null;
  if (/** @type {{ retiredAt?: unknown }} */ (jwk).retiredAt !== undefined) {
    const at = /** @type {{ retiredAt?: unknown }} */ (jwk).retiredAt;
    if (!isUtcTime(at)) return { ok: false, reason: "bad_key" };
    const body = /** @type {{ issuedAt?: unknown }} */ (receipt.body);
    if (!isUtcTime(body?.issuedAt) || Date.parse(body.issuedAt) >= Date.parse(at)) return { ok: false, reason: "retired_key_after" };
    retiredAt = at;
  }
  let signature;
  try {
    signature = base64urlToBytes(receipt.signature);
  } catch {
    return { ok: false, reason: "malformed_signature" };
  }
  if (signature.length !== 64) return { ok: false, reason: "malformed_signature" };
  let key;
  try {
    key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return { ok: false, reason: "bad_key" };
  }
  let payload;
  try {
    payload = new TextEncoder().encode(canonicalJson(receipt.body));
  } catch {
    // The engine signs only what canonicalJson accepts, so no key signed this body.
    return { ok: false, reason: "malformed_body" };
  }
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, payload);
  if (!ok) return { ok: false, reason: "signature_mismatch" };
  return retiredAt === null ? { ok: true, reason: "valid" } : { ok: true, reason: "valid_retired_key", retiredAt };
}

/**
 * An ISO 8601 UTC time as the engine writes it.
 *
 * @param {unknown} value
 * @returns {value is string}
 */
function isUtcTime(value) {
  if (typeof value !== "string") return false;
  const ms = Date.parse(value);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === value;
}

/**
 * Whether a ledger entry's hash is the SHA-256 of the canonical JSON of its other fields.
 *
 * @param {{ hash: string } & Record<string, unknown>} entry
 * @returns {Promise<boolean>}
 */
export async function entryHashMatches(entry) {
  const { hash, ...rest } = entry;
  let text;
  try {
    text = canonicalJson(rest);
  } catch {
    return false;
  }
  return (await sha256Hex(text)) === hash;
}

/**
 * A copy of the receipt with one character of its body changed: the first hex digit of the ledger
 * head it was signed over. What the page shows a forged receipt looking like.
 *
 * @template {{ body: { ledger: { hash: string } } }} R
 * @param {R} receipt
 * @returns {R}
 */
export function tamperedCopy(receipt) {
  const copy = structuredClone(receipt);
  const hash = copy.body.ledger.hash;
  copy.body.ledger.hash = (hash.startsWith("0") ? "1" : "0") + hash.slice(1);
  return copy;
}

/**
 * @param {string} hex
 * @returns {string} the first and last 8 characters
 */
export function shortHash(hex) {
  return hex.length <= 20 ? hex : `${hex.slice(0, 8)}...${hex.slice(-8)}`;
}
