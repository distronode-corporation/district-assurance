// Carrier webhook signature checks, each on the carrier's published scheme. Nothing here calls a
// carrier.
//
// Twilio: the `X-Twilio-Signature` header is the base64 HMAC-SHA1, under the account's auth token,
// of the full URL Twilio requested followed by every form parameter of the body, sorted by name,
// each written as name then value with nothing between. A JSON body is not signed itself: Twilio
// adds `bodySHA256=<hex SHA-256 of the body>` to the URL it signs, and the body must match it.
// Twilio's scheme has no timestamp, so a captured request replays (SECURITY-MODEL.md, "Replay").
//
// Telnyx: the `telnyx-signature-ed25519` header is the base64 Ed25519 signature, under the
// account's key pair, of `<telnyx-timestamp>|<raw body>`; the public key is the base64 of its 32
// raw bytes, as the Telnyx portal shows it.
import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";

import { EngineError } from "../core/errors.ts";
import { isIntegerIn } from "../core/shape.ts";
import type { SignatureCheck } from "./stripe.ts";

export type TwilioSignatureCheck =
  | { ok: true }
  | { ok: false; reason: "missing_header" | "no_secret" | "no_matching_signature" | "body_hash_mismatch" };

export interface TwilioSignatureInput {
  /**
   * The full URL Twilio requested, query included, exactly as configured in Twilio. Behind a proxy
   * this is the public URL, not the one the server sees.
   */
  url: string;
  /**
   * The raw request body, exactly as received: form parameters, or JSON with `bodySHA256` in the
   * URL. Give the bytes: `bodySHA256` is taken over them, never over a decoded copy, in which two
   * different invalid UTF-8 bodies would read the same. Form parameters are decoded from them.
   */
  payload: string | Uint8Array;
  header: string | null | undefined;
  /** The account's auth tokens; two while the secondary token is promoted. */
  authTokens: readonly string[];
}

export function verifyTwilioSignature(input: TwilioSignatureInput): TwilioSignatureCheck {
  // Read once: the URL whose bodySHA256 is taken is the URL whose signature is checked.
  const { url: signedUrl, payload, header } = input;
  // Like the Telnyx keys: an entry that is not a non-empty string is skipped, never thrown on.
  const tokens = input.authTokens.filter((s): s is string => typeof s === "string" && s.length > 0);
  if (tokens.length === 0) return { ok: false, reason: "no_secret" };
  if (header === null || header === undefined || header === "") return { ok: false, reason: "missing_header" };
  const query = signedUrl.indexOf("?");
  const bodyHash = query < 0 ? null : new URLSearchParams(signedUrl.slice(query + 1)).get("bodySHA256");
  // With `bodySHA256` the URL alone is signed; otherwise the body's form parameters follow it.
  const params = bodyHash === null ? sortedParams(typeof payload === "string" ? payload : Buffer.from(payload).toString("utf8")) : "";
  const matches = urlVariants(signedUrl).some((url) =>
    tokens.some((token) => stringsEqual(createHmac("sha1", token).update(url + params).digest("base64"), header)),
  );
  if (!matches) return { ok: false, reason: "no_matching_signature" };
  if (bodyHash !== null && !stringsEqual(createHash("sha256").update(payload).digest("hex"), bodyHash.toLowerCase())) {
    return { ok: false, reason: "body_hash_mismatch" };
  }
  return { ok: true };
}

/**
 * Form parameters as Twilio signs them: sorted by name, then by value for a repeated name. A pair
 * sent twice with the same value is signed once, as Twilio's own libraries do.
 */
function sortedParams(body: string): string {
  const pairs = [...new URLSearchParams(body)];
  pairs.sort(([ak, av], [bk, bv]) => (ak === bk ? compare(av, bv) : compare(ak, bk)));
  // Sorted, a pair sent twice sits next to itself.
  const distinct = pairs.filter(([k, v], i) => i === 0 || k !== pairs[i - 1]![0] || v !== pairs[i - 1]![1]);
  return distinct.map(([k, v]) => k + v).join("");
}

/** Case-sensitive code-unit order, as Twilio's own libraries sort. */
function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The URL as given, and the same URL with the scheme's default port added or removed: Twilio may
 * sign either form, and its own libraries accept both. A URL with another port is also tried with
 * the port removed, since Twilio drops it when signing HTTPS voice callbacks.
 */
function urlVariants(url: string): string[] {
  const m = /^(https?):\/\/([^/?#]+)(.*)$/s.exec(url);
  if (m === null) return [url];
  const scheme = m[1]!;
  const authority = m[2]!;
  const rest = m[3]!;
  const port = scheme === "https" ? "443" : "80";
  if (authority.endsWith(`:${port}`)) return [url, `${scheme}://${authority.slice(0, -port.length - 1)}${rest}`];
  // An IPv6 host ends in `]`, so its colons never read as a port here.
  const other = /:\d+$/.exec(authority);
  if (other !== null) return [url, `${scheme}://${authority.slice(0, other.index)}${rest}`];
  return [url, `${scheme}://${authority}:${port}${rest}`];
}

/** Constant time for equal lengths; different lengths compare unequal without throwing. */
function stringsEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export interface TelnyxSignatureInput {
  /**
   * The raw request body, exactly as received. A re-serialised body never verifies. Give the bytes:
   * a decoded copy reads two different invalid UTF-8 bodies the same.
   */
  payload: string | Uint8Array;
  /** The `telnyx-signature-ed25519` header. */
  signatureHeader: string | null | undefined;
  /** The `telnyx-timestamp` header, in unix seconds. */
  timestampHeader: string | null | undefined;
  /** The account's public keys, each the base64 of 32 raw bytes; more than one while a key is rolled. */
  publicKeys: readonly string[];
  now: Date;
  /** Default 300 seconds, as Telnyx's own libraries; an integer from 0 to 86,400. Applies to the past and the future. */
  toleranceSeconds?: number;
}

const ED25519_PUBLIC_KEY = /^[A-Za-z0-9+/]{43}=$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;

const ED25519_P = 2n ** 255n - 19n;
/**
 * The y coordinates of Ed25519's eight small-order points: the identity (1), order 2 (p - 1),
 * order 4 (0) and order 8 (two values). A key on one of them verifies forged signatures on some
 * platforms (Node 24.2's crypto accepted one under the all-zero key), so it is never used.
 */
const SMALL_ORDER_Y = new Set([0n, 1n, ED25519_P - 1n, 0x5fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n, 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n]);

/** Whether a 32-byte Ed25519 key encodes a small-order point, in any form (sign bit set, y + p). */
function isSmallOrderKey(key: Buffer): boolean {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? key[i]! & 0x7f : key[i]!);
  return SMALL_ORDER_Y.has(y % ED25519_P);
}

export function verifyTelnyxSignature(input: TelnyxSignatureInput): SignatureCheck {
  // A string only: a regex test turns an array into its text, which would pass, and a key made from
  // it is one byte long. Such an entry is skipped, like any other key that is not one.
  const keys = input.publicKeys.filter((k) => typeof k === "string" && ED25519_PUBLIC_KEY.test(k) && !isSmallOrderKey(Buffer.from(k, "base64")));
  if (keys.length === 0) return { ok: false, reason: "no_secret" };
  const { signatureHeader: signature, timestampHeader: stamp } = input;
  if (signature === null || signature === undefined || signature === "" || stamp === null || stamp === undefined || stamp === "") {
    return { ok: false, reason: "missing_header" };
  }
  if (!ED25519_SIGNATURE.test(signature) || !/^\d{1,12}$/.test(stamp)) return { ok: false, reason: "malformed_header" };
  const timestamp = Number(stamp);
  const tolerance = input.toleranceSeconds ?? 300;
  // A NaN or infinite tolerance would compare false against every skew and turn the window off.
  if (!isIntegerIn(tolerance, 0, 86_400)) throw new EngineError("invalid_input", "toleranceSeconds must be an integer from 0 to 86,400");
  // Written so that an invalid `now` (a NaN skew) is refused too.
  if (!(Math.abs(Math.floor(input.now.getTime() / 1000) - timestamp) <= tolerance)) {
    return { ok: false, reason: "timestamp_out_of_tolerance" };
  }
  const signed = Buffer.concat([Buffer.from(`${stamp}|`), Buffer.from(input.payload)]);
  const bytes = Buffer.from(signature, "base64");
  for (const k of keys) {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(k, "base64").toString("base64url") }, format: "jwk" });
    if (verify(null, signed, key, bytes)) return { ok: true, timestamp };
  }
  return { ok: false, reason: "no_matching_signature" };
}
