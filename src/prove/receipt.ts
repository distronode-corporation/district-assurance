// Signed call receipts: what was verified and how, what was filed (as a fingerprint), what was
// paid (the provider's reference), what was consented to, and the ledger head at the end of the
// call. No content and no secrets. Signed with ES256 over the canonical JSON of the body, so
// anyone holding the public key can check that not one byte changed.
import { createPrivateKey, createPublicKey, randomBytes, sign, verify, type JsonWebKey, type KeyObject } from "node:crypto";

import type { ReceiptSigner } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { sha256Hex } from "../core/hash.ts";
import type { AssuranceLevel, FactorKind } from "../core/policy.ts";

export interface ReceiptBody {
  v: 1;
  receiptId: string;
  callId: string;
  workspaceId: string;
  startedAt: string;
  endedAt: string;
  issuedAt: string;
  verification: { level: AssuranceLevel; methods: FactorKind[] };
  records: Array<{ recordId: string; formId: string; digest: string }>;
  payments: Array<{ paymentId: string; status: string; amountMinor: number; currency: string; providerRef: string }>;
  consents: Array<{ purpose: string; wordingVersion: string; wordingDigest: string; answer: "yes" | "no" }>;
  ledger: { seq: number; hash: string };
}

export interface SignedReceipt {
  body: ReceiptBody;
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature. */
  signature: string;
}

/** The exact bytes that are signed. */
export function receiptPayload(body: ReceiptBody): Uint8Array {
  return new TextEncoder().encode(canonicalJson(body));
}

export function receiptDigest(body: ReceiptBody): string {
  return sha256Hex(receiptPayload(body));
}

export async function signReceipt(signer: ReceiptSigner, body: ReceiptBody): Promise<SignedReceipt> {
  const signature = await signer.sign(receiptPayload(body));
  return { body, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
}

/**
 * Checks a receipt against a key set. False for an unknown `kid`, a wrong algorithm, a malformed
 * signature or any change to the body. Never throws on bad input.
 */
export function verifyReceipt(receipt: SignedReceipt, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  if (receipt.alg !== "ES256") return false;
  const jwk = keys.find((k) => k.kid === receipt.kid);
  if (jwk === undefined) return false;
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(receipt.signature, "base64url");
    if (signature.length !== 64) return false;
    return verify("sha256", receiptPayload(receipt.body), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/** A signer over a P-256 private key the host holds (a PEM string or a private JWK). */
export function keyPairSigner(keyId: string, privateKey: string | JsonWebKey): ReceiptSigner {
  const key: KeyObject =
    typeof privateKey === "string" ? createPrivateKey(privateKey) : createPrivateKey({ key: privateKey, format: "jwk" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new TypeError("keyPairSigner needs a P-256 private key");
  }
  const publicJwk = createPublicKey(key).export({ format: "jwk" });
  return {
    keyId,
    algorithm: "ES256",
    sign: async (payload) => new Uint8Array(sign("sha256", payload, { key, dsaEncoding: "ieee-p1363" })),
    publicJwk: () => ({ ...publicJwk, kid: keyId, alg: "ES256", use: "sig" }) as JsonWebKey,
  };
}

/** A receipt link token: 32 random bytes, base64url, 43 characters. */
const LINK_TOKEN = /^[A-Za-z0-9_-]{43}$/;

/**
 * A new capability token for a link to one receipt: 256 random bits, base64url. Hand the token
 * out once, in the link, and store only `hash`: whoever holds the token can read the receipt, and
 * a stored hash cannot be turned back into a link.
 */
export function newReceiptLinkToken(random: (size: number) => Uint8Array = randomBytes): { token: string; hash: string } {
  const bytes = random(32);
  if (bytes.length !== 32) throw new RangeError("a receipt link token needs 32 random bytes");
  const token = Buffer.from(bytes).toString("base64url");
  return { token, hash: sha256Hex(`receipt-link:${token}`) };
}

/** The stored hash of a receipt link token, or null for a string that is not one. Never throws. */
export function receiptLinkTokenHash(token: string): string | null {
  return LINK_TOKEN.test(token) ? sha256Hex(`receipt-link:${token}`) : null;
}
