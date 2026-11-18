// Signed call receipts: what was verified and how, what was filed (as a fingerprint), what was
// paid (the provider's reference), what was consented to, and the ledger head at the end of the
// call. No content and no secrets. Signed with ES256 over the canonical JSON of the body, so
// anyone holding the public key can check that not one byte changed. The same signing serves
// Gate's access grants (`signDocument`, `verifyDocument`).
import { createPrivateKey, createPublicKey, sign, verify, type JsonWebKey, type KeyObject } from "node:crypto";

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
  payments: Array<{ paymentId: string; status: string; amountMinor: number; currency: string; mode: string; providerRef: string }>;
  consents: Array<{ purpose: string; wordingVersion: string; wordingDigest: string; answer: "yes" | "no" }>;
  ledger: { seq: number; hash: string };
}

/**
 * A body signed with ES256 over its canonical JSON: receipts, and Gate's access grants. Anyone
 * holding the public key, in any language, can check that not one byte changed.
 */
export interface SignedDocument<B> {
  body: B;
  alg: "ES256";
  kid: string;
  /** base64url of the 64-byte P1363 signature. */
  signature: string;
}

export type SignedReceipt = SignedDocument<ReceiptBody>;

/** The exact bytes that are signed: the canonical JSON of the body, as UTF-8. */
export function canonicalPayload(body: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(body));
}

export async function signDocument<B>(signer: ReceiptSigner, body: B): Promise<SignedDocument<B>> {
  const signature = await signer.sign(canonicalPayload(body));
  return { body, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
}

/**
 * Checks a signed document against a key set. False for an unknown `kid`, a wrong algorithm, a
 * malformed signature, a body canonical JSON refuses, or any change to the body. Never throws.
 */
export function verifyDocument(document: SignedDocument<unknown>, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  if (document.alg !== "ES256") return false;
  const jwk = keys.find((k) => k.kid === document.kid);
  if (jwk === undefined) return false;
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" });
    const signature = Buffer.from(document.signature, "base64url");
    if (signature.length !== 64) return false;
    return verify("sha256", canonicalPayload(document.body), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

/** The exact bytes of a receipt that are signed. */
export function receiptPayload(body: ReceiptBody): Uint8Array {
  return canonicalPayload(body);
}

export function receiptDigest(body: ReceiptBody): string {
  return sha256Hex(receiptPayload(body));
}

export function signReceipt(signer: ReceiptSigner, body: ReceiptBody): Promise<SignedReceipt> {
  return signDocument(signer, body);
}

/** Checks a receipt against a key set (`verifyDocument`). Never throws on bad input. */
export function verifyReceipt(receipt: SignedReceipt, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  return verifyDocument(receipt, keys);
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
