// Signed call receipts: what was verified and how, what was filed (as a fingerprint), what was
// paid (the provider's reference), what was consented to, and the ledger head at the end of the
// call. No content and no secrets. Signed with ES256 over the canonical JSON of the body, so
// anyone holding the public key can check that not one byte changed. The same signing serves
// Gate's access grants (`signDocument`, `verifyDocument`).
import { createPrivateKey, createPublicKey, sign, verify, type JsonWebKey, type KeyObject } from "node:crypto";

import type { ReceiptSigner } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
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
  /**
   * `policyVersion` and `configRevision` name the policy and the FlowConfig revision that judged the
   * call's last finished verification; both are absent when no verification finished.
   */
  verification: { level: AssuranceLevel; methods: FactorKind[]; policyVersion?: string; configRevision?: string };
  records: Array<{ recordId: string; formId: string; digest: string }>;
  payments: Array<{ paymentId: string; status: string; amountMinor: number; currency: string; mode: string; providerRef: string }>;
  consents: Array<{ purpose: string; wordingVersion: string; wordingDigest: string; answer: "yes" | "no" }>;
  /**
   * The call's web sign-in step-up tokens as the call ended: `issued` ones may still be exchanged
   * until `expiresAt`, so a later `stepup.exchanged` or `stepup.refused` entry names one of these.
   * Absent on a call that issued none, so the format stays at `v: 1`.
   */
  stepUp?: Array<{ tokenId: string; expiresAt: string; status: string }>;
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
  if (signature.byteLength !== 64) throw new EngineError("invalid_input", `the signer returned ${signature.byteLength} bytes, not a 64-byte P1363 signature`);
  return { body, alg: signer.algorithm, kid: signer.keyId, signature: Buffer.from(signature).toString("base64url") };
}

/**
 * Checks a signed document against a key set. False for an unknown `kid`, a wrong algorithm, a
 * malformed signature, a body canonical JSON refuses, or any change to the body. Never throws.
 */
export function verifyDocument(document: SignedDocument<unknown>, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  // A parsed document can be anything: check the envelope before reading it.
  if (typeof document !== "object" || document === null || document.alg !== "ES256" || typeof document.signature !== "string") return false;
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

/**
 * Signs a receipt body. The signer must keep its contract: an ES256 signature in IEEE P1363 form,
 * exactly 64 bytes (`derToP1363` converts the DER most key stores return). Any other length is
 * refused (`invalid_input`, in `signDocument`), and so is a signature that does not verify against
 * the signer's own public key (a wrong key, a DER signature that happens to be 64 bytes, bytes that
 * are not a signature): no receipt is issued that cannot verify.
 */
export async function signReceipt(signer: ReceiptSigner, body: ReceiptBody): Promise<SignedReceipt> {
  const receipt = await signDocument(signer, body);
  if (!verifyReceipt(receipt, [{ ...signer.publicJwk(), kid: signer.keyId }])) {
    throw new EngineError("invalid_input", "the receipt signer's signature does not verify against its own public key");
  }
  return receipt;
}

/** Checks a receipt against a key set (`verifyDocument`). Never throws on bad input. */
export function verifyReceipt(receipt: SignedReceipt, keys: ReadonlyArray<JsonWebKey & { kid?: string }>): boolean {
  return verifyDocument(receipt, keys);
}

/**
 * Converts a DER ECDSA P-256 signature (`SEQUENCE { r INTEGER, s INTEGER }`, what most key
 * management services return) to the 64-byte IEEE P1363 form (`r || s`) a `ReceiptSigner` must
 * return. Strict: anything that is not a minimal DER encoding of two positive integers of at most
 * 32 bytes, with nothing after it, throws a TypeError.
 */
export function derToP1363(der: Uint8Array): Uint8Array {
  const malformed = (): never => {
    throw new TypeError("derToP1363 needs a DER-encoded ECDSA P-256 signature");
  };
  // Short-form lengths only: a P-256 signature is at most 72 bytes, so DER never uses the long form.
  if (der[0] !== 0x30 || der[1] !== der.length - 2) malformed();
  const out = new Uint8Array(64);
  let at = 2;
  for (const offset of [0, 32]) {
    const length = der[at + 1] ?? 0;
    const value = der.subarray(at + 2, at + 2 + length);
    if (der[at] !== 0x02 || length === 0 || value.length !== length) malformed();
    // Positive and minimal: no sign bit, and a leading zero only in front of one.
    if ((value[0]! & 0x80) !== 0 || (value[0] === 0 && (length === 1 || (value[1]! & 0x80) === 0))) malformed();
    const magnitude = value[0] === 0 ? value.subarray(1) : value;
    if (magnitude.length > 32) malformed();
    out.set(magnitude, offset + 32 - magnitude.length);
    at += 2 + length;
  }
  if (at !== der.length) malformed();
  return out;
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
