// Public timestamp anchors for the ledger (PRV-9). A hash chain shows that no entry changed after
// later ones were written, but whoever holds the ledger could rebuild the whole chain. An anchor
// fixes the head in time with a third party: an RFC 3161 time-stamp authority signs a hash of it,
// and Sigstore's Rekor can also log it in public. An entry an anchor covers cannot change
// afterwards without the change showing. Nothing proves the chain was honest before it was anchored.
//
// `verifyAnchor` checks a proof offline against the entries it covers, with the authority's
// certificate chain (and Rekor's public key) supplied by the host. It is built on node:crypto and
// the small DER reader below: no ASN.1 or CMS library (ADR-3).
import { createHash, createPublicKey, verify, type KeyObject, type X509Certificate } from "node:crypto";

import type { AnchorProof, AuditEntry } from "../core/adapters.ts";
import { canonicalJson } from "../core/canonical.ts";
import { isObject } from "../core/shape.ts";
import { verifyChain } from "./ledger.ts";

// ---- the anchor payload -------------------------------------------------------------------------

/**
 * Every anchor payload starts with this line. It is not JSON, and a receipt is signed over canonical
 * JSON, so a head signed for a log can never verify as a receipt, whatever key signed it.
 */
export const ANCHOR_CONTEXT = "district-assurance/ledger-anchor/v1";

/** The bytes a time-stamp authority hashes and a log's entry is signed over, for one ledger head. */
export function anchorPayload(head: { seq: number; hash: string }): Uint8Array {
  return new TextEncoder().encode(`${ANCHOR_CONTEXT}\n${canonicalJson({ seq: head.seq, hash: head.hash })}`);
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

function isBase64(value: unknown): value is string {
  return typeof value === "string" && value.length % 4 === 0 && BASE64.test(value);
}

/** Whether a value is an `AnchorProof` with nothing else in it. */
export function isAnchorProof(value: unknown): value is AnchorProof {
  if (typeof value !== "object" || value === null) return false;
  const proof = value as Record<string, unknown>;
  const fields = proof.kind === "rekor" ? ["token", "entry"] : proof.kind === "rfc3161" ? ["token"] : null;
  return fields !== null && Object.keys(proof).length === fields.length + 1 && fields.every((field) => isBase64(proof[field]));
}

// ---- DER ----------------------------------------------------------------------------------------

export interface DerElement {
  tag: number;
  /** The whole element: tag, length and contents. */
  raw: Uint8Array;
  /** The contents. */
  value: Uint8Array;
}

/**
 * Reads the DER elements that fill `bytes` exactly, one level deep. One-byte tags and definite
 * lengths of up to four bytes; anything else, or a length past the end, throws a TypeError.
 */
export function readDer(bytes: Uint8Array): DerElement[] {
  const elements: DerElement[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (offset + 2 > bytes.length) throw new TypeError("DER: truncated header");
    const tag = bytes[offset]!;
    if ((tag & 0x1f) === 0x1f) throw new TypeError("DER: multi-byte tags are not supported");
    let length = bytes[offset + 1]!;
    let start = offset + 2;
    if (length >= 0x80) {
      const count = length - 0x80;
      if (count === 0 || count > 4 || start + count > bytes.length) throw new TypeError("DER: unsupported length");
      length = 0;
      for (const byte of bytes.subarray(start, start + count)) length = length * 256 + byte;
      start += count;
    }
    const end = start + length;
    if (end > bytes.length) throw new TypeError("DER: truncated contents");
    elements.push({ tag, raw: bytes.subarray(offset, end), value: bytes.subarray(start, end) });
    offset = end;
  }
  return elements;
}

const SEQUENCE = 0x30;
const SET = 0x31;
const OCTET_STRING = 0x04;
const OID = 0x06;
const GENERALIZED_TIME = 0x18;
const CONTEXT_0 = 0xa0;

function expectTag(element: DerElement | undefined, tag: number): DerElement {
  if (element?.tag !== tag) throw new TypeError(`DER: expected tag 0x${tag.toString(16)}`);
  return element;
}

/** The one element `bytes` holds, with the tag given. */
function readOne(bytes: Uint8Array, tag: number): DerElement {
  const [element, extra] = readDer(bytes);
  if (extra !== undefined) throw new TypeError("DER: trailing data");
  return expectTag(element, tag);
}

function children(element: DerElement | undefined, tag: number): DerElement[] {
  return readDer(expectTag(element, tag).value);
}

/** An object identifier, as the hex of its encoded contents (compared, never decoded). */
function oidHex(element: DerElement | undefined): string {
  return Buffer.from(expectTag(element, OID).value).toString("hex");
}

// Object identifiers, as the hex of their DER contents.
const SIGNED_DATA = "2a864886f70d010702"; // 1.2.840.113549.1.7.2
const TST_INFO = "2a864886f70d0109100104"; // 1.2.840.113549.1.9.16.1.4
const CONTENT_TYPE = "2a864886f70d010903"; // 1.2.840.113549.1.9.3
const MESSAGE_DIGEST = "2a864886f70d010904"; // 1.2.840.113549.1.9.4
const TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

const HASHES = new Map([
  ["608648016503040201", "sha256"],
  ["608648016503040202", "sha384"],
  ["608648016503040203", "sha512"],
]);

/** Signature algorithms to the hash they sign with; null means the signer's digest algorithm. */
const SIGNATURES = new Map<string, string | null>([
  ["2a864886f70d010101", null], // rsaEncryption
  ["2a864886f70d01010b", "sha256"], // sha256WithRSAEncryption
  ["2a864886f70d01010c", "sha384"],
  ["2a864886f70d01010d", "sha512"],
  ["2a8648ce3d040302", "sha256"], // ecdsa-with-SHA256
  ["2a8648ce3d040303", "sha384"],
  ["2a8648ce3d040304", "sha512"],
]);

/** The hash an AlgorithmIdentifier names. */
function hashOf(algorithm: DerElement | undefined): string {
  const name = HASHES.get(oidHex(children(algorithm, SEQUENCE)[0]));
  if (name === undefined) throw new TypeError("unsupported digest algorithm");
  return name;
}

/** A GeneralizedTime (`YYYYMMDDHHMMSS[.f]Z`) as an ISO 8601 string. */
function generalizedTime(element: DerElement | undefined): string {
  const text = Buffer.from(expectTag(element, GENERALIZED_TIME).value).toString("latin1");
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(text);
  if (m === null) throw new TypeError("malformed GeneralizedTime");
  return new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`).toISOString();
}

// ---- RFC 3161 time-stamp tokens -----------------------------------------------------------------

interface ParsedToken {
  imprintHash: string;
  imprint: Uint8Array;
  time: string;
  /** The signed attributes as signed: a SET, not the implicit [0] they are stored as. */
  signedAttributes: Buffer;
  signatureHash: string;
  signature: Uint8Array;
}

/**
 * Reads a TimeStampToken: a CMS ContentInfo holding SignedData whose content is a TSTInfo and whose
 * one signer signed the content type and the TSTInfo's digest (RFC 3161, RFC 5652).
 */
function parseToken(der: Uint8Array): ParsedToken {
  const [contentType, wrapped] = readDer(readOne(der, SEQUENCE).value);
  if (oidHex(contentType) !== SIGNED_DATA) throw new TypeError("not SignedData");
  const signedData = children(readOne(expectTag(wrapped, CONTEXT_0).value, SEQUENCE), SEQUENCE);
  const [eContentType, eContent] = children(signedData[2], SEQUENCE);
  if (oidHex(eContentType) !== TST_INFO) throw new TypeError("not a TSTInfo");
  const tstInfo = readOne(expectTag(eContent, CONTEXT_0).value, OCTET_STRING).value;
  const [, , messageImprint, , genTime] = children(readOne(tstInfo, SEQUENCE), SEQUENCE);
  const [imprintAlgorithm, imprint] = children(messageImprint, SEQUENCE);
  const [signer, otherSigner] = children(signedData.at(-1), SET);
  if (otherSigner !== undefined) throw new TypeError("a token has one signer");
  const [, , digestAlgorithm, attributes, signatureAlgorithm, signature] = children(signer, SEQUENCE);
  const digest = hashOf(digestAlgorithm);
  const values = new Map<string, DerElement | undefined>();
  for (const attribute of children(attributes, CONTEXT_0)) {
    const [type, set] = children(attribute, SEQUENCE);
    values.set(oidHex(type), children(set, SET)[0]);
  }
  if (oidHex(values.get(CONTENT_TYPE)) !== TST_INFO) throw new TypeError("the signed content type is not a TSTInfo");
  const contentDigest = createHash(digest).update(tstInfo).digest();
  if (!contentDigest.equals(expectTag(values.get(MESSAGE_DIGEST), OCTET_STRING).value)) throw new TypeError("the signed digest is not the TSTInfo's");
  const signatureHash = SIGNATURES.get(oidHex(children(signatureAlgorithm, SEQUENCE)[0]));
  if (signatureHash === undefined) throw new TypeError("unsupported signature algorithm");
  const signedAttributes = Buffer.from(attributes!.raw);
  signedAttributes[0] = SET;
  return {
    imprintHash: hashOf(imprintAlgorithm),
    imprint: expectTag(imprint, OCTET_STRING).value,
    time: generalizedTime(genTime),
    signedAttributes,
    signatureHash: signatureHash ?? digest,
    signature: expectTag(signature, OCTET_STRING).value,
  };
}

const BASIC_CONSTRAINTS = "551d13"; // 2.5.29.19
const BOOLEAN = 0x01;
const INTEGER = 0x02;

/**
 * What a certificate may issue (RFC 5280 4.2.1.3 and 4.2.1.9): a CA only with basicConstraints
 * cA true, then at most `pathLen` CA certificates below it (null: no limit). Node exposes
 * neither, so the extensions are read from the DER; keyCertSign is OpenSSL's, in checkIssued.
 */
function issuingLimit(cert: X509Certificate): { pathLen: number | null } | null {
  // The certificate already parsed as X.509, and OpenSSL refuses an issuer whose extensions do not
  // read before this is reached; a throw here would still fail closed, in checkTimestamp.
  const tbs = children(readDer(readOne(cert.raw, SEQUENCE).value)[0], SEQUENCE);
  const wrapped = tbs.find((e) => e.tag === 0xa3);
  if (wrapped === undefined) return null;
  let limit: { pathLen: number | null } | null = null;
  for (const extension of children(readOne(wrapped.value, SEQUENCE), SEQUENCE)) {
    const parts = children(extension, SEQUENCE);
    const id = oidHex(parts[0]);
    const value = expectTag(parts.at(-1), OCTET_STRING).value;
    if (id === BASIC_CONSTRAINTS) {
      // cA is DEFAULT FALSE, so a CA's is present and true; pathLenConstraint follows when set.
      const [ca, pathLen] = readDer(readOne(value, SEQUENCE).value);
      if (ca?.tag === BOOLEAN && ca.value[0] === 0xff) {
        limit = { pathLen: pathLen === undefined ? null : expectTag(pathLen, INTEGER).value.reduce((n, byte) => n * 256 + byte, 0) };
      }
    }
  }
  // keyCertSign, when the issuer has a keyUsage extension, is checked by OpenSSL in checkIssued.
  return limit;
}

/**
 * Every certificate valid at the time, each issued and signed by the next, the first for
 * time-stamping, and every one after the first a CA allowed to issue what is below it (cA true,
 * keyCertSign when keyUsage is present, its pathLen not exceeded). The last is trusted as given.
 */
function chainValid(chain: readonly X509Certificate[], at: number): boolean {
  // Node gives no extended key usage list (undefined) when a certificate has none.
  const usage = (chain[0]!.keyUsage as string[] | undefined) ?? [];
  if (!usage.includes(TIME_STAMPING)) return false;
  return chain.every((cert, i) => {
    const issuer = chain[i + 1];
    const current = cert.validFromDate.getTime() <= at && at <= cert.validToDate.getTime();
    // The CAs below this one in the chain: every certificate between it and the leaf.
    const limit = i === 0 ? { pathLen: null } : issuingLimit(cert);
    const allowed = limit !== null && (limit.pathLen === null || i - 1 <= limit.pathLen);
    return current && allowed && (issuer === undefined || (cert.checkIssued(issuer) && cert.verify(issuer.publicKey)));
  });
}

export type TimestampCheck = { ok: true; time: string } | { ok: false; reason: "token" | "certificate" | "imprint" };

/**
 * Checks an RFC 3161 time-stamp token (base64 DER) over `payload`, against the authority's
 * certificate chain as the host has it (its signing certificate first). Certificates inside the
 * token are ignored. Never throws.
 */
export function checkTimestamp(token: string, payload: Uint8Array, chain: readonly X509Certificate[]): TimestampCheck {
  if (chain.length === 0) return { ok: false, reason: "certificate" };
  try {
    const parsed = parseToken(Buffer.from(token, "base64"));
    if (!verify(parsed.signatureHash, parsed.signedAttributes, chain[0]!.publicKey, parsed.signature)) return { ok: false, reason: "token" };
    if (!chainValid(chain, Date.parse(parsed.time))) return { ok: false, reason: "certificate" };
    if (!createHash(parsed.imprintHash).update(payload).digest().equals(parsed.imprint)) return { ok: false, reason: "imprint" };
    return { ok: true, time: parsed.time };
  } catch {
    return { ok: false, reason: "token" };
  }
}

// ---- Rekor v2 entries ---------------------------------------------------------------------------

/** A Rekor log as the host trusts it. */
export interface RekorLog {
  /** The log's public key: Ed25519, or ECDSA P-256. */
  key: KeyObject;
  /** The log's origin, the first line of its checkpoints and the name its signatures carry (for example `log2025-1.rekor.sigstore.dev`). */
  origin: string;
}

/** The parts of a Rekor v2 TransparencyLogEntry this check reads (the protobuf JSON form). */
interface RekorEntryJson {
  canonicalizedBody: string;
  inclusionProof: { logIndex: string; treeSize: string; rootHash: string; hashes: string[]; checkpoint: { envelope: string } };
}

interface HashedRekordJson {
  kind: string;
  spec: { hashedRekordV002: { data: { algorithm: string; digest: string }; signature: { content: string; verifier: { publicKey: { rawBytes: string } } } } };
}

const sha256 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
};

/** The tree root an RFC 9162 inclusion proof leads to, or null when its shape does not fit the tree. */
function inclusionRoot(leaf: Buffer, index: bigint, size: bigint, path: readonly Buffer[]): Buffer | null {
  if (index < 0n || index >= size) return null;
  let fn = index;
  let sn = size - 1n;
  let root = leaf;
  for (const sibling of path) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      root = sha256(Buffer.from([1]), sibling, root);
      // fn equals sn here and is not 0, so this stops.
      while ((fn & 1n) === 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      root = sha256(Buffer.from([1]), root, sibling);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n ? root : null;
}

/** The signed-note key id and the hash a log key signs with: C2SP's for Ed25519, the key's SPKI hash for ECDSA, as Rekor does. */
function noteKey(log: RekorLog): { id: Buffer; hash: string | null } {
  const spki = log.key.export({ type: "spki", format: "der" });
  if (log.key.asymmetricKeyType === "ed25519") return { id: sha256(Buffer.from(`${log.origin}\n\u0001`), spki.subarray(12)).subarray(0, 4), hash: null };
  if (log.key.asymmetricKeyType === "ec") return { id: sha256(spki).subarray(0, 4), hash: "sha256" };
  throw new TypeError("a Rekor log key is Ed25519 or ECDSA");
}

/** A signed checkpoint (C2SP signed note) for this tree, signed by the log. */
function checkpointValid(envelope: string, log: RekorLog, size: bigint, root: Buffer): boolean {
  const end = envelope.indexOf("\n\n");
  const text = envelope.slice(0, end + 1);
  if (!text.startsWith(`${log.origin}\n${size}\n${root.toString("base64")}\n`)) return false;
  const key = noteKey(log);
  // A signature line starts with U+2014 (EM DASH), a space and the key's name.
  const prefix = `${String.fromCharCode(0x2014)} ${log.origin} `;
  return envelope
    .slice(end + 2)
    .split("\n")
    .some((line) => {
      if (!line.startsWith(prefix)) return false;
      const signature = Buffer.from(line.slice(prefix.length), "base64");
      return signature.subarray(0, 4).equals(key.id) && verify(key.hash, Buffer.from(text), log.key, signature.subarray(4));
    });
}

export type LogCheck = { ok: true; logIndex: number } | { ok: false; reason: "log" };

/**
 * Checks a Rekor v2 entry (base64 of the JSON Rekor answered): a `hashedrekord` of `payload`, its
 * signature by the key it names, its inclusion proof, and the log's signed checkpoint for that
 * tree. Never throws.
 */
export function checkRekorEntry(entry: string, payload: Uint8Array, log: RekorLog): LogCheck {
  try {
    const parsed = JSON.parse(Buffer.from(entry, "base64").toString("utf8")) as RekorEntryJson;
    const body = Buffer.from(parsed.canonicalizedBody, "base64");
    const rekord = JSON.parse(body.toString("utf8")) as HashedRekordJson;
    const spec = rekord.spec.hashedRekordV002;
    const signer = createPublicKey({ key: Buffer.from(spec.signature.verifier.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
    const proof = parsed.inclusionProof;
    const size = BigInt(proof.treeSize);
    const root = inclusionRoot(sha256(Buffer.from([0]), body), BigInt(proof.logIndex), size, proof.hashes.map((h) => Buffer.from(h, "base64")));
    const valid =
      rekord.kind === "hashedrekord" &&
      spec.data.algorithm === "SHA2_256" &&
      spec.data.digest === sha256(payload).toString("base64") &&
      verify("sha256", payload, signer, Buffer.from(spec.signature.content, "base64")) &&
      root !== null &&
      root.equals(Buffer.from(proof.rootHash, "base64")) &&
      checkpointValid(proof.checkpoint.envelope, log, size, root);
    return valid ? { ok: true, logIndex: Number(proof.logIndex) } : { ok: false, reason: "log" };
  } catch {
    return { ok: false, reason: "log" };
  }
}

// ---- verifying an anchor ------------------------------------------------------------------------

/** What the host trusts, supplied with the check: nothing is fetched. */
export interface AnchorTrust {
  /** The time-stamp authority's certificate chain, its signing certificate first. The last one is trusted as given. */
  tsa: readonly X509Certificate[];
  /** Rekor's log, needed for `rekor` proofs. */
  rekor?: RekorLog;
}

export type AnchorFailure = "malformed" | "chain" | "token" | "certificate" | "imprint" | "log";

export type AnchorCheck =
  | { ok: true; seq: number; hash: string; time: string; logIndex: number | null }
  | { ok: false; reason: AnchorFailure };

/**
 * Checks a `ledger.anchored` entry offline against the entries it covers (from seq 1, at least up
 * to the seq it covers): the chain up to that seq, then the time-stamp token over that head, then,
 * for a Rekor proof, the log entry. `imprint` means the token is for another head: the chain was
 * changed or rebuilt after it was anchored. Never throws.
 */
export function verifyAnchor(anchored: AuditEntry, entries: readonly AuditEntry[], trust: AnchorTrust): AnchorCheck {
  // What a verifier is handed is not trusted: anything that is not an entry, a list or a trust is malformed.
  const detail: unknown = isObject(anchored) ? anchored.detail : undefined;
  if (!isObject(detail) || !Array.isArray(entries) || !isObject(trust) || !Array.isArray(trust.tsa)) return { ok: false, reason: "malformed" };
  const { seq, proof } = detail;
  if (anchored.event !== "ledger.anchored" || !Number.isSafeInteger(seq) || (seq as number) < 1 || !isAnchorProof(proof)) {
    return { ok: false, reason: "malformed" };
  }
  const chain = verifyChain(entries.slice(0, seq as number));
  if (!chain.ok || chain.head.seq !== seq) return { ok: false, reason: "chain" };
  const payload = anchorPayload(chain.head);
  const stamp = checkTimestamp(proof.token, payload, trust.tsa);
  if (!stamp.ok) return stamp;
  let logIndex: number | null = null;
  if (proof.kind === "rekor") {
    const logged: LogCheck = trust.rekor === undefined ? { ok: false, reason: "log" } : checkRekorEntry(proof.entry, payload, trust.rekor);
    if (!logged.ok) return logged;
    logIndex = logged.logIndex;
  }
  return { ok: true, seq: chain.head.seq, hash: chain.head.hash, time: stamp.time, logIndex };
}
