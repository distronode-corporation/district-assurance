// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

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
import { verifyLedgerCheckpoint, type LedgerCheckpointRef } from "./checkpoint.ts";
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

/**
 * Whether a value is an `AnchorProof` with nothing else in it: exactly its own enumerable keys, so
 * nothing inherited counts as a field (a prototype's token is not this proof's).
 */
export function isAnchorProof(value: unknown): value is AnchorProof {
  if (typeof value !== "object" || value === null) return false;
  const keys = Object.keys(value);
  const proof = value as Record<string, unknown>;
  const kind = keys.includes("kind") ? proof.kind : undefined;
  const fields = kind === "rekor" ? ["token", "entry"] : kind === "rfc3161" ? ["token"] : null;
  return fields !== null && keys.length === fields.length + 1 && fields.every((field) => keys.includes(field) && isBase64(proof[field]));
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
const INTEGER = 0x02;
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

/** An element with this tag around `parts`, in DER (definite, minimal length). */
function encode(tag: number, ...parts: Uint8Array[]): Buffer {
  const body = Buffer.concat(parts);
  const size: number[] = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) size.unshift(n % 256);
  return Buffer.concat([Buffer.from(body.length < 0x80 ? [tag, body.length] : [tag, 0x80 | size.length, ...size]), body]);
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
const SIGNING_CERTIFICATE = "2a864886f70d010910020c"; // 1.2.840.113549.1.9.16.2.12
const SIGNING_CERTIFICATE_V2 = "2a864886f70d010910022f"; // 1.2.840.113549.1.9.16.2.47
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

/** An ESSCertID or ESSCertIDv2: the hash of the certificate it names and, when present, the IssuerSerial (as encoded). */
interface EssCertId {
  hash: string;
  certHash: Uint8Array;
  issuerSerial: Uint8Array | null;
}

/**
 * The first ESSCertID of a SigningCertificate attribute value (RFC 2634: a SHA-1 hash) or, for
 * `v2`, of a SigningCertificateV2 (RFC 5035: hashAlgorithm DEFAULT SHA-256, written out only
 * when it is another). The first names the signer; any others are its chain. A hash this reader
 * does not know throws: a token whose signer it cannot tell is refused.
 */
function firstCertId(value: DerElement | undefined, v2: boolean): EssCertId {
  const [certs] = children(value, SEQUENCE);
  const parts = children(children(certs, SEQUENCE)[0], SEQUENCE);
  const hash = !v2 ? "sha1" : parts[0]?.tag === SEQUENCE ? hashOf(parts.shift()) : "sha256";
  const [certHash, issuerSerial, extra] = parts;
  if (extra !== undefined) throw new TypeError("ESSCertID: trailing data");
  return { hash, certHash: expectTag(certHash, OCTET_STRING).value, issuerSerial: issuerSerial === undefined ? null : expectTag(issuerSerial, SEQUENCE).raw };
}

/**
 * Whether an ESSCertID names this certificate: its hash over the certificate's DER and, when it
 * has an IssuerSerial, the certificate's issuer (as one directoryName) and serial, byte for byte.
 */
function namesCertificate(id: EssCertId, cert: X509Certificate): boolean {
  if (!createHash(id.hash).update(cert.raw).digest().equals(id.certHash)) return false;
  if (id.issuerSerial === null) return true;
  const tbs = children(readDer(readOne(cert.raw, SEQUENCE).value)[0], SEQUENCE);
  // The serial is the TBSCertificate's first INTEGER (a version sits inside [0]); the issuer is two after it.
  const at = tbs.findIndex((e) => e.tag === INTEGER);
  return encode(SEQUENCE, encode(SEQUENCE, encode(0xa4, tbs[at + 2]!.raw)), tbs[at]!.raw).equals(id.issuerSerial);
}

interface ParsedToken {
  imprintHash: string;
  imprint: Uint8Array;
  time: string;
  /** The TSTInfo's nonce (the INTEGER's contents), when it has one. */
  nonce: Uint8Array | null;
  /** The first ESSCertID of each SigningCertificate and SigningCertificateV2 attribute: at least one. */
  signerIds: EssCertId[];
  /** The signed attributes as signed: a SET, not the implicit [0] they are stored as. */
  signedAttributes: Buffer;
  signatureHash: string;
  signature: Uint8Array;
}

/**
 * Reads a TimeStampToken: a CMS ContentInfo holding SignedData whose content is a TSTInfo and whose
 * one signer signed the content type, the TSTInfo's digest and the certificate it signs with, as a
 * SigningCertificate or SigningCertificateV2 attribute (RFC 3161 2.4.1, RFC 5816, RFC 5652).
 */
function parseToken(der: Uint8Array): ParsedToken {
  const [contentType, wrapped] = readDer(readOne(der, SEQUENCE).value);
  if (oidHex(contentType) !== SIGNED_DATA) throw new TypeError("not SignedData");
  const signedData = children(readOne(expectTag(wrapped, CONTEXT_0).value, SEQUENCE), SEQUENCE);
  const [eContentType, eContent] = children(signedData[2], SEQUENCE);
  if (oidHex(eContentType) !== TST_INFO) throw new TypeError("not a TSTInfo");
  const tstInfo = readOne(expectTag(eContent, CONTEXT_0).value, OCTET_STRING).value;
  const [, , messageImprint, , genTime, ...optional] = children(readOne(tstInfo, SEQUENCE), SEQUENCE);
  // After genTime: accuracy (a SEQUENCE), ordering (a BOOLEAN), the nonce, tsa [0], extensions [1]. Only the nonce is an INTEGER.
  const nonce = optional.find((e) => e.tag === INTEGER)?.value ?? null;
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
  const signerIds: EssCertId[] = [];
  for (const [id, v2] of [[SIGNING_CERTIFICATE, false], [SIGNING_CERTIFICATE_V2, true]] as const) {
    if (values.has(id)) signerIds.push(firstCertId(values.get(id), v2));
  }
  if (signerIds.length === 0) throw new TypeError("the token names no signing certificate");
  const signatureHash = SIGNATURES.get(oidHex(children(signatureAlgorithm, SEQUENCE)[0]));
  if (signatureHash === undefined) throw new TypeError("unsupported signature algorithm");
  const signedAttributes = Buffer.from(attributes!.raw);
  signedAttributes[0] = SET;
  return {
    imprintHash: hashOf(imprintAlgorithm),
    imprint: expectTag(imprint, OCTET_STRING).value,
    time: generalizedTime(genTime),
    nonce,
    signerIds,
    signedAttributes,
    signatureHash: signatureHash ?? digest,
    signature: expectTag(signature, OCTET_STRING).value,
  };
}

const BASIC_CONSTRAINTS = "551d13"; // 2.5.29.19
const BOOLEAN = 0x01;

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
 * token are ignored. The token's signed SigningCertificate (or V2) must name that signing
 * certificate: `certificate` when it names another. Never throws.
 */
export function checkTimestamp(token: string, payload: Uint8Array, chain: readonly X509Certificate[]): TimestampCheck {
  if (chain.length === 0) return { ok: false, reason: "certificate" };
  try {
    const parsed = parseToken(Buffer.from(token, "base64"));
    if (!verify(parsed.signatureHash, parsed.signedAttributes, chain[0]!.publicKey, parsed.signature)) return { ok: false, reason: "token" };
    if (!parsed.signerIds.every((id) => namesCertificate(id, chain[0]!))) return { ok: false, reason: "certificate" };
    if (!chainValid(chain, Date.parse(parsed.time))) return { ok: false, reason: "certificate" };
    if (!createHash(parsed.imprintHash).update(payload).digest().equals(parsed.imprint)) return { ok: false, reason: "imprint" };
    return { ok: true, time: parsed.time };
  } catch {
    return { ok: false, reason: "token" };
  }
}

/**
 * What a time-stamp token says about the request it answers: the imprint's hash algorithm and the
 * nonce (the INTEGER's contents, null when it has none). Null when the token does not read. It
 * checks nothing (`checkTimestamp` does); a host that has just asked compares these with its
 * request. An archived token has no request to compare with, so `verifyAnchor` does not read them.
 */
export function timestampTokenFields(token: string): { imprintHash: string; nonce: Uint8Array | null } | null {
  try {
    const parsed = parseToken(Buffer.from(token, "base64"));
    return { imprintHash: parsed.imprintHash, nonce: parsed.nonce };
  } catch {
    return null;
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

/**
 * The parts of a Rekor v2 TransparencyLogEntry this check reads (the protobuf JSON form). The
 * inclusion proof's own index, size and root repeat the top-level index and the signed checkpoint;
 * the copies are optional, and when present must agree. Proto3 JSON leaves out a default value, so
 * a missing index is 0 and a missing list of hashes is empty.
 */
interface RekorEntryJson {
  logIndex?: string;
  canonicalizedBody: string;
  inclusionProof: { logIndex?: string; treeSize?: string; rootHash?: string; hashes?: string[]; checkpoint: { envelope: string } };
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

/** A decimal with no sign, no spaces and no leading zero: how int64 values (as strings) and checkpoint sizes are written. */
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

/** A proto3 JSON int64 that is not negative, as a string; a default 0 is left out of proto3 JSON. */
function uint64(value: unknown): bigint {
  if (value === undefined) return 0n;
  if (typeof value !== "string" || !DECIMAL.test(value)) throw new TypeError("not a decimal int64");
  return BigInt(value);
}

/**
 * The tree a signed checkpoint (C2SP signed note) describes, when the log signed it: its first
 * lines are the origin, the tree size in decimal and the root hash in base64 (32 bytes).
 */
function readCheckpoint(envelope: string, log: RekorLog): { size: bigint; root: Buffer } | null {
  const end = envelope.indexOf("\n\n");
  const text = envelope.slice(0, end + 1);
  const lines = /^([^\n]*)\n(0|[1-9][0-9]*)\n([A-Za-z0-9+/]{43}=)\n/.exec(text);
  if (lines === null || lines[1] !== log.origin) return null;
  const key = noteKey(log);
  // A signature line starts with U+2014 (EM DASH), a space and the key's name.
  const prefix = `${String.fromCharCode(0x2014)} ${log.origin} `;
  const signed = envelope
    .slice(end + 2)
    .split("\n")
    .some((line) => {
      if (!line.startsWith(prefix)) return false;
      const signature = Buffer.from(line.slice(prefix.length), "base64");
      return signature.subarray(0, 4).equals(key.id) && verify(key.hash, Buffer.from(text), log.key, signature.subarray(4));
    });
  return signed ? { size: BigInt(lines[2]!), root: Buffer.from(lines[3]!, "base64") } : null;
}

export type LogCheck = { ok: true; logIndex: number } | { ok: false; reason: "log" };

/**
 * Checks a Rekor v2 entry (base64 of the JSON Rekor answered): a `hashedrekord` of `payload`, its
 * signature by the key it names, its inclusion proof, and the log's signed checkpoint for that
 * tree. A log index above Number.MAX_SAFE_INTEGER is refused. Never throws.
 */
export function checkRekorEntry(entry: string, payload: Uint8Array, log: RekorLog): LogCheck {
  try {
    const parsed = JSON.parse(Buffer.from(entry, "base64").toString("utf8")) as RekorEntryJson;
    const body = Buffer.from(parsed.canonicalizedBody, "base64");
    const rekord = JSON.parse(body.toString("utf8")) as HashedRekordJson;
    const spec = rekord.spec.hashedRekordV002;
    const signer = createPublicKey({ key: Buffer.from(spec.signature.verifier.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
    const proof = parsed.inclusionProof;
    // The index is the entry's own; the tree's size and root are what the log signed (Rekor v2).
    const index = uint64(parsed.logIndex);
    const tree = readCheckpoint(proof.checkpoint.envelope, log);
    if (tree === null) return { ok: false, reason: "log" };
    const root = inclusionRoot(sha256(Buffer.from([0]), body), index, tree.size, (proof.hashes ?? []).map((h) => Buffer.from(h, "base64")));
    const valid =
      // `logIndex` is a number: an index a number cannot hold exactly is refused, never reported rounded.
      index <= BigInt(Number.MAX_SAFE_INTEGER) &&
      rekord.kind === "hashedrekord" &&
      spec.data.algorithm === "SHA2_256" &&
      spec.data.digest === sha256(payload).toString("base64") &&
      verify("sha256", payload, signer, Buffer.from(spec.signature.content, "base64")) &&
      root !== null &&
      root.equals(tree.root) &&
      // The inner copies, when present, must say the same: a disagreement is refused, never resolved.
      (proof.logIndex === undefined || uint64(proof.logIndex) === index) &&
      (proof.treeSize === undefined || uint64(proof.treeSize) === tree.size) &&
      (proof.rootHash === undefined || Buffer.from(proof.rootHash, "base64").equals(tree.root));
    return valid ? { ok: true, logIndex: Number(index) } : { ok: false, reason: "log" };
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
  /**
   * The signed `ledger_checkpoint` a pruned ledger was anchored on, with the key set that verifies
   * it: the entries then start at its point, not at seq 1, and the chain up to the covered head
   * runs from it. Without it, a pruned ledger's entries cannot reach the covered seq.
   */
  checkpoint?: LedgerCheckpointRef;
}

export type AnchorFailure = "malformed" | "chain" | "token" | "certificate" | "imprint" | "log" | "checkpoint";

export type AnchorCheck =
  | { ok: true; seq: number; hash: string; time: string; logIndex: number | null }
  | { ok: false; reason: AnchorFailure };

/**
 * Checks a `ledger.anchored` entry offline against the entries it covers (from seq 1, or from the
 * checkpoint's point when the trust carries the `ledger_checkpoint` a pruned ledger was anchored
 * on, at least up to the seq it covers): the chain up to that seq, then the time-stamp token over
 * that head, then, for a Rekor proof, the log entry. `imprint` means the token is for another
 * head: the chain was changed or rebuilt after it was anchored. Never throws.
 */
export function verifyAnchor(anchored: AuditEntry, entries: readonly AuditEntry[], trust: AnchorTrust): AnchorCheck {
  // What a verifier is handed is not trusted: anything that is not an entry, a list or a trust is malformed.
  // Each is read once: the proof and the trust that pass these checks are the ones verified.
  const detail: unknown = isObject(anchored) ? anchored.detail : undefined;
  const tsa: unknown = isObject(trust) ? trust.tsa : undefined;
  const rekor = isObject(trust) ? trust.rekor : undefined;
  const checkpoint = isObject(trust) ? trust.checkpoint : undefined;
  if (!isObject(detail) || !Array.isArray(entries) || !Array.isArray(tsa)) return { ok: false, reason: "malformed" };
  // A pruned ledger's anchor starts at the checkpoint, which must verify under the key set it came
  // with: a checkpoint that is not a signed document is malformed input, and one whose signature
  // does not verify fails `checkpoint`, never `token` (that reason is the time-stamp's). Its
  // wrapper is read inside the boundary, so a trust object with getters answers once, never throws.
  let checkpointCheck: ReturnType<typeof verifyLedgerCheckpoint> | null = null;
  if (checkpoint !== undefined) {
    if (!isObject(checkpoint)) return { ok: false, reason: "malformed" };
    try {
      const { checkpoint: signed, keys: checkpointKeys } = checkpoint as LedgerCheckpointRef;
      checkpointCheck = verifyLedgerCheckpoint(signed, checkpointKeys);
    } catch {
      return { ok: false, reason: "malformed" };
    }
  }
  if (checkpointCheck !== null && !checkpointCheck.ok) return { ok: false, reason: checkpointCheck.reason === "signature" ? "checkpoint" : "malformed" };
  const { seq, proof: given } = detail;
  // A plain copy of the proof: a getter in it answers once, here, and anything not plain data is malformed.
  let proof: unknown;
  try {
    proof = structuredClone(given);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (anchored.event !== "ledger.anchored" || !Number.isSafeInteger(seq) || (seq as number) < 1 || !isAnchorProof(proof)) {
    return { ok: false, reason: "malformed" };
  }
  let chain: ReturnType<typeof verifyChain>;
  try {
    // An export holding nothing (null, or a hole of a sparse list, which `some` and `filter` skip)
    // where an entry should be is malformed, wherever it sits. verifyChain reports any other value
    // that is not an entry as a break in the chain (SRV-7), but it reads an object's fields, and
    // one whose field throws when read is malformed too, never a throw.
    for (let at = 0; at < entries.length; at++) {
      if (!(at in entries) || entries[at] === null || entries[at] === undefined) return { ok: false, reason: "malformed" };
    }
    // The entries up to the covered seq: from seq 1 on a whole ledger, or from the checkpoint's
    // point on a pruned one, where the chain runs from the checkpoint instead of the genesis.
    const covered: unknown[] = entries.filter((e) => (e as AuditEntry).seq <= (seq as number));
    chain = verifyChain(covered as AuditEntry[], checkpointCheck === null ? undefined : checkpointCheck.point);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!chain.ok || chain.head.seq !== seq) return { ok: false, reason: "chain" };
  const payload = anchorPayload(chain.head);
  const stamp = checkTimestamp(proof.token, payload, tsa as readonly X509Certificate[]);
  if (!stamp.ok) return stamp;
  let logIndex: number | null = null;
  if (proof.kind === "rekor") {
    const logged: LogCheck = rekor === undefined ? { ok: false, reason: "log" } : checkRekorEntry(proof.entry, payload, rekor);
    if (!logged.ok) return logged;
    logIndex = logged.logIndex;
  }
  return { ok: true, seq: chain.head.seq, hash: chain.head.hash, time: stamp.time, logIndex };
}
