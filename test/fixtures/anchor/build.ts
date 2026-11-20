// Builders for the anchor tests (PRV-9): a DER writer, X.509 certificates, RFC 3161 tokens and
// responses, and a Rekor v2 style log (an RFC 9162 Merkle tree, inclusion proofs and a signed
// checkpoint). `record.ts` uses them to write the recorded fixtures; the tests use them to build
// broken tokens and entries. Test code only: every key here is a throwaway, not a secret.
import { createECDH, createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";

import { MemoryAuditLedger } from "../../../src/prove/ledger.ts";
import type { AuditEntry } from "../../../src/core/adapters.ts";

// ---- DER ----------------------------------------------------------------------------------------

export function der(tag: number, ...parts: Uint8Array[]): Buffer {
  const body = Buffer.concat(parts);
  const size: number[] = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) size.unshift(n % 256);
  const length = body.length < 0x80 ? [body.length] : [0x80 | size.length, ...size];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

export const seq = (...parts: Uint8Array[]): Buffer => der(0x30, ...parts);
export const set = (...parts: Uint8Array[]): Buffer => der(0x31, ...parts);
export const oid = (hex: string): Buffer => der(0x06, Buffer.from(hex, "hex"));
export const octets = (bytes: Uint8Array): Buffer => der(0x04, bytes);
/** A DER INTEGER of a value that is not negative: big-endian, minimal, with a leading 0x00 when the high bit is set. */
export function int(n: number): Buffer {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("int: a safe integer of 0 or more");
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  if (bytes.length === 0 || bytes[0]! >= 0x80) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}
export const text = (tag: number, value: string): Buffer => der(tag, Buffer.from(value, "latin1"));
export const explicit0 = (...parts: Uint8Array[]): Buffer => der(0xa0, ...parts);

export const OIDS = {
  sha256: "608648016503040201",
  sha384: "608648016503040202",
  sha1: "2b0e03021a",
  md5: "2a864886f70d0205",
  rsaEncryption: "2a864886f70d010101",
  sha256WithRsa: "2a864886f70d01010b",
  ecdsaSha256: "2a8648ce3d040302",
  ed25519: "2b6570",
  signedData: "2a864886f70d010702",
  data: "2a864886f70d010701",
  tstInfo: "2a864886f70d0109100104",
  contentType: "2a864886f70d010903",
  messageDigest: "2a864886f70d010904",
  signingCertificate: "2a864886f70d010910020c",
  signingCertificateV2: "2a864886f70d010910022f",
  commonName: "550403",
  extendedKeyUsage: "551d25",
  basicConstraints: "551d13",
  keyUsage: "551d0f",
  timeStamping: "2b06010505070308",
  codeSigning: "2b06010505070303",
  policy: "2a0304",
};

export const algorithm = (hex: string, params = true): Buffer => (params ? seq(oid(hex), der(0x05)) : seq(oid(hex)));

export const name = (cn: string): Buffer => seq(set(seq(oid(OIDS.commonName), text(0x0c, cn))));

/** The DER signature algorithm and hash for a signing key. */
function signatureAlgorithm(key: KeyObject): { id: Buffer; hash: string } {
  return key.asymmetricKeyType === "rsa" ? { id: algorithm(OIDS.sha256WithRsa), hash: "sha256" } : { id: algorithm(OIDS.ecdsaSha256, false), hash: "sha256" };
}

export interface CertificateSpec {
  subject: string;
  issuer: string;
  publicKey: KeyObject;
  /** The issuer's private key. */
  signingKey: KeyObject;
  serial: number;
  /** UTCTime, YYMMDDHHMMSSZ. */
  notBefore: string;
  notAfter: string;
  /** An extended key usage; none when absent. */
  usage?: string;
  ca?: boolean;
  /** basicConstraints pathLenConstraint, with `ca`. */
  pathLen?: number;
  /** A keyUsage extension: its one byte of bits (keyCertSign is 0x04, digitalSignature 0x80). */
  keyUsage?: number;
  /** Extensions added as given, to build malformed ones. */
  rawExtensions?: Buffer[];
}

export function certificate(spec: CertificateSpec): Buffer {
  const alg = signatureAlgorithm(spec.signingKey);
  const extensions: Buffer[] = [];
  if (spec.ca === true) {
    const limit = spec.pathLen === undefined ? [] : [int(spec.pathLen)];
    extensions.push(seq(oid(OIDS.basicConstraints), der(0x01, Buffer.from([0xff])), octets(seq(der(0x01, Buffer.from([0xff])), ...limit))));
  }
  extensions.push(...(spec.rawExtensions ?? []));
  if (spec.keyUsage !== undefined) extensions.push(seq(oid(OIDS.keyUsage), der(0x01, Buffer.from([0xff])), octets(der(0x03, Buffer.from([0, spec.keyUsage])))));
  if (spec.usage !== undefined) extensions.push(seq(oid(OIDS.extendedKeyUsage), der(0x01, Buffer.from([0xff])), octets(seq(oid(spec.usage)))));
  const tbs = seq(
    der(0xa0, int(2)),
    int(spec.serial),
    alg.id,
    name(spec.issuer),
    seq(text(0x17, spec.notBefore), text(0x17, spec.notAfter)),
    name(spec.subject),
    spec.publicKey.export({ type: "spki", format: "der" }),
    ...(extensions.length === 0 ? [] : [der(0xa3, seq(...extensions))]),
  );
  return seq(tbs, alg.id, der(0x03, Buffer.from([0]), sign(alg.hash, tbs, spec.signingKey)));
}

export const pem = (cert: Buffer): string => `-----BEGIN CERTIFICATE-----\n${cert.toString("base64").replace(/.{64}/g, "$&\n").replace(/\n$/, "")}\n-----END CERTIFICATE-----\n`;

// ---- RFC 3161 -----------------------------------------------------------------------------------

export interface TokenSpec {
  /** What the token's imprint covers. */
  payload: Uint8Array;
  /** GeneralizedTime. */
  time: string;
  signingKey: KeyObject;
  /** The signer's issuer name and serial (IssuerAndSerialNumber). */
  issuer: string;
  serial: number;
  /** The DER of the certificate the token's SigningCertificateV2 names. */
  signerCertificate: Buffer;
  /** The TSTInfo's nonce, an INTEGER element; null leaves it out. Default 42. */
  nonce?: Buffer | null;
  /** Certificates to carry in the token (ignored by the verifier). */
  certificates?: Buffer[];
  /** The SignerInfo's signature algorithm; default from the key. */
  signatureAlgorithm?: Buffer;
  /** The signed hash, when the signature algorithm leaves it to the digest algorithm. */
  signatureHash?: string;
  /** Replaces the TSTInfo, or parts of a token, to build broken ones. */
  tstInfo?: (parts: { imprint: Buffer; time: Buffer }) => Buffer;
  /** `extra` holds the default SigningCertificateV2 attribute. */
  attributes?: (parts: { contentType: Buffer; messageDigest: Buffer; extra: Buffer[] }) => Buffer[];
  signerInfos?: (signerInfo: Buffer) => Buffer;
  signedData?: (parts: { version: Buffer; digests: Buffer; content: Buffer; certificates: Buffer[]; signerInfos: Buffer }) => Buffer;
  contentInfo?: (signedData: Buffer) => Buffer;
}

export function timestampToken(spec: TokenSpec): Buffer {
  const imprint = seq(algorithm(OIDS.sha256), octets(createHash("sha256").update(spec.payload).digest()));
  const time = text(0x18, spec.time);
  const tstInfo =
    spec.tstInfo?.({ imprint, time }) ??
    seq(int(1), oid(OIDS.policy), imprint, int(spec.serial), time, seq(int(1)), ...(spec.nonce === null ? [] : [spec.nonce ?? int(42)]), der(0xa0, der(0xa4, name("Test TSA"))));
  const parts = {
    contentType: seq(oid(OIDS.contentType), set(oid(OIDS.tstInfo))),
    messageDigest: seq(oid(OIDS.messageDigest), set(octets(createHash("sha256").update(tstInfo).digest()))),
    extra: [signingCertificate(2, essCertIdV2(spec.signerCertificate, { issuerSerial: issuerSerial(spec.issuer, spec.serial) }))],
  };
  const attributes = spec.attributes?.(parts) ?? [parts.contentType, parts.messageDigest, ...parts.extra];
  const alg = signatureAlgorithm(spec.signingKey);
  const signature = sign(spec.signatureHash ?? alg.hash, set(...attributes), spec.signingKey);
  const signerInfo = seq(int(1), seq(name(spec.issuer), int(spec.serial)), algorithm(OIDS.sha256), der(0xa0, ...attributes), spec.signatureAlgorithm ?? alg.id, octets(signature));
  const signerInfos = spec.signerInfos?.(signerInfo) ?? set(signerInfo);
  const certificates = spec.certificates === undefined ? [] : [der(0xa0, ...spec.certificates)];
  const content = seq(oid(OIDS.tstInfo), explicit0(octets(tstInfo)));
  const signedParts = { version: int(3), digests: set(algorithm(OIDS.sha256)), content, certificates, signerInfos };
  const signedData = spec.signedData?.(signedParts) ?? seq(signedParts.version, signedParts.digests, content, ...certificates, signerInfos);
  return spec.contentInfo?.(signedData) ?? seq(oid(OIDS.signedData), explicit0(signedData));
}

/** IssuerSerial (RFC 5035) for a certificate with this issuer name and serial: one directoryName, then the serial. */
export const issuerSerial = (issuer: string, serial: number): Buffer => seq(seq(der(0xa4, name(issuer))), int(serial));

/**
 * An ESSCertIDv2 (RFC 5035) naming `cert`: its hash under `hash` (default SHA-256), the hash
 * algorithm written out only when `algorithm` is given (SHA-256 is the DEFAULT, so DER leaves it
 * out), and an IssuerSerial when given.
 */
export function essCertIdV2(cert: Uint8Array, options: { hash?: string; algorithm?: Buffer; issuerSerial?: Buffer } = {}): Buffer {
  const certHash = octets(createHash(options.hash ?? "sha256").update(cert).digest());
  return seq(...(options.algorithm === undefined ? [] : [options.algorithm]), certHash, ...(options.issuerSerial === undefined ? [] : [options.issuerSerial]));
}

/** An ESSCertID (RFC 2634): the SHA-1 hash of `cert`, and an IssuerSerial when given. */
export const essCertId = (cert: Uint8Array, serial?: Buffer): Buffer => seq(octets(createHash("sha1").update(cert).digest()), ...(serial === undefined ? [] : [serial]));

/** A signed attribute: SigningCertificate (version 1) or SigningCertificateV2 (2), holding these ESSCertIDs and no policies. */
export const signingCertificate = (version: 1 | 2, ...ids: Buffer[]): Buffer => seq(oid(version === 1 ? OIDS.signingCertificate : OIDS.signingCertificateV2), set(seq(seq(...ids))));

/** The nonce the recorded TSA answer carries; the adapter test asks with it. Eight bytes, positive and minimal. */
export const FIXTURE_NONCE = Buffer.from("5a17c0de0b5e55ed", "hex");

/** A TimeStampResp: a PKIStatusInfo and, when granted, the token. */
export function timestampResponse(status: number, token?: Buffer): Buffer {
  return seq(seq(int(status)), ...(token === undefined ? [] : [token]));
}

// ---- a Rekor v2 style log -----------------------------------------------------------------------

const hash = (...parts: Uint8Array[]): Buffer => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
};

export const leafHash = (leaf: Uint8Array): Buffer => hash(Buffer.from([0]), leaf);
const nodeHash = (left: Buffer, right: Buffer): Buffer => hash(Buffer.from([1]), left, right);

/** The largest power of two smaller than n (n > 1). */
const split = (n: number): number => 2 ** Math.floor(Math.log2(n - 1));

/** RFC 9162 MTH. */
export function merkleRoot(leaves: readonly Buffer[]): Buffer {
  // MTH({}) is the hash of the empty string.
  if (leaves.length === 0) return hash();
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/** RFC 9162 PATH(m, D[n]). */
export function inclusionPath(m: number, leaves: readonly Buffer[]): Buffer[] {
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return m < k ? [...inclusionPath(m, leaves.slice(0, k)), merkleRoot(leaves.slice(k))] : [...inclusionPath(m - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

/** A C2SP signed note over a checkpoint: Ed25519 key ids as C2SP has them, ECDSA ones as the SPKI hash. */
export function signedCheckpoint(origin: string, size: number, root: Buffer, logKey: KeyObject, logPublicKey: KeyObject): string {
  const body = `${origin}\n${size}\n${root.toString("base64")}\n`;
  const spki = logPublicKey.export({ type: "spki", format: "der" });
  const ed25519 = logKey.asymmetricKeyType === "ed25519";
  const id = ed25519 ? hash(Buffer.from(`${origin}\n\u0001`), spki.subarray(12)).subarray(0, 4) : hash(spki).subarray(0, 4);
  const signature = sign(ed25519 ? null : "sha256", Buffer.from(body), logKey);
  return `${body}\n${String.fromCharCode(0x2014)} ${origin} ${Buffer.concat([id, signature]).toString("base64")}\n`;
}

/** The canonicalized body of a hashedrekord v0.0.2 entry, as Rekor v2 writes it. */
export function hashedRekordBody(payload: Uint8Array, signature: Buffer, signerPublicKey: KeyObject): Buffer {
  return Buffer.from(
    JSON.stringify({
      apiVersion: "0.0.2",
      kind: "hashedrekord",
      spec: {
        hashedRekordV002: {
          data: { algorithm: "SHA2_256", digest: hash(payload).toString("base64") },
          signature: {
            content: signature.toString("base64"),
            verifier: { publicKey: { rawBytes: signerPublicKey.export({ type: "spki", format: "der" }).toString("base64") }, keyDetails: "PKIX_ECDSA_P256_SHA_256" },
          },
        },
      },
    }),
  );
}

/** A TransparencyLogEntry for the body at `index` in a log of `others` plus it. */
export function logEntry(input: { body: Buffer; index: number; size: number; origin: string; logKey: KeyObject; logPublicKey: KeyObject }): Record<string, unknown> {
  const leaves = Array.from({ length: input.size }, (_, i) => (i === input.index ? input.body : Buffer.from(`another entry ${i}`)));
  const root = merkleRoot(leaves);
  return {
    logIndex: String(input.index),
    logId: { keyId: hash(input.logPublicKey.export({ type: "spki", format: "der" })).toString("base64") },
    kindVersion: { kind: "hashedrekord", version: "0.0.2" },
    inclusionProof: {
      logIndex: String(input.index),
      rootHash: root.toString("base64"),
      treeSize: String(input.size),
      hashes: inclusionPath(input.index, leaves).map((h) => h.toString("base64")),
      checkpoint: { envelope: signedCheckpoint(input.origin, input.size, root, input.logKey, input.logPublicKey) },
    },
    canonicalizedBody: input.body.toString("base64"),
  };
}

// ---- the recorded ledger ------------------------------------------------------------------------

/** The ledger the fixtures anchor: five entries, the same bytes every run. */
export async function fixtureLedger(): Promise<{ ledger: MemoryAuditLedger; entries: AuditEntry[] }> {
  const ledger = new MemoryAuditLedger();
  const at = "2026-11-18T09:00:00.000Z";
  for (const event of ["call.started", "verification.started", "verification.finished", "call.ended"] as const) {
    await ledger.append({ eventId: `fixture-${event}`, callId: "call_fixture", actor: "system", event, at, detail: {} });
  }
  await ledger.append({ callId: null, actor: "system", event: "module.event", at, detail: { note: "the head the fixtures anchor" } });
  return { ledger, entries: await ledger.list() };
}

export const REKOR_ORIGIN = "log2025-test.rekor.example.test";

/**
 * The host's P-256 key the recorded Rekor entry is signed with: derived from a fixed label, so the
 * adapter test can use the same key without a private key file in the repository.
 */
export function fixtureSigner(): { privateKey: KeyObject; publicKey: KeyObject } {
  const d = createHash("sha256").update("district-assurance anchor fixture signer").digest();
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey();
  const jwk = { kty: "EC", crv: "P-256", d: d.toString("base64url"), x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") };
  const privateKey = createPrivateKey({ key: jwk, format: "jwk" });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}
