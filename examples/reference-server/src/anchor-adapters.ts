// Anchor adapters for the reference server (PRV-9): an RFC 3161 time-stamp authority, and
// Sigstore's Rekor v2 plus one. Both use fetch (no SDK, no ASN.1 library) and check what they get
// back before the engine writes it to the ledger.
//
// The host schedules anchoring; the engine never calls out on its own. Daily, for example:
//
//   const anchor = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain });
//   const engine = createEngine({ ..., adapters: { ..., anchor } });
//   setInterval(() => void engine.anchorLedger().catch(report), 24 * 60 * 60 * 1000);
//
// A time-stamp authority signs a hash of the head and never sees the ledger; only the proofs the
// operator keeps exist. Rekor is a public log: it shows anyone each anchored head (a hash), the key
// that signed it and the signature, and nothing else; the time is in the authority's token.
import { createHash, createPublicKey, randomBytes, sign, type KeyObject, type X509Certificate } from "node:crypto";

import { checkRekorEntry, checkTimestamp, readDer, timestampTokenFields, type Anchor, type AnchorProof, type RekorLog } from "../../../src/index.ts";

type Fetch = (url: string, init: { method: string; headers: Record<string, string>; body: Uint8Array | string }) => Promise<Response>;

/**
 * The most either adapter reads of a reply before refusing it. A token with its certificates, or
 * a Rekor entry with its proof and checkpoint, is a few kilobytes.
 */
export const MAX_REPLY_BYTES = 256 * 1024;

/** A reply's body, read as it streams in: past `limit` bytes the rest is cancelled and the reply refused. */
async function readCapped(response: Response, limit: number, who: string): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return Buffer.concat(chunks);
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new Error(`${who} answered more than the ${limit} bytes allowed (larger than the cap)`);
    }
    chunks.push(value);
  }
}

/** A refused reply: its body is cancelled, never read. */
async function refuse(response: Response, message: string): Promise<never> {
  await response.body?.cancel();
  throw new Error(message);
}

/** A DER element: one-byte tag, a short length (everything this request holds is under 128 bytes). */
const element = (tag: number, ...parts: Uint8Array[]): Buffer => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag, body.length]), body]);
};

/** A fresh nonce: eight random bytes, the first in 0x40 to 0x7f, so the INTEGER is positive and minimal as it is. */
function randomNonce(): Buffer {
  const nonce = randomBytes(8);
  nonce[0] = (nonce[0]! & 0x3f) | 0x40;
  return nonce;
}

/**
 * The DER TimeStampReq for a SHA-256 imprint: version 1, the imprint, the nonce (the contents of a
 * positive, minimal INTEGER, under 64 bytes) and certReq true.
 */
export function timestampRequest(payload: Uint8Array, nonce: Uint8Array): Buffer {
  const digest = createHash("sha256").update(payload).digest();
  const sha256 = Buffer.from("300d06096086480165030402010500", "hex");
  return element(0x30, element(0x02, Buffer.from([1])), element(0x30, sha256, element(0x04, digest)), element(0x02, nonce), Buffer.from("0101ff", "hex"));
}

/** An RFC 3161 time-stamp authority over HTTP (`application/timestamp-query`). */
export class TimestampAuthorityAnchor implements Anchor {
  readonly #url: string;
  readonly #chain: readonly X509Certificate[];
  readonly #fetch: Fetch;
  readonly #nonce: () => Uint8Array;
  readonly #maxReplyBytes: number;

  /**
   * `chain` is the authority's certificate chain, its signing certificate first; tokens are checked
   * against it. `nonce` makes each request's nonce (random by default; a test passes a fixed one to
   * replay a recorded answer). A reply over `maxReplyBytes` (default MAX_REPLY_BYTES) is refused.
   */
  constructor(options: { url: string; chain: readonly X509Certificate[]; fetch?: Fetch; nonce?: () => Uint8Array; maxReplyBytes?: number }) {
    this.#url = options.url;
    this.#chain = options.chain;
    this.#fetch = options.fetch ?? (fetch as Fetch);
    this.#nonce = options.nonce ?? randomNonce;
    this.#maxReplyBytes = options.maxReplyBytes ?? MAX_REPLY_BYTES;
  }

  /**
   * A checked token (base64 DER) over SHA-256 of the payload, answering this request: its imprint
   * is SHA-256, as asked, and it carries this request's nonce, so an earlier token for the same
   * payload is not taken as the answer. Both are checked here only: an archived token has no
   * request, and `verifyAnchor` checks it without them.
   */
  async timestamp(payload: Uint8Array): Promise<string> {
    const nonce = Buffer.from(this.#nonce());
    const response = await this.#fetch(this.#url, {
      method: "POST",
      headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" },
      body: timestampRequest(payload, nonce),
    });
    if (!response.ok) return refuse(response, `the time-stamp authority answered ${response.status}`);
    const [reply] = readDer(await readCapped(response, this.#maxReplyBytes, "the time-stamp authority"));
    if (reply === undefined) throw new Error("the time-stamp authority answered nothing");
    const [statusInfo, token] = readDer(reply.value);
    const [status] = readDer(statusInfo?.value ?? new Uint8Array());
    // PKIStatus 0 is granted, 1 granted with modifications.
    const granted = status?.tag === 0x02 && status.value.length === 1 && status.value[0]! <= 1;
    if (!granted || token === undefined) throw new Error("the time-stamp authority refused the request");
    const encoded = Buffer.from(token.raw).toString("base64");
    const check = checkTimestamp(encoded, payload, this.#chain);
    if (!check.ok) throw new Error(`the time-stamp token does not verify (${check.reason})`);
    // A token that verifies reads.
    const fields = timestampTokenFields(encoded)!;
    if (fields.imprintHash !== "sha256") throw new Error(`the time-stamp authority answered a ${fields.imprintHash} imprint to a SHA-256 request`);
    if (fields.nonce === null || !nonce.equals(fields.nonce)) throw new Error("the time-stamp token does not carry this request's nonce");
    return encoded;
  }

  async anchor(input: { seq: number; hash: string; payload: Uint8Array }): Promise<AnchorProof> {
    return { kind: "rfc3161", token: await this.timestamp(input.payload) };
  }
}

/** The key a Rekor v2 `hashedrekord` entry (base64 of the JSON Rekor answered) names as its signer. */
function loggedSigner(entry: string): KeyObject {
  const parsed = JSON.parse(Buffer.from(entry, "base64").toString("utf8")) as { canonicalizedBody: string };
  const body = JSON.parse(Buffer.from(parsed.canonicalizedBody, "base64").toString("utf8")) as {
    spec: { hashedRekordV002: { signature: { verifier: { publicKey: { rawBytes: string } } } } };
  };
  return createPublicKey({ key: Buffer.from(body.spec.hashedRekordV002.signature.verifier.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
}

/**
 * Sigstore's Rekor v2: the anchor payload signed with the host's P-256 key (under the payload's
 * domain separation, so it never verifies as a receipt) and logged as a `hashedrekord`. Rekor v2
 * gives an inclusion proof and a signed checkpoint but no time, so the time comes from `timestamps`.
 * The authority stamps the payload, not Rekor's answer, so it is asked first: a refused stamp
 * writes nothing to the public log, and a retry after one does not log the head twice.
 */
export class RekorAnchor implements Anchor {
  readonly #url: string;
  readonly #signingKey: KeyObject;
  readonly #log: RekorLog;
  readonly #timestamps: TimestampAuthorityAnchor;
  readonly #fetch: Fetch;
  readonly #maxReplyBytes: number;

  /**
   * `url` is the log's base URL; `log` is its public key and origin, which entries are checked
   * against. A reply over `maxReplyBytes` (default MAX_REPLY_BYTES) is refused.
   */
  constructor(options: { url: string; signingKey: KeyObject; log: RekorLog; timestamps: TimestampAuthorityAnchor; fetch?: Fetch; maxReplyBytes?: number }) {
    if (options.signingKey.asymmetricKeyType !== "ec" || options.signingKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new TypeError("RekorAnchor needs a P-256 private key");
    }
    this.#url = options.url.replace(/\/$/, "");
    this.#signingKey = options.signingKey;
    this.#log = options.log;
    this.#timestamps = options.timestamps;
    this.#fetch = options.fetch ?? (fetch as Fetch);
    this.#maxReplyBytes = options.maxReplyBytes ?? MAX_REPLY_BYTES;
  }

  async anchor(input: { seq: number; hash: string; payload: Uint8Array }): Promise<AnchorProof> {
    const token = await this.#timestamps.timestamp(input.payload);
    const signature = sign("sha256", input.payload, this.#signingKey);
    const publicKey = createPublicKey(this.#signingKey).export({ type: "spki", format: "der" });
    const request = {
      hashedRekordRequestV002: {
        digest: createHash("sha256").update(input.payload).digest("base64"),
        signature: {
          content: signature.toString("base64"),
          verifier: { publicKey: { rawBytes: publicKey.toString("base64") }, keyDetails: "PKIX_ECDSA_P256_SHA_256" },
        },
      },
    };
    const response = await this.#fetch(`${this.#url}/api/v2/log/entries`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(request),
    });
    if (!response.ok) return refuse(response, `Rekor answered ${response.status}`);
    const entry = Buffer.from(await readCapped(response, this.#maxReplyBytes, "Rekor")).toString("base64");
    const check = checkRekorEntry(entry, input.payload, this.#log);
    if (!check.ok) throw new Error("the Rekor entry does not verify");
    // A valid entry for the same payload under another key is not this host's proof.
    if (!loggedSigner(entry).equals(createPublicKey(this.#signingKey))) {
      throw new Error("the Rekor entry is signed by another key");
    }
    return { kind: "rekor", token, entry };
  }
}
