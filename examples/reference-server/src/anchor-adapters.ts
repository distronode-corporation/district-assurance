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
// that signed it and the time, and nothing else.
import { createHash, createPublicKey, sign, type KeyObject, type X509Certificate } from "node:crypto";

import { checkRekorEntry, checkTimestamp, readDer, type Anchor, type AnchorProof, type RekorLog } from "../../../src/index.ts";

type Fetch = (url: string, init: { method: string; headers: Record<string, string>; body: Uint8Array | string }) => Promise<Response>;

/** The DER TimeStampReq for a SHA-256 imprint: version 1, the imprint, certReq true, no nonce. */
export function timestampRequest(payload: Uint8Array): Buffer {
  const digest = createHash("sha256").update(payload).digest();
  return Buffer.concat([
    Buffer.from("30390201013031300d060960864801650304020105000420", "hex"),
    digest,
    Buffer.from("0101ff", "hex"),
  ]);
}

/** An RFC 3161 time-stamp authority over HTTP (`application/timestamp-query`). */
export class TimestampAuthorityAnchor implements Anchor {
  readonly #url: string;
  readonly #chain: readonly X509Certificate[];
  readonly #fetch: Fetch;

  /** `chain` is the authority's certificate chain, its signing certificate first; tokens are checked against it. */
  constructor(options: { url: string; chain: readonly X509Certificate[]; fetch?: Fetch }) {
    this.#url = options.url;
    this.#chain = options.chain;
    this.#fetch = options.fetch ?? (fetch as Fetch);
  }

  /** A checked token (base64 DER) over SHA-256 of the payload. */
  async timestamp(payload: Uint8Array): Promise<string> {
    const response = await this.#fetch(this.#url, {
      method: "POST",
      headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" },
      body: timestampRequest(payload),
    });
    if (!response.ok) throw new Error(`the time-stamp authority answered ${response.status}`);
    const [reply] = readDer(new Uint8Array(await response.arrayBuffer()));
    if (reply === undefined) throw new Error("the time-stamp authority answered nothing");
    const [statusInfo, token] = readDer(reply.value);
    const [status] = readDer(statusInfo?.value ?? new Uint8Array());
    // PKIStatus 0 is granted, 1 granted with modifications.
    const granted = status?.tag === 0x02 && status.value.length === 1 && status.value[0]! <= 1;
    if (!granted || token === undefined) throw new Error("the time-stamp authority refused the request");
    const encoded = Buffer.from(token.raw).toString("base64");
    const check = checkTimestamp(encoded, payload, this.#chain);
    if (!check.ok) throw new Error(`the time-stamp token does not verify (${check.reason})`);
    return encoded;
  }

  async anchor(input: { seq: number; hash: string; payload: Uint8Array }): Promise<AnchorProof> {
    return { kind: "rfc3161", token: await this.timestamp(input.payload) };
  }
}

/**
 * Sigstore's Rekor v2: the anchor payload signed with the host's P-256 key (under the payload's
 * domain separation, so it never verifies as a receipt) and logged as a `hashedrekord`. Rekor v2
 * gives an inclusion proof and a signed checkpoint but no time, so the time comes from `timestamps`.
 */
export class RekorAnchor implements Anchor {
  readonly #url: string;
  readonly #signingKey: KeyObject;
  readonly #log: RekorLog;
  readonly #timestamps: TimestampAuthorityAnchor;
  readonly #fetch: Fetch;

  /** `url` is the log's base URL; `log` is its public key and origin, which entries are checked against. */
  constructor(options: { url: string; signingKey: KeyObject; log: RekorLog; timestamps: TimestampAuthorityAnchor; fetch?: Fetch }) {
    if (options.signingKey.asymmetricKeyType !== "ec" || options.signingKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new TypeError("RekorAnchor needs a P-256 private key");
    }
    this.#url = options.url.replace(/\/$/, "");
    this.#signingKey = options.signingKey;
    this.#log = options.log;
    this.#timestamps = options.timestamps;
    this.#fetch = options.fetch ?? (fetch as Fetch);
  }

  async anchor(input: { seq: number; hash: string; payload: Uint8Array }): Promise<AnchorProof> {
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
    if (!response.ok) throw new Error(`Rekor answered ${response.status}`);
    const entry = Buffer.from(await response.arrayBuffer()).toString("base64");
    const check = checkRekorEntry(entry, input.payload, this.#log);
    if (!check.ok) throw new Error("the Rekor entry does not verify");
    return { kind: "rekor", token: await this.#timestamps.timestamp(input.payload), entry };
  }
}
