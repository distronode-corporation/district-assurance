// Records ONE real anchor (PRV-9) into test/fixtures/anchor/real/: a throwaway ledger (two test
// calls, no real data) anchored through the engine's own `anchorLedger()` with the reference
// server's `RekorAnchor`, which asks DigiCert's public RFC 3161 time-stamp authority first and then
// logs the head in Sigstore's public Rekor v2 log. The tests replay the files offline and never
// touch a network; this script is run by hand, once, and is not part of `npm test`.
//
//   node test/fixtures/anchor/record-real.ts
//
// What it trusts, and where each piece comes from:
// - the time-stamp authority's root, DigiCert Trusted Root G4, from the system's CA store
//   (`/etc/ssl/certs`), not from the answer. The signing certificate and its intermediate are the
//   ones the token carries (it is asked with certReq true), and the adapter only accepts the token
//   when they chain to that root.
// - Rekor's public key and origin, from Sigstore's TUF-distributed trusted root (the
//   `trusted_root.json` path given as the first argument), the log whose base URL is `REKOR_URL`.
// The host key that signs the logged head is `fixtureSigner()`, derived from a public label: the
// logged head is a test value and anyone may know that key.
import { X509Certificate, createPublicKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { RekorAnchor, TimestampAuthorityAnchor } from "../../../examples/reference-server/src/anchor-adapters.ts";
import { readDer, type RekorLog } from "../../../src/prove/anchor.ts";
import { FixedClock } from "../../../src/testing/fakes.ts";
import { createTestEngine } from "../../../src/testing/index.ts";
import { fixtureSigner } from "./build.ts";

const TSA_URL = "http://timestamp.digicert.com";
const REKOR_URL = "https://log2025-1.rekor.sigstore.dev";
const REKOR_ORIGIN = "log2025-1.rekor.sigstore.dev";

const dir = new URL("./real/", import.meta.url);
const trustedRoot = JSON.parse(readFileSync(process.argv[2] ?? "trusted_root.json", "utf8")) as {
  tlogs: Array<{ baseUrl: string; publicKey: { rawBytes: string } }>;
};
const tlog = trustedRoot.tlogs.find((t) => t.baseUrl === REKOR_URL);
if (tlog === undefined) throw new Error(`${REKOR_URL} is not in the trusted root`);
const log: RekorLog = { key: createPublicKey({ key: Buffer.from(tlog.publicKey.rawBytes, "base64"), format: "der", type: "spki" }), origin: REKOR_ORIGIN };
const root = new X509Certificate(readFileSync("/etc/ssl/certs/DigiCert_Trusted_Root_G4.pem"));

/** The certificates a TimeStampResp's token carries ([0] IMPLICIT in its SignedData). */
function tokenCertificates(reply: Uint8Array): X509Certificate[] {
  const [resp] = readDer(reply);
  const [, token] = readDer(resp!.value);
  const [, wrapped] = readDer(token!.value);
  const [signedData] = readDer(wrapped!.value);
  const certs = readDer(signedData!.value).find((e) => e.tag === 0xa0);
  return certs === undefined ? [] : readDer(certs.value).map((e) => new X509Certificate(e.raw));
}

// The chain the adapter checks against: filled from the authority's answer before the adapter reads
// it, signing certificate first, ending at the root from the CA store (which must issue the last one).
const chain: X509Certificate[] = [];
const recorded: { tsa?: Uint8Array; rekor?: Uint8Array } = {};
const nonce = Buffer.from("5f3a0c9d17e2b48a", "hex");

const recording = async (url: string, init: { method: string; headers: Record<string, string>; body: Uint8Array | string }): Promise<Response> => {
  const response = await fetch(url, init);
  const body = new Uint8Array(await response.arrayBuffer());
  if (!response.ok) throw new Error(`${url} answered ${response.status}: ${Buffer.from(body).toString("utf8").slice(0, 500)}`);
  if (url === TSA_URL) {
    recorded.tsa = body;
    const certs = tokenCertificates(body);
    // Signing certificate first: the one with the time-stamping extended key usage, then its issuers.
    let cert = certs.find((c) => (c.keyUsage ?? []).includes("1.3.6.1.5.5.7.3.8"));
    while (cert !== undefined && !cert.checkIssued(root)) {
      chain.push(cert);
      const current = cert;
      cert = certs.find((c) => c !== current && current.checkIssued(c));
    }
    if (cert === undefined) throw new Error("the token's certificates do not chain to DigiCert Trusted Root G4");
    chain.push(cert, root);
  } else {
    recorded.rekor = body;
  }
  return new Response(body, { status: response.status });
};

const timestamps = new TimestampAuthorityAnchor({ url: TSA_URL, chain, fetch: recording, nonce: () => nonce });
const anchor = new RekorAnchor({ url: REKOR_URL, signingKey: fixtureSigner().privateKey, log, timestamps, fetch: recording });
const t = createTestEngine({ clock: new FixedClock(new Date()), adapters: { anchor } });
for (let i = 0; i < 2; i++) {
  const { callId } = await t.engine.startCall();
  await t.engine.endCall(callId);
}
const anchored = await t.engine.anchorLedger();

mkdirSync(dir, { recursive: true });
writeFileSync(new URL("ledger.json", dir), `${JSON.stringify(await t.ledger.list(), null, 2)}\n`);
writeFileSync(new URL("tsa-response.der.b64", dir), `${Buffer.from(recorded.tsa!).toString("base64")}\n`);
writeFileSync(new URL("tsa-chain.pem", dir), chain.map((c) => c.toString()).join(""));
writeFileSync(new URL("rekor-log.pem", dir), log.key.export({ type: "spki", format: "pem" }));
// The checkpoint's signature lines start with U+2014, written escaped: the repository keeps that
// character out of its text files. The JSON is the same.
const entry = JSON.parse(Buffer.from(recorded.rekor!).toString("utf8")) as unknown;
writeFileSync(new URL("rekor-response.json", dir), `${JSON.stringify(entry, null, 2).replace(/\u2014/g, "\\u2014")}\n`);
writeFileSync(
  new URL("recording.json", dir),
  `${JSON.stringify({ tsa: TSA_URL, rekor: REKOR_URL, origin: REKOR_ORIGIN, nonce: nonce.toString("hex"), recordedAt: new Date().toISOString(), anchoredSeq: anchored.seq }, null, 2)}\n`,
);
console.log(`anchored seq ${anchored.seq}; chain: ${chain.map((c) => c.subject.replace(/\n/g, ", ")).join(" <- ")}`);
