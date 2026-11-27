// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// PRV-9 against real services: one anchor of a throwaway ledger, recorded by
// test/fixtures/anchor/record-real.ts through the engine's own `anchorLedger()` and the reference
// server's adapters, with DigiCert's public RFC 3161 time-stamp authority and Sigstore's public
// Rekor v2 log (log2025-1). Everything here is checked offline from the recorded files: the token's
// signature, its signing certificate and chain at the time it was stamped, the message imprint, the
// entry's signature, its inclusion proof and the log's signed checkpoint. No network.
import { strict as assert } from "node:assert";
import { X509Certificate, createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { RekorAnchor, TimestampAuthorityAnchor } from "../examples/reference-server/src/anchor-adapters.ts";
import type { AuditEntry } from "../src/core/adapters.ts";
import { anchorPayload, checkRekorEntry, checkTimestamp, readDer, timestampTokenFields, verifyAnchor, type RekorLog } from "../src/prove/anchor.ts";
import { verifyChain } from "../src/prove/ledger.ts";
import { keyPairSigner, signReceipt, verifyReceipt, type ReceiptBody, type SignedReceipt } from "../src/prove/receipt.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { fixtureSigner } from "./fixtures/anchor/build.ts";

const fixture = (file: string): Buffer => readFileSync(new URL(`./fixtures/anchor/real/${file}`, import.meta.url));
const pems = (text: string): X509Certificate[] => text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!.map((p) => new X509Certificate(p));

const recording = JSON.parse(fixture("recording.json").toString()) as { tsa: string; rekor: string; origin: string; nonce: string; anchoredSeq: number };
const entries = JSON.parse(fixture("ledger.json").toString()) as AuditEntry[];
const anchored = entries.at(-1)!;
const proof = (anchored.detail as { proof: { kind: string; token: string; entry: string } }).proof;
const covered = entries.slice(0, (anchored.detail as { seq: number }).seq);
const head = covered.at(-1)!;
const payload = anchorPayload(head);
/** DigiCert's chain: the Timestamp Responder, its 2025 CA, and DigiCert Trusted Root G4. */
const chain = pems(fixture("tsa-chain.pem").toString());
const [leaf, intermediate, root] = chain as [X509Certificate, X509Certificate, X509Certificate];
const log: RekorLog = { key: createPublicKey(fixture("rekor-log.pem")), origin: recording.origin };
const trust = { tsa: chain, rekor: log };
const tsaReply = Buffer.from(fixture("tsa-response.der.b64").toString(), "base64");
const rawEntry = Buffer.from(proof.entry, "base64");

/** The base64 of a Rekor entry after `change` edits its parsed JSON. */
function editedEntry(change: (entry: { logIndex: string; inclusionProof: { hashes: string[]; checkpoint: { envelope: string } } }) => void): string {
  const entry = JSON.parse(rawEntry.toString("utf8")) as Parameters<typeof change>[0];
  change(entry);
  return Buffer.from(JSON.stringify(entry)).toString("base64");
}

describe("PRV-9 recorded against DigiCert's TSA and Sigstore's Rekor v2", () => {
  it("is one anchor of a throwaway ledger, made through the engine and the reference server's adapters", () => {
    assert.equal(recording.tsa, "http://timestamp.digicert.com");
    assert.equal(recording.rekor, "https://log2025-1.rekor.sigstore.dev");
    assert.equal(anchored.event, "ledger.anchored");
    assert.equal(anchored.seq, recording.anchoredSeq);
    assert.equal(proof.kind, "rekor");
    // Two test calls and their receipts, then the anchor: nothing else.
    assert.deepEqual(
      entries.map((e) => e.event),
      ["call.started", "call.ended", "receipt.issued", "call.started", "call.ended", "receipt.issued", "ledger.anchored"],
    );
    const chained = verifyChain(entries);
    assert.equal(chained.ok, true);
  });

  it("verifies offline: the chain to the head, DigiCert's token over it, and the Rekor entry", () => {
    const result = verifyAnchor(anchored, entries, trust);
    assert.deepEqual(result, { ok: true, seq: head.seq, hash: head.hash, time: "2026-11-20T14:58:58.000Z", logIndex: 207735101 });
  });

  it("keeps verifying after every certificate in DigiCert's chain has expired: the chain is checked at the stamped time", (t) => {
    const later = Date.parse("2040-01-01T00:00:00Z");
    for (const cert of chain) assert.ok(cert.validToDate.getTime() < later, `${cert.subject} expires before the clock below`);
    t.mock.timers.enable({ apis: ["Date"], now: later });
    assert.equal(new Date().getUTCFullYear(), 2040);
    assert.equal(verifyAnchor(anchored, entries, trust).ok, true);
    t.mock.timers.reset();
  });

  it("is refused for a chain changed after it was anchored, or a head it does not cover", () => {
    const changed = entries.map((e) => (e.seq === 2 ? { ...e, at: "2026-11-20T15:00:00.000Z" } : e));
    assert.deepEqual(verifyAnchor(anchored, changed, trust), { ok: false, reason: "chain" });
    // The token is over seq 6's head: claimed for seq 5, the imprint does not match.
    const earlier = { ...anchored, detail: { ...(anchored.detail as object), seq: 5 } };
    assert.deepEqual(verifyAnchor(earlier, entries, trust), { ok: false, reason: "imprint" });
  });
});

describe("the recorded DigiCert time-stamp token", () => {
  it("is the token of a granted TimeStampResp, carrying the request's nonce and a SHA-256 imprint of the head", () => {
    const [resp] = readDer(tsaReply);
    const [status, token] = readDer(resp!.value);
    assert.deepEqual([...readDer(status!.value)[0]!.raw], [0x02, 0x01, 0x00]);
    assert.equal(Buffer.from(token!.raw).toString("base64"), proof.token);
    const fields = timestampTokenFields(proof.token)!;
    assert.equal(fields.imprintHash, "sha256");
    assert.equal(Buffer.from(fields.nonce!).toString("hex"), recording.nonce);
    assert.deepEqual(checkTimestamp(proof.token, payload, chain), { ok: true, time: "2026-11-20T14:58:58.000Z" });
  });

  it("names DigiCert's responder in SigningCertificate (SHA-1) and SigningCertificateV2 (SHA-256) and chains to Trusted Root G4", () => {
    const der = Buffer.from(proof.token, "base64");
    // The ESSCertID hashes, as signed, are the responder's certificate hashes.
    assert.ok(der.includes(createHash("sha1").update(leaf.raw).digest()));
    assert.ok(der.includes(createHash("sha256").update(leaf.raw).digest()));
    assert.match(leaf.subject, /CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1/);
    assert.match(intermediate.subject, /CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1/);
    assert.match(root.subject, /CN=DigiCert Trusted Root G4/);
    assert.equal(root.checkIssued(root), true);
    // The root is the one in public CA stores, by its SHA-256 fingerprint.
    assert.equal(root.fingerprint256, "55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88");
  });

  it("is refused for another payload, a chain without the intermediate or under another root, and a changed signature", () => {
    assert.deepEqual(checkTimestamp(proof.token, anchorPayload({ seq: head.seq, hash: "0".repeat(64) }), chain), { ok: false, reason: "imprint" });
    assert.deepEqual(checkTimestamp(proof.token, payload, [leaf, root]), { ok: false, reason: "certificate" });
    // The intermediate is not the signer: its key does not verify the signature.
    assert.deepEqual(checkTimestamp(proof.token, payload, [intermediate, root]), { ok: false, reason: "token" });
    // The responder alone, trusted as given, still names the right certificate: refusing it is the host's choice of chain.
    assert.deepEqual(checkTimestamp(proof.token, payload, [leaf, intermediate]), { ok: true, time: "2026-11-20T14:58:58.000Z" });
    const changed = Buffer.from(proof.token, "base64");
    changed[changed.length - 1]! ^= 0x01;
    assert.deepEqual(checkTimestamp(changed.toString("base64"), payload, chain), { ok: false, reason: "token" });
  });
});

describe("the recorded Rekor v2 entry", () => {
  it("is a hashedrekord of the head under the fixture signer, in log2025-1, whose log id is the C2SP key hash", () => {
    assert.deepEqual(checkRekorEntry(proof.entry, payload, log), { ok: true, logIndex: 207735101 });
    const entry = JSON.parse(rawEntry.toString("utf8")) as { logId: { keyId: string }; canonicalizedBody: string; inclusionProof: { checkpoint: { envelope: string } } };
    // The readable copy is the same JSON as the bytes Rekor answered.
    assert.deepEqual(JSON.parse(fixture("rekor-response.json").toString()), entry);
    const body = JSON.parse(Buffer.from(entry.canonicalizedBody, "base64").toString()) as { spec: { hashedRekordV002: { signature: { verifier: { publicKey: { rawBytes: string } } } } } };
    const signer = createPublicKey({ key: Buffer.from(body.spec.hashedRekordV002.signature.verifier.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
    assert.ok(signer.equals(fixtureSigner().publicKey));
    const spki = log.key.export({ type: "spki", format: "der" });
    assert.equal(log.key.asymmetricKeyType, "ed25519");
    assert.equal(createHash("sha256").update(`${log.origin}\n\u0001`).update(spki.subarray(12)).digest("base64"), entry.logId.keyId);
    // Witnesses cosign the checkpoint too; only the log's own signature is checked.
    assert.ok(entry.inclusionProof.checkpoint.envelope.split("\n").filter((line) => line.startsWith("\u2014 ")).length > 1);
  });

  it("is refused under another log key or origin, with a changed proof hash, a wrong index or a shortened path", () => {
    const otherKey = generateKeyPairSync("ed25519").publicKey;
    assert.deepEqual(checkRekorEntry(proof.entry, payload, { key: otherKey, origin: log.origin }), { ok: false, reason: "log" });
    assert.deepEqual(checkRekorEntry(proof.entry, payload, { key: log.key, origin: "log2026-1.rekor.sigstore.dev" }), { ok: false, reason: "log" });
    assert.deepEqual(checkRekorEntry(proof.entry, anchorPayload({ seq: 5, hash: covered[4]!.hash }), log), { ok: false, reason: "log" });
    const flipped = editedEntry((e) => {
      const hash = Buffer.from(e.inclusionProof.hashes[3]!, "base64");
      hash[0]! ^= 0x01;
      e.inclusionProof.hashes[3] = hash.toString("base64");
    });
    assert.deepEqual(checkRekorEntry(flipped, payload, log), { ok: false, reason: "log" });
    assert.deepEqual(checkRekorEntry(editedEntry((e) => void (e.logIndex = "207735102")), payload, log), { ok: false, reason: "log" });
    assert.deepEqual(checkRekorEntry(editedEntry((e) => void e.inclusionProof.hashes.pop()), payload, log), { ok: false, reason: "log" });
    const resigned = editedEntry((e) => {
      e.inclusionProof.checkpoint.envelope = e.inclusionProof.checkpoint.envelope.replace(/^(.*\n)(\d+)\n/, (_m, origin: string, size: string) => `${origin}${BigInt(size) + 1n}\n`);
    });
    assert.deepEqual(checkRekorEntry(resigned, payload, log), { ok: false, reason: "log" });
    // A Rekor proof without the log's key is refused, never passed on the token alone.
    assert.deepEqual(verifyAnchor(anchored, entries, { tsa: chain }), { ok: false, reason: "log" });
  });

  it("the head as logged, signed by the host key, never verifies as a receipt under that key", async () => {
    const body = JSON.parse(Buffer.from((JSON.parse(rawEntry.toString()) as { canonicalizedBody: string }).canonicalizedBody, "base64").toString()) as {
      spec: { hashedRekordV002: { signature: { content: string } } };
    };
    // Rekor holds an ASN.1 ECDSA signature; a receipt carries r and s, 32 bytes each.
    const [sequence] = readDer(Buffer.from(body.spec.hashedRekordV002.signature.content, "base64"));
    const raw = Buffer.concat(readDer(sequence!.value).map((n) => Buffer.from(n.value).subarray(-32).toString("hex").padStart(64, "0")).map((h) => Buffer.from(h, "hex")));
    const keys = [{ ...fixtureSigner().publicKey.export({ format: "jwk" }), kid: "fixture" }];
    const asReceipt = (receiptBody: unknown): SignedReceipt => ({ body: receiptBody as ReceiptBody, alg: "ES256", kid: "fixture", signature: raw.toString("base64url") });
    assert.equal(verifyReceipt(asReceipt({ seq: head.seq, hash: head.hash }), keys), false);
    assert.equal(verifyReceipt(asReceipt(new TextDecoder().decode(payload)), keys), false);
    assert.equal(verifyReceipt(asReceipt(JSON.parse(canonicalJson({ seq: head.seq, hash: head.hash }))), keys), false);
    // The controls: r and s are the logged signature over the anchor payload, and the key verifies a real receipt.
    assert.equal(verify("sha256", payload, { key: fixtureSigner().publicKey, dsaEncoding: "ieee-p1363" }, raw), true);
    assert.equal(verifyReceipt(await signReceipt(keyPairSigner("fixture", fixtureSigner().privateKey.export({ format: "jwk" })), { seq: head.seq, hash: head.hash } as unknown as ReceiptBody), keys), true);
  });
});

describe("the reference server's adapters, replaying the recorded answers", () => {
  /** A fetch answering DigiCert's reply, then Rekor's, and keeping the requests. */
  function replay() {
    const replies = [tsaReply, rawEntry];
    const urls: string[] = [];
    const fetch = async (url: string): Promise<Response> => {
      urls.push(url);
      return new Response(new Uint8Array(replies.shift()!), { status: 200 });
    };
    return { fetch, urls };
  }

  it("RekorAnchor accepts the real answers and makes the recorded proof", async () => {
    const { fetch, urls } = replay();
    const timestamps = new TimestampAuthorityAnchor({ url: recording.tsa, chain, fetch, nonce: () => Buffer.from(recording.nonce, "hex") });
    const anchor = new RekorAnchor({ url: recording.rekor, signingKey: fixtureSigner().privateKey, log, timestamps, fetch });
    assert.deepEqual(await anchor.anchor({ seq: head.seq, hash: head.hash, payload }), proof);
    assert.deepEqual(urls, [recording.tsa, `${recording.rekor}/api/v2/log/entries`]);
  });

  it("refuses the real token as the answer to a request with another nonce, and the real entry under another host key", async () => {
    const other = replay();
    const stale = new TimestampAuthorityAnchor({ url: recording.tsa, chain, fetch: other.fetch, nonce: () => Buffer.from("4000000000000001", "hex") });
    await assert.rejects(stale.timestamp(payload), /does not carry this request's nonce/);
    const { fetch } = replay();
    const timestamps = new TimestampAuthorityAnchor({ url: recording.tsa, chain, fetch, nonce: () => Buffer.from(recording.nonce, "hex") });
    const anchor = new RekorAnchor({ url: recording.rekor, signingKey: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey, log, timestamps, fetch });
    await assert.rejects(anchor.anchor({ seq: head.seq, hash: head.hash, payload }), /signed by another key/);
  });
});

