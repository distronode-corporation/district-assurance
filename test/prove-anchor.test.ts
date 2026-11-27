// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Public timestamp anchors for the ledger (PRV-9): the anchor payload, the DER reader, the engine's
// `anchorLedger`, offline checks with `verifyAnchor`, and the reference server's two adapters
// replaying recorded answers (test/fixtures/anchor, written by record.ts from a throwaway authority
// and log, for the failure paths). The answers of DigiCert's TSA and Sigstore's Rekor v2 are
// replayed in prove-anchor-real.test.ts. No network.
import { strict as assert } from "node:assert";
import { X509Certificate, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { RekorAnchor, TimestampAuthorityAnchor, timestampRequest } from "../examples/reference-server/src/anchor-adapters.ts";
import type { AnchorProof, AuditEntry } from "../src/core/adapters.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { ENGINE_EVENTS, type EngineEvent } from "../src/core/events.ts";
import { ANCHOR_CONTEXT, anchorPayload, checkRekorEntry, checkTimestamp, isAnchorProof, readDer, verifyAnchor, type RekorLog } from "../src/prove/anchor.ts";
import { GENESIS_HASH, chainEntry, verifyChain } from "../src/prove/ledger.ts";
import { signReceipt, verifyReceipt, type ReceiptBody, type SignedReceipt } from "../src/prove/receipt.ts";
import { FakeTimestampAuthority, FixedClock, generateTestSigner } from "../src/testing/fakes.ts";
import * as root from "../src/index.ts";
import * as testing from "../src/testing/index.ts";
import { createTestEngine } from "../src/testing/index.ts";
import {
  FIXTURE_NONCE,
  OIDS,
  REKOR_ORIGIN,
  algorithm,
  certificate,
  der,
  explicit0,
  fixtureLedger,
  fixtureSigner,
  hashedRekordBody,
  int,
  logEntry,
  octets,
  oid,
  seq,
  set,
  text,
  timestampResponse,
  timestampToken,
  type CertificateSpec,
  type TokenSpec,
} from "./fixtures/anchor/build.ts";
import { rejects } from "./helpers.ts";

const fixture = (file: string): Buffer => readFileSync(new URL(`./fixtures/anchor/${file}`, import.meta.url));
const recordedChain = fixture("tsa-chain.pem")
  .toString()
  .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!
  .map((part) => new X509Certificate(part));
const recordedTimestamp = Buffer.from(fixture("tsa-response.der.b64").toString(), "base64");
const recordedLog: RekorLog = { key: createPublicKey(fixture("rekor-log.pem")), origin: REKOR_ORIGIN };
const recordedEntry = fixture("rekor-response.json");

type FetchInit = { method: string; headers: Record<string, string>; body: Uint8Array | string };

/** A fetch that answers each call with the next recorded reply, and keeps the requests. */
function replay(...replies: Array<{ status?: number; body: Uint8Array }>) {
  const requests: Array<{ url: string; init: FetchInit }> = [];
  const fetch = async (url: string, init: FetchInit): Promise<Response> => {
    requests.push({ url, init });
    const reply = replies.shift()!;
    return new Response(new Uint8Array(reply.body), { status: reply.status ?? 200 });
  };
  return { fetch, requests };
}

/** A ledger with a few entries and an engine anchoring it with the fake authority. */
async function anchoredEngine() {
  const t = createTestEngine();
  const tsa = new FakeTimestampAuthority(t.clock);
  const engine = createTestEngine({ adapters: { ledger: t.ledger, anchor: tsa } }).engine;
  const { callId } = await engine.startCall();
  await engine.endCall(callId);
  t.clock.advance(60_000);
  return { ...t, engine, tsa };
}

const ecKeys = () => generateKeyPairSync("ec", { namedCurve: "P-256" });

describe("anchor payload", () => {
  it("is domain-separated: a context line, then the head as canonical JSON", () => {
    const head = { seq: 3, hash: "a".repeat(64) };
    assert.equal(new TextDecoder().decode(anchorPayload(head)), `${ANCHOR_CONTEXT}\n{"hash":"${"a".repeat(64)}","seq":3}`);
    assert.ok(ENGINE_EVENTS.includes("ledger.anchored"));
  });

  it("the entry points export the anchor pieces", () => {
    for (const name of ["anchorPayload", "verifyAnchor", "checkTimestamp", "checkRekorEntry", "readDer", "isAnchorProof", "timestampTokenFields", "ANCHOR_CONTEXT"]) assert.ok(name in root, name);
    assert.ok("FakeTimestampAuthority" in testing);
  });

  it("a head signed with the receipt key never verifies as a receipt", async () => {
    const signer = generateTestSigner("anchor-and-receipts");
    const keys = [signer.publicJwk()];
    const head = { seq: 3, hash: "b".repeat(64) };
    const signature = Buffer.from(await signer.sign(anchorPayload(head))).toString("base64url");
    const asReceipt = (body: unknown): SignedReceipt => ({ body: body as ReceiptBody, alg: "ES256", kid: signer.keyId, signature });
    assert.equal(verifyReceipt(asReceipt(head), keys), false);
    assert.equal(verifyReceipt(asReceipt(new TextDecoder().decode(anchorPayload(head))), keys), false);
    assert.equal(verifyReceipt(asReceipt(JSON.parse(canonicalJson(head))), keys), false);
    // The same key and the same kind of body do verify when signed as a receipt.
    assert.equal(verifyReceipt(await signReceipt(signer, head as unknown as ReceiptBody), keys), true);
  });

  it("knows a proof's shape", () => {
    const token = Buffer.from("token").toString("base64");
    assert.equal(isAnchorProof({ kind: "rfc3161", token }), true);
    assert.equal(isAnchorProof({ kind: "rekor", token, entry: token }), true);
    for (const bad of [null, "x", { kind: "other", token }, { kind: "rfc3161", token, entry: token }, { kind: "rekor", token }, { kind: "rfc3161", token: 1 }, { kind: "rfc3161", token: "abc" }, { kind: "rfc3161", token: "ab!=" }]) {
      assert.equal(isAnchorProof(bad), false, JSON.stringify(bad));
    }
  });
});

describe("DER reader", () => {
  it("reads short and long lengths, one level deep", () => {
    const long = der(0x04, Buffer.alloc(300, 1));
    assert.deepEqual(readDer(new Uint8Array()), []);
    const [a, b] = readDer(Buffer.concat([int(5), long]));
    assert.equal(a!.tag, 0x02);
    assert.deepEqual([...a!.value], [5]);
    assert.equal(b!.value.length, 300);
    assert.equal(b!.raw.length, 304);
  });

  it("refuses what it does not read", () => {
    for (const bytes of [[0x30], [0x1f, 0x00], [0x30, 0x80], [0x30, 0x85, 0, 0, 0, 0, 1], [0x30, 0x82, 0x01], [0x30, 0x05, 0x00]]) {
      assert.throws(() => readDer(Buffer.from(bytes)), TypeError, JSON.stringify(bytes));
    }
  });
});

describe("anchorLedger", () => {
  it("anchors the head and appends ledger.anchored with the proof and the seq it covers", async () => {
    const { engine, ledger, tsa, clock } = await anchoredEngine();
    const head = await ledger.head();
    const entry = await engine.anchorLedger();
    assert.deepEqual(tsa.anchored, [head]);
    assert.equal(entry.event, "ledger.anchored");
    assert.equal(entry.callId, null);
    assert.equal(entry.actor, "system");
    assert.equal(entry.seq, head.seq + 1);
    assert.deepEqual(Object.keys(entry.detail).sort(), ["proof", "seq"]);
    assert.equal(entry.detail.seq, head.seq);
    const entries = await ledger.list();
    assert.deepEqual(verifyAnchor(entry, entries, { tsa: tsa.chain }), { ok: true, seq: head.seq, hash: head.hash, time: clock.now().toISOString(), logIndex: null });
    // The anchor entry is itself chained, and the next anchor covers it.
    assert.equal(verifyChain(entries).ok, true);
    const next = await engine.anchorLedger();
    assert.equal(next.detail.seq, entry.seq);
    assert.equal(verifyAnchor(next, await ledger.list(), { tsa: tsa.chain }).ok, true);
  });

  it("tells the listener after the append, and a failing listener never stops the anchor", async () => {
    const { ledger, tsa } = await anchoredEngine();
    const events: EngineEvent[] = [];
    const told = createTestEngine({ adapters: { ledger, anchor: tsa }, onEvent: (e) => events.push(e) }).engine;
    const entry = await told.anchorLedger();
    // Delivered events carry the entry's event id and seq (INT-5).
    assert.deepEqual(events, [{ name: "ledger.anchored", callId: null, actor: "system", at: entry.at, detail: entry.detail, eventId: entry.eventId, seq: entry.seq }]);
    for (const onEvent of [() => { throw new Error("listener down"); }, async () => { throw new Error("listener down"); }]) {
      const failing = createTestEngine({ adapters: { ledger, anchor: tsa }, onEvent }).engine;
      assert.equal((await failing.anchorLedger()).event, "ledger.anchored");
    }
  });

  it("checks offline: the exported entries and the authority's chain are enough", async () => {
    const { engine, ledger, tsa } = await anchoredEngine();
    await engine.anchorLedger();
    const exported = JSON.stringify(await ledger.list());
    const pemChain = tsa.chain.map((c) => c.toString());
    const entries = JSON.parse(exported) as AuditEntry[];
    const result = verifyAnchor(entries.at(-1)!, entries, { tsa: pemChain.map((p) => new X509Certificate(p)) });
    assert.equal(result.ok, true);
  });

  it("two engines anchoring the same head append one entry", async () => {
    const { engine, ledger, tsa } = await anchoredEngine();
    const other = createTestEngine({ adapters: { ledger, anchor: tsa } }).engine;
    const [a, b] = await Promise.all([engine.anchorLedger(), other.anchorLedger()]);
    assert.deepEqual(a, b);
    assert.equal((await ledger.list()).filter((e) => e.event === "ledger.anchored").length, 1);
  });

  it("refuses without an anchor adapter, on an empty ledger, and on a malformed proof", async () => {
    await assert.rejects(createTestEngine().engine.anchorLedger(), rejects("precondition_failed", /anchor adapter/));
    const t = createTestEngine();
    const tsa = new FakeTimestampAuthority(t.clock);
    const empty = createTestEngine({ adapters: { anchor: tsa } });
    await assert.rejects(empty.engine.anchorLedger(), rejects("precondition_failed", /empty/));
    assert.deepEqual(tsa.anchored, []);
    const broken = createTestEngine({ adapters: { anchor: { anchor: async () => ({ kind: "rfc3161", token: "not base64!" }) as AnchorProof } } });
    await broken.engine.startCall();
    await assert.rejects(broken.engine.anchorLedger(), rejects("invalid_input", /malformed proof/));
    assert.equal((await broken.ledger.list()).some((e) => e.event === "ledger.anchored"), false);
  });
});

describe("verifyAnchor", () => {
  async function anchored() {
    const t = await anchoredEngine();
    const entry = await t.engine.anchorLedger();
    return { ...t, entry, entries: await t.ledger.list() };
  }

  it("catches a chain rebuilt after it was anchored", async () => {
    const { entry, entries, tsa } = await anchored();
    // The operator changes entry 2 and recomputes every hash after it: the chain verifies on its own.
    const rebuilt: AuditEntry[] = [];
    for (const original of entries) {
      const { seq, prevHash: _p, hash: _h, ...input } = original;
      if (seq === 2) input.detail = { subject: "host" };
      rebuilt.push(chainEntry(input, seq, rebuilt.at(-1)?.hash ?? GENESIS_HASH));
    }
    assert.equal(verifyChain(rebuilt).ok, true);
    assert.deepEqual(verifyAnchor(rebuilt.at(-1)!, rebuilt, { tsa: tsa.chain }), { ok: false, reason: "imprint" });
    assert.equal(verifyAnchor(entry, entries, { tsa: tsa.chain }).ok, true);
  });

  it("refuses a changed token, a changed entry, or entries that do not reach the seq", async () => {
    const { entry, entries, tsa } = await anchored();
    const proof = entry.detail.proof as { kind: "rfc3161"; token: string };
    const bytes = Buffer.from(proof.token, "base64");
    bytes[bytes.length - 5]! ^= 0x01; // inside the signature
    const changed = { ...entry, detail: { ...entry.detail, proof: { ...proof, token: bytes.toString("base64") } } };
    assert.deepEqual(verifyAnchor(changed, entries, { tsa: tsa.chain }), { ok: false, reason: "token" });
    const edited = structuredClone(entries);
    edited[0]!.detail = { locale: "fr" };
    assert.deepEqual(verifyAnchor(entry, edited, { tsa: tsa.chain }), { ok: false, reason: "chain" });
    assert.deepEqual(verifyAnchor(entry, entries.slice(0, 2), { tsa: tsa.chain }), { ok: false, reason: "chain" });
    assert.deepEqual(verifyAnchor(entry, entries, { tsa: [] }), { ok: false, reason: "certificate" });
    // Another authority's chain: the signature is not its key's.
    assert.deepEqual(verifyAnchor(entry, entries, { tsa: new FakeTimestampAuthority(new FixedClock()).chain }), { ok: false, reason: "token" });
  });

  it("refuses a malformed anchor entry", async () => {
    const { entry, entries, tsa } = await anchored();
    for (const bad of [
      { ...entry, event: "module.event" as const },
      { ...entry, detail: { ...entry.detail, seq: 0 } },
      { ...entry, detail: { ...entry.detail, seq: 1.5 } },
      { ...entry, detail: { ...entry.detail, seq: "2" } },
      { ...entry, detail: { seq: entry.detail.seq! } },
    ]) {
      assert.deepEqual(verifyAnchor(bad, entries, { tsa: tsa.chain }), { ok: false, reason: "malformed" });
    }
    // Never throws, whatever it is handed: no entry, no detail, no entries, no chain.
    for (const [anchoredBad, entriesBad, trustBad] of [
      [null, entries, { tsa: tsa.chain }],
      [{ ...entry, detail: undefined }, entries, { tsa: tsa.chain }],
      [entry, null, { tsa: tsa.chain }],
      [entry, entries, {}],
      [entry, entries, null],
    ] as const) {
      assert.equal(verifyAnchor(anchoredBad as never, entriesBad as never, trustBad as never).ok, false);
    }
  });
});

describe("RFC 3161 tokens", () => {
  const payload = anchorPayload({ seq: 1, hash: "c".repeat(64) });
  const root = ecKeys();
  const leaf = ecKeys();
  const rootCert = certificate({ subject: "Root", issuer: "Root", publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true });
  const leafSpec = { subject: "TSA", issuer: "Root", publicKey: leaf.publicKey, signingKey: root.privateKey, serial: 2, notBefore: "260101000000Z", notAfter: "300101000000Z", usage: OIDS.timeStamping };
  const leafCert = certificate(leafSpec);
  const chain = [new X509Certificate(leafCert), new X509Certificate(rootCert)];
  const spec: TokenSpec = { payload, time: "20261118120000Z", signingKey: leaf.privateKey, issuer: "Root", serial: 2, signerCertificate: leafCert };
  const check = (overrides: Partial<TokenSpec>, certs: X509Certificate[] = chain) => checkTimestamp(timestampToken({ ...spec, ...overrides }).toString("base64"), payload, certs);

  it("accepts a token from a chain the host supplies, with any supported signature algorithm", () => {
    assert.deepEqual(check({}), { ok: true, time: "2026-11-18T12:00:00.000Z" });
    assert.deepEqual(check({ signatureAlgorithm: algorithm(OIDS.ecdsaSha256, false) }), { ok: true, time: "2026-11-18T12:00:00.000Z" });
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaLeaf = certificate({ ...leafSpec, publicKey: rsa.publicKey });
    const rsaChain = [new X509Certificate(rsaLeaf), chain[1]!];
    // rsaEncryption leaves the hash to the signer's digest algorithm.
    assert.equal(check({ signingKey: rsa.privateKey, signatureAlgorithm: algorithm(OIDS.rsaEncryption), signatureHash: "sha256", signerCertificate: rsaLeaf }, rsaChain).ok, true);
  });

  it("refuses a token for another payload as imprint", () => {
    assert.deepEqual(check({ payload: anchorPayload({ seq: 2, hash: "c".repeat(64) }) }), { ok: false, reason: "imprint" });
  });

  it("refuses a chain that does not hold at the token's time", () => {
    const other = ecKeys();
    const impostor = new X509Certificate(certificate({ subject: "Root", issuer: "Root", publicKey: other.publicKey, signingKey: other.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z" }));
    const { usage: _u, ...noUsage } = leafSpec;
    // Each token names the leaf it is checked with, so the chain is what refuses it, not the SigningCertificateV2.
    for (const [why, leafDer] of [
      ["no extended key usage", certificate(noUsage)],
      ["another extended key usage", certificate({ ...leafSpec, usage: OIDS.codeSigning })],
      ["expired at the token's time", certificate({ ...leafSpec, notAfter: "261101000000Z" })],
      ["not yet valid at the token's time", certificate({ ...leafSpec, notBefore: "261201000000Z" })],
    ] as const) {
      assert.deepEqual(check({ signerCertificate: leafDer }, [new X509Certificate(leafDer), chain[1]!]), { ok: false, reason: "certificate" }, why);
    }
    const strayDer = certificate({ ...leafSpec, issuer: "Someone else" });
    assert.deepEqual(check({ signerCertificate: strayDer, issuer: "Someone else" }, [new X509Certificate(strayDer), chain[1]!]), { ok: false, reason: "certificate" }, "issued by someone else");
    assert.deepEqual(check({}, [chain[0]!, impostor]), { ok: false, reason: "certificate" }, "an impostor root");
    assert.deepEqual(check({}, [chain[0]!]), { ok: true, time: "2026-11-18T12:00:00.000Z" });
  });

  it("refuses an intermediate that is not a CA allowed to issue, and honours pathLen", () => {
    const mid = ecKeys();
    const tsa = ecKeys();
    const midCert = (overrides: Partial<CertificateSpec> = {}) =>
      new X509Certificate(certificate({ subject: "Mid", issuer: "Root", publicKey: mid.publicKey, signingKey: root.privateKey, serial: 3, notBefore: "260101000000Z", notAfter: "300101000000Z", ...overrides }));
    const rootWith = (overrides: Partial<CertificateSpec>) =>
      new X509Certificate(certificate({ subject: "Root", issuer: "Root", publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true, ...overrides }));
    const tsaDer = certificate({ subject: "TSA", issuer: "Mid", publicKey: tsa.publicKey, signingKey: mid.privateKey, serial: 4, notBefore: "260101000000Z", notAfter: "300101000000Z", usage: OIDS.timeStamping });
    const tsaCert = new X509Certificate(tsaDer);
    const through = (...rest: X509Certificate[]) => check({ signingKey: tsa.privateKey, issuer: "Mid", serial: 4, signerCertificate: tsaDer }, [tsaCert, ...rest]);
    const bits = (bytes: number[]) => seq(oid(OIDS.keyUsage), octets(der(0x03, Buffer.from(bytes))));

    assert.deepEqual(through(midCert({ ca: true }), rootWith({})), { ok: true, time: "2026-11-18T12:00:00.000Z" }, "a CA intermediate");
    assert.equal(through(midCert({ ca: true, keyUsage: 0x06 }), rootWith({ pathLen: 1, keyUsage: 0x06 })).ok, true, "keyCertSign and a pathLen that allows it");
    for (const [why, intermediate, top] of [
      ["a leaf with no extensions as an intermediate", midCert(), rootWith({})],
      ["a leaf with extensions but no basicConstraints", midCert({ usage: OIDS.timeStamping }), rootWith({})],
      ["cA false (an empty basicConstraints)", midCert({ rawExtensions: [seq(oid(OIDS.basicConstraints), octets(seq()))] }), rootWith({})],
      ["a CA without keyCertSign", midCert({ ca: true, keyUsage: 0x80 }), rootWith({})],
      ["a keyUsage with no bits", midCert({ ca: true, rawExtensions: [bits([0])] }), rootWith({})],
      ["a basicConstraints that does not read (OpenSSL refuses the issuer first)", midCert({ rawExtensions: [seq(oid(OIDS.basicConstraints), octets(int(1)))] }), rootWith({})],
      ["a root whose pathLen 0 allows no CA below it", midCert({ ca: true }), rootWith({ pathLen: 0 })],
      ["a root that is not a CA", midCert({ ca: true }), rootWith({ ca: false })],
    ] as const) {
      assert.deepEqual(through(intermediate, top), { ok: false, reason: "certificate" }, why);
    }
  });

  it("refuses a token that is not a well-formed, signed TSTInfo", () => {
    const other = ecKeys();
    const imprint = seq(algorithm(OIDS.sha256), octets(Buffer.alloc(32)));
    const broken: Array<Partial<TokenSpec>> = [
      { signingKey: other.privateKey },
      { contentInfo: (sd) => seq(oid(OIDS.data), explicit0(sd)) },
      { contentInfo: (sd) => Buffer.concat([seq(oid(OIDS.signedData), explicit0(sd)), int(0)]) },
      { contentInfo: (sd) => seq(oid(OIDS.signedData), der(0xa1, sd)) },
      { signedData: (p) => seq(p.version, p.digests, seq(oid(OIDS.data), explicit0(octets(Buffer.alloc(1)))), p.signerInfos) },
      { signerInfos: (si) => set(si, si) },
      { tstInfo: ({ imprint: i }) => seq(int(1), oid(OIDS.policy), i, int(1), text(0x18, "2026-11-18 12:00")) },
      { tstInfo: ({ imprint: i }) => seq(int(1), oid(OIDS.policy), i, int(1), text(0x18, "20261318120000Z")) },
      { tstInfo: ({ time }) => seq(int(1), oid(OIDS.policy), seq(algorithm(OIDS.md5), octets(Buffer.alloc(16))), int(1), time) },
      { tstInfo: ({ time }) => seq(int(1), oid(OIDS.policy), seq(algorithm(OIDS.sha384), octets(Buffer.alloc(48))), int(1), time) },
      { tstInfo: ({ time }) => seq(int(1), oid(OIDS.policy), imprint, int(1), time) },
      { attributes: (p) => [seq(oid(OIDS.contentType), set(oid(OIDS.data))), p.messageDigest] },
      { attributes: (p) => [p.contentType, seq(oid(OIDS.messageDigest), set(octets(Buffer.alloc(32))))] },
      { attributes: (p) => [p.messageDigest] },
      { signatureAlgorithm: algorithm(OIDS.ed25519, false) },
    ];
    const results = broken.map((overrides) => check(overrides));
    // sha384 imprint over the right payload would pass; over zeros it is the wrong imprint.
    assert.deepEqual(results.map((r) => (r.ok ? "ok" : r.reason)), ["token", "token", "token", "token", "token", "token", "token", "token", "token", "imprint", "imprint", "token", "token", "token", "token"]);
    assert.deepEqual(checkTimestamp("", payload, chain), { ok: false, reason: "token" });
  });
});

describe("the time-stamp authority adapter, on a recorded answer", () => {
  it("asks for a SHA-256 imprint, checks the token, and the anchor verifies offline", async () => {
    const { ledger, entries } = await fixtureLedger();
    const head = await ledger.head();
    const { fetch, requests } = replay({ body: recordedTimestamp });
    // The recorded answer echoes FIXTURE_NONCE, so the request is made with it.
    const anchor = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch, nonce: () => FIXTURE_NONCE });
    const { engine } = createTestEngine({ adapters: { ledger, anchor } });
    const entry = await engine.anchorLedger();
    assert.equal(requests.length, 1);
    assert.equal(requests[0]!.init.headers["content-type"], "application/timestamp-query");
    assert.deepEqual(Buffer.from(requests[0]!.init.body as Uint8Array), timestampRequest(anchorPayload(head), FIXTURE_NONCE));
    assert.equal(readDer(timestampRequest(anchorPayload(head), FIXTURE_NONCE)).length, 1);
    assert.equal((entry.detail.proof as AnchorProof).kind, "rfc3161");
    assert.deepEqual(verifyAnchor(entry, [...entries, entry], { tsa: recordedChain }), { ok: true, ...head, time: "2026-11-18T12:00:00.250Z", logIndex: null });
    // The recorded chain is a root and a time-stamping certificate it issued.
    assert.equal(recordedChain.length, 2);
  });

  it("refuses an error, a refusal, an empty answer and a token that does not verify", async () => {
    const payload = anchorPayload(await (await fixtureLedger()).ledger.head());
    const answers: Array<{ status?: number; body: Uint8Array }> = [
      { status: 503, body: new Uint8Array() },
      { body: timestampResponse(2) },
      { body: new Uint8Array() },
      { body: recordedTimestamp },
    ];
    for (const [i, answer] of answers.entries()) {
      const chain = i === 3 ? new FakeTimestampAuthority(new FixedClock()).chain : recordedChain;
      const anchor = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain, fetch: replay(answer).fetch, nonce: () => FIXTURE_NONCE });
      await assert.rejects(anchor.timestamp(payload), Error);
    }
  });
});

describe("the Rekor adapter, on a recorded answer", () => {
  const entryB64 = recordedEntry.toString("base64");
  const mutate = (fn: (entry: any, body: any) => void, payloadBody = true): string => {
    const entry = JSON.parse(recordedEntry.toString());
    const body = JSON.parse(Buffer.from(entry.canonicalizedBody, "base64").toString());
    fn(entry, body);
    if (payloadBody) entry.canonicalizedBody = Buffer.from(JSON.stringify(body)).toString("base64");
    return Buffer.from(JSON.stringify(entry)).toString("base64");
  };

  it("logs the head signed by the host's key, takes the time from the authority, and verifies offline", async () => {
    const { ledger, entries } = await fixtureLedger();
    const head = await ledger.head();
    const payload = anchorPayload(head);
    // The authority is asked first, then Rekor.
    const { fetch, requests } = replay({ body: recordedTimestamp }, { body: recordedEntry });
    const timestamps = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch, nonce: () => FIXTURE_NONCE });
    const signingKey = fixtureSigner().privateKey;
    const anchor = new RekorAnchor({ url: "https://rekor.example.test/", signingKey, log: recordedLog, timestamps, fetch });
    const { engine } = createTestEngine({ adapters: { ledger, anchor } });
    const entry = await engine.anchorLedger();
    assert.equal(requests[0]!.url, "https://tsa.example.test/");
    assert.equal(requests[1]!.url, "https://rekor.example.test/api/v2/log/entries");
    const sent = JSON.parse(requests[1]!.init.body as string).hashedRekordRequestV002;
    assert.equal(sent.digest, Buffer.from(await crypto.subtle.digest("SHA-256", payload)).toString("base64"));
    assert.equal(sent.signature.verifier.keyDetails, "PKIX_ECDSA_P256_SHA_256");
    const proof = entry.detail.proof as Extract<AnchorProof, { kind: "rekor" }>;
    assert.equal(proof.kind, "rekor");
    assert.deepEqual(verifyAnchor(entry, [...entries, entry], { tsa: recordedChain, rekor: recordedLog }), { ok: true, ...head, time: "2026-11-18T12:00:00.250Z", logIndex: 9 });
    assert.deepEqual(verifyAnchor(entry, [...entries, entry], { tsa: recordedChain }), { ok: false, reason: "log" });
    // The time comes only from the authority: a bad token fails the whole proof.
    const badToken = { ...entry, detail: { ...entry.detail, proof: { ...proof, token: Buffer.from("garbage!").toString("base64") } } };
    assert.deepEqual(verifyAnchor(badToken, [...entries, entry], { tsa: recordedChain, rekor: recordedLog }), { ok: false, reason: "token" });
  });

  it("refuses a key that is not P-256, an error answer and an entry that does not verify, each for its own cause", async () => {
    const tsaSpy = replay();
    const unused = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: tsaSpy.fetch });
    assert.throws(() => new RekorAnchor({ url: "https://r.example.test", signingKey: generateKeyPairSync("ed25519").privateKey, log: recordedLog, timestamps: unused }), TypeError);
    assert.equal(tsaSpy.requests.length, 0, "a refused key asks no one");
    const head = await (await fixtureLedger()).ledger.head();
    const input = { ...head, payload: anchorPayload(head) };
    // The recorded entry for another payload: it does not verify for this one.
    const otherHead = anchorPayload({ seq: 1, hash: "d".repeat(64) });
    const otherBody = hashedRekordBody(otherHead, sign("sha256", otherHead, fixtureSigner().privateKey), fixtureSigner().publicKey);
    const log = generateKeyPairSync("ed25519");
    const otherEntry = Buffer.from(JSON.stringify(logEntry({ body: otherBody, index: 0, size: 1, origin: REKOR_ORIGIN, logKey: log.privateKey, logPublicKey: log.publicKey })));
    for (const [reply, cause] of [
      [{ status: 500, body: new Uint8Array() }, /^Rekor answered 500$/],
      [{ body: otherEntry }, /^the Rekor entry does not verify$/],
    ] as const) {
      // The authority answers first, with the recorded token for this head, so the failure is Rekor's.
      const tsa = replay({ body: recordedTimestamp });
      const rekor = replay(reply);
      const timestamps = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: tsa.fetch, nonce: () => FIXTURE_NONCE });
      const anchor = new RekorAnchor({ url: "https://r.example.test", signingKey: fixtureSigner().privateKey, log: recordedLog, timestamps, fetch: rekor.fetch });
      await assert.rejects(anchor.anchor(input), (e: Error) => cause.test(e.message));
      assert.equal(tsa.requests.length, 1);
      assert.equal(rekor.requests.length, 1);
    }
  });

  it("refuses a valid entry for the same head under another key", async () => {
    const head = await (await fixtureLedger()).ledger.head();
    const tsa = replay({ body: recordedTimestamp });
    const timestamps = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: tsa.fetch, nonce: () => FIXTURE_NONCE });
    const { fetch, requests } = replay({ body: recordedEntry });
    const anchor = new RekorAnchor({ url: "https://r.example.test", signingKey: ecKeys().privateKey, log: recordedLog, timestamps, fetch });
    await assert.rejects(anchor.anchor({ ...head, payload: anchorPayload(head) }), /another key/);
    assert.equal(tsa.requests.length, 1);
    assert.equal(requests.length, 1);
  });

  it("checks the body, the signature, the inclusion proof and the checkpoint", async () => {
    const payload = anchorPayload(await (await fixtureLedger()).ledger.head());
    assert.deepEqual(checkRekorEntry(entryB64, payload, recordedLog), { ok: true, logIndex: 9 });
    const otherLog = generateKeyPairSync("ed25519");
    const broken = [
      mutate((_e, b) => (b.kind = "dsse")),
      mutate((_e, b) => (b.spec.hashedRekordV002.data.algorithm = "SHA2_384")),
      mutate((_e, b) => (b.spec.hashedRekordV002.data.digest = Buffer.alloc(32).toString("base64"))),
      mutate((_e, b) => (b.spec.hashedRekordV002.signature.content = sign("sha256", Buffer.from("other"), ecKeys().privateKey).toString("base64"))),
      mutate((e) => (e.inclusionProof.rootHash = Buffer.alloc(32).toString("base64")), false),
      mutate((e) => e.inclusionProof.hashes.push(Buffer.alloc(32).toString("base64")), false),
      mutate((e) => e.inclusionProof.hashes.pop(), false),
      // The index read is the top-level one; with the inner copy gone, nothing else can supply it.
      mutate((e) => { e.logIndex = "11"; delete e.inclusionProof.logIndex; }, false),
      mutate((e) => { e.logIndex = "-1"; delete e.inclusionProof.logIndex; }, false),
      mutate((e) => { e.logIndex = "nine"; delete e.inclusionProof.logIndex; }, false),
      mutate((e) => { e.logIndex = "8"; delete e.inclusionProof.logIndex; }, false),
      // An inner copy that disagrees with the top-level index is refused, never preferred.
      mutate((e) => (e.inclusionProof.logIndex = "8"), false),
      mutate((e) => (e.inclusionProof.checkpoint.envelope = e.inclusionProof.checkpoint.envelope.replace(REKOR_ORIGIN, "other.example.test")), false),
      mutate((e) => (e.inclusionProof.checkpoint.envelope = e.inclusionProof.checkpoint.envelope.replace("\n\n", "\n")), false),
      mutate((e) => (e.inclusionProof.checkpoint.envelope = e.inclusionProof.checkpoint.envelope.replace(/ (\S+)\n$/, (_m: string, sig: string) => {
        const bytes = Buffer.from(sig, "base64");
        bytes[0]! ^= 1;
        return ` ${bytes.toString("base64")}\n`;
      })), false),
      mutate((e) => (e.inclusionProof.checkpoint.envelope = e.inclusionProof.checkpoint.envelope.replace(/ (\S+)\n$/, (_m: string, sig: string) => {
        const bytes = Buffer.from(sig, "base64");
        bytes[10]! ^= 1;
        return ` ${bytes.toString("base64")}\n`;
      })), false),
      Buffer.from("not json").toString("base64"),
    ];
    for (const [i, entry] of broken.entries()) assert.deepEqual(checkRekorEntry(entry, payload, recordedLog), { ok: false, reason: "log" }, String(i));
    assert.deepEqual(checkRekorEntry(entryB64, payload, { key: otherLog.publicKey, origin: REKOR_ORIGIN }), { ok: false, reason: "log" });
    assert.deepEqual(checkRekorEntry(entryB64, payload, { key: generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey, origin: REKOR_ORIGIN }), { ok: false, reason: "log" });
  });

  it("accepts a log with an ECDSA key, and an entry at any place in the tree", () => {
    const payload = anchorPayload({ seq: 4, hash: "e".repeat(64) });
    const signer = ecKeys();
    const body = hashedRekordBody(payload, sign("sha256", payload, signer.privateKey), signer.publicKey);
    const log = ecKeys();
    const trust = { key: log.publicKey, origin: REKOR_ORIGIN };
    for (const [index, size] of [[0, 1], [0, 2], [1, 2], [4, 6], [5, 7], [6, 7], [3, 8]] as const) {
      const entry = logEntry({ body, index, size, origin: REKOR_ORIGIN, logKey: log.privateKey, logPublicKey: log.publicKey });
      assert.deepEqual(checkRekorEntry(Buffer.from(JSON.stringify(entry)).toString("base64"), payload, trust), { ok: true, logIndex: index }, `${index}/${size}`);
    }
  });
});

// Keeps the recorded files honest: they are what record.ts writes for fixtureLedger's head.
describe("recorded fixtures", () => {
  it("cover the fixture ledger's head", async () => {
    const { entries } = await fixtureLedger();
    const check = verifyChain(entries);
    assert.ok(check.ok);
    assert.equal(check.head.seq, 5);
    const payload = anchorPayload(check.head);
    const [, token] = readDer(readDer(recordedTimestamp)[0]!.value);
    assert.equal(checkTimestamp(Buffer.from(token!.raw).toString("base64"), payload, recordedChain).ok, true);
    assert.deepEqual(checkRekorEntry(recordedEntry.toString("base64"), payload, recordedLog), { ok: true, logIndex: 9 });
  });
});

describe("verifyAnchor reads what it is handed once", () => {
  it("verifies the trust and the proof that passed its checks, and never throws on a changing object", async () => {
    const { engine, ledger, tsa } = await anchoredEngine();
    const entry = await engine.anchorLedger();
    const entries = await ledger.list();
    let trustReads = 0;
    const trust = {
      get tsa() {
        trustReads += 1;
        return trustReads === 1 ? tsa.chain : "not a chain";
      },
    };
    assert.equal(verifyAnchor(entry, entries, trust as never).ok, true, "the chain checked is the chain used");
    const proof = entry.detail.proof as Record<string, unknown>;
    let tokenReads = 0;
    const changing = {
      kind: proof.kind,
      get token() {
        tokenReads += 1;
        return tokenReads === 1 ? proof.token : 42;
      },
    };
    const swapped = { ...entry, detail: { seq: entry.detail.seq, proof: changing } };
    assert.equal(verifyAnchor(swapped as never, entries, { tsa: tsa.chain }).ok, true, "the token checked is the token verified");
    const odd = { ...entry, detail: { seq: entry.detail.seq, proof: { kind: "rfc3161", token: () => "x" } } };
    assert.deepEqual(verifyAnchor(odd as never, entries, { tsa: tsa.chain }), { ok: false, reason: "malformed" });
  });
});
