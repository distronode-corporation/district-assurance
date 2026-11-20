// Review regressions for PR #133 (PRV-9, ledger anchors): what verifyAnchor, isAnchorProof and
// checkRekorEntry accept, the ESS signing-certificate check, the reference adapters' reply cap,
// nonce, imprint and ordering, and the fixture builders. Each test here failed before its fix.
import { strict as assert } from "node:assert";
import { X509Certificate, createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { MAX_REPLY_BYTES, RekorAnchor, TimestampAuthorityAnchor, timestampRequest } from "../examples/reference-server/src/anchor-adapters.ts";
import type { AnchorProof } from "../src/core/adapters.ts";
import { anchorPayload, checkRekorEntry, checkTimestamp, isAnchorProof, readDer, timestampTokenFields, verifyAnchor, type RekorLog } from "../src/prove/anchor.ts";
import { FakeTimestampAuthority, FixedClock } from "../src/testing/fakes.ts";
import { createTestEngine } from "../src/testing/index.ts";
import {
  FIXTURE_NONCE,
  OIDS,
  REKOR_ORIGIN,
  algorithm,
  certificate,
  der,
  essCertId,
  essCertIdV2,
  fixtureLedger,
  fixtureSigner,
  hashedRekordBody,
  int,
  issuerSerial,
  logEntry,
  merkleRoot,
  octets,
  oid,
  seq,
  signingCertificate,
  timestampResponse,
  timestampToken,
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

/** A fetch that answers each call with the next reply, and keeps the requests. */
function spy(...replies: Array<{ status?: number; body: Uint8Array } | (() => Response)>) {
  const requests: Array<{ url: string; init: FetchInit }> = [];
  const fetch = async (url: string, init: FetchInit): Promise<Response> => {
    requests.push({ url, init });
    const reply = replies.shift();
    if (reply === undefined) throw new Error("no reply left: an unexpected request");
    return typeof reply === "function" ? reply() : new Response(new Uint8Array(reply.body), { status: reply.status ?? 200 });
  };
  return { fetch, requests };
}

/** A reply streamed in chunks, which notes how far it was read and whether it was cancelled. */
function streamed(bytes: Uint8Array, chunk = 1024) {
  const state = { pulled: 0, cancelled: false };
  let offset = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(offset, offset + chunk));
      offset += chunk;
      state.pulled += 1;
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { response: () => new Response(body), state };
}

const fixedNonce = () => Buffer.from(FIXTURE_NONCE);


async function anchored(clock?: FixedClock) {
  const t = createTestEngine();
  const tsa = new FakeTimestampAuthority(clock ?? t.clock);
  const engine = createTestEngine({ adapters: { ledger: t.ledger, anchor: tsa } }).engine;
  const { callId } = await engine.startCall();
  await engine.endCall(callId);
  const entry = await engine.anchorLedger();
  return { ...t, tsa, engine, entry, entries: await t.ledger.list() };
}

const ecKeys = () => generateKeyPairSync("ec", { namedCurve: "P-256" });

describe("review #133: verifyAnchor on a malformed export", () => {
  it("a covered prefix holding null or a non-entry is a failed check, never a throw", async () => {
    const { entry, entries, tsa } = await anchored();
    for (const bad of [[null, ...entries], [entries[0], undefined, ...entries.slice(2)]]) {
      assert.deepEqual(verifyAnchor(entry, bad as never, { tsa: tsa.chain }), { ok: false, reason: "malformed" });
    }
    // A value that reads, but as no entry, is a broken chain.
    assert.deepEqual(verifyAnchor(entry, [42, ...entries.slice(1)] as never, { tsa: tsa.chain }), { ok: false, reason: "chain" });
  });
});

describe("review #133: isAnchorProof reads only its own keys", () => {
  it("an inherited token or kind is refused, and the engine refuses such a proof", async () => {
    const token = Buffer.from("token").toString("base64");
    assert.equal(isAnchorProof(Object.assign(Object.create({ token }), { kind: "rfc3161", extra: "x" })), false, "inherited token");
    assert.equal(isAnchorProof(Object.assign(Object.create({ kind: "rfc3161" }), { token, other: token })), false, "inherited kind");
    assert.equal(isAnchorProof(Object.assign(Object.create({ entry: token }), { kind: "rekor", token, x: 1 })), false, "inherited entry");
    assert.equal(isAnchorProof({ token, entry: token }), false, "no kind");
    // A plain JSON proof is still a proof.
    assert.equal(isAnchorProof(JSON.parse(JSON.stringify({ kind: "rfc3161", token }))), true);
    assert.equal(isAnchorProof(JSON.parse(JSON.stringify({ entry: token, token, kind: "rekor" }))), true);
    const inherited = Object.assign(Object.create({ token }), { kind: "rfc3161", extra: "x" }) as AnchorProof;
    const t = createTestEngine({ adapters: { anchor: { anchor: async () => inherited } } });
    await t.engine.startCall();
    await assert.rejects(t.engine.anchorLedger(), rejects("invalid_input", /malformed proof/));
  });
});

describe("review #133: Rekor entries as protobuf JSON writes them", () => {
  const payload = anchorPayload({ seq: 4, hash: "e".repeat(64) });
  const signer = ecKeys();
  const body = hashedRekordBody(payload, sign("sha256", payload, signer.privateKey), signer.publicKey);
  const log = ecKeys();
  const trust = { key: log.publicKey, origin: REKOR_ORIGIN };
  const built = (index: number, size: number, edit: (entry: any) => void = () => undefined): string => {
    const entry = logEntry({ body, index, size, origin: REKOR_ORIGIN, logKey: log.privateKey, logPublicKey: log.publicKey }) as any;
    edit(entry);
    return Buffer.from(JSON.stringify(entry)).toString("base64");
  };
  const dropInner = (entry: any) => {
    delete entry.inclusionProof.logIndex;
    delete entry.inclusionProof.treeSize;
    delete entry.inclusionProof.rootHash;
  };

  it("a singleton proof whose empty hashes were omitted is accepted", () => {
    assert.deepEqual(checkRekorEntry(built(0, 1, (e) => delete e.inclusionProof.hashes), payload, trust), { ok: true, logIndex: 0 });
  });

  it("index 0 with every default omitted (top-level and inner logIndex) is accepted as 0", () => {
    assert.deepEqual(checkRekorEntry(built(0, 2, (e) => { delete e.logIndex; dropInner(e); }), payload, trust), { ok: true, logIndex: 0 });
  });

  it("reads the top-level logIndex and the checkpoint's size and root: the inner copies may be left out", () => {
    assert.deepEqual(checkRekorEntry(built(5, 7, dropInner), payload, trust), { ok: true, logIndex: 5 });
  });

  it("refuses inner copies that disagree with the top-level index or the checkpoint", () => {
    const cases: Array<[string, (e: any) => void]> = [
      ["top-level index moved, inner left", (e) => (e.logIndex = "4")],
      ["inner index moved", (e) => (e.inclusionProof.logIndex = "4")],
      ["inner tree size moved", (e) => (e.inclusionProof.treeSize = "8")],
      ["inner root moved", (e) => (e.inclusionProof.rootHash = Buffer.alloc(32).toString("base64"))],
    ];
    for (const [why, edit] of cases) assert.deepEqual(checkRekorEntry(built(5, 7, edit), payload, trust), { ok: false, reason: "log" }, why);
  });

  it("refuses a top-level index that is not the entry's place, with no inner copy to fall back on", () => {
    for (const index of ["4", "6", "7", "-1", "nine", "05", " 5", "0x5", "", 5]) {
      const entry = built(5, 7, (e) => { dropInner(e); e.logIndex = index; });
      assert.deepEqual(checkRekorEntry(entry, payload, trust), { ok: false, reason: "log" }, JSON.stringify(index));
    }
  });

  it("refuses a checkpoint whose size or root line is not canonical", () => {
    const cases: Array<[string, (envelope: string) => string]> = [
      ["size with a leading zero", (s) => s.replace("\n7\n", "\n07\n")],
      ["root that is not 32 bytes", (s) => s.replace(/\n([A-Za-z0-9+/]{43}=)\n/, "\n$1$1\n")],
    ];
    for (const [why, edit] of cases) {
      const entry = built(5, 7, (e) => { dropInner(e); e.inclusionProof.checkpoint.envelope = edit(e.inclusionProof.checkpoint.envelope); });
      assert.deepEqual(checkRekorEntry(entry, payload, trust), { ok: false, reason: "log" }, why);
    }
  });
});

describe("review #133: the token must name the signing certificate (ESS, RFC 2634 and RFC 5035)", () => {
  const payload = anchorPayload({ seq: 1, hash: "f".repeat(64) });
  const root = ecKeys();
  const leaf = ecKeys();
  const rootCert = new X509Certificate(certificate({ subject: "Root", issuer: "Root", publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true }));
  const leafSpec = { subject: "TSA", issuer: "Root", publicKey: leaf.publicKey, signingKey: root.privateKey, serial: 2, notBefore: "260101000000Z", notAfter: "300101000000Z", usage: OIDS.timeStamping };
  const leafDer = certificate(leafSpec);
  // Another certificate for the same key: a token naming it is not a token from this leaf.
  const otherDer = certificate({ ...leafSpec, serial: 3 });
  const chain = [new X509Certificate(leafDer), rootCert];
  const spec: TokenSpec = { payload, time: "20261118120000Z", signingKey: leaf.privateKey, issuer: "Root", serial: 2, signerCertificate: leafDer };
  const withAttributes = (...extra: Buffer[]) => ({ attributes: (p: { contentType: Buffer; messageDigest: Buffer }) => [p.contentType, p.messageDigest, ...extra] });
  const check = (overrides: Partial<TokenSpec>, certs = chain) => {
    const result = checkTimestamp(timestampToken({ ...spec, ...overrides }).toString("base64"), payload, certs);
    return result.ok ? "ok" : result.reason;
  };
  const serialOk = issuerSerial("Root", 2);

  it("accepts a SigningCertificateV2 naming the leaf, with or without IssuerSerial and an explicit hash", () => {
    assert.equal(check({}), "ok", "the builder's default: SHA-256 by default, with IssuerSerial");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer)))), "ok", "no IssuerSerial");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer, { algorithm: algorithm(OIDS.sha256), issuerSerial: serialOk })))), "ok", "SHA-256 written out");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer, { hash: "sha384", algorithm: algorithm(OIDS.sha384, false) })))), "ok", "SHA-384");
    // Only the first ESSCertID names the signer; others are the chain's.
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer), essCertIdV2(otherDer)))), "ok", "a second ESSCertID");
  });

  it("accepts a version 1 SigningCertificate (SHA-1) naming the leaf", () => {
    assert.equal(check(withAttributes(signingCertificate(1, essCertId(leafDer)))), "ok");
    assert.equal(check(withAttributes(signingCertificate(1, essCertId(leafDer, serialOk)))), "ok");
  });

  it("accepts an IssuerSerial whose issuer name needs a long DER length", () => {
    const longIssuer = `Root ${"x".repeat(200)}`;
    const longRoot = new X509Certificate(certificate({ subject: longIssuer, issuer: longIssuer, publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true }));
    const longLeaf = certificate({ ...leafSpec, issuer: longIssuer });
    assert.equal(check({ issuer: longIssuer, signerCertificate: longLeaf }, [new X509Certificate(longLeaf), longRoot]), "ok");
  });

  it("refuses a token with neither attribute", () => {
    assert.equal(check(withAttributes()), "token");
  });

  it("refuses a token that names another certificate", () => {
    assert.equal(check({ signerCertificate: otherDer }), "certificate", "v2, another certificate's hash");
    assert.equal(check(withAttributes(signingCertificate(1, essCertId(otherDer)))), "certificate", "v1, another certificate's hash");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer, { issuerSerial: issuerSerial("Root", 3) })))), "certificate", "another serial");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(leafDer, { issuerSerial: issuerSerial("Other", 2) })))), "certificate", "another issuer");
    assert.equal(check(withAttributes(signingCertificate(1, essCertId(leafDer, issuerSerial("Root", 3))))), "certificate", "v1, another serial");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(otherDer), essCertIdV2(leafDer)))), "certificate", "the leaf only second");
    assert.equal(check(withAttributes(signingCertificate(1, essCertId(leafDer)), signingCertificate(2, essCertIdV2(otherDer)))), "certificate", "v1 right, v2 wrong");
    assert.equal(check(withAttributes(signingCertificate(2, essCertIdV2(otherDer)), signingCertificate(1, essCertId(leafDer)))), "certificate", "v2 wrong, v1 right");
  });

  it("refuses a hash it does not know and an ESSCertID that does not read (fail closed)", () => {
    const cases: Array<[string, Buffer]> = [
      ["MD5", signingCertificate(2, essCertIdV2(leafDer, { hash: "md5", algorithm: algorithm(OIDS.md5) }))],
      ["SHA-1 in a version 2", signingCertificate(2, essCertIdV2(leafDer, { hash: "sha1", algorithm: algorithm(OIDS.sha1) }))],
      ["an empty ESSCertIDv2", signingCertificate(2, seq())],
      ["no ESSCertID", signingCertificate(2)],
      ["a certHash that is not an OCTET STRING", signingCertificate(2, seq(seq(octets(Buffer.alloc(1)))))],
      ["something after IssuerSerial", signingCertificate(2, essCertIdV2(leafDer, { issuerSerial: Buffer.concat([serialOk, int(1)]) }))],
      ["an IssuerSerial that is not a SEQUENCE", signingCertificate(1, essCertId(leafDer, int(2)))],
    ];
    for (const [why, attribute] of cases) assert.equal(check(withAttributes(attribute)), "token", why);
  });
});

describe("review #133: the fake authority keeps fractional seconds", () => {
  it("a genTime with milliseconds is written with its fraction and read back", async () => {
    const clock = new FixedClock("2026-11-18T12:00:00.250Z");
    const { entry, entries, tsa } = await anchored(clock);
    const token = Buffer.from((entry.detail.proof as { token: string }).token, "base64");
    assert.ok(token.includes(Buffer.from("20261118120000.25Z", "latin1")), "the GeneralizedTime keeps .25, trailing zero removed");
    const check = verifyAnchor(entry, entries, { tsa: tsa.chain });
    assert.equal(check.ok && check.time, "2026-11-18T12:00:00.250Z");
    // Whole seconds keep no fraction at all.
    const whole = await anchored(new FixedClock("2026-11-18T12:00:01.000Z"));
    const wholeToken = Buffer.from((whole.entry.detail.proof as { token: string }).token, "base64");
    assert.ok(wholeToken.includes(Buffer.from("20261118120001Z", "latin1")));
    const odd = await anchored(new FixedClock("2026-11-18T12:00:01.001Z"));
    assert.ok(Buffer.from((odd.entry.detail.proof as { token: string }).token, "base64").includes(Buffer.from("20261118120001.001Z", "latin1")));
    const result = verifyAnchor(odd.entry, odd.entries, { tsa: odd.tsa.chain });
    assert.equal(result.ok && result.time, "2026-11-18T12:00:01.001Z");
  });
});

describe("review #133: fixture builders", () => {
  it("int encodes the whole positive value, with a leading zero when the high bit is set", () => {
    const hex = (n: number) => int(n).toString("hex");
    assert.deepEqual([1, 2, 3, 4].map(hex), ["020101", "020102", "020103", "020104"]);
    assert.equal(hex(0), "020100");
    assert.equal(hex(127), "02017f");
    assert.equal(hex(128), "02020080");
    assert.equal(hex(255), "020200ff");
    assert.equal(hex(256), "02020100");
    assert.equal(hex(65536), "0203010000");
    assert.throws(() => int(-1), RangeError);
    assert.throws(() => int(1.5), RangeError);
  });

  it("merkleRoot of no leaves is SHA-256 of the empty string (RFC 9162)", () => {
    assert.deepEqual(merkleRoot([]), createHash("sha256").digest());
  });
});

describe("review #133: the time-stamp authority adapter asks with a nonce and SHA-256, and caps the reply", () => {
  async function head() {
    const { ledger } = await fixtureLedger();
    const h = await ledger.head();
    return { ...h, payload: anchorPayload(h) };
  }

  it("sends a nonce in the request and accepts the token that echoes it", async () => {
    const { payload } = await head();
    const { fetch, requests } = spy({ body: recordedTimestamp });
    const anchor = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch, nonce: fixedNonce });
    const token = await anchor.timestamp(payload);
    const sent = Buffer.from(requests[0]!.init.body as Uint8Array);
    assert.deepEqual(sent, timestampRequest(payload, FIXTURE_NONCE));
    // TimeStampReq: version, messageImprint, nonce, certReq.
    const fields = readDer(readDer(sent)[0]!.value);
    assert.deepEqual(fields.map((f) => f.tag), [0x02, 0x30, 0x02, 0x01]);
    assert.deepEqual(Buffer.from(fields[2]!.value), FIXTURE_NONCE);
    assert.deepEqual(Buffer.from(timestampTokenFields(token)!.nonce!), FIXTURE_NONCE);
  });

  it("refuses a recorded token answered to a new request (another nonce, or none)", async () => {
    const { payload } = await head();
    // The default nonce is random, so the recorded answer is a replay.
    const random = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy({ body: recordedTimestamp }).fetch });
    await assert.rejects(random.timestamp(payload), /nonce/);
    const other = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy({ body: recordedTimestamp }).fetch, nonce: () => Buffer.from("0102030405060708", "hex") });
    await assert.rejects(other.timestamp(payload), /nonce/);
    // Two requests never share a nonce.
    const { fetch, requests } = spy({ body: recordedTimestamp }, { body: recordedTimestamp });
    const twice = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch });
    await assert.rejects(twice.timestamp(payload), /nonce/);
    await assert.rejects(twice.timestamp(payload), /nonce/);
    assert.notDeepEqual(requests[0]!.init.body, requests[1]!.init.body);
  });

  describe("on tokens built here", () => {
    const root = ecKeys();
    const leaf = ecKeys();
    const rootCert = new X509Certificate(certificate({ subject: "Root", issuer: "Root", publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true }));
    const leafDer = certificate({ subject: "TSA", issuer: "Root", publicKey: leaf.publicKey, signingKey: root.privateKey, serial: 2, notBefore: "260101000000Z", notAfter: "300101000000Z", usage: OIDS.timeStamping });
    const chain = [new X509Certificate(leafDer), rootCert];
    const payload = anchorPayload({ seq: 2, hash: "9".repeat(64) });
    const build = (overrides: Partial<TokenSpec>) =>
      timestampResponse(0, timestampToken({ payload, time: "20261118120000Z", signingKey: leaf.privateKey, issuer: "Root", serial: 2, signerCertificate: leafDer, nonce: der(0x02, FIXTURE_NONCE), ...overrides }));
    const ask = (reply: Buffer) => new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain, fetch: spy({ body: reply }).fetch, nonce: fixedNonce }).timestamp(payload);

    it("refuses a token with no nonce", async () => {
      await assert.rejects(ask(build({ nonce: null })), /nonce/);
      assert.equal(timestampTokenFields(build({ nonce: null }).subarray(5).toString("base64")), null, "a TimeStampResp is not a token");
    });

    it("refuses a SHA-384 imprint to a SHA-256 request, which still verifies offline", async () => {
      const sha384 = createHash("sha384").update(payload).digest();
      const reply = build({ tstInfo: ({ time }) => seq(int(1), oid(OIDS.policy), seq(algorithm(OIDS.sha384), octets(sha384)), int(2), time, der(0x02, FIXTURE_NONCE)) });
      await assert.rejects(ask(reply), /SHA-256/);
      const [, token] = readDer(readDer(reply)[0]!.value);
      assert.equal(checkTimestamp(Buffer.from(token!.raw).toString("base64"), payload, chain).ok, true, "offline verification is unchanged");
    });

    it("accepts the token it asked for", async () => {
      assert.equal(typeof (await ask(build({}))), "string");
    });
  });

  it("reads at most maxReplyBytes, cancels the rest and refuses", async () => {
    const { payload } = await head();
    const big = streamed(new Uint8Array(MAX_REPLY_BYTES * 4));
    const anchor = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy(big.response).fetch, nonce: fixedNonce });
    await assert.rejects(anchor.timestamp(payload), /larger than/);
    assert.equal(big.state.cancelled, true);
    assert.ok(big.state.pulled <= MAX_REPLY_BYTES / 1024 + 2, `read ${big.state.pulled} chunks`);
    // A smaller cap: the recorded reply at its size passes the cap, one byte less does not.
    const capped = (max: number) =>
      new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy(streamed(recordedTimestamp, 100).response).fetch, nonce: fixedNonce, maxReplyBytes: max });
    assert.equal(typeof (await capped(recordedTimestamp.length).timestamp(payload)), "string");
    await assert.rejects(capped(recordedTimestamp.length - 1).timestamp(payload), /larger than/);
  });

  it("refuses an error answer without reading its body, and a reply with no body", async () => {
    const { payload } = await head();
    const error = streamed(new Uint8Array(10));
    const failing = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy(() => new Response(new Response(null).body, { status: 503 })).fetch, nonce: fixedNonce });
    await assert.rejects(failing.timestamp(payload), /answered 503/);
    const cancelled = new TimestampAuthorityAnchor({
      url: "https://tsa.example.test/",
      chain: recordedChain,
      fetch: spy(() => {
        const r = error.response();
        return new Response(r.body, { status: 500 });
      }).fetch,
    });
    await assert.rejects(cancelled.timestamp(payload), /answered 500/);
    assert.equal(error.state.cancelled, true);
    const empty = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: spy(() => new Response(null)).fetch, nonce: fixedNonce });
    await assert.rejects(empty.timestamp(payload), /answered nothing/);
  });
});

describe("review #133: the Rekor adapter stamps first, then logs", () => {
  async function setup(rekorReply: Parameters<typeof spy>[0], tsaReply: Parameters<typeof spy>[0] = { body: recordedTimestamp }) {
    const { ledger, entries } = await fixtureLedger();
    const head = await ledger.head();
    const tsa = spy(tsaReply);
    const rekor = spy(rekorReply);
    // Both fetches write to one log, so the order of the two requests shows.
    const order: string[] = [];
    const logged = (f: typeof tsa.fetch): typeof tsa.fetch => (url, init) => (order.push(url), f(url, init));
    const timestamps = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: logged(tsa.fetch), nonce: fixedNonce });
    const anchor = new RekorAnchor({ url: "https://rekor.example.test/", signingKey: fixtureSigner().privateKey, log: recordedLog, timestamps, fetch: logged(rekor.fetch) });
    return { anchor, tsa, rekor, order, head, entries, input: { ...head, payload: anchorPayload(head) } };
  }

  it("a refused time-stamp writes nothing to the public log", async () => {
    for (const tsaReply of [{ status: 503, body: new Uint8Array() }, { body: timestampResponse(2) }]) {
      const { anchor, tsa, rekor, input } = await setup({ body: recordedEntry }, tsaReply);
      await assert.rejects(anchor.anchor(input), /time-stamp authority/);
      assert.equal(tsa.requests.length, 1);
      assert.equal(rekor.requests.length, 0, "Rekor was never asked");
    }
  });

  it("asks the authority, then Rekor, and the proof verifies offline", async () => {
    const { anchor, order, input, entries, head } = await setup({ body: recordedEntry });
    const proof = await anchor.anchor(input);
    assert.deepEqual(order, ["https://tsa.example.test/", "https://rekor.example.test/api/v2/log/entries"]);
    assert.equal(proof.kind, "rekor");
    const entry = { ...entries.at(-1)!, seq: 6, event: "ledger.anchored" as const, detail: { seq: head.seq, proof } };
    assert.equal(verifyAnchor(entry as never, entries, { tsa: recordedChain, rekor: recordedLog }).ok, true);
  });

  it("names the cause of each Rekor failure, after one time-stamp request", async () => {
    const tampered = JSON.parse(recordedEntry.toString());
    tampered.logIndex = "8";
    const big = streamed(new Uint8Array(MAX_REPLY_BYTES * 2));
    const cases: Array<[Parameters<typeof spy>[0], RegExp]> = [
      [{ status: 500, body: new Uint8Array() }, /^Error: Rekor answered 500$/],
      [{ body: Buffer.from(JSON.stringify(tampered)) }, /^Error: the Rekor entry does not verify$/],
      [big.response, /larger than/],
    ];
    for (const [reply, cause] of cases) {
      const { anchor, tsa, rekor, input } = await setup(reply);
      await assert.rejects(anchor.anchor(input), (e: Error) => cause.test(String(e)));
      assert.equal(tsa.requests.length, 1, String(cause));
      assert.equal(rekor.requests.length, 1, String(cause));
    }
    assert.equal(big.state.cancelled, true);
  });

  it("refuses a valid entry for the same head under another key", async () => {
    const { tsa, rekor, input } = await setup({ body: recordedEntry });
    const timestamps = new TimestampAuthorityAnchor({ url: "https://tsa.example.test/", chain: recordedChain, fetch: tsa.fetch, nonce: fixedNonce });
    const anchor = new RekorAnchor({ url: "https://rekor.example.test", signingKey: ecKeys().privateKey, log: recordedLog, timestamps, fetch: rekor.fetch });
    await assert.rejects(anchor.anchor(input), /another key/);
    assert.equal(rekor.requests.length, 1);
  });
});
