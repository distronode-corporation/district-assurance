// Hostile-pass regressions for #109 (PRV-9, ledger anchors). Y1 failed before the listener was
// handed a copy of the anchored entry's detail; the rest held. Y1 also checks that the listener
// was told at all, so a listener never called cannot pass it.
import { strict as assert } from "node:assert";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";

import type { AnchorProof, AuditEntry } from "../src/core/adapters.ts";
import { anchorPayload, checkRekorEntry, verifyAnchor } from "../src/prove/anchor.ts";
import { hashedRekordBody, signedCheckpoint } from "./fixtures/anchor/build.ts";
import { FakeTimestampAuthority } from "../src/testing/fakes.ts";
import { createTestEngine } from "../src/testing/index.ts";

async function anchoredEngine(onEvent?: (e: { detail: Record<string, unknown> }) => void, firstCallId?: string) {
  const t = createTestEngine();
  const tsa = new FakeTimestampAuthority(t.clock);
  const engine = createTestEngine({ adapters: { ledger: t.ledger, anchor: tsa }, ...(onEvent === undefined ? {} : { onEvent: onEvent as never }) }).engine;
  const { callId } = await engine.startCall(firstCallId === undefined ? {} : { callId: firstCallId });
  await engine.endCall(callId);
  t.clock.advance(60_000);
  return { ...t, engine, tsa };
}

describe("hostile #109: anchorLedger", () => {
  it("Y1: a listener that rewrites the event cannot change the entry anchorLedger returns, nor the ledger", async () => {
    const heard: Array<{ name: unknown; seq: unknown; proof: unknown }> = [];
    const { engine, ledger, tsa } = await anchoredEngine((e) => {
      const event = e as { name?: unknown; detail: Record<string, unknown> };
      if (event.name === "ledger.anchored") heard.push({ name: event.name, seq: e.detail.seq, proof: structuredClone(e.detail.proof) });
      e.detail.seq = 999;
      delete e.detail.proof;
    });
    const head = await ledger.head();
    const entry = await engine.anchorLedger();
    const stored = (await ledger.list()).at(-1)!;
    // The listener was told, once, of this anchor, and its rewrite reached its own copy only.
    assert.equal(heard.length, 1, "the listener received ledger.anchored");
    assert.equal(heard[0]!.name, "ledger.anchored");
    assert.equal(heard[0]!.seq, head.seq);
    for (const copy of [entry, stored]) {
      assert.equal(copy.event, "ledger.anchored");
      assert.equal(copy.detail.seq, head.seq, "seq unchanged");
      assert.deepEqual(copy.detail.proof, heard[0]!.proof, "proof unchanged");
    }
    assert.deepEqual(entry, stored);
    assert.equal(verifyAnchor(stored, await ledger.list(), { tsa: tsa.chain }).ok, true);
  });

  it("Y2: an adapter that answers a proof for an earlier head is caught when the anchor is checked", async () => {
    const { engine, ledger, tsa } = await anchoredEngine();
    const first = await engine.anchorLedger();
    const stale = first.detail.proof as AnchorProof;
    const replaying = createTestEngine({ adapters: { ledger, anchor: { anchor: async () => stale } } }).engine;
    const entry = await replaying.anchorLedger();
    assert.deepEqual(verifyAnchor(entry, await ledger.list(), { tsa: tsa.chain }), { ok: false, reason: "imprint" });
  });

  it("Y3: two ledgers: an anchor from one never verifies against the other", async () => {
    const a = await anchoredEngine();
    // Built the same way on the same fixed clock, the two ledgers would be equal: b's first call differs.
    const b = await anchoredEngine(undefined, "call_other");
    const entry = await a.engine.anchorLedger();
    assert.equal(verifyAnchor(entry, await a.ledger.list(), { tsa: a.tsa.chain }).ok, true);
    assert.deepEqual(verifyAnchor(entry, await b.ledger.list(), { tsa: a.tsa.chain }), { ok: false, reason: "imprint" });
    assert.deepEqual(verifyAnchor(entry, await a.ledger.list(), { tsa: b.tsa.chain }), { ok: false, reason: "token" }, "another authority's chain");
  });
});

describe("hostile #109: verifyAnchor on what it is handed", () => {
  async function anchored() {
    const t = await anchoredEngine();
    const entry = await t.engine.anchorLedger();
    return { ...t, entry, entries: await t.ledger.list() };
  }

  it("Y4: a seq that is not a safe integer of 1 or more, or past the entries, is refused", async () => {
    const { entry, entries, tsa } = await anchored();
    for (const seq of ["1", 0, -1, 1.5, 2 ** 53, Number.NaN, null]) {
      const bad = { ...entry, detail: { ...entry.detail, seq } } as unknown as AuditEntry;
      assert.deepEqual(verifyAnchor(bad, entries, { tsa: tsa.chain }), { ok: false, reason: "malformed" }, String(seq));
    }
    const past = { ...entry, detail: { ...entry.detail, seq: entries.length + 5 } } as AuditEntry;
    assert.deepEqual(verifyAnchor(past, entries, { tsa: tsa.chain }), { ok: false, reason: "chain" });
    assert.deepEqual(verifyAnchor(entry, entries.slice(1), { tsa: tsa.chain }), { ok: false, reason: "chain" }, "entries that do not start at seq 1");
  });

  it("Y5: a proof with another kind, an extra field, or a Rekor kind without a log in the trust is refused", async () => {
    const { entry, entries, tsa } = await anchored();
    const proof = entry.detail.proof as { kind: string; token: string };
    for (const changed of [{ ...proof, kind: "RFC3161" }, { ...proof, extra: "x" }, { kind: "rfc3161" }, { ...proof, token: `${proof.token}\n` }, { ...proof, token: "" }]) {
      const bad = { ...entry, detail: { ...entry.detail, proof: changed } } as unknown as AuditEntry;
      assert.deepEqual(verifyAnchor(bad, entries, { tsa: tsa.chain }), { ok: false, reason: "malformed" }, JSON.stringify(changed).slice(0, 60));
    }
    const asRekor = { ...entry, detail: { ...entry.detail, proof: { ...proof, kind: "rekor", entry: proof.token } } } as unknown as AuditEntry;
    assert.deepEqual(verifyAnchor(asRekor, entries, { tsa: tsa.chain }), { ok: false, reason: "log" });
  });

  it("Y6: an entry that is not ledger.anchored, and an empty or non-certificate chain, are refused without throwing", async () => {
    const { entry, entries, tsa } = await anchored();
    assert.deepEqual(verifyAnchor({ ...entry, event: "call.started" } as AuditEntry, entries, { tsa: tsa.chain }), { ok: false, reason: "malformed" });
    assert.deepEqual(verifyAnchor(entry, entries, { tsa: [] }), { ok: false, reason: "certificate" });
    assert.doesNotThrow(() => verifyAnchor(entry, entries, { tsa: [null, "pem"] as never }));
    assert.equal(verifyAnchor(entry, entries, { tsa: [null, "pem"] as never }).ok, false);
  });
});

describe("hostile #109: a Rekor log index past what a number holds", () => {
  const h = (...parts: Uint8Array[]) => {
    const hash = createHash("sha256");
    for (const part of parts) hash.update(part);
    return hash.digest();
  };
  /** A valid entry at `index`, the last leaf of a tree of `index + 1` leaves, with made-up siblings. */
  function entryAt(index: bigint) {
    const log = generateKeyPairSync("ed25519");
    const signer = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const payload = anchorPayload({ seq: 3, hash: "a".repeat(64) });
    const body = hashedRekordBody(payload, sign("sha256", payload, signer.privateKey), signer.publicKey);
    // The path for the last leaf: one sibling per set bit of the index, lowest first.
    const siblings: Buffer[] = [];
    let root = h(Buffer.from([0]), body);
    for (let bit = 0n; index >> bit > 0n; bit++) {
      if (((index >> bit) & 1n) === 1n) {
        const sibling = h(Buffer.from(`sibling ${bit}`));
        siblings.push(sibling);
        root = h(Buffer.from([1]), sibling, root);
      }
    }
    const size = index + 1n;
    const entry = {
      logIndex: String(index),
      inclusionProof: {
        logIndex: String(index),
        rootHash: root.toString("base64"),
        treeSize: String(size),
        hashes: siblings.map((b) => b.toString("base64")),
        checkpoint: { envelope: signedCheckpoint("log.example.test", size as unknown as number, root, log.privateKey, log.publicKey) },
      },
      canonicalizedBody: body.toString("base64"),
    };
    return { encoded: Buffer.from(JSON.stringify(entry)).toString("base64"), payload, log: { key: log.publicKey, origin: "log.example.test" } };
  }

  it("Y7: an index above Number.MAX_SAFE_INTEGER is refused, never reported rounded", () => {
    const safe = BigInt(Number.MAX_SAFE_INTEGER);
    const atLimit = entryAt(safe);
    assert.deepEqual(checkRekorEntry(atLimit.encoded, atLimit.payload, atLimit.log), { ok: true, logIndex: Number.MAX_SAFE_INTEGER });
    const past = entryAt(safe + 2n);
    assert.deepEqual(checkRekorEntry(past.encoded, past.payload, past.log), { ok: false, reason: "log" });
  });
});
