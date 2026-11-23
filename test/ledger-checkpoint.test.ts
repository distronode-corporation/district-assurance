// Ledger checkpoints and pruning (#157, #158, #159): the signed ledger_checkpoint document and its
// verifier, pruneLedger's gate on a written checkpoint, the checkpoint-aware export, and the engine
// on a pruned ledger.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { canonicalJson, type JsonValue } from "../src/core/canonical.ts";
import { EngineError } from "../src/core/errors.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import type { WriteHint } from "../src/core/adapters.ts";
import {
  LEDGER_CHECKPOINT_DOMAIN,
  ledgerCheckpointPayload,
  pruneLedger,
  signLedgerCheckpoint,
  verifyLedgerCheckpoint,
  type LedgerCheckpointBody,
  type SignedLedgerCheckpoint,
} from "../src/prove/checkpoint.ts";
import { encodeCursor, exportLedger, verifyLedgerExport, type LedgerExportInput } from "../src/prove/export.ts";
import { verifyAnchor } from "../src/prove/anchor.ts";
import { monthlyReport } from "../src/prove/report.ts";
import { MemoryAuditLedger, chainEntry, verifyChain } from "../src/prove/ledger.ts";
import type { AuditEntry, AuditInput, AuditLedger } from "../src/core/adapters.ts";
import type { ChainPoint } from "../src/prove/export.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeTimestampAuthority, FixedClock, MemoryConsentStore, TEST_KNOWLEDGE_KEY, generateTestSigner, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, heard, rejects, setup, verifiedCall } from "./helpers.ts";

const clock = new FixedClock("2026-11-18T12:00:00.000Z");
const signer = generateTestSigner("k1");
const keys = [signer.publicJwk()];
const OTHER_KEYS = [generateTestSigner("k1").publicJwk()];

const input = (n: number, eventId?: string): AuditInput => ({ ...(eventId === undefined ? {} : { eventId }), callId: "c1", actor: "code", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { n } });

/** A ledger of `n` entries; `salt` shifts every detail, so two ledgers never share a chain. */
async function ledgerOf(n: number, salt = 0): Promise<MemoryAuditLedger> {
  const ledger = new MemoryAuditLedger();
  for (let i = 1; i <= n; i++) await ledger.append(input(i + salt));
  return ledger;
}

async function collect(lines: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const line of lines) out += line;
  return out;
}

const run = (ledger: AuditLedger, more: Partial<LedgerExportInput>): Promise<string> =>
  collect(exportLedger({ ledger, signer, clock, ledgerId: "ws_1", ...more } as LedgerExportInput));

/** A ledger whose reads can be tampered with, as storage that was rewritten mid-flight. */
class EditedLedger implements AuditLedger {
  readonly inner: MemoryAuditLedger;
  readonly edit: (entries: AuditEntry[]) => AuditEntry[];

  constructor(inner: MemoryAuditLedger, edit: EditedLedger["edit"]) {
    this.inner = inner;
    this.edit = edit;
  }

  append(i: AuditInput): Promise<AuditEntry> {
    return this.inner.append(i);
  }

  head(): Promise<{ seq: number; hash: string }> {
    return this.inner.head();
  }

  async list(fromSeq?: number, limit?: number): Promise<AuditEntry[]> {
    return this.edit(await this.inner.list(fromSeq, limit));
  }

  base(): Promise<{ seq: number; hash: string } | null> {
    return this.inner.base();
  }

  prune(checkpoint: { seq: number; hash: string }): Promise<void> {
    return this.inner.prune(checkpoint);
  }
}

/** A checkpoint of `ledger` at `seq` (the head), signed with the suite's signer. */
const checkpoint = (ledger: AuditLedger, seq?: number): Promise<SignedLedgerCheckpoint> =>
  signLedgerCheckpoint(ledger, { signer, clock, ledgerId: "ws_1", ...(seq === undefined ? {} : { seq }) });

describe("the ledger checkpoint document", () => {
  it("is signed at the head by default, over its own domain, and names the ledger, the point and what the prune would cut", async () => {
    const ledger = await ledgerOf(3);
    const head = await ledger.head();
    const signed = await checkpoint(ledger);
    assert.deepEqual(signed.body, {
      v: 1,
      type: "ledger_checkpoint",
      ledgerId: "ws_1",
      seq: head.seq,
      hash: head.hash,
      prunedCount: 3,
      at: "2026-11-18T12:00:00.000Z",
    } satisfies LedgerCheckpointBody);
    assert.equal(signed.alg, "ES256");
    assert.equal(signed.kid, "k1");
    assert.equal(new TextDecoder().decode(ledgerCheckpointPayload(signed.body)).startsWith(`${LEDGER_CHECKPOINT_DOMAIN}\n{`), true);
    assert.deepEqual(verifyLedgerCheckpoint(signed, keys), { ok: true, point: head, body: signed.body });
  });

  it("is signed at a given seq, and a checkpoint above a base cuts only the gap", async () => {
    const ledger = await ledgerOf(6);
    const first = await checkpoint(ledger, 3);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: first, keys });
    const second = await checkpoint(ledger);
    const head = await ledger.head();
    assert.deepEqual([second.body.seq, second.body.prunedCount, second.body.hash], [6, 3, head.hash], "the base was 3; the second checkpoint cuts 3 more");
  });

  it("is refused for an empty ledger, a bad seq or ledgerId, a seq at or below the base, or a ledger it cannot check", async () => {
    const empty = new MemoryAuditLedger();
    await assert.rejects(checkpoint(empty), rejects("precondition_failed", /empty/));
    const ledger = await ledgerOf(3);
    await assert.rejects(checkpoint(ledger, 0), rejects("invalid_input", /seq must be an integer/));
    await assert.rejects(checkpoint(ledger, 1.5), rejects("invalid_input", /seq must be an integer/));
    await assert.rejects(signLedgerCheckpoint(ledger, { signer, clock, ledgerId: "", seq: 1 }), rejects("invalid_input", /ledgerId/));
    await assert.rejects(checkpoint(ledger, 4), rejects("invalid_input", /past the ledger head/));
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: await checkpoint(ledger, 2), keys });
    await assert.rejects(checkpoint(ledger, 2), rejects("precondition_failed", /nothing would be cut/));
    await assert.rejects(checkpoint(ledger, 1), rejects("precondition_failed", /nothing would be cut/));
    // A ledger whose reads were rewritten is never vouched for.
    const tampered = new EditedLedger(await ledgerOf(4), (entries) => entries.map((e) => (e.seq === 2 ? { ...e, detail: { n: 99 } } : e)));
    await assert.rejects(checkpoint(tampered), rejects("precondition_failed", /does not verify at seq 2/));
    // A rewritten head whose hash is recomputed walks as a consistent chain, but it still ends on
    // another hash than the head the ledger answers: the default checkpoint names the head, and an
    // inconsistent read is never vouched for.
    const swapped = new EditedLedger(await ledgerOf(4), (entries) =>
      entries.map((e) => (e.seq === 4 ? chainEntry(input(99), e.seq, e.prevHash) : e)),
    );
    await assert.rejects(checkpoint(swapped), rejects("precondition_failed", /head does not match the chain walked/));
    const belowHead = await checkpoint(swapped, 3);
    assert.equal(belowHead.body.seq, 3, "a checkpoint below the head signs the seq it names, untouched by the swapped read");
    // A ledger that stops short of the seq holds no point there.
    const short = new EditedLedger(await ledgerOf(4), (entries) => entries.filter((e) => e.seq !== 4));
    await assert.rejects(checkpoint(short, 4), rejects("precondition_failed", /does not hold seq 4/));
  });

  it("is refused for a signer that answers a wrong-length signature, or one that does not verify against its own key", async () => {
    const ledger = await ledgerOf(2);
    const other = generateTestSigner("k1");
    const badSigners = [
      { ...signer, sign: async () => new Uint8Array(10) },
      { keyId: "k1", algorithm: "ES256" as const, sign: (p: Uint8Array) => other.sign(p), publicJwk: () => signer.publicJwk() },
    ];
    for (const bad of badSigners) {
      await assert.rejects(signLedgerCheckpoint(ledger, { signer: bad, clock, ledgerId: "ws_1" }), (e: unknown) => e instanceof EngineError && e.code === "invalid_input", "the signer's own key must verify its signature");
    }
  });
});

describe("verifyLedgerCheckpoint", () => {
  it("answers the point for a signed checkpoint, and never throws on anything else", async () => {
    const signed = await checkpoint(await ledgerOf(4));
    const check = verifyLedgerCheckpoint(signed, keys);
    assert.ok(check.ok);
    assert.deepEqual(check.point, { seq: 4, hash: signed.body.hash });
    const bodies: unknown[] = [
      { ...signed.body, v: 2 },
      { ...signed.body, type: "ledger_export" },
      { ...signed.body, ledgerId: "" },
      { ...signed.body, seq: 0 },
      { ...signed.body, seq: 1.5 },
      { ...signed.body, hash: "XY" },
      { ...signed.body, prunedCount: 0 },
      { ...signed.body, prunedCount: 5 },
      { ...signed.body, at: "2026-11-18T12:00:00Z" },
      { ...signed.body, at: 7 },
      null,
      7,
    ];
    for (const body of bodies) assert.deepEqual(verifyLedgerCheckpoint({ ...signed, body }, keys), { ok: false, reason: "malformed" }, JSON.stringify(body));
    for (const value of [null, undefined, "x", 7, Buffer.from("x")]) assert.deepEqual(verifyLedgerCheckpoint(value, keys), { ok: false, reason: "malformed" });
    for (const envelope of [{ ...signed, alg: "HS256" }, { ...signed, kid: "" }, { ...signed, kid: 7 }, { ...signed, signature: 7 }]) {
      assert.deepEqual(verifyLedgerCheckpoint(envelope, keys), { ok: false, reason: "malformed" });
    }
  });

  it("says signature for an unknown kid or key set, a changed body, or a signature of the wrong shape", async () => {
    const signed = await checkpoint(await ledgerOf(2));
    assert.deepEqual(verifyLedgerCheckpoint(signed, OTHER_KEYS), { ok: false, reason: "signature" }, "another key under the same kid");
    assert.deepEqual(verifyLedgerCheckpoint(signed, [{ kid: "k1", kty: "EC", crv: "P-256", x: "bad", y: "bad" }]), { ok: false, reason: "signature" }, "a key that is not one");
    assert.deepEqual(verifyLedgerCheckpoint(signed, []), { ok: false, reason: "signature" });
    for (const keySet of [null, undefined, {}, "keys", [null, 7]] as never[]) {
      assert.deepEqual(verifyLedgerCheckpoint(signed, keySet), { ok: false, reason: "signature" }, "a key set that is not a list of keys");
    }
    assert.deepEqual(verifyLedgerCheckpoint({ ...signed, body: { ...signed.body, at: "2026-11-18T12:00:01.000Z" } }, keys), { ok: false, reason: "signature" }, "any change to the body");
    assert.deepEqual(verifyLedgerCheckpoint({ ...signed, signature: signed.signature.slice(4) }, keys), { ok: false, reason: "signature" });
    // A signature over the bare canonical body, as a receipt is signed, never passes.
    const bare = Buffer.from(await signer.sign(new TextEncoder().encode(canonicalJson(signed.body)))).toString("base64url");
    assert.deepEqual(verifyLedgerCheckpoint({ ...signed, signature: bare }, keys), { ok: false, reason: "signature" });
  });
});

describe("pruneLedger", () => {
  it("removes the entries at or below the checkpoint once it is written, and the ledger continues from it", async () => {
    const ledger = await ledgerOf(5);
    const signed = await checkpoint(ledger, 3);
    const [third] = await ledger.list(3, 1);
    assert.deepEqual(await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys: keys }), { seq: 3, hash: third!.hash });
    assert.deepEqual(await ledger.base(), { seq: 3, hash: third!.hash });
    assert.deepEqual((await ledger.list()).map((e) => e.seq), [4, 5]);
    assert.deepEqual(await ledger.head(), { seq: 5, hash: (await ledger.list(5, 1))[0]!.hash }, "the head is untouched");
    const next = await ledger.append(input(6));
    const fifth = (await ledger.list(5, 1))[0]!;
    assert.deepEqual({ seq: next.seq, prevHash: next.prevHash }, { seq: 6, prevHash: fifth.hash }, "an append continues from the last entry the prune left");
    assert.deepEqual(verifyChain(await ledger.list(), { seq: 3, hash: third!.hash }), { ok: true, head: await ledger.head() });
  });

  it("refuses a checkpoint that is not signed or not by this key set, one of another ledger's chain, past the head, or below the base", async () => {
    const ledger = await ledgerOf(3);
    const forged: unknown = { alg: "ES256", kid: "k1", signature: "AAAA", body: { v: 1, type: "ledger_checkpoint", ledgerId: "ws_1", seq: 1, hash: "ab".repeat(32), prunedCount: 1, at: clock.now().toISOString() } };
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: forged as never, keys }), rejects("invalid_input", /does not verify against the key set/));
    const early = await checkpoint(ledger, 1);
    const signed = await checkpoint(ledger, 2);
    const malformed: unknown = { alg: "ES256", kid: "k1", signature: signed.signature, body: 7 };
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: malformed as never, keys }), rejects("invalid_input", /not a signed ledger_checkpoint document/));
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys: OTHER_KEYS }), rejects("invalid_input", /does not verify/));
    // A checkpoint of another ledger's chain, at a seq this ledger holds with another hash.
    const foreign = await checkpoint(await ledgerOf(5, 100), 2);
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: foreign, keys: keys }), rejects("precondition_failed", /does not hold the checkpoint's entry/));
    // A checkpoint past this ledger's head.
    const ahead = await checkpoint(await ledgerOf(5), 5);
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: ahead, keys: keys }), rejects("precondition_failed", /does not hold the checkpoint's entry/));
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    // A rollback to an earlier checkpoint, and one at the base with another chain's hash.
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: early, keys: keys }), rejects("precondition_failed", /already pruned through seq 2/));
    const sameSeqOtherChain = await checkpoint(await ledgerOf(2, 100), 2);
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: sameSeqOtherChain, keys: keys }), rejects("precondition_failed", /already pruned through seq 2/));
  });

  it("refuses a checkpoint seq that is not an integer of 1 or more, without pruning anything", async () => {
    const ledger = await ledgerOf(2);
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(ledger.prune({ seq: bad, hash: "ab".repeat(32) }), TypeError, String(bad));
    }
    assert.deepEqual((await ledger.list()).map((e) => e.seq), [1, 2], "nothing was pruned");
  });

  it("refuses a checkpoint that names another ledger, and one whose prunedCount no longer names the gap", async () => {
    const ledger = await ledgerOf(4);
    const foreignName = await signLedgerCheckpoint(ledger, { signer, clock, ledgerId: "ws_other", seq: 2 });
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: foreignName, keys }), rejects("invalid_input", /names the ledger ws_other, not ws_1/));
    // A checkpoint signed before an earlier prune overstates what the next prune cuts.
    const first = await checkpoint(ledger, 2);
    const second = await checkpoint(ledger, 4);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: first, keys });
    await assert.rejects(pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: second, keys }), rejects("invalid_input", /says it cuts 4 entries, but this prune cuts 2/), "sign one checkpoint at a time, after the last prune");
  });

  it("settles concurrent prunes: the same checkpoint twice is idempotent, and two checkpoints leave one base", async () => {
    const same = await ledgerOf(6);
    const c3a = await signLedgerCheckpoint(same, { signer, clock, ledgerId: "ws_1", seq: 3 });
    const raced = await Promise.allSettled([
      pruneLedger(same, { ledgerId: "ws_1", checkpoint: c3a, keys }),
      pruneLedger(same, { ledgerId: "ws_1", checkpoint: c3a, keys }),
    ]);
    assert.ok(raced.every((r) => r.status === "fulfilled"), "the second pruner of the same checkpoint answers the point, never an error");
    assert.deepEqual((await same.base())?.seq, 3, "the same checkpoint prunes once");
    const two = await ledgerOf(6);
    const c3 = await signLedgerCheckpoint(two, { signer, clock, ledgerId: "ws_1", seq: 3 });
    const c5 = await signLedgerCheckpoint(two, { signer, clock, ledgerId: "ws_1", seq: 5 });
    const settled = await Promise.allSettled([
      pruneLedger(two, { ledgerId: "ws_1", checkpoint: c3, keys }),
      pruneLedger(two, { ledgerId: "ws_1", checkpoint: c5, keys }),
    ]);
    // The deeper checkpoint prunes and the shallower one answers its point, never an error read
    // as a failed prune that happened; the base ends at the deeper point either way.
    assert.ok(settled.every((r) => r.status === "fulfilled"), settled.map((r) => (r.status === "rejected" ? String(r.reason) : "")).join("; "));
    assert.deepEqual((await two.base())?.seq, 5, "whichever pruner won, the base ends at the deeper point");
  });

  it("answers the point when the base moves under the hold check, to the very point", async () => {
    // The pruner reads a base of nothing, another pruner wins to the very point while the hold
    // check reads, and the recovery reads the base back as the point: answered, never an error.
    const inner = await ledgerOf(6);
    const signed = await signLedgerCheckpoint(inner, { signer, clock, ledgerId: "ws_1", seq: 3 });
    let reads = 0;
    const racing: AuditLedger = {
      append: (i) => inner.append(i),
      head: () => inner.head(),
      list: async (fromSeq?: number, limit?: number) => (await inner.list(fromSeq, limit)).filter((e) => e.seq > 3),
      base: async () => {
        if (++reads === 1) return null;
        await inner.prune({ seq: 3, hash: signed.body.hash });
        return inner.base();
      },
      prune: (point: { seq: number; hash: string }) => inner.prune(point),
      spentEventId: (id: string) => inner.spentEventId(id),
    };
    assert.deepEqual(await pruneLedger(racing, { ledgerId: "ws_1", checkpoint: signed, keys }), { seq: 3, hash: signed.body.hash });
  });

  it("checks the prunedCount the signature vouches for, not the caller's object read again later", async () => {
    const ledger = await ledgerOf(4);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: await checkpoint(ledger, 2), keys });
    const second = await checkpoint(ledger, 4);
    // The caller's object changes under the base read: the count checked is the one the signature
    // verified, read once before any await, never the caller's later word.
    const mutating: AuditLedger = {
      append: (i) => ledger.append(i),
      head: () => ledger.head(),
      list: (fromSeq?: number, limit?: number) => ledger.list(fromSeq, limit),
      base: async () => {
        second.body.prunedCount = 99;
        return ledger.base();
      },
      prune: (point: { seq: number; hash: string }) => ledger.prune(point),
      spentEventId: (id: string) => ledger.spentEventId(id),
    };
    assert.deepEqual(await pruneLedger(mutating, { ledgerId: "ws_1", checkpoint: second, keys }), { seq: 4, hash: second.body.hash });
  });

  it("keeps a pruned eventId spent: a replay is refused, never a second entry", async () => {
    const ledger = new MemoryAuditLedger();
    const first = await ledger.append(input(1, "evt_once"));
    await ledger.append(input(2));
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: await checkpoint(ledger, 1), keys });
    await assert.rejects(ledger.append(input(1, "evt_once")), rejects("precondition_failed", /stays spent/));
    assert.deepEqual((await ledger.list()).map((e) => e.seq), [2], "nothing appended, and the first entry is not back");
    assert.notEqual((await ledger.head()).hash, first.hash);
  });

  it("answers the point for the same checkpoint again and prunes nothing, and refuses a ledger that cannot prune or one whose prune moves nothing", async () => {
    const ledger = await ledgerOf(3);
    const signed = await checkpoint(ledger);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    assert.deepEqual(await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys: keys }), { seq: signed.body.seq, hash: signed.body.hash }, "already done");
    assert.deepEqual((await ledger.list()).map((e) => e.seq), []);
    const plain: AuditLedger = { append: (input: AuditInput) => ledger.append(input), head: () => ledger.head(), list: (fromSeq?: number, limit?: number) => ledger.list(fromSeq, limit) };
    await assert.rejects(pruneLedger(plain, { ledgerId: "ws_1", checkpoint: signed, keys: keys }), rejects("precondition_failed", /cannot prune/));
    // A ledger with prune and base but no spentEventId would free replayed ids as it pruned them
    // and leave the engine blind to spent ones: it cannot prune either.
    const noTombstone: AuditLedger = {
      append: (input: AuditInput) => ledger.append(input),
      head: () => ledger.head(),
      list: (fromSeq?: number, limit?: number) => ledger.list(fromSeq, limit),
      base: () => ledger.base(),
      prune: (point: { seq: number; hash: string }) => ledger.prune(point),
    };
    await assert.rejects(pruneLedger(noTombstone, { ledgerId: "ws_1", checkpoint: signed, keys }), rejects("precondition_failed", /cannot prune/), "a ledger that prunes must also answer which ids it spent");
    class LazyPruner extends MemoryAuditLedger {
      override async prune(): Promise<void> {}
    }
    const lazy = new LazyPruner();
    await lazy.append(input(1));
    const lazyCheckpoint = await checkpoint(lazy);
    await assert.rejects(pruneLedger(lazy, { ledgerId: "ws_1", checkpoint: lazyCheckpoint, keys: keys }), rejects("precondition_failed", /did not prune to the checkpoint/));
    class FailingPruner extends MemoryAuditLedger {
      override async prune(): Promise<void> {
        throw new Error("storage refused the prune");
      }
    }
    const failing = new FailingPruner();
    await failing.append(input(1));
    const failingCheckpoint = await checkpoint(failing);
    await assert.rejects(
      pruneLedger(failing, { ledgerId: "ws_1", checkpoint: failingCheckpoint, keys }),
      (e: unknown) => e instanceof Error && /storage refused the prune/.test(e.message),
      "a prune that failed without moving the base throws the store's own error, never a masked one",
    );
  });
});

describe("exportLedger on a pruned ledger", () => {
  it("starts a full export at the base, only below a checkpoint that matches it, and the reader anchors the run on it", async () => {
    const ledger = await ledgerOf(6);
    const signed = await checkpoint(ledger, 3);
    const otherLedger = await signLedgerCheckpoint(ledger, { signer, clock, ledgerId: "ws_other", seq: 3 });
    const point = verifyLedgerCheckpoint(signed, keys);
    assert.ok(point.ok);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    // A pruned ledger is not exported without the checkpoint: the base alone is storage's word.
    await assert.rejects(run(ledger, { fromSeq: 1 }), rejects("precondition_failed", /give the checkpoint it was pruned below/));
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: { checkpoint: await checkpoint(await ledgerOf(6, 100), 3), keys } }), rejects("precondition_failed", /base \(seq 3\) is not the checkpoint's point/), "a checkpoint of another chain does not match the base");
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: { checkpoint: otherLedger, keys } }), rejects("invalid_input", /names the ledger ws_other/), "a checkpoint that names another ledger");
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: { checkpoint: { alg: "ES256", kid: "k1", signature: "AAAA", body: 7 } as never, keys } }), rejects("invalid_input", /not a signed ledger_checkpoint/));
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: { checkpoint: { alg: "ES256", kid: "k1", signature: "AAAA", body: { v: 1, type: "ledger_checkpoint", ledgerId: "ws_1", seq: 3, hash: "ab".repeat(32), prunedCount: 3, at: clock.now().toISOString() } } as never, keys } }), rejects("invalid_input", /signature does not verify/));
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: null as never }), rejects("invalid_input", /not a signed ledger_checkpoint/), "a checkpoint reference that is not an object");
    const text = await run(ledger, { fromSeq: 1, checkpoint: { checkpoint: signed, keys } });
    const check = verifyLedgerExport(text, keys, undefined, signed);
    assert.ok(check.ok);
    assert.deepEqual(check.trailer.from, point.point, "the reader checks the trailer's from against the signed checkpoint");
    assert.deepEqual(check.entries.map((e) => e.seq), [4, 5, 6]);
    assert.equal(verifyChain(check.entries, point.point).ok, true);
    // Without the anchor, the run still verifies on its own; with a mismatched anchor it does not.
    assert.ok(verifyLedgerExport(text, keys).ok);
    const other = await checkpoint(await ledgerOf(6, 100), 3);
    assert.deepEqual(verifyLedgerExport(text, keys, undefined, other), { ok: false, reason: "checkpoint" }, "the anchored start must be the checkpoint's point");
    assert.deepEqual(verifyLedgerExport(text, keys, undefined, otherLedger), { ok: false, reason: "checkpoint" }, "the checkpoint must name the trailer's ledger");
    assert.deepEqual(verifyLedgerExport(text, keys, undefined, { alg: "HS256", kid: "k1", signature: "AAAA" } as never), { ok: false, reason: "malformed" });
    assert.deepEqual(verifyLedgerExport(text, keys, undefined, { alg: "ES256", kid: "k1", signature: "AAAA", body: { v: 1, type: "ledger_checkpoint", ledgerId: "ws_1", seq: 3, hash: "ab".repeat(32), prunedCount: 3, at: clock.now().toISOString() } } as never), { ok: false, reason: "signature" });
  });

  it("refuses to sign a full export for a base that storage moved with no checkpoint vouching for it", async () => {
    // A legitimate checkpoint at 2, then storage hides rows and moves its base to 7 with nothing
    // signed for it: the export is refused, where a base taken at its word would sign the gap.
    const ledger = await ledgerOf(10);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: await checkpoint(ledger, 2), keys });
    const [seventh] = await ledger.list(7, 1);
    const second = await checkpoint(ledger, 7);
    await ledger.prune({ seq: 7, hash: seventh!.hash });
    await assert.rejects(run(ledger, { fromSeq: 1 }), rejects("precondition_failed", /give the checkpoint/));
    const moved = verifyLedgerExport(await run(ledger, { fromSeq: 1, checkpoint: { checkpoint: second, keys } }), keys, undefined, second);
    assert.ok(moved.ok, "a base that a matching checkpoint vouches for exports, whatever happened before");
    assert.deepEqual(moved.entries.map((e) => e.seq), [8, 9, 10]);
  });

  it("refuses the same hidden rows on an adapter that reports no base at all, as before the checkpoint", async () => {
    const inner = await ledgerOf(10);
    const hiding: AuditLedger = {
      append: (i) => inner.append(i),
      head: () => inner.head(),
      list: async (f, l) => (await inner.list(f, l)).filter((e) => e.seq > 5),
    };
    await assert.rejects(run(hiding, { fromSeq: 1 }), rejects("precondition_failed", /does not hold seq 0|does not verify/), "the chain from the genesis is refused, never signed");
  });

  it("resumes by a cursor naming the base, refuses one below it, and starts a fromSeq above the base on the entry it holds", async () => {
    const ledger = await ledgerOf(6);
    const signed = await checkpoint(ledger, 3);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    const base = (await ledger.base())!;
    const fromBase = verifyLedgerExport(await run(ledger, { cursor: encodeCursor(base), checkpoint: { checkpoint: signed, keys } }), keys);
    assert.ok(fromBase.ok);
    assert.deepEqual(fromBase.entries.map((e) => e.seq), [4, 5, 6]);
    await assert.rejects(run(ledger, { cursor: `1.${"ab".repeat(32)}`, checkpoint: { checkpoint: signed, keys } }), rejects("precondition_failed", /no longer holds the cursor's entry/), "a cursor below the base");
    await assert.rejects(run(ledger, { cursor: encodeCursor({ seq: base.seq, hash: "ab".repeat(32) }), checkpoint: { checkpoint: signed, keys } }), rejects("precondition_failed", /no longer holds the cursor's entry/), "a cursor naming the base with another hash");
    const [fourth] = await ledger.list(4, 1);
    const above = verifyLedgerExport(await run(ledger, { fromSeq: 5, checkpoint: { checkpoint: signed, keys } }), keys);
    assert.ok(above.ok);
    assert.deepEqual(above.trailer.from, { seq: fourth!.seq, hash: fourth!.hash });
    const limited = verifyLedgerExport(await run(ledger, { fromSeq: 1, limit: 2, checkpoint: { checkpoint: signed, keys } }), keys);
    assert.ok(limited.ok);
    assert.deepEqual(limited.entries.map((e) => e.seq), [4, 5], "a limited run of what the ledger holds, from the checkpoint on");
  });

  it("exports an empty run from a ledger pruned to its head, and refuses a fromSeq between 1 and the base", async () => {
    const ledger = await ledgerOf(3);
    const signed = await checkpoint(ledger);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    // A fromSeq below the base, other than a full export's 1, is refused as ever: the entry before
    // it is gone, and only the checkpoint anchors the run.
    await assert.rejects(run(ledger, { fromSeq: 2, checkpoint: { checkpoint: signed, keys } }), rejects("precondition_failed", /does not hold seq 1/));
    const check = verifyLedgerExport(await run(ledger, { fromSeq: 1, checkpoint: { checkpoint: signed, keys } }), keys, undefined, signed);
    assert.ok(check.ok);
    assert.deepEqual([check.entries, check.trailer.count], [[], 0]);
    assert.deepEqual(check.trailer.from, check.trailer.through);
    assert.deepEqual(check.trailer.head, verifyLedgerCheckpoint(signed, keys).ok ? { seq: signed.body.seq, hash: signed.body.hash } : null);
  });

  it("refuses to sign an export for a base that the remaining entries do not continue", async () => {
    class LyingBase extends MemoryAuditLedger {
      lie = false;
      override async base(): Promise<ChainPoint | null> {
        const base = await super.base();
        return base === null || !this.lie ? base : { seq: base.seq, hash: "ab".repeat(32) };
      }
    }
    const ledger = new LyingBase();
    for (let i = 1; i <= 4; i++) await ledger.append(input(i));
    const signed = await checkpoint(ledger, 2);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    ledger.lie = true;
    await assert.rejects(run(ledger, { fromSeq: 1, checkpoint: { checkpoint: signed, keys } }), rejects("precondition_failed", /base \(seq 2\) is not the checkpoint's point/));
  });
});

describe("the engine on a pruned ledger", () => {
  const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

  it("anchors the head a prune left, and the entry continues from the checkpoint", async () => {
    const t = createTestEngine({ adapters: { anchor: new FakeTimestampAuthority(new FixedClock()) } });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    const point = await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    const entry = await t.engine.anchorLedger();
    assert.deepEqual({ seq: entry.seq, prevHash: entry.prevHash }, { seq: point.seq + 1, prevHash: point.hash }, "the anchor continues the pruned chain");
    assert.deepEqual(verifyChain(await t.ledger.list(), point), { ok: true, head: await t.ledger.head() });
    // And once more, on the entry the first anchor appended.
    const again = await t.engine.anchorLedger();
    assert.equal(again.seq, entry.seq + 1);
  });

  it("answers a consent.revoked the ledger already wrote below a pruned base, without writing it twice", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    const callId = await verifiedCall(t);
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.endCall(callId);
    const first = await t.engine.revokeConsent({ consentId: yes.consentId, via: "text" });
    assert.equal((await t.ledger.list()).filter((e) => e.event === "consent.revoked").length, 1);
    // The checkpoint is the head, so the prune takes the consent.revoked entry with it: the id
    // stays spent, and a second STOP must not write a second entry either.
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    const held = (await t.ledger.list()).length;
    const again = await t.engine.revokeConsent({ consentId: yes.consentId, via: "web" });
    assert.deepEqual(again, first, "the revocation the store already holds answers");
    assert.equal((await t.ledger.list()).length, held, "nothing was appended for the spent id");
  });

  it("refuses an anchor whose checkpoint does not verify, and a prune whose ledgerId is empty", async () => {
    const tsa = new FakeTimestampAuthority(new FixedClock());
    const t = createTestEngine({ adapters: { anchor: tsa } });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const anchored = await t.engine.anchorLedger();
    const entries = await t.ledger.list();
    assert.deepEqual(verifyAnchor(anchored, entries, { tsa: tsa.chain, checkpoint: { checkpoint: { alg: "ES256", kid: "k1", signature: "AAAA", body: 7 } as never, keys } }), { ok: false, reason: "malformed" }, "a checkpoint that is not a document");
    assert.deepEqual(verifyAnchor(anchored, entries, { tsa: tsa.chain, checkpoint: { checkpoint: { alg: "ES256", kid: "k1", signature: "AAAA", body: { v: 1, type: "ledger_checkpoint", ledgerId: "ws_test", seq: 1, hash: "ab".repeat(32), prunedCount: 1, at: clock.now().toISOString() } } as never, keys } }), { ok: false, reason: "checkpoint" }, "a checkpoint whose signature does not verify, never a token failure");
    const ledger = await ledgerOf(2);
    const signed = await checkpoint(ledger);
    await assert.rejects(pruneLedger(ledger, { ledgerId: "", checkpoint: signed, keys }), rejects("invalid_input", /ledgerId must be a non-empty string/));
  });

  it("answers the point when the store's prune throws after its own write", async () => {
    // The store moved the base and then reported a hiccup: the prune happened, and the caller is
    // told the point, not the store's complaint.
    class Hiccup extends MemoryAuditLedger {
      override async prune(checkpoint: { seq: number; hash: string }): Promise<void> {
        await super.prune(checkpoint);
        throw new Error("storage hiccup after the write");
      }
    }
    const ledger = new Hiccup();
    for (let i = 1; i <= 3; i++) await ledger.append(input(i));
    const signed = await checkpoint(ledger);
    assert.deepEqual(await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys }), { seq: signed.body.seq, hash: signed.body.hash });
    assert.deepEqual(await ledger.base(), { seq: signed.body.seq, hash: signed.body.hash });
  });

  it("verifies an anchor written after a prune against the checkpoint, and refuses it without one", async () => {
    const tsa = new FakeTimestampAuthority(new FixedClock());
    const t = createTestEngine({ adapters: { anchor: tsa } });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    const point = await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    const anchored = await t.engine.anchorLedger();
    assert.equal(anchored.seq, point.seq + 1);
    const entries = await t.ledger.list();
    assert.equal(verifyAnchor(anchored, entries, { tsa: tsa.chain }).ok, false, "without the checkpoint the pruned entries cannot reach the covered seq");
    const checked = verifyAnchor(anchored, entries, { tsa: tsa.chain, checkpoint: { checkpoint: signed, keys } });
    assert.ok(checked.ok, "the checkpoint anchors the chain the anchor covers");
    // The anchor covers the head it anchored: the pruned ledger's head, the checkpoint's point.
    assert.deepEqual({ seq: checked.seq, hash: checked.hash, logIndex: checked.logIndex }, { seq: point.seq, hash: point.hash, logIndex: null });
  });

  it("names the head a prune left in a monthly report, not the genesis", async () => {
    const ledger = await ledgerOf(3);
    const signed = await checkpoint(ledger);
    await pruneLedger(ledger, { ledgerId: "ws_1", checkpoint: signed, keys });
    const report = await monthlyReport({ ledger, workspaceId: "ws_1", month: "2026-01" });
    assert.deepEqual(report.ledger, { seq: signed.body.seq, hash: signed.body.hash }, "the ledger point is the head the pruned ledger keeps");
  });

  it("lists and erases a subject on a pruned ledger, appending above the checkpoint", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak under the sink");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    await t.engine.endCall(callId);
    const entries = await t.ledger.list();
    // Prune below the record's filing, leaving the entries that name it.
    const cut = entries.findIndex((e) => e.event === "intake.confirmed" && e.detail.recordId === record.recordId);
    assert.ok(cut > 0, "the record was filed on the ledger");
    const point = { seq: entries[cut - 1]!.seq, hash: entries[cut - 1]!.hash };
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test", seq: point.seq });
    await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    const exported = await t.engine.exportSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(exported.body.intakeRecords.map((r) => r.recordId).includes(record.recordId), true, "the record itself is not pruned");
    assert.ok(exported.body.ledgerEntries.every((e) => e.seq > point.seq), "only the entries the ledger still holds are listed");
    const erased = await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(erased.erased, true);
    const left = await t.ledger.list();
    assert.ok(left.some((e) => e.event === "subject.erased" && e.seq > point.seq));
    assert.deepEqual(verifyChain(left, point), { ok: true, head: await t.ledger.head() });
  });

  it("erases a subject again after a prune: the spent number is skipped, never taken twice", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak under the sink");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    await t.engine.endCall(callId);
    const first = await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(first.erased, true);
    // The checkpoint is the head, so the prune takes the first erasure's plan and completion too.
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    // A record filed since: the numbering starts again at 0 below the base, whose keyed id the
    // first erasure spent, so the second erasure takes the next free number and completes.
    const again = await verifiedCall(t);
    await t.engine.startIntake(again, "repair");
    await t.engine.setIntakeField(again, "issue", "new leak");
    const refiled = await t.engine.confirmIntake(again, { confirmedBy: "voice", readBack: await heard(t, again) });
    await t.engine.endCall(again);
    const base = (await t.ledger.base())!;
    const second = await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(second.erased, true);
    assert.equal(second.recordIds.includes(refiled.recordId), true, "the re-filed record is erased");
    assert.equal(await t.records.getIntakeRecord("ws_test", refiled.recordId), null, "the record store no longer holds it");
    const entries = await t.ledger.list();
    const plans = entries.filter((e) => e.event === "subject.erased");
    assert.equal(plans.length, 1, "one fresh plan above the base, never the spent number taken twice");
    assert.ok(plans[0]!.seq > base.seq);
    assert.deepEqual(verifyChain(entries, base), { ok: true, head: await t.ledger.head() });
  });

  it("skips the spent-id probe on a ledger that never pruned, or cannot", async () => {
    const inner = new MemoryAuditLedger();
    let probed = 0;
    const counting: AuditLedger = {
      append: (i) => inner.append(i),
      head: () => inner.head(),
      list: (fromSeq?: number, limit?: number) => inner.list(fromSeq, limit),
      base: async () => null,
      spentEventId: async () => {
        probed++;
        return false;
      },
    };
    const t = setup({ adapters: { ledger: counting } });
    const callId = await verifiedCall(t);
    await t.engine.endCall(callId);
    assert.ok((await inner.list()).length > 0, "the appends flowed");
    assert.equal(probed, 0, "a ledger whose base is null never pruned, so its tombstone is never probed");
    // And a ledger with no base at all (one that cannot prune): the appends flow as ever.
    const bareInner = new MemoryAuditLedger();
    const bare: AuditLedger = { append: (i) => bareInner.append(i), head: () => bareInner.head(), list: (fromSeq?: number, limit?: number) => bareInner.list(fromSeq, limit) };
    const plain = setup({ adapters: { ledger: bare } });
    const second = await verifiedCall(plain);
    await plain.engine.endCall(second);
    assert.ok((await bareInner.list()).length > 0, "a ledger without base or spentEventId appends as ever");
  });

  it("finishes a pin change again after a prune: the spent id is skipped and nothing is appended", async () => {
    const t = setup();
    const ref = { at: t.clock.now().toISOString(), change: "b".repeat(64) };
    await t.engine.finishPinChange(SUBJECT, ref);
    assert.equal((await t.ledger.list()).length, 1, "the pin.reset entry");
    // The checkpoint is the head, so the prune takes the pin.reset entry with it.
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    const held = (await t.ledger.list()).length;
    await t.engine.finishPinChange(SUBJECT, ref);
    assert.equal((await t.ledger.list()).length, held, "the id is spent: the counters still cleared, and no second entry written");
  });

  it("clears an outbox whose entries a prune spent, appending nothing twice", async () => {
    // The session store refuses the outbox's clear while the call is ended (a store that was
    // partitioned): the entries are appended but stay queued, the engine's own retry appends
    // nothing twice (the ledger dedups), and the call is left pending. A prune past them spends
    // their ids, and the next flush skips every one and clears the outbox.
    class EndClearLost extends MemorySessionStore {
      #lost = true;
      release(): void {
        this.#lost = false;
      }
      override async compareAndSet(w: string, c: string, version: number, record: JsonValue, hint?: WriteHint): Promise<{ ok: true; version: number } | { ok: false }> {
        if (this.#lost && hint?.ledgerPending === false && (record as { state?: { phase?: string } }).state?.phase === "ended") {
          const stored = (await super.get(w, c))?.record as { outbox?: unknown[] } | undefined;
          if ((stored?.outbox?.length ?? 0) > 0) return { ok: false };
        }
        return super.compareAndSet(w, c, version, record, hint);
      }
    }
    const sessions = new EndClearLost();
    const t = setup({ adapters: { sessions } });
    const callId = await verifiedCall(t);
    await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.endCall(callId);
    const appended = (await t.ledger.list()).length;
    assert.ok(appended > 0, "the queued entries were appended, however often the clear was refused");
    const queued = ((await sessions.get("ws_test", callId))!.record as { outbox?: unknown[] }).outbox?.length ?? 0;
    assert.ok(queued > 0, "the outbox still holds its entries");
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    await pruneLedger(t.ledger, { ledgerId: "ws_test", checkpoint: signed, keys });
    sessions.release();
    const report = await t.engine.flushPending();
    assert.deepEqual(report.failed, []);
    assert.ok(report.flushed.includes(callId), "the call's outbox was cleared");
    assert.equal((await t.ledger.list()).length, 0, "nothing was re-appended for the spent ids");
    assert.deepEqual(await t.engine.flushPending(), { flushed: [], failed: [] }, "nothing is pending any more");
  });
});
