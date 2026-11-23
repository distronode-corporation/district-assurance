// Ledger checkpoints and pruning (#157, #158, #159): the signed ledger_checkpoint document and its
// verifier, pruneLedger's gate on a written checkpoint, the checkpoint-aware export, and the engine
// on a pruned ledger.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { canonicalJson } from "../src/core/canonical.ts";
import { EngineError } from "../src/core/errors.ts";
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
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import type { AuditEntry, AuditInput, AuditLedger } from "../src/core/adapters.ts";
import type { ChainPoint } from "../src/prove/export.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeTimestampAuthority, FixedClock, TEST_KNOWLEDGE_KEY, generateTestSigner, createTestEngine } from "../src/testing/index.ts";
import { ACCOUNT, heard, rejects, setup, verifiedCall } from "./helpers.ts";

const clock = new FixedClock("2026-11-18T12:00:00.000Z");
const signer = generateTestSigner("k1");
const keys = [signer.publicJwk()];
const OTHER_KEYS = [generateTestSigner("k1").publicJwk()];

const input = (n: number): AuditInput => ({ callId: "c1", actor: "code", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { n } });

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
    await pruneLedger(ledger, first, keys);
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
    await pruneLedger(ledger, await checkpoint(ledger, 2), keys);
    await assert.rejects(checkpoint(ledger, 2), rejects("precondition_failed", /nothing would be cut/));
    await assert.rejects(checkpoint(ledger, 1), rejects("precondition_failed", /nothing would be cut/));
    // A ledger whose reads were rewritten is never vouched for.
    const tampered = new EditedLedger(await ledgerOf(4), (entries) => entries.map((e) => (e.seq === 2 ? { ...e, detail: { n: 99 } } : e)));
    await assert.rejects(checkpoint(tampered), rejects("precondition_failed", /does not verify at seq 2/));
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
    assert.deepEqual(await pruneLedger(ledger, signed, keys), { seq: 3, hash: third!.hash });
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
    await assert.rejects(pruneLedger(ledger, forged as never, keys), rejects("invalid_input", /does not verify against the key set/));
    const early = await checkpoint(ledger, 1);
    const signed = await checkpoint(ledger, 2);
    const malformed: unknown = { alg: "ES256", kid: "k1", signature: signed.signature, body: 7 };
    await assert.rejects(pruneLedger(ledger, malformed as never, keys), rejects("invalid_input", /not a signed ledger_checkpoint document/));
    await assert.rejects(pruneLedger(ledger, signed, OTHER_KEYS), rejects("invalid_input", /does not verify/));
    // A checkpoint of another ledger's chain, at a seq this ledger holds with another hash.
    const foreign = await checkpoint(await ledgerOf(5, 100), 2);
    await assert.rejects(pruneLedger(ledger, foreign, keys), rejects("precondition_failed", /does not hold the checkpoint's entry/));
    // A checkpoint past this ledger's head.
    const ahead = await checkpoint(await ledgerOf(5), 5);
    await assert.rejects(pruneLedger(ledger, ahead, keys), rejects("precondition_failed", /does not hold the checkpoint's entry/));
    await pruneLedger(ledger, signed, keys);
    // A rollback to an earlier checkpoint, and one at the base with another chain's hash.
    await assert.rejects(pruneLedger(ledger, early, keys), rejects("precondition_failed", /already pruned through seq 2/));
    const sameSeqOtherChain = await checkpoint(await ledgerOf(2, 100), 2);
    await assert.rejects(pruneLedger(ledger, sameSeqOtherChain, keys), rejects("precondition_failed", /already pruned through seq 2/));
  });

  it("refuses a checkpoint seq that is not an integer of 1 or more, without pruning anything", async () => {
    const ledger = await ledgerOf(2);
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(ledger.prune({ seq: bad, hash: "ab".repeat(32) }), TypeError, String(bad));
    }
    assert.deepEqual((await ledger.list()).map((e) => e.seq), [1, 2], "nothing was pruned");
  });

  it("answers the point for the same checkpoint again and prunes nothing, and refuses a ledger that cannot prune or one whose prune moves nothing", async () => {
    const ledger = await ledgerOf(3);
    const signed = await checkpoint(ledger);
    await pruneLedger(ledger, signed, keys);
    assert.deepEqual(await pruneLedger(ledger, signed, keys), { seq: signed.body.seq, hash: signed.body.hash }, "already done");
    assert.deepEqual((await ledger.list()).map((e) => e.seq), []);
    const plain: AuditLedger = { append: (input: AuditInput) => ledger.append(input), head: () => ledger.head(), list: (fromSeq?: number, limit?: number) => ledger.list(fromSeq, limit) };
    await assert.rejects(pruneLedger(plain, signed, keys), rejects("precondition_failed", /cannot prune/));
    class LazyPruner extends MemoryAuditLedger {
      override async prune(): Promise<void> {}
    }
    const lazy = new LazyPruner();
    await lazy.append(input(1));
    const lazyCheckpoint = await checkpoint(lazy);
    await assert.rejects(pruneLedger(lazy, lazyCheckpoint, keys), rejects("precondition_failed", /did not prune to the checkpoint/));
  });
});

describe("exportLedger on a pruned ledger", () => {
  it("starts a full export at the base: the trailer's from is the checkpoint, and the run is everything the ledger holds", async () => {
    const ledger = await ledgerOf(6);
    const signed = await checkpoint(ledger, 3);
    const point = verifyLedgerCheckpoint(signed, keys);
    assert.ok(point.ok);
    await pruneLedger(ledger, signed, keys);
    const text = await run(ledger, { fromSeq: 1 });
    const check = verifyLedgerExport(text, keys);
    assert.ok(check.ok);
    assert.deepEqual(check.trailer.from, point.point, "the reader checks the trailer's from against the signed checkpoint");
    assert.deepEqual(check.entries.map((e) => e.seq), [4, 5, 6]);
    assert.equal(verifyChain(check.entries, point.point).ok, true);
  });

  it("resumes by a cursor naming the base, refuses one below it, and starts a fromSeq above the base on the entry it holds", async () => {
    const ledger = await ledgerOf(6);
    await pruneLedger(ledger, await checkpoint(ledger, 3), keys);
    const base = (await ledger.base())!;
    const fromBase = verifyLedgerExport(await run(ledger, { cursor: encodeCursor(base) }), keys);
    assert.ok(fromBase.ok);
    assert.deepEqual(fromBase.entries.map((e) => e.seq), [4, 5, 6]);
    await assert.rejects(run(ledger, { cursor: `1.${"ab".repeat(32)}` }), rejects("precondition_failed", /no longer holds the cursor's entry/), "a cursor below the base");
    await assert.rejects(run(ledger, { cursor: encodeCursor({ seq: base.seq, hash: "ab".repeat(32) }) }), rejects("precondition_failed", /no longer holds the cursor's entry/), "a cursor naming the base with another hash");
    const [fourth] = await ledger.list(4, 1);
    const above = verifyLedgerExport(await run(ledger, { fromSeq: 5 }), keys);
    assert.ok(above.ok);
    assert.deepEqual(above.trailer.from, { seq: fourth!.seq, hash: fourth!.hash });
    const limited = verifyLedgerExport(await run(ledger, { fromSeq: 1, limit: 2 }), keys);
    assert.ok(limited.ok);
    assert.deepEqual(limited.entries.map((e) => e.seq), [4, 5], "a limited run of what the ledger holds, from the checkpoint on");
  });

  it("exports an empty run from a ledger pruned to its head", async () => {
    const ledger = await ledgerOf(3);
    const signed = await checkpoint(ledger);
    await pruneLedger(ledger, signed, keys);
    const check = verifyLedgerExport(await run(ledger, { fromSeq: 1 }), keys);
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
    await pruneLedger(ledger, await checkpoint(ledger, 2), keys);
    ledger.lie = true;
    await assert.rejects(run(ledger, { fromSeq: 1 }), rejects("precondition_failed", /does not verify at seq 3/));
  });
});

describe("the engine on a pruned ledger", () => {
  const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

  it("anchors the head a prune left, and the entry continues from the checkpoint", async () => {
    const t = createTestEngine({ adapters: { anchor: new FakeTimestampAuthority(new FixedClock()) } });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const signed = await signLedgerCheckpoint(t.ledger, { signer, clock: t.clock, ledgerId: "ws_test" });
    const point = (await pruneLedger(t.ledger, signed, keys))!;
    const entry = await t.engine.anchorLedger();
    assert.deepEqual({ seq: entry.seq, prevHash: entry.prevHash }, { seq: point.seq + 1, prevHash: point.hash }, "the anchor continues the pruned chain");
    assert.deepEqual(verifyChain(await t.ledger.list(), point), { ok: true, head: await t.ledger.head() });
    // And once more, on the entry the first anchor appended.
    const again = await t.engine.anchorLedger();
    assert.equal(again.seq, entry.seq + 1);
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
    await pruneLedger(t.ledger, signed, keys);
    const exported = await t.engine.exportSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(exported.body.intakeRecords.map((r) => r.recordId).includes(record.recordId), true, "the record itself is not pruned");
    assert.ok(exported.body.ledgerEntries.every((e) => e.seq > point.seq), "only the entries the ledger still holds are listed");
    const erased = await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey: SUBJECT });
    assert.equal(erased.erased, true);
    const left = await t.ledger.list();
    assert.ok(left.some((e) => e.event === "subject.erased" && e.seq > point.seq));
    assert.deepEqual(verifyChain(left, point), { ok: true, head: await t.ledger.head() });
  });
});
