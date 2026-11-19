// SRV-7: properties of the audit ledger. Any sequence of appends from several writers, in any order
// and interleaving, keeps one valid hash chain; any single changed byte in a stored entry breaks it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import fc from "fast-check";

import type { AuditEntry, AuditInput } from "../../src/core/adapters.ts";
import type { JsonValue } from "../../src/core/canonical.ts";
import { EngineError } from "../../src/core/errors.ts";
import { ENGINE_EVENTS, type Actor } from "../../src/core/events.ts";
import { GENESIS_HASH, MemoryAuditLedger, chainEntry, detailCarriesCardNumber, verifyChain } from "../../src/prove/ledger.ts";
import { flipByte, fuzz, int, jsonObject, nastyString, pick, setOwn } from "../fuzz/harness.ts";

const ACTORS: readonly Actor[] = ["caller", "ai", "code", "member", "system"];
/** Card numbers that pass the Luhn check: an append carrying one is refused. */
const CARDS = ["4242 4242 4242 4242", "4000-0566-5566-5556", "5555555555554444"];

function auditInput(writer: number): fc.Arbitrary<AuditInput> {
  return fc
    .record({
      // A small pool of event ids shared by every writer, so retries and clashes happen.
      eventId: fc.oneof({ weight: 7, arbitrary: fc.constant(undefined) }, { weight: 3, arbitrary: fc.integer({ min: 0, max: 5 }).map((n) => `evt_${n}`) }),
      callId: fc.oneof({ weight: 1, arbitrary: fc.constant(null) }, { weight: 9, arbitrary: nastyString(6).map((s) => `call_${writer}_${s}`) }),
      actor: fc.constantFrom(...ACTORS),
      event: fc.constantFrom(...ENGINE_EVENTS),
      at: fc.integer({ min: 0, max: 10 ** 9 }).map((ms) => new Date(Date.UTC(2026, 0, 1) + ms).toISOString()),
      detail: jsonObject(3),
      card: fc.oneof({ weight: 19, arbitrary: fc.constant(undefined) }, { weight: 1, arbitrary: fc.constantFrom(...CARDS) }),
    })
    .map(({ eventId, card, detail, ...rest }) => {
      const copy = { ...detail } as { [key: string]: JsonValue };
      if (card !== undefined) setOwn(copy, "note", card);
      return { ...(eventId === undefined ? {} : { eventId }), ...rest, detail: copy };
    });
}

interface Writers {
  /** One list of appends per writer, in the writer's own order. */
  writers: AuditInput[][];
  /** Microtask yields before each append, so concurrent writers interleave differently every case. */
  yields: number[][];
  concurrent: boolean;
}

const writers: fc.Arbitrary<Writers> = fc
  .integer({ min: 1, max: 6 })
  .chain((count) =>
    fc.record({
      writers: fc.tuple(...Array.from({ length: count }, (_, w) => fc.array(auditInput(w), { maxLength: 12 }))),
      yields: fc.array(fc.array(fc.integer({ min: 0, max: 3 }), { minLength: 12, maxLength: 12 }), { minLength: count, maxLength: count }),
      concurrent: fc.boolean(),
    }),
  );

/** What a ledger must do with one append, given the event ids it has already stored. */
type Expected = { kind: "first"; eventId: string } | { kind: "refused" } | { kind: "appended" };

async function runWriters(ledger: MemoryAuditLedger, plan: Writers, g: fc.GeneratorValue) {
  const stored = new Set<string>();
  const results: Array<{ writer: number; expected: Expected; input: AuditInput; outcome: AuditEntry | Error }> = [];
  const appendOne = async (writer: number, input: AuditInput) => {
    // The model, taken when the append is made: an id seen before returns its first entry.
    let expected: Expected;
    if (input.eventId !== undefined && stored.has(input.eventId)) expected = { kind: "first", eventId: input.eventId };
    else if (detailCarriesCardNumber(input.detail)) expected = { kind: "refused" };
    else {
      expected = { kind: "appended" };
      if (input.eventId !== undefined) stored.add(input.eventId);
    }
    const outcome = await ledger.append(input).catch((error: unknown) => error as Error);
    results.push({ writer, expected, input, outcome });
  };
  if (plan.concurrent) {
    await Promise.all(
      plan.writers.map(async (list, w) => {
        for (const [i, input] of list.entries()) {
          for (let y = plan.yields[w]![i]!; y > 0; y--) await Promise.resolve();
          await appendOne(w, input);
        }
      }),
    );
  } else {
    // One at a time, in an interleaving that keeps each writer's own order.
    const next = plan.writers.map(() => 0);
    for (;;) {
      const ready = next.flatMap((n, w) => (n < plan.writers[w]!.length ? [w] : []));
      if (ready.length === 0) break;
      const w = pick(g, ready);
      await appendOne(w, plan.writers[w]![next[w]!++]!);
    }
  }
  return results;
}

/** A small chain to tamper with: a few entries with details of every JSON kind. */
async function chain(g: fc.GeneratorValue): Promise<AuditEntry[]> {
  const ledger = new MemoryAuditLedger();
  for (let n = int(g, 1, 6); n > 0; n--) {
    const input = g(auditInput, n);
    delete input.eventId;
    if (detailCarriesCardNumber(input.detail)) input.detail = {};
    await ledger.append(input);
  }
  return ledger.list();
}

/** A copy with every object's keys in an order drawn by `g`. */
function reordered(g: fc.GeneratorValue, value: JsonValue): JsonValue {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => reordered(g, item));
  const keys = Object.keys(value);
  const out: { [key: string]: JsonValue } = {};
  for (const key of g(fc.shuffledSubarray, keys, { minLength: keys.length })) setOwn(out, key, reordered(g, value[key]!));
  return out;
}

describe("property: the ledger's hash chain", () => {
  it("stays one valid chain for any sequence of appends from several writers", async () => {
    await fuzz(
      fc.asyncProperty(writers, fc.gen(), async (plan, g) => {
        const ledger = new MemoryAuditLedger();
        const results = await runWriters(ledger, plan, g);
        const stored = await ledger.list();

        assert.deepEqual(verifyChain(stored), { ok: true, head: await ledger.head() });
        assert.deepEqual(
          stored.map((e) => e.seq),
          stored.map((_, i) => i + 1),
        );
        assert.equal(stored.length, results.filter((r) => r.expected.kind === "appended").length);
        for (const { expected, input, outcome } of results) {
          if (expected.kind === "refused") {
            assert.ok(outcome instanceof EngineError && outcome.code === "invalid_input", "a detail with a card number is refused");
            continue;
          }
          assert.ok(!(outcome instanceof Error), String(outcome));
          assert.deepEqual(outcome, stored[outcome.seq - 1], "each append returns what is stored");
          if (expected.kind === "first") assert.equal(stored.find((e) => e.eventId === expected.eventId), stored[outcome.seq - 1]);
          else assert.deepEqual(outcome, chainEntry(input, outcome.seq, outcome.seq === 1 ? GENESIS_HASH : stored[outcome.seq - 2]!.hash));
        }
        // Each writer's entries are in its own order, and an event id is stored once.
        for (const w of plan.writers.keys()) {
          const seqs = results.filter((r) => r.writer === w && r.expected.kind === "appended").map((r) => (r.outcome as AuditEntry).seq);
          assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b));
        }
        const ids = stored.flatMap((e) => (e.eventId === undefined ? [] : [e.eventId]));
        assert.equal(new Set(ids).size, ids.length);
        // Any slice continues the chain from the entry before it.
        const from = int(g, 0, stored.length);
        const head = from === 0 ? { seq: 0, hash: GENESIS_HASH } : { seq: from, hash: stored[from - 1]!.hash };
        assert.equal(verifyChain(stored.slice(from), head).ok, true);
      }),
    );
  });

  it("hashes a detail the same whatever the order of its keys", async () => {
    await fuzz(
      fc.property(auditInput(0), fc.gen(), (input, g) => {
        if (detailCarriesCardNumber(input.detail)) return;
        const shuffled = { ...input, detail: reordered(g, input.detail) as { [key: string]: JsonValue } };
        assert.equal(chainEntry(shuffled, 1, GENESIS_HASH).hash, chainEntry(input, 1, GENESIS_HASH).hash);
      }),
    );
  });

  // A stored number changed to 1e999 (Infinity once parsed) once made verifyChain throw instead of
  // reporting the break; test/prove.test.ts keeps that entry as a fixed case.
  it("breaks on any single changed byte in any stored entry", async () => {
    await fuzz(
      fc.asyncProperty(fc.gen(), async (g) => {
        const entries = await chain(g);
        const index = int(g, 0, entries.length - 1);
        // An entry as a store would keep it: one line of JSON.
        const line = Buffer.from(JSON.stringify(entries[index]), "utf8");
        const bytes = g(flipByte, line);
        let changed: AuditEntry;
        try {
          changed = JSON.parse(bytes.toString("utf8")) as AuditEntry;
        } catch {
          return; // The line no longer parses: the store cannot read it, which is a break too.
        }
        if (typeof changed !== "object" || changed === null) return;
        // `\u001f` and `\u001F` are one string: a byte that changes no value changes nothing.
        try {
          assert.deepEqual(changed, entries[index]);
          return;
        } catch {
          // The value changed.
        }
        const tampered = entries.with(index, changed);
        assert.equal(verifyChain(tampered).ok, false, "a changed entry breaks the chain");
        // And a verifier that skips the changed entry still sees the break at the next one.
        if (index < entries.length - 1) {
          const from = { seq: entries[index]!.seq, hash: changed.hash };
          assert.equal(verifyChain(entries.slice(index + 1), from).ok, changed.hash === entries[index]!.hash);
        }
      }),
    );
  });

  it("breaks after an entry rewritten with its hash recomputed, and moves the head of a rewritten last entry", async () => {
    await fuzz(
      fc.asyncProperty(fc.gen(), async (g) => {
        const entries = await chain(g);
        const index = int(g, 0, entries.length - 1);
        const entry = entries[index]!;
        const rewritten = chainEntry({ callId: entry.callId, actor: entry.actor, event: entry.event, at: entry.at, detail: { ...entry.detail, rewritten: true } }, entry.seq, entry.prevHash);
        const result = verifyChain(entries.with(index, rewritten));
        if (index < entries.length - 1) assert.deepEqual(result, { ok: false, seq: entry.seq + 1, reason: "prev_hash" });
        else assert.ok(result.ok && result.head.hash !== entry.hash, "only the published head shows a rewritten last entry");
      }),
    );
  });

  it("breaks when an entry is removed or two are swapped", async () => {
    await fuzz(
      fc.asyncProperty(fc.gen(), async (g) => {
        const entries = await chain(g);
        if (entries.length < 2) return;
        const i = int(g, 0, entries.length - 2);
        const j = int(g, i + 1, entries.length - 1);
        assert.equal(verifyChain(entries.with(i, entries[j]!).with(j, entries[i]!)).ok, false);
        assert.equal(verifyChain(entries.toSpliced(i, 1)).ok, false);
      }),
    );
  });
});
