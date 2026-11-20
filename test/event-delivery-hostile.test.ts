// Hostile-pass regressions for INT-5 (event delivery, #97): a hostile or re-entrant listener,
// races between a write and the background flush, two engines on one store, hostile limits and
// two workspaces sharing call ids. Each attack held; kept so it keeps holding.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditInput, SessionStore, WriteHint } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { DeliveredEvent } from "../src/core/events.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { FakeTimestampAuthority } from "../src/testing/fakes.ts";
import { sessionStoreContract } from "../src/testing/index.ts";
import { rejects, setup } from "./helpers.ts";

class SwitchedLedger extends MemoryAuditLedger {
  down = false;
  override async append(input: AuditInput) {
    if (this.down) throw new Error("ledger down");
    return super.append(input);
  }
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

/** Holds the next unmarking write (hint false, empty outbox) until `release`, and says when it is reached. */
class HeldUnmarkStore extends MemorySessionStore {
  hold = false;
  readonly reached = deferred();
  readonly release = deferred();
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue, h?: WriteHint): Promise<{ ok: true; version: number } | { ok: false }> {
    if (this.hold && h?.ledgerPending === false) {
      this.hold = false;
      this.reached.resolve();
      await this.release.promise;
    }
    return super.compareAndSet(w, c, v, r, h);
  }
}

const deepMutate = (value: unknown): void => {
  if (value === null || typeof value !== "object") return;
  for (const key of Object.keys(value)) {
    const v = (value as Record<string, unknown>)[key];
    if (v !== null && typeof v === "object") deepMutate(v);
    else (value as Record<string, unknown>)[key] = "MUTATED";
  }
  (value as Record<string, unknown>).injected = "MUTATED";
};

describe("hostile #97: the listener", () => {
  it("A1: a listener that rewrites every event it is told changes nothing stored", async () => {
    const plain = setup();
    const hostile = setup({
      onEvent: (e) => {
        deepMutate(e.detail);
        (e as { name: string }).name = "MUTATED";
      },
    });
    for (const t of [plain, hostile]) {
      const { callId } = await t.engine.startCall();
      await t.engine.markUntrusted(callId, "document");
      await t.engine.endCall(callId);
    }
    assert.deepEqual(await hostile.ledger.list(), await plain.ledger.list());
    // The receipt's ES256 signature is randomised per signing; everything else must match.
    const unsigned = (s: unknown) => JSON.stringify(s).replace(/"signature":"[^"]*"/g, '"signature":""');
    const [a, b] = await Promise.all([plain.sessions.get("ws_test", "call_1"), hostile.sessions.get("ws_test", "call_1")]);
    assert.equal(unsigned(b), unsigned(a));
  });

  it("A2: a listener that re-enters the engine on every event leaves one chain, each entry once", async () => {
    const told: DeliveredEvent[] = [];
    let reentered = 0;
    let marked: Promise<{ ok: true } | { ok: false; error: unknown }> | undefined;
    const t = setup({
      onEvent: (e) => {
        told.push(e);
        // Captured with its rejection handled at once, so a failure is asserted, never left unhandled.
        if (e.name === "call.started" && reentered++ === 0) {
          marked = t.engine.markUntrusted(e.callId!, "document").then(
            () => ({ ok: true as const }),
            (error: unknown) => ({ ok: false as const, error }),
          );
        }
      },
    });
    const { callId } = await t.engine.startCall();
    assert.notEqual(marked, undefined, "the listener re-entered during startCall");
    assert.deepEqual(await marked, { ok: true }, "the re-entrant markUntrusted succeeded");
    await new Promise((resolve) => setImmediate(resolve));
    await t.engine.flushLedger(callId);
    const entries = await t.ledger.list();
    assert.equal(verifyChain(entries).ok, true);
    assert.equal(new Set(entries.map((e) => e.eventId)).size, entries.length);
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "session.tainted"]);
    for (const e of told) assert.equal(e.seq, entries.find((x) => x.eventId === e.eventId)!.seq, "a repeat carries its first seq");
  });

  it("A3: a listener or hook that throws a value which throws on any touch is contained", async () => {
    const poison = new Proxy({}, { get: () => { throw new Error("touched"); }, getPrototypeOf: () => { throw new Error("touched"); } });
    const t = setup({
      onEvent: () => {
        throw poison;
      },
      onListenerError: () => {
        throw poison;
      },
    });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    assert.equal((await t.ledger.list()).length >= 2, true);
  });

  it("A10: anchorLedger returns the appended entry when a custom ledger hands back a detail that cannot be copied", async () => {
    class UnclonableDetail extends MemoryAuditLedger {
      override async append(input: AuditInput) {
        const entry = await super.append(input);
        // A function is not structured-cloneable: copying it for the listener throws a DataCloneError.
        return input.event === "ledger.anchored" ? { ...entry, detail: { ...entry.detail, hook: (() => undefined) as never } } : entry;
      }
    }
    const ledger = new UnclonableDetail();
    const told: string[] = [];
    const reported: Array<{ error: unknown; event: DeliveredEvent }> = [];
    const plain = setup();
    const t = setup({
      adapters: { ledger, anchor: new FakeTimestampAuthority(plain.clock) },
      onEvent: (e) => void told.push(e.name),
      onListenerError: (error, event) => void reported.push({ error, event }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    const entry = await t.engine.anchorLedger();
    assert.equal(entry.event, "ledger.anchored");
    assert.equal(entry.seq, (await ledger.list()).at(-1)!.seq);
    assert.equal(told.includes("ledger.anchored"), false, "the listener is not handed an uncopied detail");
    assert.equal(reported.length, 1);
    assert.equal((reported[0]!.error as Error).name, "DataCloneError");
    assert.equal(reported[0]!.event.name, "ledger.anchored");
    assert.deepEqual(reported[0]!.event.detail, {}, "the hook never holds the entry's own detail");
  });

  it("A11: anchorLedger with an unclonable detail and no listener copies nothing and returns the entry", async () => {
    class UnclonableDetail extends MemoryAuditLedger {
      override async append(input: AuditInput) {
        const entry = await super.append(input);
        return input.event === "ledger.anchored" ? { ...entry, detail: { ...entry.detail, hook: (() => undefined) as never } } : entry;
      }
    }
    const ledger = new UnclonableDetail();
    const plain = setup();
    const t = setup({ adapters: { ledger, anchor: new FakeTimestampAuthority(plain.clock) } });
    const { callId } = await t.engine.startCall();
    await t.engine.endCall(callId);
    assert.equal((await t.engine.anchorLedger()).event, "ledger.anchored");
  });
});

describe("hostile #97: races on the outbox and the pending mark", () => {
  it("A4: a write that lands between flushPending's read and its unmark keeps the call marked", { timeout: 10_000 }, async () => {
    const ledger = new SwitchedLedger();
    const sessions = new HeldUnmarkStore();
    const t = setup({ adapters: { ledger, sessions } });
    const { callId } = await t.engine.startCall();
    // Marked with an empty outbox (a hintless clear from an older engine).
    const stored = (await sessions.get("ws_test", callId))!;
    const record = stored.record as unknown as { outbox: unknown[] };
    await sessions.compareAndSet("ws_test", callId, stored.version, { ...record, outbox: [{ eventId: "x" }] } as never, { ledgerPending: true });
    await sessions.compareAndSet("ws_test", callId, stored.version + 1, { ...record, outbox: [] } as never);
    sessions.hold = true;
    const run = t.engine.flushPending();
    // Settled either way, so a flush that ends early (or throws) is reported instead of hanging on `reached`.
    const early = run.then(
      () => "settled" as const,
      () => "settled" as const,
    );
    try {
      assert.equal(await Promise.race([sessions.reached.promise.then(() => "reached" as const), early]), "reached", "flushPending reached its unmarking write");
      // The ledger is down: this write's events stay pending in the record.
      ledger.down = true;
      await assert.rejects(t.engine.markUntrusted(callId, "document"), /ledger down/);
    } finally {
      // Never left holding the gate, whatever failed above.
      sessions.release.resolve();
    }
    await run;
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), [callId], "still listed: its outbox holds an entry");
    ledger.down = false;
    assert.deepEqual(await t.engine.flushPending(), { flushed: [callId], failed: [] });
    assert.deepEqual((await ledger.list()).map((e) => e.event), ["call.started", "session.tainted"]);
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), []);
  });

  it("A12: a sweep whose clear loses to a write that left an entry pending reports the call as still pending", { timeout: 10_000 }, async () => {
    const ledger = new SwitchedLedger();
    const sessions = new HeldUnmarkStore();
    const t = setup({ adapters: { ledger, sessions } });
    ledger.down = true;
    await assert.rejects(t.engine.startCall({ callId: "c1" }), /ledger down/);
    ledger.down = false;
    sessions.hold = true;
    const run = t.engine.flushPending();
    const early = run.then(
      () => "settled" as const,
      () => "settled" as const,
    );
    try {
      // The sweep has appended call.started and holds its clear.
      assert.equal(await Promise.race([sessions.reached.promise.then(() => "reached" as const), early]), "reached", "the sweep reached its clear");
      ledger.down = true;
      await assert.rejects(t.engine.markUntrusted("c1", "document"), /ledger down/);
    } finally {
      sessions.release.resolve();
    }
    // The clear was stale: session.tainted is still in the outbox, so the call is not flushed.
    assert.deepEqual(await run, { flushed: [], failed: ["c1"] });
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), ["c1"]);
    ledger.down = false;
    assert.deepEqual(await t.engine.flushPending(), { flushed: ["c1"], failed: [] });
    assert.deepEqual((await ledger.list()).map((e) => e.event), ["call.started", "session.tainted"]);
  });

  it("A13: a sweep whose clear is lost and whose call is then gone reports it flushed (nothing left pending)", async () => {
    const ledger = new SwitchedLedger();
    class GoneAfterClear extends MemorySessionStore {
      gone = false;
      override async compareAndSet(w: string, c: string, v: number, r: JsonValue, h?: WriteHint): Promise<{ ok: true; version: number } | { ok: false }> {
        if (h?.ledgerPending === false) {
          this.gone = true;
          return { ok: false };
        }
        return super.compareAndSet(w, c, v, r, h);
      }
      override async get(w: string, c: string) {
        return this.gone ? null : super.get(w, c);
      }
    }
    const sessions = new GoneAfterClear();
    const t = setup({ adapters: { ledger, sessions } });
    ledger.down = true;
    await assert.rejects(t.engine.startCall({ callId: "c1" }), /ledger down/);
    ledger.down = false;
    assert.deepEqual(await t.engine.flushPending(), { flushed: ["c1"], failed: [] });
    assert.deepEqual((await ledger.list()).map((e) => e.event), ["call.started"]);
  });

  it("A5: two engines on one store and ledger, a write and a background flush at once, append each entry once", async () => {
    const ledger = new SwitchedLedger();
    const sessions = new MemorySessionStore();
    const a = setup({ adapters: { ledger, sessions } });
    const b = setup({ adapters: { ledger, sessions } });
    ledger.down = true;
    await assert.rejects(a.engine.startCall({ callId: "c1" }), /ledger down/);
    ledger.down = false;
    await Promise.all([a.engine.markUntrusted("c1", "document"), b.engine.flushPending(), b.engine.flushPending(), a.engine.flushPending()]);
    const entries = await ledger.list();
    assert.deepEqual(entries.map((e) => e.event), ["call.started", "session.tainted"]);
    assert.equal(verifyChain(entries).ok, true);
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), []);
  });
});

describe("hostile #97: hostile input and tenants", () => {
  it("A6: refuses every limit that is not a positive safe integer", async () => {
    const t = setup();
    for (const limit of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 2 ** 53, -0, 1e300, "5", null, {}, 0.5]) {
      await assert.rejects(t.engine.flushPending(limit as number), rejects("invalid_input"), String(limit));
    }
  });

  it("A7: two workspaces with the same call id on one store and ledger: a flush reaches only its own", async () => {
    const ledger = new SwitchedLedger();
    const sessions = new MemorySessionStore();
    const a = setup({ adapters: { ledger, sessions } });
    const b = setup({ workspaceId: "__proto__", adapters: { ledger, sessions } } as never);
    ledger.down = true;
    await assert.rejects(a.engine.startCall({ callId: "c_1" }), /ledger down/);
    await assert.rejects(b.engine.startCall({ callId: "c_1" }), /ledger down/);
    ledger.down = false;
    assert.deepEqual(await a.engine.flushPending(), { flushed: ["c_1"], failed: [] });
    assert.deepEqual(await sessions.pendingCalls("__proto__", 10), ["c_1"], "the other workspace is untouched");
    assert.deepEqual(await b.engine.flushPending(), { flushed: ["c_1"], failed: [] });
    const entries = await ledger.list();
    assert.equal(new Set(entries.map((e) => e.eventId)).size, 2, "distinct event ids per workspace");
  });

  it("A8: a call the store lists but no longer holds fails alone; the others still flush", async () => {
    const ledger = new SwitchedLedger();
    class ListsAGhost extends MemorySessionStore {
      override async pendingCalls(w: string, limit: number): Promise<string[]> {
        return ["c_gone", ...(await super.pendingCalls(w, limit))];
      }
    }
    const sessions: SessionStore = new ListsAGhost();
    const t = setup({ adapters: { ledger, sessions } });
    ledger.down = true;
    await assert.rejects(t.engine.startCall({ callId: "c1" }), /ledger down/);
    ledger.down = false;
    assert.deepEqual(await t.engine.flushPending(), { flushed: ["c1"], failed: ["c_gone"] });
  });
});

describe("hostile #97: the session store contract", () => {
  it("A9: catches a store that always lists the same first `limit` pending calls (no rotation)", async () => {
    class NoRotation extends MemorySessionStore {
      // The same order every time (sorted ids): the first `limit` marked calls, never rotated.
      override async pendingCalls(w: string, limit: number): Promise<string[]> {
        return (await super.pendingCalls(w, Number.MAX_SAFE_INTEGER)).sort().slice(0, limit);
      }
    }
    const failed: string[] = [];
    for (const c of sessionStoreContract(() => new NoRotation())) await c.run().catch(() => failed.push(c.name));
    assert.deepEqual(failed, ["lists the pending calls listed least recently first, so the same few never hold back the rest"]);
  });
});
