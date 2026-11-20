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
    const t = setup({
      onEvent: (e) => {
        told.push(e);
        if (e.name === "call.started" && reentered++ === 0) void t.engine.markUntrusted(e.callId!, "document");
      },
    });
    const { callId } = await t.engine.startCall();
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
});

describe("hostile #97: races on the outbox and the pending mark", () => {
  it("A4: a write that lands between flushPending's read and its unmark keeps the call marked", async () => {
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
    await sessions.reached.promise;
    // The ledger is down: this write's events stay pending in the record.
    ledger.down = true;
    await assert.rejects(t.engine.markUntrusted(callId, "document"), /ledger down/);
    sessions.release.resolve();
    await run;
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), [callId], "still listed: its outbox holds an entry");
    ledger.down = false;
    assert.deepEqual(await t.engine.flushPending(), { flushed: [callId], failed: [] });
    assert.deepEqual((await ledger.list()).map((e) => e.event), ["call.started", "session.tainted"]);
    assert.deepEqual(await sessions.pendingCalls("ws_test", 10), []);
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
