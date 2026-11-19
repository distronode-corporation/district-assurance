// L2 review fixes (worker e), flow-start counts: a start is given back when its write definitely did
// not commit, and read back when the store gave no answer; one that committed keeps its count.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, SessionStore } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { MemorySessionStore } from "../src/core/session-store.ts";
import { FLOW_START, numberKeyFor } from "../src/verify/counters.ts";
import { TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { rejects, setup, testConfig } from "./helpers.ts";

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const CALLING = "+15555550142";
const NUMBER = numberKeyFor(TEST_KNOWLEDGE_KEY, CALLING);
const startCounter = (key: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor: FLOW_START, scope: "number", key });
const starts = async (t: TestEngine) => (await t.counters.get(startCounter(NUMBER), LONG_AGO)).length;
const verify2 = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
const cfg = (patch: (c: FlowConfig) => void = () => undefined): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [verify2] } };
    patch(c);
  });

/** The test engine's store, with some of its methods replaced. */
function patchStore(t: TestEngine, patch: (store: MemorySessionStore, original: Pick<SessionStore, "create" | "get" | "compareAndSet">) => Partial<SessionStore>): void {
  const store = t.sessions as MemorySessionStore;
  const original = { create: store.create.bind(store), get: store.get.bind(store), compareAndSet: store.compareAndSet.bind(store) };
  Object.assign(store, patch(store, original));
}

describe("l2fx-e T2: startCall gives its count back when the create did not write", () => {
  it("releases the start when create rejects and nothing was stored", async () => {
    const t = setup({ config: cfg() });
    patchStore(t, () => ({ create: () => Promise.reject(new Error("store down")) }));
    await assert.rejects(t.engine.startCall({ callId: "call_a", flow: "pay", callingNumber: CALLING }), /store down/);
    assert.equal(await starts(t), 0);
  });

  it("keeps the start when create rejects after it wrote (read back: this call's flow is stored)", async () => {
    const t = setup({ config: cfg() });
    patchStore(t, (_s, o) => ({
      create: async (...args) => {
        await o.create(...args);
        throw new Error("lost reply");
      },
    }));
    await assert.rejects(t.engine.startCall({ callId: "call_b", flow: "pay", callingNumber: CALLING }), /lost reply/);
    assert.equal(await starts(t), 1);
    assert.equal((await t.engine.flowPosition("call_b"))!.flow, "pay");
  });

  it("releases the start when the record read back is another start's, without this flow", async () => {
    const t = setup({ config: cfg() });
    patchStore(t, (_s, o) => ({
      create: async (workspaceId, callId, record) => {
        await o.create(workspaceId, callId, { ...(record as { [key: string]: JsonValue }), flow: null });
        throw new Error("lost reply");
      },
    }));
    await assert.rejects(t.engine.startCall({ callId: "call_c", flow: "pay", callingNumber: CALLING }), /lost reply/);
    assert.equal(await starts(t), 0);
  });

  it("keeps the start when the read back fails too (fails closed)", async () => {
    const t = setup({ config: cfg() });
    let gets = 0;
    patchStore(t, (_s, o) => ({
      get: (...args) => (++gets > 1 ? Promise.reject(new Error("read down")) : o.get(...args)),
      create: () => Promise.reject(new Error("store down")),
    }));
    await assert.rejects(t.engine.startCall({ callId: "call_d", flow: "pay", callingNumber: CALLING }), /store down/);
    assert.equal(await starts(t), 1);
  });
});

describe("l2fx-e T3: startFlow gives its count back when no write committed", () => {
  it("releases the start when every compare-and-set finds the version moved", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    patchStore(t, () => ({ compareAndSet: async () => ({ ok: false as const }) }));
    await assert.rejects(t.engine.startFlow(callId, "pay"), rejects("conflict"));
    assert.equal(await starts(t), 0);
  });

  it("releases the start when the call's read fails before any write", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    let gets = 0;
    patchStore(t, (_s, o) => ({ get: (...args) => (++gets === 2 ? Promise.reject(new Error("read down")) : o.get(...args)) }));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /read down/);
    assert.equal(await starts(t), 0);
  });

  it("releases the start when compare-and-set rejects and the read back shows no flow", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    patchStore(t, () => ({ compareAndSet: () => Promise.reject(new Error("store down")) }));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /store down/);
    assert.equal(await starts(t), 0);
  });

  it("keeps the start when compare-and-set rejects after it wrote", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    let once = false;
    patchStore(t, (_s, o) => ({
      compareAndSet: async (...args) => {
        const saved = await o.compareAndSet(...args);
        if (once) return saved;
        once = true;
        throw new Error("lost reply");
      },
    }));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /lost reply/);
    assert.equal(await starts(t), 1);
    assert.equal((await t.engine.flowPosition(callId))!.flow, "pay");
  });

  it("keeps the start when compare-and-set rejects and the read back fails too", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    let gets = 0;
    patchStore(t, (_s, o) => ({
      get: (...args) => (++gets > 2 ? Promise.reject(new Error("read down")) : o.get(...args)),
      compareAndSet: () => Promise.reject(new Error("store down")),
    }));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /store down/);
    assert.equal(await starts(t), 1);
  });

  it("keeps the start when only the ledger flush after the write failed", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ callingNumber: CALLING });
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = () => Promise.reject(new Error("ledger down"));
    await assert.rejects(t.engine.startFlow(callId, "pay"), /ledger down/);
    t.ledger.append = append;
    assert.equal(await starts(t), 1);
  });
});
