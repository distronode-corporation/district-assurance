// L2 review fixes (worker e): flow cursors stored before `counted`, grant lists never written to,
// and alert enumeration past a null record.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule, FlowStep } from "../src/core/module.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const verify2 = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] };
const cfg = (patch: (c: FlowConfig) => void = () => undefined): FlowConfig =>
  testConfig((c) => {
    c.flows = { pay: { steps: [verify2] } };
    patch(c);
  });

describe("l2fx-e T4: a flow cursor stored before `counted` existed", () => {
  it("binds a subject on a running legacy flow without counting it, and without throwing", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ flow: "pay" });
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = stored.record as { flow: { counted?: unknown } };
    delete record.flow.counted;
    assert.ok((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as unknown as JsonValue)).ok);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
    const after = (await t.sessions.get("ws_test", callId))!.record as { flow: { counted?: unknown } };
    assert.equal(Object.hasOwn(after.flow, "counted"), false, "a legacy cursor stays legacy");
  });

  it("still counts the first subject of a new limited flow, whose cursor is []", async () => {
    const t = setup({ config: cfg() });
    const { callId } = await t.engine.startCall({ flow: "pay" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const after = (await t.sessions.get("ws_test", callId))!.record as { flow: { counted: string[] } };
    assert.equal(after.flow.counted.length, 1);
  });
});

describe("l2fx-e: #limited never writes to a module's grant list", () => {
  const vault = (grants: string[]): AssuranceModule => ({
    manifest: { name: "vault", version: "1", summary: "vault", provides: { factors: [], steps: ["vault.open"], outcomes: [] }, scopes: { grants: [], needs: { "vault.open": "status.read" } }, adapters: [] },
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    stepLevel: () => 1,
    stepGrants: (_step: FlowStep) => grants,
    initCall: () => null,
    enterStep: () => null,
    stepStatus: () => "pending",
  });
  const vaultConfig = () =>
    testConfig((c) => {
      c.modules.vault = { settings: {} };
      c.flows = { open: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] }, { type: "vault.open" }] } };
    });

  it("starts a flow whose module returns a frozen grant list", async () => {
    const grants = Object.freeze([]) as unknown as string[];
    const t = setup();
    t.engine.use(vault(grants));
    t.engine.configure(vaultConfig());
    const { callId } = await t.engine.startCall();
    assert.equal((await t.engine.startFlow(callId, "open")).flow, "open");
  });

  it("leaves a shared grant list as it was", async () => {
    const grants: string[] = [];
    const t = setup();
    t.engine.use(vault(grants));
    t.engine.configure(vaultConfig());
    const { callId } = await t.engine.startCall();
    await t.engine.startFlow(callId, "open");
    assert.deepEqual(grants, []);
  });
});

describe("l2fx-e: alert enumeration over a null record", () => {
  it("lists only the calls whose record owes alerts, past a null record", async () => {
    const store = new MemorySessionStore();
    await store.create("ws", "call_null", null);
    await store.create("ws", "call_owes", { owesAlerts: true });
    await store.create("ws", "call_number", 7);
    await store.create("ws", "call_string", { owesAlerts: "true" });
    assert.deepEqual(await store.listCallsOwingAlerts("ws"), ["call_owes"]);
  });
});
