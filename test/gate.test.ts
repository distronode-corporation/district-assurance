// Gate (GAT-1): signed, time-limited access grants after verification, delivered once through an
// AccessController, and every grant and outcome in the ledger.
import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { validateConfig } from "../src/core/config.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { sha256Hex } from "../src/core/hash.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { SeenGrants, accessGrantDigest, verifyAccessGrant, type AccessGrantBody, type SignedAccessGrant, type UnlockResult } from "../src/gate/access.ts";
import { GateModule, gateModule, type GateHost, type GateSlice } from "../src/gate/gate.ts";
import { builtInModules } from "../src/modules.ts";
import { keyPairSigner } from "../src/prove/receipt.ts";
import { FakeAccessController, generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] };
const targets = [
  { id: "front-door", controller: "lobby", ref: "door-1" },
  { id: "garage", controller: "lobby", ref: "door-2" },
];

function gateConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["entry.open"] = 2;
    c.modules.gate = { settings: { targets: structuredClone(targets) } };
    c.flows = { entry: { steps: [verify as never, { type: "gate.grant", target: "front-door" }] } };
    patch(c);
  });
}

function gateSetup(mode: FakeAccessController["mode"] = "confirm", patch?: (c: FlowConfig) => void) {
  const door = new FakeAccessController(mode);
  const gate = gateModule({ signer: generateTestSigner("gate-key-1"), controllers: { lobby: door } });
  const t = setup({ modules: [gate], config: gateConfig(patch) });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, gate, door };
}

async function verified(t: ReturnType<typeof gateSetup>, flow: string | null = "entry"): Promise<string> {
  const { callId } = await t.engine.startCall(flow === null ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

const slice = async (t: ReturnType<typeof gateSetup>, callId: string) => (await t.engine.moduleState(callId, "gate")) as unknown as GateSlice;
const gateEvents = async (t: ReturnType<typeof gateSetup>) =>
  (await t.ledger.list()).filter((e) => e.event === "module.event" && e.detail.module === "gate").map((e) => [e.detail.event, e.detail.detail] as const);

/** A test module whose records are named by their reservation: `{ records: { [ref]: status } }`. */
function recordsModule(name: string) {
  return {
    manifest: { name, version: "1", summary: "x", provides: { factors: [], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => ({ records: {} }),
    enterStep: () => null,
    stepStatus: () => "pending" as const,
    outcomeRecord(slice: JsonValue, ref: string) {
      const { records, ...other } = slice as { records: Record<string, JsonValue> };
      if (!Object.hasOwn(records, ref)) return null;
      const { [ref]: record, ...rest } = records;
      return { record: record!, rest: { ...other, records: rest } as JsonValue };
    },
    /** "open" to "open" stays pending, "open" to "done" settles; anything else is refused. */
    checkOutcome(before: JsonValue, after: JsonValue): "open" | "settled" | { refused: string } {
      if (before !== "open") return { refused: "already settled" };
      return after === "open" ? "open" : after === "done" ? "settled" : { refused: `no transition to ${String(after)}` };
    },
  };
}

describe("gate: config", () => {
  const registry = (gate: GateModule) => new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer"], modules: [...builtInModules(), gate] });
  const gate = gateModule({ signer: generateTestSigner(), controllers: { lobby: new FakeAccessController(), "side-2": new FakeAccessController() } });

  it("refuses bad controllers at construction", () => {
    assert.throws(() => gateModule({ signer: generateTestSigner(), controllers: {} }), /at least one controller/);
    assert.throws(() => gateModule({ signer: generateTestSigner(), controllers: { Lobby: new FakeAccessController() } }), /lower-case letters, digits and hyphens: Lobby/);
  });

  it("checks every gate setting", () => {
    assert.deepEqual(gate.validateSettings({ targets, maxGrantsPerCall: 5 }), []);
    assert.deepEqual(gate.validateSettings(undefined), ["must be an object with the targets"]);
    assert.deepEqual(gate.validateSettings({ targets: [], maxGrantsPerCall: 6, x: 1 }), [
      "x is not a gate setting",
      "maxGrantsPerCall must be an integer from 1 to 5",
      "targets must list at least one target",
    ]);
    assert.deepEqual(gate.validateSettings({ targets: "front-door" }), ["targets must list at least one target"]);
    const sparse: unknown[] = [];
    sparse[1] = targets[0];
    assert.deepEqual(gate.validateSettings({ targets: sparse }), ["targets must list at least one target"], "a hole is not a target");
    assert.deepEqual(gate.validateSettings({ targets: [7, { id: "Front", controller: "attic", ref: " ", y: 1 }, { id: "a", controller: "lobby", ref: "x".repeat(201) }, { id: "a", controller: 1, ref: 1 }] }), [
      "targets[0] must be { id, controller, ref }",
      "targets[1].y is not a target field",
      "targets[1].id must be lower-case letters, digits and hyphens, at most 64",
      "targets[1].controller must name a controller this gate was given (lobby, side-2)",
      "targets[1].ref must be 1 to 200 characters",
      "targets[2].ref must be 1 to 200 characters",
      "targets[3].controller must name a controller this gate was given (lobby, side-2)",
      "targets[3].ref must be 1 to 200 characters",
      "two targets have the same id",
    ]);
  });

  it("checks gate.grant steps, and holds them to entry.open at level 2", () => {
    const problems = (c: FlowConfig) => validateConfig(c, registry(gate));
    assert.deepEqual(problems(gateConfig()), []);
    const step = (s: Record<string, unknown>) => problems(gateConfig((c) => (c.flows = { entry: { steps: [verify as never, s as never] } })));
    assert.deepEqual(step({ type: "gate.grant", target: "front-door", lifetimeSeconds: 900 }), []);
    assert.deepEqual(step({ type: "gate.grant", target: "attic", lifetimeSeconds: 9, x: 1 }), [
      "flows.entry.steps[1] (gate.grant): x is not a field of this step",
      "flows.entry.steps[1] (gate.grant): lifetimeSeconds must be an integer from 10 to 900",
      "flows.entry.steps[1] (gate.grant): no target attic in the gate settings",
    ]);
    assert.deepEqual(step({ type: "gate.grant", lifetimeSeconds: 901 }), [
      "flows.entry.steps[1] (gate.grant): lifetimeSeconds must be an integer from 10 to 900",
      "flows.entry.steps[1] (gate.grant): target must name a target in the gate settings",
    ]);
    // Settings that did not validate: the step is not cross-checked against them.
    assert.deepEqual(
      problems(gateConfig((c) => (c.modules.gate = { settings: { targets: [] } }))),
      ["modules.gate.settings: targets must list at least one target"],
    );
    assert.deepEqual(problems(gateConfig((c) => (c.policy.scopes["entry.open"] = 1))), ["policy: scope entry.open is access, and below its floor of level 2"]);
    assert.deepEqual(
      problems(gateConfig((c) => (c.flows = { entry: { steps: [{ ...verify, scopes: ["payment.request"] } as never, { type: "gate.grant", target: "front-door" }] } }))),
      ["flows.entry.steps[1] (gate.grant): needs the scope entry.open, which the last verification step does not grant"],
    );
    assert.deepEqual(
      problems(gateConfig((c) => (c.flows = { entry: { steps: [{ type: "gate.grant", target: "front-door" }] } }))),
      ["flows.entry.steps[0] (gate.grant): needs the scope entry.open at level 2, but the flow has verified to level 0 at this point"],
    );
  });
});

describe("gate: grants", () => {
  it("runs an entry flow: a signed grant to the door, verified with the public key only", async () => {
    const t = gateSetup();
    const callId = await verified(t);
    assert.deepEqual(await t.gate.grantAccess(t.engine, callId), { grantId: "acc_1", status: "delivered", confirmed: true });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    const [sent] = t.door.received;
    assert.equal(sent!.target, "door-1");
    assert.deepEqual(JSON.parse(sent!.idempotencyKey), ["ws_test", callId, "acc_1", "unlock"]);
    const grant = sent!.grant;
    assert.deepEqual(grant.body, {
      v: 1,
      kind: "access",
      grantId: "acc_1",
      workspaceId: "ws_test",
      audience: "lobby",
      target: "door-1",
      action: "unlock",
      scope: "entry.open",
      level: 2,
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:01:00.000Z",
    });
    assert.equal(grant.kid, "gate-key-1");
    const keys = t.gate.keys();
    assert.deepEqual(verifyAccessGrant(grant, keys, { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: true, body: grant.body });
    const changed = structuredClone(grant);
    changed.body.target = "door-2";
    assert.deepEqual(verifyAccessGrant(changed, keys, { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: false, reason: "signature" });
    assert.deepEqual(verifyAccessGrant(grant, t.engine.receiptKeys(), { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: false, reason: "signature" }, "not the receipt key");

    const digest = accessGrantDigest(grant.body);
    assert.equal(digest, sha256Hex(canonicalJson(grant.body)));
    const events = await gateEvents(t);
    assert.deepEqual(events, [
      ["access.issued", { grantId: "acc_1", target: "front-door", controller: "lobby", scope: "entry.open", level: 2, verificationGrantId: "grant_1", expiresAt: "2026-01-01T00:01:00.000Z" }],
      ["access.delivered", { grantId: "acc_1", digest, confirmed: true, kid: "gate-key-1" }],
    ]);
    assert.ok(!JSON.stringify(await t.ledger.list()).includes(grant.signature), "the grant itself is never in the ledger");
    assert.deepEqual((await slice(t, callId)).grants[0], {
      grantId: "acc_1",
      target: "front-door",
      controller: "lobby",
      ref: "door-1",
      level: 2,
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:01:00.000Z",
      status: "delivered",
      confirmed: true,
      providerRef: "door_fake_1",
      digest,
      kid: "gate-key-1",
    });
  });

  it("refuses without a verification grant covering entry.open", async () => {
    const t = gateSetup();
    const { callId } = await t.engine.startCall({ flow: "entry" });
    await assert.rejects(t.gate.grantAccess(t.engine, callId), rejects("precondition_failed", /on step badge.verify/), "not Gate's step yet");
    const open = await t.engine.startCall();
    await assert.rejects(t.gate.grantAccess(t.engine, open.callId, { target: "front-door" }), rejects("scope_denied", /entry.open/));
    // Verified, then tainted: the grant is gone.
    const callId2 = await verified(t, null);
    await t.engine.markUntrusted(callId2, "crm_note");
    await assert.rejects(t.gate.grantAccess(t.engine, callId2, { target: "front-door" }), rejects("scope_denied"));
    // Verified, then the verification grant expired.
    const callId3 = await verified(t, null);
    t.clock.advance(900_000);
    await assert.rejects(t.gate.grantAccess(t.engine, callId3, { target: "front-door" }), rejects("scope_denied"));
    assert.equal(t.door.received.length, 0, "no door was ever asked");
  });

  it("holds the step to entry.open in the engine even if the module never asked", async () => {
    const t = gateSetup();
    const { callId } = await t.engine.startCall({ flow: "entry" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed", "level 1 is below the step's level");
    const c2 = await verified(t);
    t.clock.advance(900_000);
    await assert.rejects(t.engine.updateModule(c2, "gate", (s) => s), rejects("scope_denied", /entry.open/));
  });

  it("takes the target from the step in a flow and from the host outside one", async () => {
    const t = gateSetup();
    const inFlow = await verified(t);
    await assert.rejects(t.gate.grantAccess(t.engine, inFlow, { target: "garage" }), rejects("invalid_input", /pass no input/));
    const outside = await verified(t, null);
    await assert.rejects(t.gate.grantAccess(t.engine, outside), rejects("invalid_input", /target is required/));
    await assert.rejects(t.gate.grantAccess(t.engine, outside, { target: "attic" }), rejects("invalid_input", /no target attic/));
    await assert.rejects(t.gate.grantAccess(t.engine, outside, { target: "garage", lifetimeSeconds: 5 }), rejects("invalid_input", /lifetimeSeconds/));
    assert.equal((await t.gate.grantAccess(t.engine, outside, { target: "garage", lifetimeSeconds: 120 })).status, "delivered");
    assert.equal(t.door.received[0]!.target, "door-2");
    assert.equal(t.door.received[0]!.grant.body.expiresAt, "2026-01-01T00:02:00.000Z");
  });

  it("never outlives the verification grant", async () => {
    const t = gateSetup("deliver", (c) => (c.flows.entry!.steps[1] = { type: "gate.grant", target: "front-door", lifetimeSeconds: 900 }));
    const callId = await verified(t);
    t.clock.advance(600_000);
    assert.deepEqual(await t.gate.grantAccess(t.engine, callId), { grantId: "acc_1", status: "delivered", confirmed: false });
    assert.equal(t.door.received[0]!.grant.body.expiresAt, "2026-01-01T00:15:00.000Z", "the verification grant's own expiry");
  });

  it("records a lost answer as unknown, never retries it, and needs a fresh request", async () => {
    const t = gateSetup("lose", (c) => (c.modules.gate!.settings = { targets: structuredClone(targets), maxGrantsPerCall: 2 }));
    const callId = await verified(t);
    assert.deepEqual(await t.gate.grantAccess(t.engine, callId), { grantId: "acc_1", status: "unknown", confirmed: false });
    assert.equal(t.door.received.length, 1, "sent once");
    assert.equal((await t.engine.flowPosition(callId))!.status, "running", "the step waits for a fresh request");
    t.door.mode = "refuse";
    assert.deepEqual(await t.gate.grantAccess(t.engine, callId), { grantId: "acc_2", status: "refused", confirmed: false });
    assert.deepEqual(t.door.received.map((r) => r.grant.body.grantId), ["acc_1", "acc_2"], "a fresh grant, never the lost one again");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed", "every grant used, the door never opened");
    const events = (await gateEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]);
    assert.deepEqual(events, [["access.issued", null], ["access.unknown", null], ["access.issued", null], ["access.refused", "door_offline"]]);

    const outside = await verified(t, null);
    await t.gate.grantAccess(t.engine, outside, { target: "front-door" });
    await t.gate.grantAccess(t.engine, outside, { target: "front-door" });
    await assert.rejects(t.gate.grantAccess(t.engine, outside, { target: "front-door" }), rejects("precondition_failed", /every access grant/));
  });

  it("writes a controller's refusal reason as a short code only", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    t.door.unlock = async () => ({ outcome: "refused", reason: "Door said: <script>" });
    await t.gate.grantAccess(t.engine, callId, { target: "front-door" });
    assert.equal(((await gateEvents(t)).at(-1)![1] as { reason: string }).reason, "refused");
  });

  it("fails a grant whose signing failed, sends nothing, and allows a new one", async () => {
    const door = new FakeAccessController();
    const signer = generateTestSigner("gate-key-1");
    let broken = true;
    const gate = gateModule({
      signer: { ...signer, sign: (payload) => (broken ? Promise.reject(new Error("kms down")) : signer.sign(payload)) },
      controllers: { lobby: door },
    });
    const t = { ...setup({ modules: [gate], config: gateConfig() }), gate, door };
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const callId = await verified(t);
    await assert.rejects(t.gate.grantAccess(t.engine, callId), /kms down/);
    assert.equal((await slice(t, callId)).grants[0]!.status, "failed");
    assert.equal(door.received.length, 0);
    broken = false;
    assert.equal((await t.gate.grantAccess(t.engine, callId)).status, "delivered");
    assert.deepEqual((await gateEvents(t)).map(([e]) => e), ["access.issued", "access.failed", "access.issued", "access.delivered"]);
  });

  it("allows one grant in flight per call", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const unlock = t.door.unlock.bind(t.door);
    let nested: Promise<unknown> | null = null;
    t.door.unlock = async (input) => {
      nested = t.gate.grantAccess(t.engine, callId, { target: "garage" });
      await assert.rejects(nested, rejects("precondition_failed", /being delivered/));
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, callId, { target: "front-door" })).status, "delivered");
    assert.ok(nested !== null);
  });

  it("settles a reservation whose answer was never recorded as unknown, once its grant expired", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const lost: GateHost = {
      workspaceId: t.engine.workspaceId,
      updateModule: (c, n, fn) => t.engine.updateModule(c, n, fn),
      moduleState: (c, n) => t.engine.moduleState(c, n),
      // The check before sending is written; the answer after it is not.
      recordModuleOutcome: (c, n, r, fn) => (t.door.received.length === 0 ? t.engine.recordModuleOutcome(c, n, r, fn) : Promise.reject(new Error("the process stopped"))),
    };
    // The door answered "delivered", then writing it failed: that error is thrown as it is, never turned into "unknown".
    await assert.rejects(t.gate.grantAccess(lost, callId, { target: "front-door" }), /the process stopped/);
    assert.equal(t.door.received.length, 1);
    assert.equal((await slice(t, callId)).grants[0]!.status, "reserved");
    await assert.rejects(t.gate.grantAccess(t.engine, callId, { target: "front-door" }), rejects("precondition_failed", /being delivered/));
    t.clock.advance(60_000);
    assert.equal((await t.gate.grantAccess(t.engine, callId, { target: "front-door" })).status, "delivered");
    assert.deepEqual((await slice(t, callId)).grants.map((g) => g.status), ["unknown", "delivered"]);
    const stale = (await gateEvents(t))[1]![1] as Record<string, unknown>;
    assert.deepEqual(Object.keys(stale).sort(), ["digest", "grantId", "kid", "reason"], "the grant that never got its answer is still named");
    assert.deepEqual((await gateEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["access.issued", null],
      ["access.unknown", "no_answer_recorded"],
      ["access.issued", null],
      ["access.delivered", null],
    ]);
  });

  it("throws a store failure met while settling a stale grant, and sends nothing", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const stopped: GateHost = {
      workspaceId: t.engine.workspaceId,
      updateModule: (c, n, fn) => t.engine.updateModule(c, n, fn),
      moduleState: (c, n) => t.engine.moduleState(c, n),
      recordModuleOutcome: () => Promise.reject(new Error("store down")),
    };
    await assert.rejects(t.gate.grantAccess(stopped, callId, { target: "front-door" }), /store down/);
    t.clock.advance(60_000);
    await assert.rejects(t.gate.grantAccess(stopped, callId, { target: "front-door" }), /store down/, "met in the stale settle, before any reserve");
    assert.equal(t.door.received.length, 0);
    assert.equal((await slice(t, callId)).grants.length, 1, "no second grant was reserved");
  });

  it("fails the step at the grant limit once a stale reservation settles, and keeps that settlement", async () => {
    const t = gateSetup("confirm", (c) => (c.modules.gate!.settings = { targets: structuredClone(targets), maxGrantsPerCall: 1 }));
    const callId = await verified(t);
    const lost: GateHost = {
      workspaceId: t.engine.workspaceId,
      updateModule: (c, n, fn) => t.engine.updateModule(c, n, fn),
      moduleState: (c, n) => t.engine.moduleState(c, n),
      // The check before sending is written; the answer after it is not.
      recordModuleOutcome: (c, n, r, fn) => (t.door.received.length === 0 ? t.engine.recordModuleOutcome(c, n, r, fn) : Promise.reject(new Error("the process stopped"))),
    };
    await assert.rejects(t.gate.grantAccess(lost, callId), /the process stopped/);
    t.clock.advance(60_000);
    // Settling the stale grant uses the call's last one, so the step fails and the request is refused.
    await assert.rejects(t.gate.grantAccess(t.engine, callId), rejects("precondition_failed", /flow entry has failed/));
    assert.equal((await slice(t, callId)).grants[0]!.status, "unknown", "settled in its own write, though the request was refused");
    assert.equal(t.door.received.length, 1, "no second grant was sent");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("settles a reservation that stopped before it was signed as unknown, naming no grant it never had", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const stopped: GateHost = {
      workspaceId: t.engine.workspaceId,
      updateModule: (c, n, fn) => t.engine.updateModule(c, n, fn),
      moduleState: (c, n) => t.engine.moduleState(c, n),
      recordModuleOutcome: () => Promise.reject(new Error("the process stopped")),
    };
    await assert.rejects(t.gate.grantAccess(stopped, callId, { target: "front-door" }), /the process stopped/);
    assert.equal(t.door.received.length, 0, "stopped before the send");
    t.clock.advance(60_000);
    assert.equal((await t.gate.grantAccess(t.engine, callId, { target: "front-door" })).status, "delivered");
    const stale = (await gateEvents(t))[1]!;
    assert.deepEqual(stale, ["access.unknown", { grantId: "acc_1", reason: "no_answer_recorded" }]);
  });

  it("records the answer even if the grant expired or the call ended while the door answered", async () => {
    const t = gateSetup();
    const callId = await verified(t);
    const unlock = t.door.unlock.bind(t.door);
    t.door.unlock = async (input) => {
      t.clock.advance(900_000);
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, callId)).status, "delivered");
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");

    // The entry flow has no receipt step: a call that ends while the door answers still records it.
    const c2 = await verified(t);
    t.door.unlock = async (input) => {
      await t.engine.endCall(c2);
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, c2)).status, "delivered");
    assert.equal((await slice(t, c2)).grants[0]!.status, "delivered");
  });

  it("writes nothing once the call's receipt is signed, a late door answer included (review b3)", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const unlock = t.door.unlock.bind(t.door);
    t.door.unlock = async (input) => {
      assert.notEqual(await t.engine.endCall(callId), null, "a call with no flow ends with a receipt here");
      return unlock(input);
    };
    const head = (await t.ledger.list()).length;
    await assert.rejects(t.gate.grantAccess(t.engine, callId, { target: "front-door" }), rejects("precondition_failed", /receipt is signed/));
    const after = await t.ledger.list();
    assert.deepEqual(after.slice(head).map((e) => e.event === "module.event" ? e.detail.event : e.event).filter((e) => e !== "access.issued" && e !== "call.ended" && e !== "receipt.issued"), [], "nothing after the receipt");
    assert.equal((await slice(t, callId)).grants[0]!.status, "reserved", "the answer is not recorded: the receipt does not change");
  });

  it("sends nothing when the call was tainted or the grant expired while it was being signed", async () => {
    const door = new FakeAccessController();
    const signer = generateTestSigner("gate-key-1");
    let during: () => Promise<void> = async () => undefined;
    const gate = gateModule({
      signer: { ...signer, sign: async (payload) => (await during(), signer.sign(payload)) },
      controllers: { lobby: door },
    });
    const t = { ...setup({ modules: [gate], config: gateConfig() }), gate, door };
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const tainted = await verified(t, null);
    during = () => t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.gate.grantAccess(t.engine, tainted, { target: "front-door" }), rejects("scope_denied", /no longer authorized/));
    const slow = await verified(t, null);
    during = async () => t.clock.advance(60_000);
    await assert.rejects(t.gate.grantAccess(t.engine, slow, { target: "front-door" }), rejects("scope_denied", /it expired/));
    assert.equal(door.received.length, 0, "no door was asked");
    assert.deepEqual((await slice(t, tainted)).grants.map((g) => g.status), ["failed"]);
    const reasons = (await gateEvents(t)).filter(([e]) => e === "access.failed").map(([, d]) => (d as { reason: string }).reason);
    assert.deepEqual(reasons, ["not_authorized", "expired"]);
    assert.equal(((await gateEvents(t)).find(([e]) => e === "access.failed")![1] as { kid: string }).kid, "gate-key-1");
    // Settled by another process while signing (it saw the grant expire): left as that process left it.
    const raced = await verified(t, null);
    during = async () => {
      t.clock.advance(60_000);
      const [open] = await t.engine.moduleReservations(raced, "gate");
      // The grant (60 seconds) has expired: the other process's stale settle is a legal one.
      await t.engine.recordModuleOutcome(raced, "gate", open!, (s) => {
        (s as unknown as GateSlice).grants[0]!.status = "unknown";
        return s;
      });
    };
    await assert.rejects(t.gate.grantAccess(t.engine, raced, { target: "front-door" }), rejects("scope_denied", /settled meanwhile/));
    assert.deepEqual((await slice(t, raced)).grants.map((g) => g.status), ["unknown"]);
    assert.equal(door.received.length, 0);
  });

  it("keeps an outcome settled meanwhile as it is", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const unlock = t.door.unlock.bind(t.door);
    let first = true;
    t.door.unlock = async (input) => {
      if (first) {
        first = false;
        t.clock.advance(61_000);
        // Another process sees the first grant expired with no answer, settles it, and opens again.
        await t.gate.grantAccess(t.engine, callId, { target: "garage" });
      }
      return unlock(input);
    };
    const firstResult = await t.gate.grantAccess(t.engine, callId, { target: "front-door" });
    assert.deepEqual((await slice(t, callId)).grants.map((g) => g.status), ["unknown", "delivered"]);
    assert.deepEqual(firstResult, { grantId: "acc_1", status: "unknown", confirmed: false }, "what the call holds, not what the door said");
  });

  it("keeps the targets a call started with when the config changes", async () => {
    const t = gateSetup();
    const { callId } = await t.engine.startCall();
    t.engine.configure(
      gateConfig((c) => {
        c.modules.gate = { settings: { targets: [{ id: "attic", controller: "lobby", ref: "door-9" }] } };
        c.flows = { attic: { steps: [verify as never, { type: "gate.grant", target: "attic" }] } };
      }),
    );
    await assert.rejects(t.engine.startFlow(callId, "attic"), rejects("precondition_failed", /no target attic/));
  });

  it("never lets an outcome write create a grant: a forged delivery after the grant expired is refused (review R2, R2b)", async () => {
    const t = gateSetup();
    const callId = await verified(t);
    t.clock.advance(900_000);
    await assert.rejects(t.gate.grantAccess(t.engine, callId), rejects("scope_denied"));
    const forge = (reservation: string) =>
      t.engine.recordModuleOutcome(callId, "gate", reservation, (s, call) => {
        const slice = s as unknown as GateSlice;
        slice.grants.push({ ...structuredClone(slice.grants[0] ?? ({} as never)), grantId: call.newId("acc"), status: "delivered" } as never);
        call.emit("access.delivered", { grantId: "forged", confirmed: true });
        return slice as never;
      });
    await assert.rejects(forge("acc_1"), rejects("precondition_failed", /no open reservation acc_1/));
    await assert.rejects(forge(""), rejects("precondition_failed"));
    assert.equal((await t.engine.flowPosition(callId))!.status, "running", "the flow did not complete");
    assert.deepEqual((await slice(t, callId)).grants, []);
    assert.equal(t.door.received.length, 0);
    assert.deepEqual(await gateEvents(t), [], "nothing was written to the ledger");
  });

  it("writes nothing after the call ended unless a grant is still in flight (review R3)", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    await t.engine.endCall(callId);
    const before = (await t.ledger.list()).length;
    await assert.rejects(
      t.engine.recordModuleOutcome(callId, "gate", "acc_1", (s, call) => {
        call.emit("access.delivered", { grantId: "after-end", confirmed: true });
        return s;
      }),
      rejects("precondition_failed"),
    );
    assert.equal((await t.ledger.list()).length, before, "nothing appended after the receipt");
    // A grant in flight when the call ends still records its answer (a flow with no receipt): that is
    // the reservation's purpose, and the settling write consumes it.
    const c2 = await verified(t);
    const unlock = t.door.unlock.bind(t.door);
    t.door.unlock = async (input) => {
      await t.engine.endCall(c2);
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, c2)).status, "delivered");
    assert.deepEqual(await t.engine.moduleReservations(c2, "gate"), [], "and its reservation is closed");
  });

  it("never sends a grant another process settled while this one's write was being retried", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const real = t.engine;
    let raced = false;
    // A host whose pre-send write loses its first compare-and-set to another process, which
    // settles this grant meanwhile: the retry is refused, and the discarded attempt said "send".
    const racing: GateHost = {
      workspaceId: real.workspaceId,
      updateModule: (c, n, fn) => real.updateModule(c, n, fn),
      moduleState: (c, n) => real.moduleState(c, n),
      recordModuleOutcome: async (c, n, r, fn) => {
        if (!raced) {
          raced = true;
          fn(await real.moduleState(c, n), { authorized: () => true, now: t.clock.now().toISOString(), emit: () => undefined } as never);
          // The other process settles it as stale, which it may once the grant expired.
          t.clock.advance(60_000);
          await real.recordModuleOutcome(c, n, r, (s) => {
            (s as unknown as GateSlice).grants.find((g) => g.grantId === r)!.status = "unknown";
            return s;
          });
        }
        return real.recordModuleOutcome(c, n, r, fn);
      },
    };
    await assert.rejects(t.gate.grantAccess(racing, callId, { target: "front-door" }), rejects("scope_denied", /settled meanwhile/));
    assert.equal(t.door.received.length, 0, "the door was never asked");
  });

  it("keeps reservations for a module named constructor (own properties only)", async () => {
    const t = setup();
    // Not a reserved name (only core, engine, flow and module are), and an inherited property of every object.
    t.engine.use(recordsModule("constructor"));
    t.engine.configure(testConfig((c) => ((c.modules as Record<string, unknown>)["constructor"] = {})));
    const { callId } = await t.engine.startCall();
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), []);
    await assert.rejects(t.engine.recordModuleOutcome(callId, "constructor", "r1", (s) => s), rejects("precondition_failed"));
    await t.engine.updateModule(callId, "constructor", (_s, call) => (call.reserve("r1"), { records: { r1: "open" } }));
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), ["r1"]);
    await t.engine.recordModuleOutcome(callId, "constructor", "r1", () => ({ records: { r1: "done" } }));
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), []);
  });

  it("opens reservations only in updateModule, on a live call, and closes them with the first settling write (review b2)", async () => {
    const t = setup();
    t.engine.use(recordsModule("ledger-test"));
    t.engine.configure(testConfig((c) => (c.modules["ledger-test"] = {})));
    const { callId } = await t.engine.startCall();
    const name = "ledger-test";
    await assert.rejects(t.engine.updateModule(callId, name, (s, call) => (call.reserve(""), s)), rejects("invalid_input"));
    await t.engine.updateModule(callId, name, (_s, call) => (call.reserve("r1"), call.reserve("r1"), call.reserve("r2"), { records: { r1: "open", r2: "open" } }));
    assert.deepEqual(await t.engine.moduleReservations(callId, name), ["r1", "r2"]);
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", (s, call) => (call.reserve("r3"), s)), rejects("precondition_failed", /only updateModule/));
    // A write that leaves the record pending keeps the reservation; one that settles it consumes it.
    await t.engine.recordModuleOutcome(callId, name, "r1", (s) => s);
    assert.deepEqual(await t.engine.moduleReservations(callId, name), ["r1", "r2"]);
    await t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done", r2: "open" } }));
    assert.deepEqual(await t.engine.moduleReservations(callId, name), ["r2"]);
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done", r2: "open" } })), rejects("precondition_failed", /no open reservation r1/), "settled once: the second is refused");
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r2", () => ({ records: { r1: "done", r2: "undone" } })), rejects("precondition_failed", /refused the outcome for r2: no transition to undone/));
    // After the call ended: no new reservation, and only a settling write for one opened before.
    await t.engine.updateModule(callId, name, (_s, call) => (call.reserve("r3"), { records: { r1: "done", r2: "open", r3: "open" } }));
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.updateModule(callId, name, (s, call) => (call.reserve("r4"), s)), rejects("invalid_transition", /no new reservation/));
  });

  it("after the call ended, takes only a settling write for a reservation opened before, and nothing once a receipt is signed (review b3)", async () => {
    const name = "ledger-test";
    const make = async (receipts: boolean) => {
      const t = setup();
      t.engine.use(recordsModule(name));
      t.engine.configure(testConfig((c) => ((c.modules[name] = {}), (c.modules.trace = { settings: { receipts, wordings: [] } }))));
      const { callId } = await t.engine.startCall();
      await t.engine.updateModule(callId, name, (_s, call) => (call.reserve("r1"), { records: { r1: "open" } }));
      await t.engine.endCall(callId);
      return { t, callId };
    };
    const { t, callId } = await make(false);
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", (s) => s), rejects("precondition_failed", /only a final outcome/));
    await t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done" } }));
    assert.deepEqual(await t.engine.moduleState(callId, name), { records: { r1: "done" } });
    const signed = await make(true);
    const before = (await signed.t.ledger.list()).length;
    await assert.rejects(
      signed.t.engine.recordModuleOutcome(signed.callId, name, "r1", (_s, call) => (call.emit("late", {}), { records: { r1: "done" } })),
      rejects("precondition_failed", /receipt is signed/),
    );
    assert.equal((await signed.t.ledger.list()).length, before, "nothing after the receipt");
  });

  it("lets an outcome write change only the record its reservation names (review A3)", async () => {
    const t = setup();
    const name = "ledger-test";
    t.engine.use(recordsModule(name));
    t.engine.configure(testConfig((c) => (c.modules[name] = {})));
    const { callId } = await t.engine.startCall();
    await t.engine.updateModule(callId, name, (_s, call) => (call.reserve("r1"), call.reserve("r2"), { records: { r1: "open", r2: "open" } }));
    const refused = rejects("precondition_failed", /may change that record only/);
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done", r2: "done" } })), refused, "touches another record");
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done", r2: "open", forged: "done" } })), refused, "adds a record");
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r2: "open" } })), refused, "drops its own record");
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r1", () => ({ records: { r1: "done", r2: "open" }, extra: 1 })), refused, "changes the rest");
    assert.deepEqual(await t.engine.moduleState(callId, name), { records: { r1: "open", r2: "open" } }, "nothing was written");
    await t.engine.updateModule(callId, name, (_s, call) => (call.reserve("r3"), { records: { r1: "open", r2: "open" } }));
    await assert.rejects(t.engine.recordModuleOutcome(callId, name, "r3", (s) => s), rejects("precondition_failed", /no record for its reservation r3/));
    const bare = { ...recordsModule("bare"), outcomeRecord: undefined };
    t.engine.use(bare as never);
    await assert.rejects(t.engine.recordModuleOutcome(callId, "bare", "r1", (s) => s), rejects("precondition_failed", /does not say which record/));
  });

  it("never lets a pending grant's reservation write a forged delivered grant (review A3)", async () => {
    const t = gateSetup();
    const callId = await verified(t);
    // The real grant waits on the door; meanwhile the verification grant expires.
    let answer: (r: UnlockResult) => void = () => undefined;
    let reached: () => void = () => undefined;
    const atDoor = new Promise<void>((resolve) => (reached = resolve));
    t.door.unlock = (input) => {
      t.door.received.push(structuredClone(input));
      reached();
      return new Promise<UnlockResult>((resolve) => (answer = resolve));
    };
    const pending = t.gate.grantAccess(t.engine, callId);
    await atDoor;
    const [open] = await t.engine.moduleReservations(callId, "gate");
    t.clock.advance(900_000);
    await assert.rejects(
      t.engine.recordModuleOutcome(callId, "gate", open!, (s, call) => {
        const slice = s as unknown as GateSlice;
        slice.grants.push({ ...structuredClone(slice.grants[0]!), grantId: call.newId("acc"), status: "delivered", confirmed: true });
        return slice as never;
      }),
      rejects("precondition_failed", /may change that record only/),
    );
    await assert.rejects(
      t.engine.recordModuleOutcome(callId, "gate", open!, (s) => {
        (s as unknown as GateSlice).grants[0]!.grantId = "acc_forged";
        return s;
      }),
      rejects("precondition_failed", /may change that record only/),
      "renaming its own grant leaves no record under the reservation",
    );
    assert.equal((await t.engine.flowPosition(callId))!.status, "running", "the flow did not complete");
    answer({ outcome: "refused", reason: "door_offline" });
    assert.equal((await pending).status, "refused", "the real grant still settles, and only it");
    assert.deepEqual((await slice(t, callId)).grants.map((g) => g.status), ["refused"]);
  });

  /** A door that holds its answer until told, so the grant's reservation stays open meanwhile. */
  function holdDoor(t: ReturnType<typeof gateSetup>) {
    let answer: (r: UnlockResult) => void = () => undefined;
    let reached: () => void = () => undefined;
    const atDoor = new Promise<void>((resolve) => (reached = resolve));
    t.door.unlock = (input) => {
      t.door.received.push(structuredClone(input));
      reached();
      return new Promise<UnlockResult>((resolve) => (answer = resolve));
    };
    return { atDoor, answer: (r: UnlockResult) => answer(r) };
  }

  for (const [label, patch] of [
    ["delivered and confirmed, with the door still deciding", { status: "delivered", confirmed: true, providerRef: "forged" }],
    ["re-pointed at another door", { ref: "door-999", controller: "other", target: "back-door", status: "delivered", confirmed: true }],
    ["lowered to level 0 with a far expiry", { level: 0, expiresAt: "2099-01-01T00:00:00.000Z", status: "delivered", confirmed: true }],
    ["an invented status", { status: "opened_by_magic" }],
    ["a reserved grant given an answer", { confirmed: true, providerRef: "forged" }],
    ["its key id rewritten", { kid: "other-key" }],
  ] as const) {
    it(`refuses a forged outcome on the reserved grant itself: ${label} (review round 3, a)`, async () => {
      const t = gateSetup();
      const door = holdDoor(t);
      const callId = await verified(t);
      const pending = t.gate.grantAccess(t.engine, callId);
      await door.atDoor;
      const [open] = await t.engine.moduleReservations(callId, "gate");
      t.clock.advance(900_000);
      const before = (await t.ledger.list()).length;
      await assert.rejects(
        t.engine.recordModuleOutcome(callId, "gate", open!, (s, call) => {
          const slice = s as unknown as GateSlice;
          Object.assign(slice.grants.find((g) => g.grantId === open)!, patch);
          call.emit("access.delivered", { grantId: open!, confirmed: true });
          return slice as never;
        }),
        rejects("precondition_failed", /refused the outcome/),
      );
      assert.equal((await t.ledger.list()).length, before, "no forged ledger entry");
      assert.equal((await t.engine.flowPosition(callId))!.status, "running", "the flow did not complete");
      door.answer({ outcome: "refused", reason: "door_offline" });
      assert.deepEqual(await pending, { grantId: open!, status: "refused", confirmed: false }, "the door's real answer, nothing else");
      const g = (await slice(t, callId)).grants[0]!;
      assert.deepEqual([g.status, g.ref, g.target, g.level], ["refused", "door-1", "front-door", 2]);
    });
  }

  it("refuses a no-op settle that would write forged events, and settles once (review round 3, a2)", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t, null);
    const pending = t.gate.grantAccess(t.engine, callId, { target: "front-door" });
    await door.atDoor;
    const [open] = await t.engine.moduleReservations(callId, "gate");
    for (let i = 0; i < 3; i++) {
      await assert.rejects(
        t.engine.recordModuleOutcome(callId, "gate", open!, (s, call) => (call.emit("access.delivered", { grantId: open!, i }), s)),
        rejects("precondition_failed", /only takes its digest and key id, once/),
      );
    }
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: true });
    assert.equal((await pending).status, "delivered");
    const delivered = (await gateEvents(t)).filter(([e]) => e === "access.delivered");
    assert.equal(delivered.length, 1, "only the real one");
    assert.deepEqual(await t.engine.moduleReservations(callId, "gate"), [], "consumed by the settling write");
    await assert.rejects(t.engine.recordModuleOutcome(callId, "gate", open!, (s) => s), rejects("precondition_failed", /no open reservation/));
  });

  it("refuses a final outcome this gate never received, or one at odds with it", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t, null);
    const pending = t.gate.grantAccess(t.engine, callId, { target: "front-door" });
    await door.atDoor;
    const [open] = await t.engine.moduleReservations(callId, "gate");
    // Unknown before the grant expired: only the gate that sent it may say so (a lost answer).
    for (const forged of [{ status: "unknown" }, { status: "refused" }, { status: "failed" }]) {
      await assert.rejects(
        t.engine.recordModuleOutcome(callId, "gate", open!, (s) => (Object.assign((s as unknown as GateSlice).grants[0]!, forged), s)),
        rejects("precondition_failed", /never received/),
        JSON.stringify(forged),
      );
    }
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: false });
    assert.deepEqual(await pending, { grantId: open!, status: "delivered", confirmed: false });
  });

  it("records outcomes only for installed outside modules", async () => {
    const t = gateSetup();
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.recordModuleOutcome(callId, "paylink", "x", (s) => s), rejects("precondition_failed", /built in/));
    await assert.rejects(t.engine.recordModuleOutcome(callId, "nope", "x", (s) => s), rejects("module_disabled"));
  });
});

describe("access grants: the verifier and replay", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const signer = keyPairSigner("k1", privateKey.export({ format: "pem", type: "pkcs8" }).toString());
  const keys = [signer.publicJwk()];
  const now = new Date("2026-01-01T00:00:00.000Z");
  const body: AccessGrantBody = {
    v: 1,
    kind: "access",
    grantId: "acc_1",
    workspaceId: "w",
    audience: "lobby",
    target: "door-1",
    action: "unlock",
    scope: "entry.open",
    level: 2,
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-01-01T00:01:00.000Z",
  };
  const sign = async (patch: Partial<AccessGrantBody> | Record<string, unknown> = {}): Promise<SignedAccessGrant> => {
    const { signDocument } = await import("../src/prove/receipt.ts");
    return signDocument(signer, { ...body, ...patch } as AccessGrantBody);
  };
  const check = (grant: unknown, at = now, extra: { clockSkewSeconds?: number } = {}) => verifyAccessGrant(grant, keys, { workspaceId: "w", audience: "lobby", now: at, ...extra });

  it("accepts a good grant inside its window, allowing clock skew", async () => {
    const grant = await sign();
    assert.equal(check(grant).ok, true);
    assert.equal(check(grant, new Date("2025-12-31T23:59:31.000Z")).ok, true, "30 seconds early");
    assert.deepEqual(check(grant, new Date("2025-12-31T23:59:29.000Z")), { ok: false, reason: "not_yet_valid" });
    assert.equal(check(grant, new Date("2026-01-01T00:01:29.000Z")).ok, true);
    assert.deepEqual(check(grant, new Date("2026-01-01T00:01:30.000Z")), { ok: false, reason: "expired" });
    assert.deepEqual(check(grant, new Date("2026-01-01T00:01:01.000Z"), { clockSkewSeconds: 0 }), { ok: false, reason: "expired" });
  });

  it("refuses a grant another workspace issued, even on a shared key and controller name (review R1)", async () => {
    const other = await sign({ workspaceId: "ws_other_tenant" });
    assert.equal(check(await sign()).ok, true);
    assert.deepEqual(check(other), { ok: false, reason: "workspace" });
    for (const workspaceId of ["", undefined, 7]) {
      assert.deepEqual(verifyAccessGrant(await sign(), keys, { workspaceId: workspaceId as never, audience: "lobby", now }), { ok: false, reason: "workspace" }, String(workspaceId));
    }
  });

  it("refuses the wrong audience, a long or inverted lifetime, and anything malformed", async () => {
    assert.deepEqual(verifyAccessGrant(await sign(), keys, { workspaceId: "w", audience: "garage", now }), { ok: false, reason: "audience" });
    assert.deepEqual(check(await sign({ expiresAt: "2026-01-01T00:15:01.000Z" })), { ok: false, reason: "lifetime" });
    assert.deepEqual(check(await sign({ expiresAt: "2025-12-31T23:59:00.000Z" })), { ok: false, reason: "lifetime" });
    const good = await sign();
    for (const bad of [null, "x", { ...good, kid: 1 }, { ...good, signature: undefined }, { ...good, body: null }, { ...good, body: [] }]) {
      assert.deepEqual(check(bad), { ok: false, reason: "malformed" });
    }
    for (const patch of [{ v: 2 }, { kind: "receipt" }, { action: "lock" }, { level: 4 }, { target: "" }, { grantId: 1 }, { issuedAt: "soon" }, { expiresAt: "later" }]) {
      assert.deepEqual(check({ ...good, body: { ...good.body, ...patch } }), { ok: false, reason: "malformed" }, JSON.stringify(patch));
    }
    assert.deepEqual(check({ ...good, alg: "none" }), { ok: false, reason: "signature" });
  });

  it("refuses a grant id it has seen until the grant expired", async () => {
    const seen = new SeenGrants();
    const first = await sign();
    assert.equal(seen.accept(first.body, now), true);
    assert.equal(seen.accept(first.body, now), false);
    const later = new Date("2026-01-01T00:02:01.000Z");
    assert.equal(seen.accept({ ...body, grantId: "acc_2", expiresAt: "2026-01-01T00:03:00.000Z" }, later), true, "and forgets the expired one");
    assert.equal(seen.accept(first.body, later), true, "forgotten after expiry plus skew, when the verifier refuses it anyway");
  });

  it("keeps a grant id as long as a verifier with a wider skew still accepts the grant", async () => {
    const seen = new SeenGrants({ clockSkewSeconds: 120 });
    const grant = await sign();
    assert.equal(seen.accept(grant.body, now), true);
    const late = new Date("2026-01-01T00:02:59.000Z");
    assert.equal(check(grant, late, { clockSkewSeconds: 120 }).ok, true, "still valid to this verifier");
    assert.equal(seen.accept(grant.body, late), false, "so still refused as a replay");
    const gone = new Date("2026-01-01T00:03:00.000Z");
    assert.equal(check(grant, gone, { clockSkewSeconds: 120 }).ok, false);
  });

  it("is the GateModule class gateModule builds", () => {
    assert.ok(gateModule({ signer, controllers: { lobby: new FakeAccessController() } }) instanceof GateModule);
  });
});
