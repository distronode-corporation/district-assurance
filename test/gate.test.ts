// Gate (GAT-1, ADR-25): signed, time-limited access grants after verification, delivered once
// through an AccessController the engine holds, with the engine itself recording every outcome.
// Every hostile-review case of PR 2 that applies to the engine-owned design is kept here.
import { strict as assert } from "node:assert";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";

import type { AccessController, UnlockResult } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import { ModuleRegistry, type AssuranceModule } from "../src/core/module.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { SeenGrants, accessGrantDigest, verifyAccessGrant, type AccessGrantBody, type SignedAccessGrant } from "../src/gate/access.ts";
import { gateModule } from "../src/gate/gate.ts";
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

/** A session store that can be told to refuse one write: a process that stops after the door answered. */
class StoppingStore extends MemorySessionStore {
  stopWhen: (() => boolean) | null = null;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
    if (this.stopWhen?.() === true) {
      this.stopWhen = null;
      throw new Error("the process stopped");
    }
    return super.compareAndSet(w, c, v, r);
  }
}

function gateSetup(options: { mode?: FakeAccessController["mode"]; patch?: (c: FlowConfig) => void; signer?: ReturnType<typeof generateTestSigner> } = {}) {
  const door = new FakeAccessController(options.mode ?? "confirm");
  const sessions = new StoppingStore();
  const accessSigner = options.signer ?? generateTestSigner("gate-key-1");
  const t = setup({ config: gateConfig(options.patch), adapters: { sessions, access: { lobby: door }, accessSigner } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, door, sessions, accessSigner };
}

type GateTest = ReturnType<typeof gateSetup>;

async function verified(t: GateTest, flow: string | null = "entry"): Promise<string> {
  const { callId } = await t.engine.startCall(flow === null ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

const accessEvents = async (t: GateTest) => (await t.ledger.list()).filter((e) => e.event.startsWith("access.")).map((e) => [e.event, e.detail] as const);

/** A door that holds its answer until told: the grant stays in flight meanwhile. */
function holdDoor(t: GateTest) {
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

/** A signer that holds its signature until told. */
function holdSigner(t: GateTest) {
  const sign = t.accessSigner.sign.bind(t.accessSigner);
  let go: () => void = () => undefined;
  let started: () => void = () => undefined;
  const signing = new Promise<void>((resolve) => (started = resolve));
  t.accessSigner.sign = async (payload) => {
    started();
    await new Promise<void>((resolve) => (go = resolve));
    return sign(payload);
  };
  return { signing, go: () => go() };
}

const registry = (adapters = ["ledger", "records", "carrier", "identity", "messages", "payments", "signer", "pinVerifier", "access", "accessSigner"], capabilities: Record<string, unknown> = {}) =>
  new ModuleRegistry({ adapters, capabilities, modules: builtInModules() });

describe("gate: config", () => {
  it("checks every gate setting", () => {
    assert.deepEqual(gateModule.validateSettings({ targets, maxGrantsPerCall: 5 }), []);
    assert.deepEqual(gateModule.validateSettings(undefined), ["must be an object with the targets"]);
    assert.deepEqual(gateModule.validateSettings({ targets: [], maxGrantsPerCall: 6, x: 1 }), [
      "x is not a gate setting",
      "maxGrantsPerCall must be an integer from 1 to 5",
      "targets must list at least one target",
    ]);
    const sparse: unknown[] = [];
    sparse[1] = targets[0];
    assert.deepEqual(gateModule.validateSettings({ targets: sparse }), ["targets must list at least one target"], "a hole is not a target");
    assert.deepEqual(gateModule.validateSettings({ targets: [7, { id: "Front", controller: "", ref: " ", y: 1 }, { id: "a", controller: "lobby", ref: "x".repeat(201) }, { id: "a", controller: 1, ref: 1 }] }), [
      "targets[0] must be { id, controller, ref }",
      "targets[1].y is not a target field",
      "targets[1].id must be lower-case letters, digits and hyphens, at most 64",
      "targets[1].controller must name a controller",
      "targets[1].ref must be 1 to 200 characters",
      "targets[2].ref must be 1 to 200 characters",
      "targets[3].controller must name a controller",
      "targets[3].ref must be 1 to 200 characters",
      "two targets have the same id",
    ]);
  });

  it("needs the access adapters, and holds targets to the controllers the engine has", () => {
    assert.deepEqual(validateConfig(gateConfig(), registry()), [], "a registry that knows only adapter names skips the controller check");
    assert.deepEqual(validateConfig(gateConfig(), registry(["ledger", "records", "carrier", "identity", "messages", "payments", "signer", "pinVerifier"])), [
      "modules.gate: needs the access adapter, which the engine does not have",
      "modules.gate: needs the accessSigner adapter, which the engine does not have",
    ]);
    assert.deepEqual(validateConfig(gateConfig(), registry(undefined, { access: { controllers: ["side"] } })), [
      "modules.gate: target front-door names the controller lobby, which the access adapter does not have (it has: side)",
      "modules.gate: target garage names the controller lobby, which the access adapter does not have (it has: side)",
    ]);
    assert.throws(() => setup({ config: gateConfig(), adapters: { access: {} } }), /the access adapter does not have \(it has: none\)/);
  });

  it("checks gate.grant steps, and holds them to entry.open at level 2", () => {
    const problems = (c: FlowConfig) => validateConfig(c, registry());
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
    assert.deepEqual(problems(gateConfig((c) => (c.modules.gate = { settings: { targets: [] } }))), ["modules.gate.settings: targets must list at least one target"]);
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
  it("runs an entry flow: a signed grant to the door, verified with the access key only", async () => {
    const t = gateSetup();
    const callId = await verified(t);
    assert.deepEqual(await t.engine.grantAccess(callId), { grantId: "acc_1", status: "delivered", confirmed: true });
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
    const keys = t.engine.accessKeys();
    assert.deepEqual(verifyAccessGrant(grant, keys, { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: true, body: grant.body });
    const changed = structuredClone(grant);
    changed.body.target = "door-2";
    assert.deepEqual(verifyAccessGrant(changed, keys, { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: false, reason: "signature" });
    assert.deepEqual(verifyAccessGrant(grant, t.engine.receiptKeys(), { workspaceId: "ws_test", audience: "lobby", now: t.clock.now() }), { ok: false, reason: "signature" }, "not the receipt key");
    const digest = accessGrantDigest(grant.body);
    assert.deepEqual(await accessEvents(t), [
      ["access.issued", { grantId: "acc_1", target: "front-door", controller: "lobby", scope: "entry.open", level: 2, verificationGrantId: "grant_1", expiresAt: "2026-01-01T00:01:00.000Z" }],
      ["access.delivered", { grantId: "acc_1", digest, kid: "gate-key-1", confirmed: true }],
    ]);
    assert.ok(!JSON.stringify(await t.ledger.list()).includes(grant.signature), "the grant itself is never in the ledger");
    assert.deepEqual(await t.engine.accessGrants(callId), [
      {
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
      },
    ]);
  });

  it("refuses without a verification grant covering entry.open, in a flow and outside one", async () => {
    const t = gateSetup();
    const { callId } = await t.engine.startCall({ flow: "entry" });
    await assert.rejects(t.engine.grantAccess(callId), rejects("precondition_failed", /on step badge.verify/), "not Gate's step yet");
    const open = await t.engine.startCall();
    await assert.rejects(t.engine.grantAccess(open.callId, { target: "front-door" }), rejects("scope_denied", /entry.open/), "no flow, no verification");
    const tainted = await verified(t, null);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.grantAccess(tainted, { target: "front-door" }), rejects("scope_denied"));
    const expired = await verified(t, null);
    t.clock.advance(900_000);
    await assert.rejects(t.engine.grantAccess(expired, { target: "front-door" }), rejects("scope_denied"));
    assert.equal(t.door.received.length, 0, "no door was ever asked");
    assert.deepEqual(await accessEvents(t), [], "and nothing reached the ledger");
  });

  it("takes the target from the step in a flow and from the host outside one", async () => {
    const t = gateSetup();
    const inFlow = await verified(t);
    await assert.rejects(t.engine.grantAccess(inFlow, { target: "garage" }), rejects("invalid_input", /pass no input/));
    const outside = await verified(t, null);
    await assert.rejects(t.engine.grantAccess(outside), rejects("invalid_input", /target is required/));
    await assert.rejects(t.engine.grantAccess(outside, { target: "attic" }), rejects("invalid_input", /no target attic/));
    await assert.rejects(t.engine.grantAccess(outside, { target: "garage", lifetimeSeconds: 5 }), rejects("invalid_input", /lifetimeSeconds/));
    assert.equal((await t.engine.grantAccess(outside, { target: "garage", lifetimeSeconds: 120 })).status, "delivered");
    assert.equal(t.door.received[0]!.target, "door-2");
    assert.equal(t.door.received[0]!.grant.body.expiresAt, "2026-01-01T00:02:00.000Z");
  });

  it("never outlives the verification grant", async () => {
    const t = gateSetup({ mode: "deliver", patch: (c) => (c.flows.entry!.steps[1] = { type: "gate.grant", target: "front-door", lifetimeSeconds: 900 }) });
    const callId = await verified(t);
    t.clock.advance(600_000);
    assert.deepEqual(await t.engine.grantAccess(callId), { grantId: "acc_1", status: "delivered", confirmed: false });
    assert.equal(t.door.received[0]!.grant.body.expiresAt, "2026-01-01T00:15:00.000Z", "the verification grant's own expiry");
  });

  it("records a lost answer as unknown, never retries it, and needs a fresh request", async () => {
    const t = gateSetup({ mode: "lose", patch: (c) => (c.modules.gate!.settings = { targets: structuredClone(targets), maxGrantsPerCall: 2 }) });
    const callId = await verified(t);
    assert.deepEqual(await t.engine.grantAccess(callId), { grantId: "acc_1", status: "unknown", confirmed: false });
    assert.equal(t.door.received.length, 1, "sent once");
    assert.equal((await t.engine.flowPosition(callId))!.status, "running", "the step waits for a fresh request");
    t.door.mode = "refuse";
    assert.deepEqual(await t.engine.grantAccess(callId), { grantId: "acc_2", status: "refused", confirmed: false });
    assert.deepEqual(t.door.received.map((r) => r.grant.body.grantId), ["acc_1", "acc_2"], "a fresh grant, never the lost one again");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed", "every grant used, the door never opened");
    assert.deepEqual((await accessEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["access.issued", null],
      ["access.unknown", "answer_lost"],
      ["access.issued", null],
      ["access.refused", "door_offline"],
    ]);
    const outside = await verified(t, null);
    await t.engine.grantAccess(outside, { target: "front-door" });
    await t.engine.grantAccess(outside, { target: "front-door" });
    await assert.rejects(t.engine.grantAccess(outside, { target: "front-door" }), rejects("precondition_failed", /every access grant/));
  });

  it("writes a controller's refusal reason as a short code only", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    t.door.unlock = async () => ({ outcome: "refused", reason: "Door said: <script>" });
    await t.engine.grantAccess(callId, { target: "front-door" });
    assert.equal(((await accessEvents(t)).at(-1)![1] as { reason: string }).reason, "refused");
  });

  it("fails a grant whose signing failed, sends nothing, and allows a new one", async () => {
    const t = gateSetup();
    const sign = t.accessSigner.sign.bind(t.accessSigner);
    let broken = true;
    t.accessSigner.sign = (payload) => (broken ? Promise.reject(new Error("kms down")) : sign(payload));
    const callId = await verified(t);
    await assert.rejects(t.engine.grantAccess(callId), /kms down/);
    assert.equal((await t.engine.accessGrants(callId))[0]!.status, "failed");
    assert.equal(t.door.received.length, 0);
    broken = false;
    assert.equal((await t.engine.grantAccess(callId)).status, "delivered");
    assert.deepEqual((await accessEvents(t)).map(([e]) => e), ["access.issued", "access.failed", "access.issued", "access.delivered"]);
  });

  it("allows one grant in flight per call", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    const unlock = t.door.unlock.bind(t.door);
    let nested: Promise<unknown> | null = null;
    t.door.unlock = async (input) => {
      nested = t.engine.grantAccess(callId, { target: "garage" });
      await assert.rejects(nested, rejects("precondition_failed", /being delivered/));
      return unlock(input);
    };
    assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    assert.ok(nested !== null);
  });

  it("sends nothing when the call was tainted, the grant expired or the call ended while it was signed", async () => {
    for (const [what, during, reason] of [
      ["tainted", (t: GateTest, callId: string) => t.engine.markUntrusted(callId, "crm_note"), /no longer authorized/],
      ["expired", async (t: GateTest) => t.clock.advance(60_000), /it expired/],
      ["ended", async (t: GateTest, callId: string) => void (await t.engine.endCall(callId)), /settled meanwhile/],
    ] as const) {
      const t = gateSetup();
      const hold = holdSigner(t);
      const callId = await verified(t, null);
      const pending = t.engine.grantAccess(callId, { target: "front-door" });
      await hold.signing;
      await during(t, callId);
      hold.go();
      await assert.rejects(pending, rejects("scope_denied", reason), what);
      assert.equal(t.door.received.length, 0, `${what}: no door was asked`);
    }
  });

  it("records nothing for a grant whose signing failed after the call ended", async () => {
    const t = gateSetup();
    let started: () => void = () => undefined;
    const signing = new Promise<void>((resolve) => (started = resolve));
    let fail: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (fail = resolve));
    t.accessSigner.sign = async () => {
      started();
      await held;
      throw new Error("kms down");
    };
    const callId = await verified(t);
    const pending = t.engine.grantAccess(callId);
    await signing;
    await t.engine.endCall(callId);
    fail();
    await assert.rejects(pending, /kms down/);
    assert.deepEqual((await accessEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["access.issued", null],
      ["access.unknown", "call_ended"],
    ], "settled by the end; the failed signing changes nothing");
  });

  it("settles a stale grant as unknown in its own write, naming its digest, once its answer was never recorded", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    // The door answers; the process stops before writing it.
    t.sessions.stopWhen = () => t.door.received.length === 1;
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), /the process stopped/);
    assert.equal(t.door.received.length, 1);
    assert.equal((await t.engine.accessGrants(callId))[0]!.status, "reserved");
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), rejects("precondition_failed", /being delivered/));
    t.clock.advance(60_000);
    assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    assert.deepEqual((await t.engine.accessGrants(callId)).map((g) => g.status), ["unknown", "delivered"]);
    const stale = (await accessEvents(t))[1]!;
    assert.deepEqual(stale, ["access.unknown", { grantId: "acc_1", digest: accessGrantDigest(t.door.received[0]!.grant.body), kid: "gate-key-1", reason: "no_answer_recorded" }]);
  });

  it("names no digest for a stale grant that stopped before it was signed", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    let writes = 0;
    t.sessions.stopWhen = () => ++writes === 2;
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), /the process stopped/);
    t.clock.advance(60_000);
    await t.engine.grantAccess(callId, { target: "front-door" });
    assert.deepEqual((await accessEvents(t))[1], ["access.unknown", { grantId: "acc_1", reason: "no_answer_recorded" }]);
  });

  it("fails the step at the grant limit once a stale grant settles, and keeps that settlement", async () => {
    const t = gateSetup({ patch: (c) => (c.modules.gate!.settings = { targets: structuredClone(targets), maxGrantsPerCall: 1 }) });
    const callId = await verified(t);
    t.sessions.stopWhen = () => t.door.received.length === 1;
    await assert.rejects(t.engine.grantAccess(callId), /the process stopped/);
    t.clock.advance(60_000);
    // Settling the stale grant uses the call's last one, so the step fails and the request is refused.
    await assert.rejects(t.engine.grantAccess(callId), rejects("precondition_failed", /flow entry has failed/));
    assert.equal((await t.engine.accessGrants(callId))[0]!.status, "unknown", "settled in its own write, though the request was refused");
    assert.equal(t.door.received.length, 1, "no second grant was sent");
  });

  it("settles a stale grant once when several requests find it at the same time (review round 4, R1)", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t, null);
    const first = t.engine.grantAccess(callId, { target: "front-door" });
    await door.atDoor;
    // Later requests get their answers at once; the first one's stays held.
    t.door.unlock = async () => ({ outcome: "delivered", providerRef: "garage-1", confirmed: true });
    t.clock.advance(120_000);
    await Promise.allSettled([1, 2, 3].map(() => t.engine.grantAccess(callId, { target: "garage" })));
    assert.equal((await accessEvents(t)).filter(([e]) => e === "access.unknown").length, 1, "settled once");
    // The late real answer to the first grant changes nothing (review round 4, R3).
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: true });
    assert.deepEqual(await first, { grantId: "acc_1", status: "unknown", confirmed: false });
    assert.equal((await t.engine.accessGrants(callId))[0]!.status, "unknown");
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

  it("refuses when Gate is off, and has no grants or keys to show then", async () => {
    const t = setup({ adapters: { accessSigner: undefined } });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), rejects("module_disabled"));
    assert.deepEqual(await t.engine.accessGrants(callId), []);
    assert.deepEqual(t.engine.accessKeys(), []);
  });
});

describe("gate: the engine owns every outcome (ADR-25)", () => {
  it("never lets module code reach Gate's grants: updateModule and moduleState refuse it (review round 4, U1 to U3)", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t);
    const pending = t.engine.grantAccess(callId);
    await door.atDoor;
    const forge = (s: JsonValue) => {
      const g = (s as unknown as { grants: Array<Record<string, unknown>> }).grants.at(-1)!;
      Object.assign(g, { status: "delivered", confirmed: true, providerRef: "forged", ref: "door-999" });
      return s;
    };
    await assert.rejects(t.engine.updateModule(callId, "gate", forge), rejects("precondition_failed", /gate is built in/), "U1: in flight");
    await assert.rejects(t.engine.moduleState(callId, "gate"), rejects("precondition_failed", /gate is built in/));
    door.answer({ outcome: "refused", reason: "door_offline" });
    assert.deepEqual(await pending, { grantId: "acc_1", status: "refused", confirmed: false }, "the door's real answer");
    await assert.rejects(t.engine.updateModule(callId, "gate", forge), rejects("precondition_failed", /built in/), "U3: settled");
    assert.deepEqual((await t.engine.accessGrants(callId)).map((g) => [g.status, g.ref]), [["refused", "door-1"]]);
    // U2: no flow and no verification at all.
    const bare = await t.engine.startCall();
    await assert.rejects(t.engine.updateModule(bare.callId, "gate", forge), rejects("precondition_failed", /built in/));
    assert.deepEqual((await accessEvents(t)).filter(([e]) => e === "access.delivered"), [], "no forged delivery anywhere");
    assert.equal("recordModuleOutcome" in t.engine, false, "and there is no outcome API to reach them by");
  });

  it("holds an outside module's updateModule outside a flow to every scope its manifest needs (review round 4, U2)", async () => {
    const t = setup();
    const scoped: AssuranceModule = {
      manifest: { name: "tier", version: "1", summary: "x", provides: { factors: [], steps: ["tier.lookup"], outcomes: [] }, scopes: { grants: [], needs: { "tier.lookup": "status.read" } }, adapters: [] },
      validateSettings: () => [],
      requiredAdapters: () => [],
      validateStep: () => [],
      initCall: () => ({ n: 0 }),
      enterStep: () => null,
      stepStatus: () => "pending",
    };
    t.engine.use(scoped);
    t.engine.configure(testConfig((c) => (c.modules.tier = {})));
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.updateModule(callId, "tier", () => ({ n: 1 })), rejects("scope_denied", /status.read/), "no flow, not verified");
    assert.deepEqual(await t.engine.moduleState(callId, "tier"), { n: 0 });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.engine.updateModule(callId, "tier", () => ({ n: 1 })), { n: 1 }, "verified for status.read: allowed");
    assert.deepEqual(await t.engine.updateModule(callId, "tier", (_s, call) => ({ id: call.newId("tier"), at: call.now })), { id: "tier_1", at: "2026-01-01T00:00:00.000Z" }, "the engine's ids and clock");
  });

  it("computes each grant's digest itself, from the grant it signed (review round 4, D1)", async () => {
    const t = gateSetup({ mode: "lose" });
    const callId = await verified(t, null);
    await t.engine.grantAccess(callId, { target: "front-door" });
    const digest = accessGrantDigest(t.door.received[0]!.grant.body);
    assert.equal((await t.engine.accessGrants(callId))[0]!.digest, digest);
    assert.deepEqual((await accessEvents(t)).filter(([e]) => e !== "access.issued").map(([, d]) => (d as { digest: string }).digest), [digest]);
  });

  it("settles a grant in flight as unknown when the call ends, before the receipt's head, so nothing follows the receipt (review round 4, R4)", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t, null);
    const pending = t.engine.grantAccess(callId, { target: "front-door" });
    await door.atDoor;
    // The receipt signer is slow too: the door answers while the receipt is being signed.
    const sign = t.engine.receiptKeys().length;
    assert.equal(sign, 1);
    const ending = t.engine.endCall(callId);
    await new Promise((resolve) => setImmediate(resolve));
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: true });
    assert.deepEqual(await pending, { grantId: "acc_1", status: "unknown", confirmed: false }, "settled by the end");
    const receipt = (await ending)!;
    const after = (await t.ledger.list()).filter((e) => e.seq > receipt.body.ledger.seq).map((e) => e.event);
    assert.deepEqual(after, ["receipt.issued"], "no access outcome after the receipt's ledger head");
    assert.deepEqual((await accessEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["access.issued", null],
      ["access.unknown", "call_ended"],
    ]);
  });

  it("never carries a delivery for a refused grant under the receipt's head (review round 4, R5)", async () => {
    const t = gateSetup({ mode: "refuse" });
    const callId = await verified(t, null);
    await t.engine.grantAccess(callId, { target: "front-door" });
    const receipt = (await t.engine.endCall(callId))!;
    const under = (await t.ledger.list()).filter((e) => e.seq <= receipt.body.ledger.seq);
    assert.equal(under.filter((e) => e.event === "access.delivered").length, 0);
    assert.equal(JSON.stringify(receipt.body).includes("delivered"), false);
  });

  it("settles a grant in flight as unknown when a flow call without a receipt ends, and its late answer changes nothing", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t);
    const pending = t.engine.grantAccess(callId);
    await door.atDoor;
    assert.equal(await t.engine.endCall(callId), null, "the entry flow has no receipt step");
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: true });
    assert.deepEqual(await pending, { grantId: "acc_1", status: "unknown", confirmed: false });
  });

  it("uses an access controller only by the name a target gives", async () => {
    const side: AccessController = { unlock: async () => ({ outcome: "delivered", providerRef: "side-1", confirmed: true }) };
    const lobby = new FakeAccessController();
    const t = setup({
      config: gateConfig((c) => (c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }, { id: "side-door", controller: "side", ref: "s-1" }] } })),
      adapters: { access: { lobby, side } },
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const callId = await verified(t as unknown as GateTest, null);
    assert.equal((await t.engine.grantAccess(callId, { target: "side-door" })).status, "delivered");
    assert.equal(lobby.received.length, 0);
    assert.equal((await t.engine.accessGrants(callId))[0]!.providerRef, "side-1");
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

});
