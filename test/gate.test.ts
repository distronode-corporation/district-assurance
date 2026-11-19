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
import { FakeAccessController, FakeMessageSender, FixedClock, generateTestSigner } from "../src/testing/index.ts";
import type { CodeStore, MessageSender } from "../src/core/adapters.ts";
import {
  AccessCodes,
  MemoryAccessCodeStore,
  ACCESS_CODE_SEND_LIMITS,
  accessCodeDigest,
  accessCodes,
  type AccessCodeEntry,
  type AccessCodeStore,
} from "../src/gate/codes.ts";
import { MemoryCodeStore, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject } from "../src/testing/index.ts";
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
    // Only a controller with an unlock function counts, own or from its class.
    assert.throws(() => setup({ config: gateConfig(), adapters: { access: { lobby: { unlock: "not a function" } as never } } }), /names the controller lobby, which the access adapter does not have/);
    class Door {
      async unlock(): Promise<UnlockResult> {
        return { outcome: "delivered", providerRef: "p", confirmed: true };
      }
    }
    assert.doesNotThrow(() => setup({ config: gateConfig(), adapters: { access: { lobby: new Door() } } }), "a class-based adapter");
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

  it("never ends a call while a signed grant is at its door, so no door acts on a grant after the receipt (review rounds 4 and 5, R4 and E2)", async () => {
    const t = gateSetup();
    const door = holdDoor(t);
    const callId = await verified(t, null);
    const pending = t.engine.grantAccess(callId, { target: "front-door" });
    await door.atDoor;
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /at its door/), "refused while the door decides");
    assert.equal((await t.engine.state(callId)).phase, "open");
    door.answer({ outcome: "delivered", providerRef: "p", confirmed: true });
    assert.deepEqual(await pending, { grantId: "acc_1", status: "delivered", confirmed: true });
    const receipt = (await t.engine.endCall(callId))!;
    const ledger = await t.ledger.list();
    const delivered = ledger.find((e) => e.event === "access.delivered")!;
    assert.ok(delivered.seq <= receipt.body.ledger.seq, "the outcome is under the receipt's head");
    assert.deepEqual(ledger.filter((e) => e.seq > receipt.body.ledger.seq).map((e) => e.event), ["receipt.issued"], "nothing after it but the receipt");
  });

  it("refuses an end that lands between the check before sending and the send itself (review round 5, E2)", async () => {
    // A store that runs a hook right after the write that checks the grant and records its digest.
    class Hooked extends StoppingStore {
      after: (() => Promise<void>) | null = null;
      override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
        const out = await super.compareAndSet(w, c, v, r);
        const g = (r as unknown as { modules: { gate?: { grants: Array<{ digest: string | null; status: string }> } } }).modules.gate?.grants.at(-1);
        const run = this.after;
        if (out.ok && run !== null && g?.digest !== null && g?.digest !== undefined && g.status === "reserved") {
          this.after = null;
          await run();
        }
        return out;
      }
    }
    const sessions = new Hooked();
    const door = new FakeAccessController();
    const t = setup({ config: gateConfig(), adapters: { sessions, access: { lobby: door }, accessSigner: generateTestSigner("gate-key-1") } });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const callId = await verified(t as unknown as GateTest, null);
    let ended: unknown = null;
    sessions.after = async () => {
      ended = await t.engine.endCall(callId).then(() => "ended", (e: unknown) => (e as { code?: string }).code);
    };
    assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    assert.equal(ended, "precondition_failed", "the end was refused: the grant was on its way to the door");
    const receipt = (await t.engine.endCall(callId))!;
    assert.ok((await t.ledger.list()).find((e) => e.event === "access.delivered")!.seq <= receipt.body.ledger.seq);
  });

  it("never ends a call while a grant whose answer was lost may still be acted on, until it expires", async () => {
    const t = gateSetup({ mode: "lose" });
    const callId = await verified(t, null);
    assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, "unknown");
    // The controller timed out, but may still be working on the request: the call waits for the expiry.
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /may still be acted on/));
    t.clock.advance(60_000);
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual(verifyAccessGrant(t.door.received[0]!.grant, t.engine.accessKeys(), { workspaceId: "ws_test", audience: "lobby", now: new Date(Date.parse(receipt.body.issuedAt) + 1) }), { ok: false, reason: "expired" });
    // A definitive answer lets the call end at once.
    const r = gateSetup({ mode: "refuse" });
    const c2 = await verified(r, null);
    await r.engine.grantAccess(c2, { target: "front-door" });
    assert.notEqual(await r.engine.endCall(c2), null);
  });

  it("ends a call whose grant's process stopped at the door once that grant expired, recording it unknown", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    t.sessions.stopWhen = () => t.door.received.length === 1;
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), /the process stopped/);
    await assert.rejects(t.engine.endCall(callId), rejects("precondition_failed", /at its door/));
    t.clock.advance(60_000);
    const receipt = (await t.engine.endCall(callId))!;
    assert.deepEqual((await accessEvents(t)).at(-1), [
      "access.unknown",
      { grantId: "acc_1", digest: accessGrantDigest(t.door.received[0]!.grant.body), kid: "gate-key-1", reason: "no_answer_recorded" },
    ]);
    assert.ok(receipt.body.ledger.seq >= (await t.ledger.list()).find((e) => e.event === "access.unknown")!.seq);
    // The grant the door got is dead for any relay from the moment the receipt was issued (review round 6, E2).
    const at = new Date(Date.parse(receipt.body.issuedAt) + 1);
    assert.deepEqual(verifyAccessGrant(t.door.received[0]!.grant, t.engine.accessKeys(), { workspaceId: "ws_test", audience: "lobby", now: at }), { ok: false, reason: "expired" });
    assert.deepEqual(verifyAccessGrant(t.door.received[0]!.grant, t.engine.accessKeys(), { workspaceId: "ws_test", audience: "lobby", now: at, clockSkewSeconds: 900 }), { ok: false, reason: "expired" }, "whatever skew the relay allows");
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

  it("never lets a host module take a built-in module's name, even after it was removed (review round 5, F5)", () => {
    const t = gateSetup();
    t.engine.configure(testConfig((c) => (c.policy.scopes["entry.open"] = 2)));
    t.engine.remove("gate");
    assert.throws(() => t.engine.use({ ...gateModule, stepStatus: () => "complete" }), (e: unknown) => /gate is the name of a built-in module/.test(String((e as Error).message)));
    assert.throws(() => setup({ modules: [{ ...gateModule }] }), /gate is the name of a built-in module/);
  });

  it("refuses an input that is not { target } with invalid_input, never a TypeError (review round 5, I3)", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    for (const bad of [null, 7, "front-door", [], {}, { target: 1 }]) {
      await assert.rejects(t.engine.grantAccess(callId, bad as never), rejects("invalid_input"), JSON.stringify(bad));
    }
    for (const target of ["nope", "__proto__", "constructor", "toString", "", "FRONT-DOOR"]) {
      await assert.rejects(t.engine.grantAccess(callId, { target }), rejects("invalid_input"), target);
    }
    assert.equal(t.door.received.length, 0);
    assert.deepEqual(await t.engine.accessGrants(callId), []);
  });

  it("never records unknown for a grant it could not send: a controller gone before or while it was signed (review round 5, I5)", async () => {
    const access: Record<string, AccessController> = { lobby: new FakeAccessController() };
    const accessSigner = generateTestSigner("gate-key-1");
    const t = setup({ config: gateConfig(), adapters: { access, accessSigner } });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const callId = await verified(t as unknown as GateTest, null);
    const lobby = access.lobby!;
    delete access.lobby;
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), rejects("precondition_failed", /no access controller named lobby/));
    assert.deepEqual(await t.engine.accessGrants(callId), [], "nothing reserved");
    access.lobby = { unlock: "not a function" } as never;
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), rejects("precondition_failed"), "not a controller");
    access.lobby = lobby;
    const sign = accessSigner.sign.bind(accessSigner);
    accessSigner.sign = async (payload) => {
      delete access.lobby;
      return sign(payload);
    };
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), rejects("precondition_failed", /not sent/));
    const [g] = await t.engine.accessGrants(callId);
    assert.equal(g!.status, "failed", "failed, not unknown: nothing was sent");
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "access.failed").map((e) => e.detail.reason), ["not_sent"]);
  });

  it("refuses an access signer that is the receipt signer's key (its key id or its public key)", () => {
    const shared = generateTestSigner("shared-1");
    assert.throws(() => setup({ adapters: { signer: shared, accessSigner: shared } }), /accessSigner must have its own key id/);
    assert.throws(() => setup({ adapters: { signer: shared, accessSigner: { ...shared, keyId: "other-id" } } }), /accessSigner must be its own key/);
    // The same key written differently: '=' padding, or the standard base64 alphabet (review round 6).
    const jwk = shared.publicJwk();
    const toStd = (v: string) => Buffer.from(v, "base64url").toString("base64");
    for (const [label, x, y] of [
      ["padded", `${jwk.x}=`, `${jwk.y}=`],
      ["standard base64", toStd(jwk.x!), toStd(jwk.y!)],
    ] as const) {
      const disguised = { ...shared, keyId: `disguised-${label}`, publicJwk: () => ({ ...jwk, x, y }) };
      assert.throws(() => setup({ adapters: { signer: shared, accessSigner: disguised } }), /accessSigner must be its own key/, label);
    }
    const broken = { ...generateTestSigner("broken-1"), publicJwk: () => ({ kty: "EC", crv: "P-256", x: "not-a-key", y: "nope" }) };
    assert.doesNotThrow(() => setup({ adapters: { signer: shared, accessSigner: broken } }), "a key that does not import is not this check's to judge");
    assert.doesNotThrow(() => setup({ adapters: { signer: shared, accessSigner: generateTestSigner("access-1") } }));
    const noReceipts = testConfig((c) => (c.modules.trace = { settings: { receipts: false, wordings: [] } }));
    assert.doesNotThrow(() => setup({ config: noReceipts, adapters: { signer: undefined, accessSigner: shared } }), "no receipts: nothing to clash with");
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

  it("accepts a good grant inside its window, with clock skew on its start only and a strict expiry", async () => {
    const grant = await sign();
    assert.equal(check(grant).ok, true);
    assert.equal(check(grant, new Date("2025-12-31T23:59:31.000Z")).ok, true, "30 seconds early");
    assert.deepEqual(check(grant, new Date("2025-12-31T23:59:29.000Z")), { ok: false, reason: "not_yet_valid" });
    assert.equal(check(grant, new Date("2026-01-01T00:00:59.999Z")).ok, true);
    assert.deepEqual(check(grant, new Date("2026-01-01T00:01:00.000Z")), { ok: false, reason: "expired" }, "never extended past the expiry");
    assert.deepEqual(check(grant, new Date("2026-01-01T00:01:00.000Z"), { clockSkewSeconds: 120 }), { ok: false, reason: "expired" }, "whatever the skew");
    assert.deepEqual(check(grant, new Date("2025-12-31T23:59:59.000Z"), { clockSkewSeconds: 0 }), { ok: false, reason: "not_yet_valid" });
  });

  it("refuses a clock skew that is not a finite, non-negative number, so the not-before check never turns off", async () => {
    const early = await sign({ issuedAt: "2026-01-01T00:10:00.000Z", expiresAt: "2026-01-01T00:11:00.000Z" });
    for (const bad of [Number.NaN, Infinity, -Infinity, -1, -0.001, "30", null]) {
      assert.deepEqual(check(early, now, { clockSkewSeconds: bad as never }), { ok: false, reason: "invalid_options" }, String(bad));
    }
    assert.deepEqual(check(early, now, { clockSkewSeconds: 0 }), { ok: false, reason: "not_yet_valid" }, "zero is a valid skew");
    assert.deepEqual(check(early, now), { ok: false, reason: "not_yet_valid" }, "and the default holds the check");
  });

  it("refuses an unusable clock reading, so an expired grant never passes", async () => {
    const expired = await sign({ issuedAt: "2025-01-01T00:00:00.000Z", expiresAt: "2025-01-01T00:01:00.000Z" });
    for (const bad of [new Date(Number.NaN), undefined, "2026-01-01", 0]) {
      assert.deepEqual(verifyAccessGrant(expired, keys, { workspaceId: "w", audience: "lobby", now: bad as never }), { ok: false, reason: "invalid_options" }, String(bad));
    }
    assert.deepEqual(check(expired), { ok: false, reason: "expired" });
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
    assert.equal(seen.accept(first.body, later), true, "forgotten after its expiry, when the verifier refuses it anyway");
  });

  it("keeps a grant id for exactly as long as the verifier accepts the grant", async () => {
    const seen = new SeenGrants();
    const grant = await sign();
    assert.equal(seen.accept(grant.body, now), true);
    const last = new Date("2026-01-01T00:00:59.999Z");
    assert.equal(check(grant, last).ok, true, "still valid");
    assert.equal(seen.accept(grant.body, last), false, "so still refused as a replay");
    const gone = new Date("2026-01-01T00:01:00.000Z");
    assert.equal(check(grant, gone).ok, false, "and from its expiry the verifier refuses it");
  });

});

// One-time access codes (GAT-3): a code texted to the number on file, redeemed once at a keypad.
const CODE_KEY = "access-code-key-not-a-secret";
const keypadTarget = { id: "side-door", controller: "keypad", ref: "keypad-1" };
const keypadDoor = { workspaceId: "ws_test", audience: "keypad", target: "keypad-1" };
const TEXT = /^Your one-time door code: (\d{8})\. It works once, within (\d+) min\.$/;

function codesSetup(options: { limits?: CodeStore; newCode?: () => string; messages?: MessageSender; store?: AccessCodeStore } = {}) {
  const clock = new FixedClock();
  const texts = new FakeMessageSender();
  const store = options.store ?? new MemoryAccessCodeStore();
  const accessSigner = generateTestSigner("gate-key-1");
  const codes = accessCodes({
    key: CODE_KEY,
    signer: accessSigner,
    store,
    messages: options.messages ?? texts,
    limits: options.limits ?? new MemoryCodeStore(),
    clock,
    ...(options.newCode === undefined ? {} : { newCode: options.newCode }),
  });
  const door = new FakeAccessController();
  const t = setup({
    clock,
    adapters: { access: { lobby: door, keypad: codes.controller }, accessSigner },
    config: gateConfig((c) => {
      c.modules.gate = { settings: { targets: [...structuredClone(targets), keypadTarget] } };
      c.flows["code-entry"] = { steps: [verify as never, { type: "gate.grant", target: "side-door", lifetimeSeconds: 600 }] };
    }),
  });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, clock, door, codes, texts, store, accessSigner };
}

type CodesSetup = ReturnType<typeof codesSetup>;

async function codeCall(t: CodesSetup, locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ flow: "code-entry", locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

const textedCode = (t: CodesSetup, i = -1) => TEXT.exec(t.texts.sent.at(i)!.body)![1]!;
const codeEvents = async (t: CodesSetup) => (await accessEvents(t as never)).map(([event, detail]) => [event, detail as Record<string, unknown>] as const);
const codeGrants = (t: CodesSetup, callId: string) => t.engine.accessGrants(callId);

describe("gate: one-time access codes", () => {
  it("texts a code to the number on file and redeems it once, for the grant it stands for", async () => {
    const t = codesSetup();
    const callId = await codeCall(t);
    assert.deepEqual(await t.codes.issue(t.engine, callId), { grantId: "acc_1", status: "delivered", confirmed: false });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");
    assert.equal(t.door.received.length, 0, "no door was asked");
    const [text] = t.texts.sent;
    assert.equal(text!.to, PHONE_ON_FILE);
    assert.equal(text!.purpose, "one_time_code");
    assert.equal(TEXT.exec(text!.body)![2], "10");
    const code = textedCode(t);
    // The code is in the text and nowhere else.
    assert.ok(!JSON.stringify(await t.ledger.list()).includes(code));
    const digest = (await codeGrants(t, callId))[0]!.digest!;
    assert.deepEqual(await codeEvents(t), [
      ["access.issued", { grantId: "acc_1", target: "side-door", controller: "keypad", scope: "entry.open", level: 2, verificationGrantId: "grant_1", expiresAt: "2026-01-01T00:10:00.000Z" }],
      ["access.delivered", { grantId: "acc_1", digest, confirmed: false, kid: "gate-key-1" }],
    ]);

    assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code: code === "00000000" ? "00000001" : "00000000" }), { ok: false });
    t.clock.advance(9 * 60_000);
    const redeemed = await t.codes.redeem({ ...keypadDoor, code });
    assert.ok(redeemed.ok);
    const check = verifyAccessGrant(redeemed.grant, t.engine.accessKeys(), { workspaceId: "ws_test", audience: "keypad", now: t.clock.now() });
    assert.ok(check.ok);
    assert.equal(check.body.grantId, "acc_1");
    assert.equal(check.body.target, "keypad-1");
    assert.equal(accessGrantDigest(check.body), digest, "the very grant Gate issued");
    assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code }), { ok: false }, "single use");
  });

  it("stores only a keyed hash of the code, with the unsigned grant", async () => {
    const put: AccessCodeEntry[] = [];
    const store = new (class extends MemoryAccessCodeStore {
      override async put(entry: AccessCodeEntry, now: Date): Promise<boolean> {
        put.push(structuredClone(entry));
        return super.put(entry, now);
      }
    })();
    const t = codesSetup({ store });
    const callId = await codeCall(t);
    await t.codes.issue(t.engine, callId);
    const code = textedCode(t);
    const [entry] = put;
    assert.deepEqual(Object.keys(entry!).sort(), ["body", "callId", "digest", "grantId", "workspaceId"]);
    assert.equal(entry!.digest, accessCodeDigest(CODE_KEY, keypadDoor, code));
    assert.ok(!JSON.stringify(entry).includes(code));
    assert.ok(!("signature" in entry!.body));
  });

  it("binds a code to its workspace, its controller, its door and its grant's lifetime, in French too", async () => {
    const t = codesSetup();
    const callId = await codeCall(t, "fr");
    await t.codes.issue(t.engine, callId);
    const match = /^Votre code de porte, à usage unique : (\d{8})\. Valable une fois, dans les 10 min\.$/.exec(t.texts.sent[0]!.body);
    const code = match![1]!;
    for (const door of [{ ...keypadDoor, workspaceId: "ws_other" }, { ...keypadDoor, audience: "lobby" }, { ...keypadDoor, target: "door-1" }]) {
      assert.deepEqual(await t.codes.redeem({ ...door, code }), { ok: false });
    }
    for (const bad of [null, 12345678, "1".repeat(33)]) assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code: bad as never }), { ok: false });
    t.clock.advance(10 * 60_000);
    assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code }), { ok: false }, "expired with its grant");
  });

  it("never outlives the verification grant", async () => {
    const t = codesSetup();
    const callId = await codeCall(t);
    t.clock.advance(14 * 60_000 + 30_000);
    await t.codes.issue(t.engine, callId);
    assert.equal(TEXT.exec(t.texts.sent[0]!.body)![2], "1");
    assert.equal((await codeGrants(t, callId))[0]!.expiresAt, "2026-01-01T00:15:00.000Z");
  });

  it("revokes a code before its end, and revoking one already gone is success", async () => {
    const t = codesSetup();
    const callId = await codeCall(t);
    await t.codes.issue(t.engine, callId);
    const code = textedCode(t);
    await t.codes.revoke("ws_test", "acc_1");
    await t.codes.revoke("ws_test", "acc_1");
    await t.codes.revoke("ws_other", "acc_9");
    assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code }), { ok: false });
  });

  it("counts against VER-2's send limits in the same CodeStore texted codes use, and a limited send texts nothing", async () => {
    const limits = new MemoryCodeStore();
    const t = codesSetup({ limits });
    const callId = await codeCall(t);
    const { subjectKey } = await t.engine.numberOnFile(callId);
    // A texted code (VER-2) to the same subject a moment ago, counted the way VER-2 counts it, in the same store.
    const subject = { scope: "subject", key: subjectKey } as const;
    assert.equal(await limits.take({ workspaceId: "ws_test", key: subject, at: t.clock.now().toISOString(), ...ACCESS_CODE_SEND_LIMITS }), true);
    assert.deepEqual(await t.codes.issue(t.engine, callId), { grantId: "acc_1", status: "refused", confirmed: false });
    assert.equal(t.texts.sent.length, 0);
    const digest = (await codeGrants(t, callId))[0]!.digest!;
    assert.deepEqual((await codeEvents(t)).at(-1), ["access.refused", { grantId: "acc_1", digest, reason: "send_limit", kid: "gate-key-1" }]);
    t.clock.advance(60_000);
    assert.equal((await t.codes.issue(t.engine, callId)).status, "delivered");
    // The access code counted too: a texted code right after it is refused.
    assert.equal(await limits.take({ workspaceId: "ws_test", key: subject, at: t.clock.now().toISOString(), ...ACCESS_CODE_SEND_LIMITS }), false);
  });

  it("uses VER-2's subject limits: 5 sends in 24 hours, 60 seconds apart, per workspace and key", async () => {
    assert.deepEqual(ACCESS_CODE_SEND_LIMITS, { max: 5, windowSeconds: 86_400, minIntervalSeconds: 60 });
    const limits = new MemoryCodeStore();
    const at = (s: number) => new Date(Date.parse("2026-01-01T00:00:00.000Z") + s * 1000).toISOString();
    const send = (key: string, s: number, scope: "subject" | "number" = "subject") => limits.take({ workspaceId: "ws_test", key: { scope, key }, at: at(s), ...ACCESS_CODE_SEND_LIMITS });
    assert.equal(await send("a", 0), true);
    assert.equal(await send("a", 59), false);
    assert.equal(await send("b", 59), true, "per key");
    assert.equal(await send("a", 59, "number"), true, "per scope");
    for (const s of [60, 120, 180, 240]) assert.equal(await send("a", s), true);
    assert.equal(await send("a", 300), false, "the sixth in a day");
    assert.equal(await send("a", 86_400), true, "a day after the first");
  });

  it("takes the code back when its text fails, and records unknown when that cannot prove it unused", async () => {
    const failing: MessageSender = {
      sendText: async () => {
        throw new Error("the carrier is down");
      },
    };
    const t = codesSetup({ messages: failing, newCode: () => "24681357" });
    const callId = await codeCall(t);
    assert.deepEqual(await t.codes.issue(t.engine, callId), { grantId: "acc_1", status: "refused", confirmed: false });
    assert.equal((await codeEvents(t)).at(-1)![1].reason, "text_failed");
    assert.deepEqual(await t.codes.redeem({ ...keypadDoor, code: "24681357" }), { ok: false });

    const stuck = new (class extends MemoryAccessCodeStore {
      override async take(): Promise<AccessCodeEntry | null> {
        throw new Error("the store is down");
      }
    })();
    const u = codesSetup({ messages: failing, store: stuck });
    const other = await codeCall(u);
    assert.deepEqual(await u.codes.issue(u.engine, other), { grantId: "acc_1", status: "unknown", confirmed: false });
  });

  it("records unknown, not refused, when the text arrived and the code was redeemed before the send failed", async () => {
    let codes: AccessCodes | null = null;
    let redeemed: Awaited<ReturnType<AccessCodes["redeem"]>> | null = null;
    const lateFailure: MessageSender = {
      sendText: async (input) => {
        // The text reached the phone and the code was used at the door; then the carrier's answer was lost.
        redeemed = await codes!.redeem({ ...keypadDoor, code: TEXT.exec(input.body)![1]! });
        throw new Error("the answer was lost");
      },
    };
    const t = codesSetup({ messages: lateFailure });
    codes = t.codes;
    const callId = await codeCall(t);
    assert.deepEqual(await t.codes.issue(t.engine, callId), { grantId: "acc_1", status: "unknown", confirmed: false });
    assert.ok(redeemed!.ok, "the door may have opened");
    assert.equal((await codeEvents(t)).at(-1)![0], "access.unknown");
  });

  it("keeps a code redeemable when signing fails, and never signs one used or revoked meanwhile", async () => {
    const t = codesSetup({ newCode: () => "11112222" });
    const callId = await codeCall(t);
    await t.codes.issue(t.engine, callId);
    const sign = t.accessSigner.sign.bind(t.accessSigner);
    t.accessSigner.sign = async () => {
      throw new Error("the key store is down");
    };
    await assert.rejects(t.codes.redeem({ ...keypadDoor, code: "11112222" }), /key store is down/);
    t.accessSigner.sign = sign;
    assert.ok((await t.codes.redeem({ ...keypadDoor, code: "11112222" })).ok, "the code survived the failed signature");

    // Revoked while it was being signed: refused, and the signature is dropped.
    const u = codesSetup({ newCode: () => "33334444" });
    const second = await codeCall(u);
    await u.codes.issue(u.engine, second);
    u.accessSigner.sign = async (payload) => {
      await u.codes.revoke("ws_test", "acc_1");
      return sign(payload);
    };
    assert.deepEqual(await u.codes.redeem({ ...keypadDoor, code: "33334444" }), { ok: false });

    // Expired while it was being signed.
    const v = codesSetup({ newCode: () => "55556666" });
    const third = await codeCall(v);
    await v.codes.issue(v.engine, third);
    v.accessSigner.sign = async (payload) => {
      v.clock.advance(10 * 60_000);
      return sign(payload);
    };
    assert.deepEqual(await v.codes.redeem({ ...keypadDoor, code: "55556666" }), { ok: false });

    // Replaced by another grant's code under the same digest meanwhile: that grant was never signed, so refused.
    const swapped = new (class extends MemoryAccessCodeStore {
      override async take(workspaceId: string, digest: string): Promise<AccessCodeEntry | null> {
        const entry = await super.take(workspaceId, digest);
        return entry === null ? null : { ...entry, grantId: "acc_other" };
      }
    })();
    const w = codesSetup({ store: swapped, newCode: () => "77778888" });
    const fourth = await codeCall(w);
    await w.codes.issue(w.engine, fourth);
    assert.deepEqual(await w.codes.redeem({ ...keypadDoor, code: "77778888" }), { ok: false });
  });

  it("tries a new code when one is live for the same door, and frees a code once its grant expired", async () => {
    const t = codesSetup({ newCode: () => "12345678" });
    const first = await codeCall(t);
    assert.equal((await t.codes.issue(t.engine, first)).status, "delivered");
    const second = await codeCall(t);
    t.clock.advance(60_000);
    assert.deepEqual(await t.codes.issue(t.engine, second), { grantId: "acc_2", status: "refused", confirmed: false });
    assert.equal((await codeEvents(t)).at(-1)![1].reason, "no_free_code");
    assert.equal(t.texts.sent.length, 1);
    t.clock.advance(10 * 60_000);
    const third = await codeCall(t);
    assert.equal((await t.codes.issue(t.engine, third)).status, "delivered");
    assert.equal((t.store as MemoryAccessCodeStore).size, 1, "the expired code was dropped");
  });

  it("texts only for its own issue calls, each for its own call", async () => {
    const t = codesSetup({ limits: { take: async () => true } });
    const callId = await codeCall(t);
    assert.deepEqual(await t.engine.grantAccess(callId), { grantId: "acc_1", status: "refused", confirmed: false });
    assert.equal((await codeEvents(t)).at(-1)![1].reason, "not_requested");
    assert.equal(t.texts.sent.length, 0);
    const a = await codeCall(t);
    const b = await codeCall(t);
    const results = await Promise.all([t.codes.issue(t.engine, a), t.codes.issue(t.engine, b)]);
    assert.deepEqual(results.map((r) => r.status), ["delivered", "delivered"]);
    const keys = t.texts.sent.map((s) => s.messageId);
    assert.equal(new Set(keys).size, 2);
    assert.deepEqual((await codeGrants(t, a)).map((g) => g.status), ["delivered"]);
    assert.deepEqual((await codeGrants(t, b)).map((g) => g.status), ["delivered"]);
  });

  it("texts each code to its own call's number when two workspaces hand out the same grant id at once", async () => {
    const t = codesSetup();
    const OTHER_PHONE = "+15555550199";
    const u = createTestEngine({
      workspaceId: "ws_other",
      clock: t.clock,
      adapters: { access: { keypad: t.codes.controller }, accessSigner: t.accessSigner },
      config: gateConfig((c) => {
        c.modules.gate = { settings: { targets: [keypadTarget] } };
        c.flows = {};
        c.flows["code-entry"] = { steps: [verify as never, { type: "gate.grant", target: "side-door", lifetimeSeconds: 600 }] };
      }),
    });
    u.records.putSubject("ws_other", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: OTHER_PHONE, knowledge: { dob: DOB } }));
    u.carrier.set(OTHER_PHONE, { identityMatch: "match" });
    const mine = await codeCall(t);
    const theirs = await codeCall(u as never);
    // Both engines' first grant is acc_1, and both are in flight together; the other workspace's issue started first.
    const [other, own] = await Promise.all([t.codes.issue(u.engine, theirs), t.codes.issue(t.engine, mine)]);
    assert.deepEqual([other.grantId, own.grantId, other.status, own.status], ["acc_1", "acc_1", "delivered", "delivered"]);
    assert.deepEqual(t.texts.sent.map((m) => m.to).sort(), [OTHER_PHONE, PHONE_ON_FILE].sort());
    const toOther = t.texts.sent.find((m) => m.to === OTHER_PHONE)!;
    assert.ok((await t.codes.redeem({ ...keypadDoor, workspaceId: "ws_other", code: TEXT.exec(toOther.body)![1]! })).ok, "the other workspace's code is its own");
  });

  it("refuses before a keypad match, without entry.open, and with a short key", async () => {
    const t = codesSetup();
    const { callId } = await t.engine.startCall({ flow: "code-entry" });
    await assert.rejects(t.engine.numberOnFile(callId), rejects("precondition_failed"));
    await assert.rejects(t.codes.issue(t.engine, callId), rejects("precondition_failed"));
    const open = await t.engine.startCall({});
    await assert.rejects(t.codes.issue(t.engine, open.callId, { target: "side-door" }), rejects("scope_denied"));
    assert.equal(t.texts.sent.length, 0);
    const parts = { signer: generateTestSigner(), store: new MemoryAccessCodeStore(), messages: t.texts, limits: new MemoryCodeStore() };
    assert.throws(() => accessCodes({ key: "short", ...parts }), /at least 16 bytes/);
    assert.ok(accessCodes({ key: new Uint8Array(16), ...parts }) instanceof AccessCodes);
  });
});
