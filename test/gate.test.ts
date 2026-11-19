// Gate (GAT-1): signed, time-limited access grants after verification, delivered once through an
// AccessController, and every grant and outcome in the ledger.
import { strict as assert } from "node:assert";
import { createPublicKey, generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { validateConfig } from "../src/core/config.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { hmacSha256Hex, sha256Hex } from "../src/core/hash.ts";
import { canonicalJson } from "../src/core/canonical.ts";
import { SeenGrants, accessGrantDigest, verifyAccessGrant, type AccessGrantBody, type SignedAccessGrant } from "../src/gate/access.ts";
import { GateModule, gateModule, type GateHost, type GateSlice } from "../src/gate/gate.ts";
import { builtInModules } from "../src/modules.ts";
import { keyPairSigner } from "../src/prove/receipt.ts";
import { StepUpModule, stepUpAcr, stepUpModule, stepUpSubject, type StepUpHost, type StepUpSlice } from "../src/gate/step-up.ts";
import { FakeAccessController, TEST_KNOWLEDGE_KEY, generateTestSigner } from "../src/testing/index.ts";
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

    const c2 = await verified(t, null);
    t.door.unlock = async (input) => {
      await t.engine.endCall(c2);
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, c2, { target: "front-door" })).status, "delivered");
    assert.equal((await slice(t, c2)).grants[0]!.status, "delivered");
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
      await t.engine.recordModuleOutcome(raced, "gate", open!, (s, call) => {
        const sl = s as unknown as GateSlice;
        sl.grants[0]!.status = "unknown";
        call.release();
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
    // A grant in flight when the call ends still records its answer: that is the reservation's purpose.
    const c2 = await verified(t, null);
    const unlock = t.door.unlock.bind(t.door);
    t.door.unlock = async (input) => {
      await t.engine.endCall(c2);
      return unlock(input);
    };
    assert.equal((await t.gate.grantAccess(t.engine, c2, { target: "front-door" })).status, "delivered");
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
          fn(await real.moduleState(c, n), { authorized: () => true, now: t.clock.now().toISOString(), emit: () => undefined, release: () => undefined } as never);
          await real.recordModuleOutcome(c, n, r, (s, call) => {
            (s as unknown as GateSlice).grants.find((g) => g.grantId === r)!.status = "unknown";
            call.release();
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
    const constructorModule = {
      manifest: { name: "constructor", version: "1", summary: "x", provides: { factors: [], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
      validateSettings: () => [],
      requiredAdapters: () => [],
      validateStep: () => [],
      initCall: () => ({}),
      enterStep: () => null,
      stepStatus: () => "pending" as const,
    };
    // Not a reserved name (only core, engine, flow and module are), and an inherited property of every object.
    t.engine.use(constructorModule);
    t.engine.configure(testConfig((c) => ((c.modules as Record<string, unknown>)["constructor"] = {})));
    const { callId } = await t.engine.startCall();
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), []);
    await assert.rejects(t.engine.recordModuleOutcome(callId, "constructor", "r1", (s) => s), rejects("precondition_failed"));
    await t.engine.updateModule(callId, "constructor", (s, call) => (call.reserve("r1"), s));
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), ["r1"]);
    await t.engine.recordModuleOutcome(callId, "constructor", "r1", (s, call) => (call.release(), s));
    assert.deepEqual(await t.engine.moduleReservations(callId, "constructor"), []);
  });

  it("opens reservations only in updateModule and closes them only in recordModuleOutcome", async () => {
    const t = gateSetup();
    const callId = await verified(t, null);
    await assert.rejects(t.engine.updateModule(callId, "gate", (s, call) => (call.release(), s)), rejects("precondition_failed", /only recordModuleOutcome/));
    await assert.rejects(t.engine.updateModule(callId, "gate", (s, call) => (call.reserve(""), s)), rejects("invalid_input"));
    await t.engine.updateModule(callId, "gate", (s, call) => (call.reserve("r1"), call.reserve("r1"), call.reserve("r2"), s));
    assert.deepEqual(await t.engine.moduleReservations(callId, "gate"), ["r1", "r2"]);
    await assert.rejects(t.engine.recordModuleOutcome(callId, "gate", "r1", (s, call) => (call.reserve("r3"), s)), rejects("precondition_failed", /only updateModule/));
    await t.engine.recordModuleOutcome(callId, "gate", "r1", (s, call) => (call.release(), s));
    assert.deepEqual(await t.engine.moduleReservations(callId, "gate"), ["r2"]);
    await t.engine.recordModuleOutcome(callId, "gate", "r2", (s, call) => (call.release(), s));
    assert.deepEqual(await t.engine.moduleReservations(callId, "gate"), []);
    await assert.rejects(t.engine.recordModuleOutcome(callId, "gate", "r2", (s) => s), rejects("precondition_failed"), "closed: refused");
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

// Web sign-in step-up (GAT-4): a short-lived ES256 JWT, bound to the site's nonce, the verified
// subject and the call's verification grant, exchanged once by the host's web sign-in.
const ISSUER = "https://verify.example.test";
const PORTAL = "https://portal.example.test";
const NONCE = "482913";
const SUBJECT_KEY = hmacSha256Hex(TEST_KNOWLEDGE_KEY, `subject:${ACCOUNT}`);
const webVerify = { ...verify, scopes: ["entry.sign_in"] };
const sites = [
  { id: "portal", audience: PORTAL },
  { id: "shop", audience: "shop-client-1" },
];

function stepUpConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["entry.sign_in"] = 2;
    c.modules["step-up"] = { settings: { sites: structuredClone(sites) } };
    c.flows = { web: { steps: [webVerify as never, { type: "step-up.issue", site: "portal" }] } };
    patch(c);
  });
}

function stepUpSetup(options: { patch?: (c: FlowConfig) => void; signer?: ReturnType<typeof generateTestSigner> } = {}) {
  const stepUp = stepUpModule({ signer: options.signer ?? generateTestSigner("step-up-key-1"), issuer: ISSUER });
  const t = setup({ modules: [stepUp], config: stepUpConfig(options.patch) });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, stepUp };
}

async function webVerified(t: ReturnType<typeof stepUpSetup>, flow: string | null = "web"): Promise<string> {
  const { callId } = await t.engine.startCall(flow === null ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
const stepUpSlice = async (t: ReturnType<typeof stepUpSetup>, callId: string) => (await t.engine.moduleState(callId, "step-up")) as unknown as StepUpSlice;
const stepUpEvents = async (t: ReturnType<typeof stepUpSetup>) =>
  (await t.ledger.list()).filter((e) => e.event === "module.event" && e.detail.module === "step-up").map((e) => [e.detail.event, e.detail.detail] as const);
const portal = { audience: PORTAL, subjectKey: SUBJECT_KEY, nonce: NONCE };
/** A compact token with these claims and a junk signature: the shape of a step-up token, never one the engine issued. */
const forged = (claims: unknown) => `${Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln`;

describe("step-up: config", () => {
  const registry = (m: StepUpModule) => new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer"], modules: [...builtInModules(), m] });
  const stepUp = stepUpModule({ signer: generateTestSigner(), issuer: ISSUER });

  it("needs an https issuer", () => {
    for (const issuer of ["http://verify.example.test", "https://verify.example.test/?x=1", "https://user@verify.example.test", "https://", 7]) {
      assert.throws(() => stepUpModule({ signer: generateTestSigner(), issuer: issuer as never }), rejects("invalid_input", /https URL/), String(issuer));
    }
    assert.ok(stepUpModule({ signer: generateTestSigner(), issuer: "https://verify.example.test/ws_test" }) instanceof StepUpModule);
  });

  it("checks every step-up setting", () => {
    assert.deepEqual(stepUp.validateSettings({ sites, maxTokensPerCall: 5 }), []);
    assert.deepEqual(stepUp.validateSettings(null), ["must be an object with the sites"]);
    assert.deepEqual(stepUp.validateSettings({ sites: [], maxTokensPerCall: 0, x: 1 }), [
      "x is not a step-up setting",
      "maxTokensPerCall must be an integer from 1 to 5",
      "sites must list at least one site",
    ]);
    const sparse: unknown[] = [];
    sparse[1] = sites[0];
    assert.deepEqual(stepUp.validateSettings({ sites: sparse }), ["sites must list at least one site"], "a hole is not a site");
    assert.deepEqual(stepUp.validateSettings({ sites: ["portal", { id: "Portal", audience: "a b", y: 1 }, { id: "a", audience: "x".repeat(201) }, { id: "a", audience: 1 }] }), [
      "sites[0] must be { id, audience }",
      "sites[1].y is not a site field",
      "sites[1].id must be lower-case letters, digits and hyphens, at most 64",
      "sites[1].audience must be 1 to 200 characters, no spaces",
      "sites[2].audience must be 1 to 200 characters, no spaces",
      "sites[3].audience must be 1 to 200 characters, no spaces",
      "two sites have the same id",
    ]);
  });

  it("checks step-up.issue steps, and holds them to entry.sign_in at level 2", () => {
    const problems = (c: FlowConfig) => validateConfig(c, registry(stepUp));
    assert.deepEqual(problems(stepUpConfig()), []);
    const step = (s: Record<string, unknown>) => problems(stepUpConfig((c) => (c.flows = { web: { steps: [webVerify as never, s as never] } })));
    assert.deepEqual(step({ type: "step-up.issue", site: "shop", lifetimeSeconds: 300 }), []);
    assert.deepEqual(step({ type: "step-up.issue", site: "bank", lifetimeSeconds: 119, x: 1 }), [
      "flows.web.steps[1] (step-up.issue): x is not a field of this step",
      "flows.web.steps[1] (step-up.issue): lifetimeSeconds must be an integer from 120 to 300",
      "flows.web.steps[1] (step-up.issue): no site bank in the step-up settings",
    ]);
    assert.deepEqual(step({ type: "step-up.issue", lifetimeSeconds: 301 }), [
      "flows.web.steps[1] (step-up.issue): lifetimeSeconds must be an integer from 120 to 300",
      "flows.web.steps[1] (step-up.issue): site must name a site in the step-up settings",
    ]);
    assert.deepEqual(problems(stepUpConfig((c) => (c.modules["step-up"] = { settings: { sites: [] } }))), ["modules.step-up.settings: sites must list at least one site"]);
    assert.deepEqual(problems(stepUpConfig((c) => (c.policy.scopes["entry.sign_in"] = 1))), ["policy: scope entry.sign_in is access, and below its floor of level 2"]);
    assert.deepEqual(
      problems(stepUpConfig((c) => (c.flows = { web: { steps: [{ ...webVerify, scopes: ["payment.request"] } as never, { type: "step-up.issue", site: "portal" }] } }))),
      ["flows.web.steps[1] (step-up.issue): needs the scope entry.sign_in, which the last verification step does not grant"],
    );
  });

  it("keeps the sites a call started with when the config changes", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    t.engine.configure(
      stepUpConfig((c) => {
        c.modules["step-up"] = { settings: { sites: [{ id: "bank", audience: "bank-1" }] } };
        c.flows = { bank: { steps: [webVerify as never, { type: "step-up.issue", site: "bank" }] } };
      }),
    );
    await assert.rejects(t.engine.startFlow(callId, "bank"), rejects("precondition_failed", /no site bank/));
  });
});

describe("step-up: tokens", () => {
  it("runs a web flow: an ES256 JWT for an OpenID Connect acr step-up, checked against the JWKS, exchanged once", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    t.clock.advance(1_500);
    const issued = await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE });
    assert.deepEqual({ ...issued, token: "" }, { token: "", tokenId: "stu_1", expiresAt: "2026-01-01T00:02:01.000Z" });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");

    const [header, payload, signature] = issued.token.split(".") as [string, string, string];
    assert.deepEqual(decode(header), { alg: "ES256", kid: "step-up-key-1", typ: "JWT" });
    const claims = {
      iss: ISSUER,
      aud: PORTAL,
      sub: stepUpSubject(SUBJECT_KEY, PORTAL),
      iat: 1767225601,
      exp: 1767225721,
      auth_time: 1767225600,
      jti: "stu_1",
      acr: "urn:district-assurance:level:2",
      nonce: NONCE,
      sid: callId,
      grant: "grant_1",
    };
    assert.deepEqual(decode(payload), claims);
    assert.equal(claims.acr, stepUpAcr(2));
    assert.notEqual(stepUpSubject(SUBJECT_KEY, "shop-client-1"), claims.sub, "a handle per site");
    // What any JOSE library does with the JWKS: find the key by kid, check ES256 over header.payload.
    const jwks = t.stepUp.keys();
    assert.deepEqual(jwks.keys.map((k) => [k.kid, k.alg, k.use, k.kty, k.crv]), [["step-up-key-1", "ES256", "sig", "EC", "P-256"]]);
    const key = createPublicKey({ key: jwks.keys.find((k) => k.kid === "step-up-key-1")!, format: "jwk" });
    assert.ok(cryptoVerify("sha256", Buffer.from(`${header}.${payload}`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature, "base64url")));
    assert.ok(!cryptoVerify("sha256", Buffer.from(`${header}.${payload}x`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature, "base64url")));

    // The call ended before the web sign-in got there: the token is still exchanged, once.
    await t.engine.endCall(callId);
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, issued.token, portal), { ok: true, claims });
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, issued.token, portal), { ok: false, reason: "unknown" }, "used once");

    const digest = sha256Hex(issued.token);
    assert.deepEqual(await stepUpEvents(t), [
      ["step_up.issued", { tokenId: "stu_1", site: "portal", scope: "entry.sign_in", level: 2, verificationGrantId: "grant_1", expiresAt: "2026-01-01T00:02:01.000Z" }],
      ["step_up.exchanged", { tokenId: "stu_1", digest, kid: "step-up-key-1" }],
    ]);
    const ledger = JSON.stringify(await t.ledger.list());
    assert.ok(!ledger.includes(NONCE) && !ledger.includes(signature) && !ledger.includes(claims.sub), "never the nonce, the token or the subject");
    assert.deepEqual((await stepUpSlice(t, callId)).tokens, [
      {
        tokenId: "stu_1",
        site: "portal",
        audience: PORTAL,
        subject: claims.sub,
        level: 2,
        verificationGrantId: "grant_1",
        authTime: "2026-01-01T00:00:00.000Z",
        issuedAt: "2026-01-01T00:00:01.000Z",
        expiresAt: "2026-01-01T00:02:01.000Z",
        status: "exchanged",
        digest,
        kid: "step-up-key-1",
      },
    ]);
    assert.ok(!JSON.stringify(await t.engine.moduleState(callId, "step-up")).includes(NONCE), "the call record keeps no nonce");
  });

  it("refuses without a verification grant covering entry.sign_in, or while a verification runs", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall({ flow: "web" });
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE }), rejects("precondition_failed", /on step badge.verify/));
    const open = await t.engine.startCall();
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, open.callId, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /entry.sign_in/));
    const tainted = await webVerified(t, null);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, tainted, { nonce: NONCE, site: "portal" }), rejects("scope_denied"));
    const expired = await webVerified(t, null);
    t.clock.advance(900_000);
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, expired, { nonce: NONCE, site: "portal" }), rejects("scope_denied"));
    // Verified, then a new verification started (maybe for another account): its subject is not the grant's.
    const again = await webVerified(t, null);
    await t.engine.beginVerification(again, { accountNumber: "99999999" });
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, again, { nonce: NONCE, site: "portal" }), rejects("precondition_failed", /verification is running/));
    assert.deepEqual(await stepUpEvents(t), []);
  });

  it("takes the site from the step in a flow and from the host outside one, and the nonce always from the keypad", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { sites: structuredClone(sites), maxTokensPerCall: 2 }) });
    const inFlow = await webVerified(t);
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, inFlow, { nonce: NONCE, site: "shop" }), rejects("invalid_input", /pass only the nonce/));
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, inFlow, { nonce: NONCE, lifetimeSeconds: 300 }), rejects("invalid_input", /pass only the nonce/));
    for (const nonce of ["12345", "1234567890123", "48291a", 482913]) {
      await assert.rejects(t.stepUp.issueStepUpToken(t.engine, inFlow, { nonce: nonce as never }), (e: unknown) => rejects("invalid_input", /6 to 12 digits/)(e) && !String(e).includes(String(nonce)));
    }
    const outside = await webVerified(t, null);
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE }), rejects("invalid_input", /site is required/));
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE, site: "bank" }), rejects("invalid_input", /no site bank/));
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE, site: "shop", lifetimeSeconds: 600 }), rejects("invalid_input", /lifetimeSeconds/));
    const shop = await t.stepUp.issueStepUpToken(t.engine, outside, { nonce: "123456789012", site: "shop", lifetimeSeconds: 300 });
    assert.equal(shop.expiresAt, "2026-01-01T00:05:00.000Z");
    assert.equal(decode(shop.token.split(".")[1]!).aud, "shop-client-1");
    await t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE, site: "portal" });
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE, site: "portal" }), rejects("precondition_failed", /every step-up token/));
  });

  it("never outlives the verification grant", async () => {
    const t = stepUpSetup({ patch: (c) => (c.flows.web!.steps[1] = { type: "step-up.issue", site: "portal", lifetimeSeconds: 300 }) });
    const callId = await webVerified(t);
    t.clock.advance(800_500);
    const issued = await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE });
    assert.equal(issued.expiresAt, "2026-01-01T00:15:00.000Z", "the verification grant's own expiry");
    assert.equal(decode(issued.token.split(".")[1]!).exp, Date.parse("2026-01-01T00:15:00.000Z") / 1000);
  });

  it("refuses an exchange after the call is tainted, and that uses the token up", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    const { token } = await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, token, portal), { ok: false, reason: "tainted" });
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, token, portal), { ok: false, reason: "unknown" });
    assert.deepEqual((await stepUpEvents(t)).at(-1), ["step_up.refused", { tokenId: "stu_1", digest: sha256Hex(token), reason: "tainted" }]);
    assert.equal((await stepUpSlice(t, callId)).tokens[0]!.status, "refused");
  });

  it("refuses an expired token, and one for another site, subject or nonce, each using it up", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { sites: structuredClone(sites), maxTokensPerCall: 5 }) });
    const callId = await webVerified(t, null);
    const issue = async () => (await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE, site: "portal" })).token;
    const expired = await issue();
    t.clock.advance(119_000);
    const live = [await issue(), await issue(), await issue()];
    t.clock.advance(1_000);
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, expired, portal), { ok: false, reason: "expired" });
    for (const [i, wrong] of [{ audience: "shop-client-1" }, { subjectKey: "a".repeat(64) }, { nonce: "482914" }].entries()) {
      assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, live[i]!, { ...portal, ...wrong }), { ok: false, reason: "mismatch" }, JSON.stringify(wrong));
      assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, live[i]!, portal), { ok: false, reason: "unknown" }, "the first refusal used it up");
    }
    const fresh = await issue();
    assert.equal((await t.stepUp.exchangeStepUpToken(t.engine, fresh, portal)).ok, true);
    assert.deepEqual((await stepUpSlice(t, callId)).tokens.map((s) => s.status), ["refused", "refused", "refused", "refused", "exchanged"]);
  });

  it("refuses a token whose call was verified again since", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { sites: structuredClone(sites), maxTokensPerCall: 5 }) });
    const callId = await webVerified(t, null);
    const first = (await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE, site: "portal" })).token;
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, first, portal), { ok: false, reason: "not_authorized" }, "a new grant");
    const second = (await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE, site: "portal" })).token;
    assert.equal(decode(second.split(".")[1]!).grant, "grant_2");
    // Verified again and failed: the call holds no grant.
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, second, portal), { ok: false, reason: "not_authorized" });
  });

  it("refuses anything that is not a token this call issued, without using up the real one", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t, null);
    const { token } = await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE, site: "portal" });
    for (const bad of [null, 7, "a.b", "a.b.c.d", forged({ sid: callId, jti: "stu_1" }), forged({ sid: callId, jti: 1, nonce: NONCE }), forged([]), "a.bm90IGpzb24.c"]) {
      assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, bad, portal), { ok: false, reason: "malformed" }, String(bad));
    }
    const claims = decode(token.split(".")[1]!);
    for (const bad of [forged(claims), forged({ ...claims, sid: "call_unknown" }), forged({ ...claims, jti: "stu_9" }), `${token.slice(0, -2)}AA`]) {
      assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, bad, portal), { ok: false, reason: "unknown" });
    }
    // A reservation the module never made a token for (a host's own write): still not a token.
    await t.engine.updateModule(callId, "step-up", (s, call) => (call.reserve("stu_x"), s));
    assert.deepEqual(await t.stepUp.exchangeStepUpToken(t.engine, forged({ ...claims, jti: "stu_x" }), portal), { ok: false, reason: "unknown" });
    assert.deepEqual(await t.engine.moduleReservations(callId, "step-up"), ["stu_1", "stu_x"], "nothing was settled");
    assert.equal((await t.stepUp.exchangeStepUpToken(t.engine, token, portal)).ok, true, "the real token was never used up");
  });

  it("throws a failed write as it is", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    const { token } = await t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE });
    const down: StepUpHost = { updateModule: (c, n, fn) => t.engine.updateModule(c, n, fn), recordModuleOutcome: () => Promise.reject(new Error("store down")) };
    await assert.rejects(t.stepUp.exchangeStepUpToken(down, token, portal), /store down/);
    assert.equal((await t.stepUp.exchangeStepUpToken(t.engine, token, portal)).ok, true);
  });

  it("fails a token whose signing failed, hands out nothing, and fails the step at the limit", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let broken = true;
    const t = stepUpSetup({
      signer: { ...signer, sign: (payload) => (broken ? Promise.reject(new Error("kms down")) : signer.sign(payload)) },
      patch: (c) => (c.modules["step-up"]!.settings = { sites: structuredClone(sites), maxTokensPerCall: 2 }),
    });
    const callId = await webVerified(t);
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE }), /kms down/);
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, callId, { nonce: NONCE }), /kms down/);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed", "every token used, none valid");
    assert.deepEqual(await t.engine.moduleReservations(callId, "step-up"), []);
    assert.deepEqual((await stepUpEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["step_up.issued", null],
      ["step_up.failed", "signing"],
      ["step_up.issued", null],
      ["step_up.failed", "signing"],
    ]);
    broken = false;
    const outside = await webVerified(t, null);
    assert.equal((await t.stepUp.issueStepUpToken(t.engine, outside, { nonce: NONCE, site: "portal" })).tokenId, "stu_3");
  });

  it("issues nothing when the call was tainted, verified again or the token expired while it was signed", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let during: () => Promise<unknown> = async () => undefined;
    const t = stepUpSetup({ signer: { ...signer, sign: async (payload) => (await during(), signer.sign(payload)) } });
    const tainted = await webVerified(t, null);
    during = () => t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, tainted, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    const again = await webVerified(t, null);
    during = () => t.engine.beginVerification(again, { accountNumber: ACCOUNT });
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, again, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    const slow = await webVerified(t, null);
    during = async () => t.clock.advance(120_000);
    await assert.rejects(t.stepUp.issueStepUpToken(t.engine, slow, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /it expired/));
    for (const callId of [tainted, again, slow]) {
      assert.deepEqual((await stepUpSlice(t, callId)).tokens.map((s) => [s.status, s.digest]), [["failed", null]]);
      assert.deepEqual(await t.engine.moduleReservations(callId, "step-up"), []);
    }
    const reasons = (await stepUpEvents(t)).filter(([e]) => e === "step_up.failed").map(([, d]) => (d as { reason: string }).reason);
    assert.deepEqual(reasons, ["not_authorized", "not_authorized", "expired"]);
  });

  it("allows one token being signed per call", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let nested: Promise<unknown> | null = null;
    let call = { t: null as ReturnType<typeof stepUpSetup> | null, id: "" };
    const t = stepUpSetup({
      signer: {
        ...signer,
        sign: async (payload) => {
          nested ??= call.t!.stepUp.issueStepUpToken(call.t!.engine, call.id, { nonce: NONCE, site: "shop" });
          await assert.rejects(nested, rejects("precondition_failed", /being issued/));
          return signer.sign(payload);
        },
      },
    });
    call = { t, id: await webVerified(t, null) };
    assert.equal((await t.stepUp.issueStepUpToken(t.engine, call.id, { nonce: NONCE, site: "portal" })).tokenId, "stu_1");
    assert.ok(nested !== null);
  });
});
