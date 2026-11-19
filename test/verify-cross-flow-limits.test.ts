// VER-15: limits across flows. Failures in one flow count in every other, and flows that need a
// money, contact or access scope are limited per hour, per calling number and per subject.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, AttemptCounters } from "../src/core/adapters.ts";
import { ConfigError, validateConfig, type FlowConfig } from "../src/core/config.ts";
import { EngineError } from "../src/core/errors.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { builtInModules } from "../src/modules.ts";
import { FLOW_START, numberKeyFor } from "../src/verify/counters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig, waitOut } from "./helpers.ts";

const HOUR = 3_600_000;
const LONG_AGO = "2000-01-01T00:00:00.000Z";
const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const OTHER_ACCOUNT = "87654321";
const number = (n: number): string => `+1555555${String(n).padStart(4, "0")}`;
const startCounter = (scope: AttemptCounterKey["scope"], key: string): AttemptCounterKey => ({ workspaceId: "ws_test", factor: FLOW_START, scope, key });
const pay = { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" } as const;
const verify2 = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"] };

/** Flows for an owner's command, a status check, a payment, a door, and a level 2 verification with no listed scopes. */
function limitsConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"]] };
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopes["entry.open"] = 2;
    c.policy.scopeClasses = { "owner.command": "none" };
    c.flows = {
      "owner-command": { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] },
      status: { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] }] },
      deposit: { steps: [{ ...verify2, scopes: ["payment.request"] }, pay] },
      door: { steps: [{ ...verify2, scopes: ["entry.open"] }] },
      "verify-only": { steps: [verify2] },
    };
    patch(c);
  });
}

function limitsSetup(patch: (c: FlowConfig) => void = () => undefined, counters?: AttemptCounters): TestEngine {
  const t = setup({ config: limitsConfig(patch), ...(counters === undefined ? {} : { adapters: { counters } }) });
  t.records.putSubject("ws_test", { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, OTHER_ACCOUNT), phoneOnFile: "+15555550199", knowledge: {} });
  return t;
}

function withLimits(limits: { subject?: number; number?: number }): (c: FlowConfig) => void {
  return (c) => {
    (c.modules.badge!.settings as { lockout?: unknown }).lockout = { flowStartsPerHour: limits };
  };
}

/** The error a call to the engine threw. */
async function thrown(promise: Promise<unknown>): Promise<EngineError> {
  try {
    await promise;
  } catch (e) {
    assert.ok(e instanceof EngineError);
    return e;
  }
  assert.fail("expected a refusal");
}

async function lastEvent(t: TestEngine, name: string): Promise<Record<string, unknown> | undefined> {
  return (await t.ledger.list()).filter((e) => e.event === name).at(-1)?.detail;
}

/** Counters that remember every key they were asked about. */
class KeyedCounters extends MemoryAttemptCounters {
  readonly keys: AttemptCounterKey[] = [];

  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    this.keys.push(key);
    return super.get(key, since);
  }

  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    this.keys.push(key);
    return super.recordFailure(key, at, since);
  }
}

describe("failures count across flows (VER-15)", () => {
  it("counts a failure in one flow in every other: a status check, then a payment, then a door", async () => {
    const counters = new KeyedCounters();
    const t = limitsSetup(undefined, counters);
    const callingNumber = number(142);
    const flows = ["status", "deposit", "door"];
    for (let failures = 0; failures < 9; failures++) {
      waitOut(t);
      const { callId } = await t.engine.startCall({ flow: flows[failures % 3]!, callingNumber });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "1" }), { matched: false, locked: false }, `failure ${failures + 1}`);
      t.clock.advance(HOUR / 2);
    }
    const { callId: first } = await t.engine.startCall({ flow: "status" });
    await t.engine.beginVerification(first, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(first, { dob: "1" }), { matched: false, locked: true }, "the tenth, in a flow of its own, locks");
    const { callId: next } = await t.engine.startCall({ flow: "door" });
    await t.engine.beginVerification(next, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitKeypad(next, { dob: DOB }), { matched: false, locked: true }, "and holds in the door flow, even for the right answer");
    const locked = await lastEvent(t, "verification.locked");
    assert.deepEqual([locked?.kind, locked?.scope, locked?.hard], ["keypad_knowledge", "subject", true]);
    const factorKeys = counters.keys.filter((k) => k.factor !== FLOW_START);
    assert.ok(factorKeys.length > 0);
    for (const key of counters.keys) assert.deepEqual(Object.keys(key).sort(), ["factor", "key", "scope", "workspaceId"], "no flow, no call in a key");
    assert.deepEqual(new Set(factorKeys.map((k) => JSON.stringify(k))).size, 2, "one subject counter and one number counter, whatever the flow");
  });

  it("has no setting that separates them by flow or call", () => {
    const registry = new ModuleRegistry({ adapters: ["ledger", "records", "counters", "carrier", "identity", "messages", "payments", "signer"], modules: builtInModules() });
    const problems = (patch: (c: Record<string, any>) => void): string[] => {
      const c = limitsConfig() as unknown as Record<string, any>;
      patch(c);
      return validateConfig(c, registry);
    };
    assert.deepEqual(problems(() => undefined), []);
    assert.deepEqual(problems((c) => (c.modules.badge.settings.lockout = { perFlow: true })), ["modules.badge.settings: lockout.perFlow is not a lockout setting"]);
    assert.deepEqual(problems((c) => (c.modules.badge.settings.lockout = { perCall: true })), ["modules.badge.settings: lockout.perCall is not a lockout setting"]);
    assert.ok(problems((c) => (c.flows.deposit.lockout = {})).some((p) => p.startsWith("flows.deposit")));
    assert.deepEqual(problems((c) => (c.flows.door.steps[0].lockout = {})), ["flows.door.steps[0] (badge.verify): lockout is not a field of this step"]);
  });
});

describe("the hourly limit on flow starts (VER-15)", () => {
  it("checks the limits in Badge's lockout setting: 5 per subject and 10 per number are the most", () => {
    const registry = new ModuleRegistry({ adapters: ["ledger", "records", "counters", "carrier", "identity", "messages", "payments", "signer"], modules: builtInModules() });
    const at = (value: unknown) => validateConfig(limitsConfig(withLimits(value as never)), registry);
    assert.deepEqual(at({}), []);
    assert.deepEqual(at({ subject: 1, number: 10 }), []);
    assert.deepEqual(at({ subject: 6, number: 11 }), [
      "modules.badge.settings: lockout.flowStartsPerHour.subject must be 1 to 5",
      "modules.badge.settings: lockout.flowStartsPerHour.number must be 1 to 10",
    ]);
    assert.deepEqual(at({ subject: 0, number: 1.5 }), [
      "modules.badge.settings: lockout.flowStartsPerHour.subject must be 1 to 5",
      "modules.badge.settings: lockout.flowStartsPerHour.number must be 1 to 10",
    ]);
    assert.deepEqual(at({ flow: 1 }), ["modules.badge.settings: lockout.flowStartsPerHour.flow is not a scope: subject or number"]);
    assert.deepEqual(at("5"), ["modules.badge.settings: lockout.flowStartsPerHour must be an object"]);
  });

  it("never lifts a start limit with a pass: a pass forgets only its own factor's failures", async () => {
    const t = limitsSetup();
    const callingNumber = number(150);
    const { callId } = await t.engine.startCall({ flow: "deposit", callingNumber });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false }, "a pass");
    const numberKey = numberKeyFor(TEST_KNOWLEDGE_KEY, callingNumber);
    assert.equal((await t.counters.get(startCounter("subject", SUBJECT), LONG_AGO)).length, 1, "the subject's start stays counted");
    assert.equal((await t.counters.get(startCounter("number", numberKey), LONG_AGO)).length, 1, "the number's start stays counted");
  });

  it("allows 10 starts an hour per calling number, whatever their outcome, then refuses the same way and writes flow.rate_limited", async () => {
    const t = limitsSetup();
    const callingNumber = number(142);
    const numberKey = numberKeyFor(TEST_KNOWLEDGE_KEY, callingNumber);
    for (let i = 0; i < 10; i++) {
      const { callId } = await t.engine.startCall({ flow: i % 2 === 0 ? "deposit" : "door", callingNumber });
      if (i === 0) await t.engine.endCall(callId);
      t.clock.advance(60_000);
    }
    const refused = await thrown(t.engine.startCall({ callId: "call_refused", flow: "deposit", callingNumber }));
    assert.equal(refused.code, "rate_limited");
    assert.deepEqual(await t.engine.flowPosition("call_refused"), { flow: "deposit", revision: "default", status: "failed", index: 0, step: null });
    assert.deepEqual(await lastEvent(t, "flow.rate_limited"), { flow: "deposit", scope: "number" });
    await assert.rejects(t.engine.beginVerification("call_refused", { accountNumber: ACCOUNT }), rejects("precondition_failed", /has failed/));
    await assert.rejects(t.engine.startFlow("call_refused", "status"), rejects("precondition_failed", /already ran a flow/));
    assert.equal((await t.counters.get(startCounter("number", numberKey), LONG_AGO)).length, 10, "a refused start is not counted");

    const { callId: open } = await t.engine.startCall({ callingNumber });
    assert.equal((await thrown(t.engine.startFlow(open, "verify-only"))).message, refused.message, "a level 2 grant with no listed scopes reaches a payment: limited too");
    const { callId: status } = await t.engine.startCall({ flow: "status", callingNumber });
    assert.equal((await t.engine.flowPosition(status))!.status, "running", "a flow with no money, contact or access scope is not limited");
    await t.engine.startCall({ flow: "deposit", callingNumber: number(143) });

    t.clock.advance(HOUR - 10 * 60_000 - 1);
    await assert.rejects(t.engine.startCall({ flow: "deposit", callingNumber }), rejects("rate_limited"), "the first start is not yet an hour old");
    t.clock.advance(1);
    const { callId: later } = await t.engine.startCall({ flow: "deposit", callingNumber });
    assert.equal((await t.engine.flowPosition(later))!.status, "running");
    const ledger = JSON.stringify(await t.ledger.list());
    for (const value of [callingNumber, numberKey, SUBJECT]) assert.equal(ledger.includes(value), false, "never a value");
  });

  it("allows 5 starts an hour per subject once verification names one, from any number, then fails the flow with the same answer", async () => {
    const t = limitsSetup();
    for (let i = 0; i < 5; i++) {
      const { callId } = await t.engine.startCall({ flow: "deposit", callingNumber: number(i) });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.finishVerification(callId);
    }
    const stepUp = limitsSetup((c) => {
      c.flows["step-up"] = { steps: [{ type: "badge.verify", level: 1, factors: ["keypad_knowledge"], scopes: ["status.read"] }, { ...verify2, scopes: ["payment.request"] }] };
    });
    const { callId: restarted } = await stepUp.engine.startCall({ flow: "step-up", callingNumber: number(5) });
    await stepUp.engine.beginVerification(restarted, { accountNumber: ACCOUNT });
    await stepUp.engine.submitKeypad(restarted, { dob: DOB });
    await stepUp.engine.finishVerification(restarted);
    await stepUp.engine.beginVerification(restarted, { accountNumber: ACCOUNT });
    assert.equal((await stepUp.counters.get(startCounter("subject", SUBJECT), LONG_AGO)).length, 1, "a restart for the same subject is not counted twice");
    assert.equal((await t.counters.get(startCounter("subject", SUBJECT), LONG_AGO)).length, 5, "every start counts, whatever its outcome");
    const numberLimited = limitsSetup(withLimits({ number: 1 }));
    await numberLimited.engine.startCall({ flow: "door", callingNumber: number(1) });
    const byNumber = await thrown(numberLimited.engine.startCall({ flow: "door", callingNumber: number(1) }));

    const { callId } = await t.engine.startCall({ flow: "door", callingNumber: number(99) });
    const bySubject = await thrown(t.engine.beginVerification(callId, { accountNumber: ACCOUNT }));
    assert.deepEqual([bySubject.code, bySubject.message], [byNumber.code, byNumber.message], "the host cannot tell which limit was hit");
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
    assert.deepEqual(await lastEvent(t, "flow.rate_limited"), { flow: "door", scope: "subject" });
    await assert.rejects(t.engine.submitKeypad(callId, { dob: DOB }), rejects("precondition_failed", /has failed/));
    assert.equal((await t.counters.get(startCounter("subject", SUBJECT), LONG_AGO)).length, 5, "a refused start is not counted");
  });

  it("does not lift the subject limit for a changed calling number, or a withheld one", async () => {
    const t = limitsSetup(withLimits({ subject: 1 }));
    const { callId } = await t.engine.startCall({ flow: "deposit", callingNumber: number(1) });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    for (const input of [{ callingNumber: number(2) }, {}]) {
      const { callId: next } = await t.engine.startCall({ flow: "deposit", ...input });
      await assert.rejects(t.engine.beginVerification(next, { accountNumber: ACCOUNT }), rejects("rate_limited"));
    }
    const { callId: host } = await t.engine.startCall({ flow: "door", callingNumber: number(3) });
    await assert.rejects(t.engine.beginVerification(host, { subjectKey: SUBJECT }), rejects("rate_limited"), "nor a subject the host chose");
  });

  it("keeps separate subjects and separate numbers separate", async () => {
    const t = limitsSetup(withLimits({ subject: 1, number: 1 }));
    const { callId } = await t.engine.startCall({ flow: "deposit", callingNumber: number(1) });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const { callId: other } = await t.engine.startCall({ flow: "deposit", callingNumber: number(2) });
    await t.engine.beginVerification(other, { accountNumber: OTHER_ACCOUNT });
    assert.equal((await t.engine.flowPosition(other))!.status, "running");
    const { callId: unknown } = await t.engine.startCall({ flow: "door", callingNumber: number(3) });
    await t.engine.beginVerification(unknown, { accountNumber: "11112222" });
    assert.equal((await t.engine.flowPosition(unknown))!.status, "running", "an unknown subject is counted under its own key");
    assert.equal((await t.counters.get(startCounter("subject", subjectKeyFor(TEST_KNOWLEDGE_KEY, "11112222")), LONG_AGO)).length, 1);
  });

  it("counts a number first given at verification, and both counters on a call verified before its flow", async () => {
    const t = limitsSetup(withLimits({ number: 1 }));
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber: number(1) });
    assert.equal((await t.counters.get(startCounter("number", numberKeyFor(TEST_KNOWLEDGE_KEY, number(1))), LONG_AGO)).length, 1);
    const { callId: kept } = await t.engine.startCall({ callingNumber: number(2) });
    await t.engine.beginVerification(kept, { accountNumber: OTHER_ACCOUNT });
    await t.engine.finishVerification(kept);
    await t.engine.startFlow(kept, "door");
    assert.equal((await t.counters.get(startCounter("number", numberKeyFor(TEST_KNOWLEDGE_KEY, number(2))), LONG_AGO)).length, 1, "the number given at the start was kept");
    assert.equal((await t.counters.get(startCounter("subject", subjectKeyFor(TEST_KNOWLEDGE_KEY, OTHER_ACCOUNT)), LONG_AGO)).length, 1);
    const { callId: late } = await t.engine.startCall();
    await assert.rejects(t.engine.startFlow(late, "door", { callingNumber: number(2) }), rejects("rate_limited"));
    assert.equal((await t.engine.flowPosition(late))!.status, "failed");
  });

  it("refuses one of two starts that race past the last one left", async () => {
    const t = limitsSetup(withLimits({ number: 1 }));
    const results = await Promise.allSettled([1, 2].map(() => t.engine.startCall({ flow: "deposit", callingNumber: number(1) })));
    assert.deepEqual(results.map((r) => r.status).sort(), ["fulfilled", "rejected"]);
    assert.ok((results.find((r) => r.status === "rejected") as PromiseRejectedResult).reason instanceof EngineError);
  });

  it("counts nothing for a start the call refuses anyway, and refuses a calling number that is not E.164", async () => {
    const t = limitsSetup(withLimits({ number: 1 }));
    await t.engine.startCall({ callId: "taken" });
    await assert.rejects(t.engine.startCall({ callId: "taken", flow: "deposit", callingNumber: number(1) }), rejects("invalid_input", /exists/));
    const { callId } = await t.engine.startCall({ flow: "status" });
    await assert.rejects(t.engine.startFlow(callId, "deposit", { callingNumber: number(1) }), rejects("precondition_failed", /already ran a flow/));
    assert.deepEqual(await t.counters.get(startCounter("number", numberKeyFor(TEST_KNOWLEDGE_KEY, number(1))), LONG_AGO), []);
    await assert.rejects(t.engine.startCall({ callingNumber: "5555550142" }), rejects("invalid_input", /E\.164/));
    await assert.rejects(t.engine.startFlow(callId, "deposit", { callingNumber: "anonymous" }), rejects("invalid_input", /E\.164/));
  });

  it("takes a calling number with Badge off, and keeps nothing for it", async () => {
    const t = createTestEngine();
    const config = t.engine.config;
    config.modules.badge = { enabled: false };
    t.engine.configure(config);
    const { callId } = await t.engine.startCall({ callingNumber: number(1) });
    assert.equal((await t.engine.state(callId)).phase, "open");
  });

  it("needs the counters adapter for a limited flow, even with no factor the caller enters", () => {
    const noEntered = (c: FlowConfig): void => {
      c.modules.badge = { settings: { factors: ["carrier_identity_match", "photo_id"] } };
      c.policy.levels = c.policy.levels.map((l) => (l.level === 3 ? { level: 3, anyOf: [["carrier_identity_match", "photo_id"]] } : l));
      c.flows = { door: { steps: [{ type: "badge.verify", level: 3, factors: ["carrier_identity_match", "photo_id"], scopes: ["entry.open"] }] } };
    };
    const config = limitsConfig(noEntered);
    assert.throws(
      () => createTestEngine({ config, adapters: { counters: undefined } }),
      (e: unknown) => e instanceof ConfigError && e.problems.includes("flows.door: needs the counters adapter: it needs a money, contact or access scope, so its starts are limited"),
    );
    const t = createTestEngine({ config: limitsConfig((c) => {
      noEntered(c);
      c.flows = { look: { steps: [{ type: "badge.verify", level: 3, factors: ["carrier_identity_match", "photo_id"], scopes: ["status.read"] }] } };
    }), adapters: { counters: undefined } });
    assert.ok(t.engine.isEnabled("badge"));
  });
});
