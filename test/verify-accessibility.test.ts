// The accessible verification path (VER-11): keypad fields said instead of keyed, through the
// spoken_knowledge factor and within the policy's limits; keypad repeat and slower requests and
// longer idle timeouts that never add an attempt; and relay or TTY calls, which get longer
// timeouts and nothing else, and leave no mark in the ledger or the receipt.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { ConfigError } from "../src/core/config.ts";
import { DEFAULT_KEYPAD_IDLE_SECONDS, KeypadCollector, type KeypadCollectorOptions, type KeypadRequest } from "../src/core/keypad.ts";
import type { StepContext } from "../src/core/module.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

const POSTAL = "K1A0B1";
const SPOKEN = { fields: { postal_code: "ca_postal_code" as const }, maxAttemptsPerCall: 2 };

type Accessibility = { spokenKeypadFields?: string[]; keypadIdleSeconds?: number; maxKeypadIdleSeconds?: number };

/** Spoken answers on, a level 1 set of spoken_knowledge alone, and Badge's accessibility settings. */
function accessibleConfig(accessibility: Accessibility = { spokenKeypadFields: ["dob"] }, patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.spoken = structuredClone(SPOKEN);
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["spoken_knowledge"]] };
    const settings = c.modules.badge!.settings as { factors: string[]; accessibility?: Accessibility };
    settings.factors.push("spoken_knowledge");
    settings.accessibility = accessibility;
    patch(c);
  });
}

function accessibleSetup(config: FlowConfig = accessibleConfig()): TestEngine {
  const t = setup({ config });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB, postal_code: POSTAL }, pin: "4826" }));
  return t;
}

async function verifying(t: TestEngine, input: Parameters<TestEngine["engine"]["startCall"]>[0] = {}): Promise<string> {
  const { callId } = await t.engine.startCall(input);
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  return callId;
}

async function attempts(t: TestEngine, callId: string): Promise<Record<string, number>> {
  const stored = await t.sessions.get("ws_test", callId);
  return (stored!.record as unknown as CallRecord).modules.badge as unknown as Record<string, number>;
}

describe("a keypad field said instead of keyed", () => {
  it("is judged with the spoken fields as one spoken_knowledge factor, and reaches the level that factor reaches", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    const said = { postal_code: "K one A zero B one", dob: "one nine eight five zero two one four" };
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", said), { matched: true, locked: false });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] });
    const factors = (await t.ledger.list()).filter((e) => e.event === "verification.factor").map((e) => e.detail);
    assert.deepEqual(factors, [{ kind: "spoken_knowledge", passed: true }], "recorded as spoken, never as keypad knowledge");
  });

  it("must be given with every spoken field, and a wrong one fails the whole answer", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1" }), { matched: false, locked: false }, "the spoken keypad field is missing");
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: "19850215" }), { matched: false, locked: true });
    assert.equal(JSON.stringify(await t.ledger.list()).includes("1985"), false, "no value in the ledger");
  });

  it("stays within the policy's spoken attempt limit, and the keypad's own limit is untouched", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    const wrong = { postal_code: "K1A 0B1", dob: "11111111" };
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", wrong), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", wrong), { matched: false, locked: true });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: DOB }), { matched: false, locked: true }, "even the right answer");
    assert.deepEqual((await attempts(t, callId)).attempts, { spoken_knowledge: 2 });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false }, "keypad attempts are their own");
  });

  it("is never judged when the policy has no spoken fields", async () => {
    const t = accessibleSetup(
      accessibleConfig(undefined, (c) => {
        delete c.policy.spoken;
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"]] };
      }),
    );
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { dob: DOB }), { matched: false, locked: true });
  });

  it("only counts the policy's keypad fields, whatever a step-less config lists", async () => {
    const t = accessibleSetup(accessibleConfig({ spokenKeypadFields: ["dob", "pet_name"] }));
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A0B1", dob: DOB }), { matched: true, locked: false });
  });

  it("does not unlock texts to the number on file", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A0B1", dob: DOB });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
  });

  it("gives the same answer for an unknown account", async () => {
    const t = accessibleSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A0B1", dob: DOB }), { matched: false, locked: false });
  });
});

describe("a spoken PIN", () => {
  it("is refused before it is counted or judged", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    await assert.rejects(t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A0B1", dob: DOB, pin: "four eight two six" }), rejects("invalid_input", /never taken by speech/));
    assert.deepEqual((await attempts(t, callId)).attempts, {});
    assert.equal((await t.ledger.list()).some((e) => e.event === "verification.factor"), false);
    assert.equal(JSON.stringify(await t.ledger.list()).includes("four"), false);
  });

  it("cannot be turned on in Badge's settings", () => {
    const errors = badgeModule().validateSettings({ factors: ["spoken_knowledge", "keypad_knowledge"], accessibility: { spokenKeypadFields: ["pin"] } });
    assert.deepEqual(errors, ["accessibility.spokenKeypadFields cannot hold the PIN: a PIN is never taken by speech"]);
    assert.throws(() => createTestEngine({ config: accessibleConfig({ spokenKeypadFields: ["pin"] }) }), ConfigError);
  });
});

describe("Badge's accessibility settings", () => {
  const badge = badgeModule();
  const base = ["keypad_knowledge", "spoken_knowledge"];
  const check = (accessibility: unknown, factors: unknown = base) => badge.validateSettings({ factors, accessibility });

  it("accept the speech fields and the timeouts", () => {
    assert.deepEqual(check({ spokenKeypadFields: ["dob"], keypadIdleSeconds: 5, maxKeypadIdleSeconds: 300 }), []);
    assert.deepEqual(check({}), []);
    assert.deepEqual(check({ maxKeypadIdleSeconds: 10 }), [], "the default idle timeout is the floor of the maximum");
    assert.deepEqual(accessibleSetup().engine.config.modules.badge!.settings, accessibleConfig().modules.badge!.settings);
  });

  it("refuse every malformed part", () => {
    assert.deepEqual(check("on"), ["accessibility must be an object"]);
    assert.deepEqual(check({ relay: true }), ["accessibility.relay is not an accessibility setting"]);
    assert.deepEqual(check({ spokenKeypadFields: [] }), ["accessibility.spokenKeypadFields must list at least one keypad field"]);
    assert.deepEqual(check({ spokenKeypadFields: "dob" }), ["accessibility.spokenKeypadFields must list at least one keypad field"]);
    assert.deepEqual(check({ spokenKeypadFields: ["dob", "dob"] }), ["accessibility.spokenKeypadFields has duplicates"]);
    assert.deepEqual(check({ spokenKeypadFields: ["dob"] }, ["keypad_knowledge"]), ["accessibility.spokenKeypadFields needs the spoken_knowledge factor on"]);
    assert.ok(check({ spokenKeypadFields: ["dob"] }, null).includes("accessibility.spokenKeypadFields needs the spoken_knowledge factor on"));
    assert.deepEqual(check({ keypadIdleSeconds: 4 }), ["accessibility.keypadIdleSeconds must be an integer from 5 to 60"]);
    assert.deepEqual(check({ keypadIdleSeconds: 61, maxKeypadIdleSeconds: 5 }), ["accessibility.keypadIdleSeconds must be an integer from 5 to 60"]);
    assert.deepEqual(check({ keypadIdleSeconds: 20, maxKeypadIdleSeconds: 19 }), ["accessibility.maxKeypadIdleSeconds must be an integer from keypadIdleSeconds to 300"]);
    assert.deepEqual(check({ maxKeypadIdleSeconds: 301 }), ["accessibility.maxKeypadIdleSeconds must be an integer from keypadIdleSeconds to 300"]);
  });

  it("are held to the policy's keypad fields by a step that uses spoken answers", () => {
    const policy = { ...defaultVerificationPolicy(), spoken: SPOKEN, levels: [{ level: 1 as const, anyOf: [["spoken_knowledge" as const], ["keypad_knowledge" as const]] }] };
    const settings = { factors: base, accessibility: { spokenKeypadFields: ["dob", "pet_name"] } };
    const ctx = (s: unknown, p: StepContext["policy"] = policy): StepContext => ({ settings: s, policy: p, adapters: new Set<string>() });
    const step = { type: "badge.verify", level: 1, factors: ["spoken_knowledge"] };
    assert.deepEqual(badge.validateStep(step, ctx(settings)), ["spoken keypad field pet_name is not one of the policy's keypad fields"]);
    assert.deepEqual(badge.validateStep(step, ctx({ factors: base })), []);
    assert.deepEqual(badge.validateStep({ ...step, factors: ["keypad_knowledge"] }, ctx(settings)), [], "a step without spoken answers");
    assert.deepEqual(badge.validateStep(step, ctx(settings, null)), [], "the policy did not validate");
  });
});

/** A collector whose callbacks are recorded, with `*` for repeat and `A` for slower. */
type Overrides = { [K in keyof KeypadCollectorOptions]?: KeypadCollectorOptions[K] | undefined };

function collector(options: Overrides = {}) {
  const digits: string[] = [];
  const requests: KeypadRequest[] = [];
  let timeouts = 0;
  const c = new KeypadCollector({
    maxLength: 8,
    idleTimeoutMs: 5000,
    maxIdleTimeoutMs: 20000,
    requestKeys: { "*": "repeat", A: "slower" },
    onDigits: (d) => digits.push(d),
    onRequest: (r) => requests.push(r),
    onTimeout: () => timeouts++,
    ...options,
  } as KeypadCollectorOptions);
  const press = (keys: string, at = 0) => {
    for (const key of keys) c.press(key, at);
  };
  return { c, digits, requests, press, timeouts: () => timeouts };
}

describe("the keypad collector (stand-in for INT-1)", () => {
  it("buffers digits until # and hands them to one callback, never through toString, JSON or inspect", async () => {
    const { c, digits, press } = collector();
    press("4826");
    assert.equal(c.collecting, true);
    assert.equal(String(c), "[KeypadCollector]");
    assert.equal(JSON.stringify({ c }), '{"c":"[KeypadCollector]"}');
    const { inspect } = await import("node:util");
    assert.equal(inspect(c), "[KeypadCollector]");
    press("#");
    assert.deepEqual(digits, ["4826"]);
    assert.equal(c.collecting, false);
    press("#");
    assert.deepEqual(digits, ["4826"], "an empty entry is not handed over");
  });

  it("drops an entry longer than its maximum, and ignores keys that are not digits, # or a request", () => {
    const { digits, press } = collector({ maxLength: 3 });
    press("1234#");
    assert.deepEqual(digits, [], "the fourth digit dropped the buffer, so no part of the entry is handed over");
    press("12B#");
    assert.deepEqual(digits, ["12"]);
  });

  it("hands a repeat or slower request instead of digits, and drops the partial entry", () => {
    const { digits, requests, press } = collector();
    press("19*");
    press("A");
    press("19850214#");
    assert.deepEqual(requests, ["repeat", "slower"]);
    assert.deepEqual(digits, ["19850214"], "the digits before the request never reach the host");
  });

  it("ignores * when no request is set on it", () => {
    const { digits, requests, press } = collector({ requestKeys: undefined });
    press("12*3#");
    assert.deepEqual(requests, []);
    assert.deepEqual(digits, ["123"]);
  });

  it("drops a partial entry after the idle timeout, which the call can lengthen up to its limit", () => {
    const { c, digits, press, timeouts } = collector();
    press("12", 0);
    c.tick(4999);
    assert.equal(c.collecting, true);
    c.tick(5000);
    assert.equal(c.collecting, false);
    assert.equal(timeouts(), 1);
    assert.equal(c.lengthenIdleTimeout(10000), 15000);
    assert.equal(c.lengthenIdleTimeout(10000), 20000, "never past the limit");
    assert.equal(c.idleTimeoutMs, 20000);
    press("34", 30000);
    press("#", 49999);
    assert.deepEqual(digits, ["34"]);
    c.tick(99999);
    assert.equal(timeouts(), 1, "nothing buffered, nothing dropped");
  });

  it("drops a stale entry on the next tone even without a tick, and without an onTimeout", () => {
    const { digits, press } = collector({ onTimeout: undefined });
    press("12", 0);
    press("34#", 6000);
    assert.deepEqual(digits, ["34"]);
  });

  it("cannot be lengthened by default", () => {
    const { c } = collector({ maxIdleTimeoutMs: undefined });
    assert.equal(c.lengthenIdleTimeout(1000), 5000);
  });

  it("refuses bad options and a bad lengthening", () => {
    const bad = (options: Overrides, message: RegExp) => assert.throws(() => collector(options), rejects("invalid_input", message));
    bad({ maxLength: 0 }, /maxLength must be 1 to 32/);
    bad({ idleTimeoutMs: 999 }, /idleTimeoutMs must be an integer of 1000 or more/);
    bad({ maxIdleTimeoutMs: 4999 }, /maxIdleTimeoutMs must be an integer of idleTimeoutMs or more/);
    bad({ requestKeys: { "#": "repeat" } }, /request key "#" must be one of/);
    bad({ requestKeys: { "*": "louder" as KeypadRequest } }, /request on \* must be repeat or slower/);
    bad({ onRequest: undefined }, /onRequest is required with requestKeys/);
    assert.throws(() => collector().c.lengthenIdleTimeout(0), rejects("invalid_input"));
  });
});

describe("repeats and longer timeouts", () => {
  it("never use, add or give back an attempt", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    const entries: string[] = [];
    const c = new KeypadCollector({ maxLength: 8, ...(await t.engine.keypadTiming(callId)), requestKeys: { "*": "repeat" }, onDigits: (d) => entries.push(d), onRequest: () => undefined });
    for (const key of "1985*") c.press(key, 0);
    for (const key of "19850215#") c.press(key, 0);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: entries.shift()! }), { matched: false, locked: false });
    for (const key of "*****") c.press(key, 0);
    c.lengthenIdleTimeout(60000);
    assert.deepEqual(entries, [], "requests hand nothing to the engine");
    assert.deepEqual((await attempts(t, callId)).attempts, { keypad_knowledge: 1 }, "the attempt before the repeats is still used");
    for (const key of "19850214#") c.press(key, 0);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: entries.shift()! }), { matched: true, locked: false });
    assert.deepEqual((await attempts(t, callId)).attempts, { keypad_knowledge: 2 });
  });

  it("come from Badge's settings: the default, the configured idle time and its limit", async () => {
    const plain = setup();
    const { callId: a } = await plain.engine.startCall();
    const dflt = DEFAULT_KEYPAD_IDLE_SECONDS * 1000;
    assert.deepEqual(await plain.engine.keypadTiming(a), { idleTimeoutMs: dflt, maxIdleTimeoutMs: dflt });
    const t = accessibleSetup(accessibleConfig({ keypadIdleSeconds: 8, maxKeypadIdleSeconds: 40 }));
    const { callId: b } = await t.engine.startCall();
    assert.deepEqual(await t.engine.keypadTiming(b), { idleTimeoutMs: 8000, maxIdleTimeoutMs: 40000 });
  });
});

describe("a call marked relay or TTY", () => {
  const flowConfig = () =>
    accessibleConfig({ keypadIdleSeconds: 10, maxKeypadIdleSeconds: 60 }, (c) => {
      c.flows.deposit = {
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
          { type: "trace.receipt" },
        ],
      };
    });

  async function depositCall(t: TestEngine, access?: "relay" | "tty") {
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall(access === undefined ? { flow: "deposit" } : { flow: "deposit", access });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: DOB }), rejects("precondition_failed"), "the step's factors, as for anyone");
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "00000000" }), { matched: false, locked: false });
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
    await t.engine.checkCarrier(callId);
    const result = await t.engine.finishVerification(callId);
    const position = await t.engine.flowPosition(callId);
    const receipt = await t.engine.endCall(callId);
    return { callId, result, position, receipt };
  }

  it("gets the longer timeout and nothing else: same steps, same attempts, same level, no mark in the ledger or the receipt", async () => {
    for (const access of ["relay", "tty"] as const) {
      const plain = accessibleSetup(flowConfig());
      const marked = accessibleSetup(flowConfig());
      const a = await depositCall(plain);
      const b = await depositCall(marked, access);
      assert.deepEqual(b.result, { level: 2, scopes: ["payment.request"] });
      assert.deepEqual(b.result, a.result);
      assert.deepEqual(b.position, a.position);
      assert.deepEqual(b.receipt!.body, a.receipt!.body, "the same receipt, byte for byte");
      const plainLedger = await plain.ledger.list();
      const markedLedger = await marked.ledger.list();
      assert.deepEqual(markedLedger, plainLedger, "the same ledger, entry for entry");
      assert.equal(JSON.stringify(markedLedger).includes(access), false);
      assert.equal(JSON.stringify(b.receipt).includes(access), false);
      assert.equal(JSON.stringify(await marked.engine.state(b.callId)).includes(access), false, "nor in the session state");
    }
  });

  it("keeps the mark in the call record, where it only sets the keypad timeouts", async () => {
    const t = accessibleSetup(flowConfig());
    const { callId: plain } = await t.engine.startCall();
    const { callId: relay } = await t.engine.startCall({ access: "relay" });
    assert.deepEqual(await t.engine.keypadTiming(plain), { idleTimeoutMs: 10000, maxIdleTimeoutMs: 60000 });
    assert.deepEqual(await t.engine.keypadTiming(relay), { idleTimeoutMs: 60000, maxIdleTimeoutMs: 60000 });
    const stored = (await t.sessions.get("ws_test", relay))!.record as unknown as CallRecord;
    assert.equal(stored.access, "relay");
    assert.equal(Object.hasOwn((await t.sessions.get("ws_test", plain))!.record as object, "access"), false);
  });

  it("is refused when it is neither relay nor tty", async () => {
    const t = accessibleSetup();
    await assert.rejects(t.engine.startCall({ access: "deaf" as "relay" }), rejects("invalid_input", /relay or tty/));
    assert.deepEqual(await t.ledger.list(), []);
  });
});
