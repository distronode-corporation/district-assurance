// The accessible verification path (VER-11): keypad fields said instead of keyed, through the
// spoken_knowledge factor and within the policy's limits; keypad repeat and slower requests and
// longer idle timeouts that never add an attempt; and relay or TTY calls, which get longer
// timeouts and nothing else, and leave no mark in the ledger or the receipt.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { ConfigError } from "../src/core/config.ts";
import { KeypadCollector, type KeypadPress } from "../src/core/keypad.ts";
import type { StepContext } from "../src/core/module.ts";
import { defaultVerificationPolicy } from "../src/core/policy.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import { FixedClock } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { DEFAULT_KEYPAD_IDLE_SECONDS, badgeModule } from "../src/verify/badge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, waitOut } from "./helpers.ts";

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

  it("stays within the policy's spoken attempt limit, and shares the keypad's budget for the fields it carries", async () => {
    const t = accessibleSetup(accessibleConfig(undefined, (c) => (c.policy.maxKeypadAttemptsPerCall = 3)));
    const callId = await verifying(t);
    const wrong = { postal_code: "K1A 0B1", dob: "11111111" };
    // Each failure waits out VER-1's backoff (#71), so only the call's budget answers.
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", wrong), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", wrong), { matched: false, locked: true });
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: DOB }), { matched: false, locked: true }, "even the right answer");
    assert.deepEqual((await attempts(t, callId)).attempts, { spoken_knowledge: 2, keypad_knowledge: 2 }, "each spoken guess at the date of birth is a keypad guess too");
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "11111111" }), { matched: false, locked: true }, "3 guesses at the date of birth on this call, not 3 plus 2");
    waitOut(t);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: false, locked: true });
  });

  it("counts a failed answer under keypad_knowledge too across calls, so alternating keyed and spoken guesses reach the same lock", async () => {
    const t = accessibleSetup(accessibleConfig(undefined, (c) => ((c.modules.badge!.settings as Record<string, unknown>).lockout = { lockAfterFailures: 3 })));
    const wrong = { postal_code: "K1A 0B1", dob: "11111111" };
    const first = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(first, "spoken_knowledge", wrong), { matched: false, locked: false });
    const subject = { workspaceId: "ws_test", factor: "keypad_knowledge", scope: "subject" as const, key: (await attempts(t, first)).subjectKey as unknown as string };
    assert.equal((await t.counters.get(subject, "2000-01-01T00:00:00.000Z")).length, 1, "a spoken guess at the date of birth is a keypad failure across calls");
    waitOut(t);
    assert.deepEqual(await t.engine.submitKeypad(await verifying(t), { dob: "11111111" }), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(await verifying(t), "spoken_knowledge", wrong), { matched: false, locked: true }, "the third guess, keyed or said, locks");
    waitOut(t);
    assert.deepEqual(await t.engine.submitKeypad(await verifying(t), { dob: DOB }), { matched: false, locked: true }, "the keypad is locked by guesses that were mostly spoken");
    assert.deepEqual(await t.engine.submitFactor(await verifying(t), "spoken_knowledge", { postal_code: "K1A 0B1", dob: DOB }), { matched: false, locked: true }, "and so is the voice");
  });

  it("forgets the subject's keypad failures on a spoken pass, as a keyed pass does", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "11111111" }), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: DOB }), { matched: true, locked: false });
    const subject = { workspaceId: "ws_test", factor: "keypad_knowledge", scope: "subject" as const, key: (await attempts(t, callId)).subjectKey as unknown as string };
    assert.deepEqual(await t.counters.get(subject, "2000-01-01T00:00:00.000Z"), []);
  });

  it("is refused once the keypad used up the budget it shares, and counts only the spoken limit without keypad fields", async () => {
    const t = accessibleSetup(accessibleConfig(undefined, (c) => (c.policy.maxKeypadAttemptsPerCall = 2)));
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: "11111111" }), { matched: false, locked: false });
    // The keypad failure's wait (#71) holds the spoken answer too, which shares its counter.
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: "11111111" }), { matched: false, locked: true }, "the last shared guess");
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1", dob: DOB }), { matched: false, locked: true }, "spoken limit left, keypad budget gone");
    assert.deepEqual((await attempts(t, callId)).attempts, { keypad_knowledge: 2, spoken_knowledge: 1 });

    const plain = accessibleSetup(accessibleConfig({}));
    const other = await verifying(plain);
    await plain.engine.submitFactor(other, "spoken_knowledge", { postal_code: "K1A 0B1" });
    assert.deepEqual((await attempts(plain, other)).attempts, { spoken_knowledge: 1 }, "no keypad field said, no keypad guess");
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

  it("matches every value a keypad field can hold, 1 to 32 digits, and nothing else", async () => {
    for (const [value, said] of [
      ["7", "seven"],
      ["123", "one two three"],
      ["1234567890123", "1234567890123"],
      ["9".repeat(32), "9".repeat(32)],
    ] as const) {
      const t = setup({ config: accessibleConfig() });
      t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: value, postal_code: POSTAL } }));
      const callId = await verifying(t);
      assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: said }), { matched: true, locked: false }, value);
    }
    const t = setup({ config: accessibleConfig() });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: "9".repeat(32), postal_code: POSTAL } }));
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: "9".repeat(33) }), { matched: false, locked: false }, "33 digits");
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: "A123" }), { matched: false, locked: true }, "a letter");
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
  it("counts an entry that is not a set of answers as an unusable answer, never a crash", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    for (const bad of [null, { postal_code: "K1A0B1", dob: 19850214 }]) {
      assert.equal((await t.engine.submitFactor(callId, "spoken_knowledge", bad as never)).matched, false, JSON.stringify(bad));
      waitOut(t);
    }
    assert.deepEqual((await attempts(t, callId)).attempts, { spoken_knowledge: 2, keypad_knowledge: 2 }, "a number is never read as its digits");
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.factor").map((e) => e.detail), [
      { kind: "spoken_knowledge", passed: false },
      { kind: "spoken_knowledge", passed: false },
    ]);
  });

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
    const ctx = (s: unknown, p: StepContext["policy"] = policy): StepContext => ({ settings: s, policy: p, adapters: new Set<string>(), capabilities: {} });
    const step = { type: "badge.verify", level: 1, factors: ["spoken_knowledge"] };
    assert.deepEqual(badge.validateStep(step, ctx(settings)), ["spoken keypad field pet_name is not one of the policy's keypad fields"]);
    assert.deepEqual(badge.validateStep(step, ctx({ factors: base })), []);
    assert.deepEqual(badge.validateStep({ ...step, factors: ["keypad_knowledge"] }, ctx(settings)), [], "a step without spoken answers");
    assert.deepEqual(badge.validateStep(step, ctx(settings, null)), [], "the policy did not validate");
  });
});

/** A collector whose callbacks are recorded, with `*` for repeat and `A` for slower. */
/** Presses every key of `keys` and returns each press's status (and request, when it is one). */
function pressAll<R>(c: KeypadCollector<R>, keys: string): string[] {
  return [...keys].map((key) => {
    const p: KeypadPress<R> = c.press(key);
    return p.status === "request" ? `request:${p.request}` : p.status;
  });
}

describe("#73's keypad collector with VER-11's request keys and longer timeouts (decision 7)", () => {
  it("hands a repeat or slower request instead of digits, and drops the partial entry", () => {
    const entries: string[] = [];
    const c = new KeypadCollector({ maxDigits: 8, idleTimeoutMs: 5000, requestKeys: { "*": "repeat", A: "slower" }, onDigits: (d) => entries.push(d), clock: new FixedClock() });
    assert.deepEqual(pressAll(c, "19*"), ["buffering", "buffering", "request:repeat"]);
    assert.deepEqual(pressAll(c, "A"), ["request:slower"]);
    pressAll(c, "19850214#");
    assert.deepEqual(entries, ["19850214"], "only the entry after the requests");
    assert.deepEqual(pressAll(c, "B"), ["rejected"], "a key no request is set on is still rejected");
  });

  it("keeps * as start over when no request is set on it", () => {
    const entries: string[] = [];
    const c = new KeypadCollector({ maxDigits: 8, idleTimeoutMs: 5000, requestKeys: { A: "repeat" }, onDigits: (d) => entries.push(d), clock: new FixedClock() });
    assert.deepEqual(pressAll(c, "12*3#"), ["buffering", "buffering", "cleared", "buffering", "submitted"]);
    assert.deepEqual(entries, ["3"]);
  });

  it("ends an overlong or rejected entry on a request, and the next entry counts", () => {
    const entries: string[] = [];
    const c = new KeypadCollector({ maxDigits: 4, idleTimeoutMs: 5000, requestKeys: { "*": "repeat" }, onDigits: (d) => entries.push(d), clock: new FixedClock() });
    assert.deepEqual(pressAll(c, "12345*"), ["buffering", "buffering", "buffering", "buffering", "overflow", "request:repeat"]);
    pressAll(c, "678#");
    assert.deepEqual(entries, ["678"]);
  });

  it("drops a partial entry after the idle timeout, which the call can lengthen up to its limit", () => {
    const clock = new FixedClock();
    const entries: string[] = [];
    const c = new KeypadCollector({ maxDigits: 8, idleTimeoutMs: 5000, maxIdleTimeoutMs: 20000, requestKeys: { "*": "slower" }, onDigits: (d) => entries.push(d), clock });
    assert.equal(c.idleTimeoutMs, 5000);
    pressAll(c, "12");
    clock.advance(5000);
    assert.equal(c.expire(), true, "dropped at the default timeout");
    assert.equal(c.lengthenIdleTimeout(10000), 15000);
    assert.equal(c.lengthenIdleTimeout(10000), 20000, "never past the limit");
    pressAll(c, "34");
    clock.advance(19999);
    assert.equal(c.press("#").status, "submitted");
    assert.deepEqual(entries, ["34"]);
  });

  it("cannot be lengthened by default", () => {
    const c = new KeypadCollector({ maxDigits: 8, idleTimeoutMs: 5000, onDigits: () => undefined, clock: new FixedClock() });
    assert.equal(c.lengthenIdleTimeout(1000), 5000);
  });

  it("refuses bad request keys, a bad limit and a bad lengthening", () => {
    const base = { maxDigits: 8, idleTimeoutMs: 5000, onDigits: () => undefined };
    assert.throws(() => new KeypadCollector({ ...base, requestKeys: { "#": "repeat" } }), rejects("invalid_input", /request key "#"/));
    assert.throws(() => new KeypadCollector({ ...base, requestKeys: { "1": "repeat" } }), rejects("invalid_input", /request key "1"/));
    assert.throws(() => new KeypadCollector({ ...base, requestKeys: { "*": "louder" as never } }), rejects("invalid_input", /repeat or slower/));
    assert.throws(() => new KeypadCollector({ ...base, requestKeys: "*" as never }), rejects("invalid_input", /requestKeys/));
    assert.throws(() => new KeypadCollector({ ...base, maxIdleTimeoutMs: 4999 }), rejects("invalid_input", /maxIdleTimeoutMs/));
    assert.throws(() => new KeypadCollector({ ...base, maxIdleTimeoutMs: 600_001 }), rejects("invalid_input", /maxIdleTimeoutMs/));
    const c = new KeypadCollector({ ...base, maxIdleTimeoutMs: 6000 });
    for (const bad of [0, -1, 1.5, Number.NaN, 600_001]) assert.throws(() => c.lengthenIdleTimeout(bad), rejects("invalid_input", /lengthened/), String(bad));
  });

  it("takes its timeouts straight from keypadTiming", async () => {
    const t = accessibleSetup(accessibleConfig({ keypadIdleSeconds: 8, maxKeypadIdleSeconds: 40 }));
    const { callId } = await t.engine.startCall({ access: "relay" });
    const c = new KeypadCollector({ maxDigits: 8, ...(await t.engine.keypadTiming(callId)), onDigits: () => undefined, clock: t.clock });
    assert.equal(c.idleTimeoutMs, 40000, "a relay call starts at the limit");
    assert.equal(c.lengthenIdleTimeout(1000), 40000);
  });
});

describe("repeats and longer timeouts", () => {
  it("never use, add or give back an attempt", async () => {
    const t = accessibleSetup();
    const callId = await verifying(t);
    const entries: string[] = [];
    const c = new KeypadCollector({ maxDigits: 8, ...(await t.engine.keypadTiming(callId)), requestKeys: { "*": "repeat" }, onDigits: (d) => entries.push(d), clock: t.clock });
    pressAll(c, "1985*");
    pressAll(c, "19850215#");
    assert.deepEqual(await t.engine.submitKeypad(callId, { dob: entries.shift()! }), { matched: false, locked: false });
    waitOut(t);
    pressAll(c, "*****");
    c.lengthenIdleTimeout(60000);
    assert.deepEqual(entries, [], "requests hand nothing to the engine");
    assert.deepEqual((await attempts(t, callId)).attempts, { keypad_knowledge: 1 }, "the attempt before the repeats is still used");
    pressAll(c, "19850214#");
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
    waitOut(t);
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
