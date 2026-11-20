// The PIN factor (keyed hash or the host's verifier) and factor plug-ins.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { validateConfig } from "../src/core/config.ts";
import { ModuleRegistry, type AssuranceModule } from "../src/core/module.ts";
import { builtInModules } from "../src/modules.ts";
import { badgeModule } from "../src/verify/badge.ts";
import type { FactorJudgeInput, FactorPlugin } from "../src/verify/factors.ts";
import { numberKeyFor } from "../src/verify/counters.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { isWeakPin } from "../src/verify/pin.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PIN, pinOnFile, rejects, setup, testConfig, waitOut } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

/** Resolves with `p`, or rejects once `ms` pass, so a missed checkpoint fails the test instead of hanging it. */
function within<T>(p: Promise<T>, label: string, ms = 2000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error(`${label}: not reached in ${ms} ms`)), ms)));
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}

/** Real counters that also keep every reset they are asked for. */
function resetRecorder(resets: unknown[]): MemoryAttemptCounters {
  return new (class extends MemoryAttemptCounters {
    override async reset(key: AttemptCounterKey): Promise<void> {
      resets.push(structuredClone(key));
      return super.reset(key);
    }
  })();
}

describe("PIN factor, keyed hash", () => {
  it("matches the PIN on file, on a subject the host chose, and reaches level 1 alone when the policy says so", async () => {
    const t = setup({ config: testConfig((c) => (c.policy.levels[0] = { level: 1, anyOf: [["pin"]] })) });
    const { callId } = await t.engine.startCall();
    await assert.rejects(t.engine.beginVerification(callId, { subjectKey: "not-hex" }), rejects("invalid_input"));
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] });
    const entries = await t.ledger.list();
    assert.deepEqual(entries[1]!.detail, { subject: "host" });
    const { tag, ...detail } = entries[2]!.detail;
    assert.deepEqual(detail, { kind: "pin", passed: true });
    assert.match(String(tag), /^[0-9a-f]{64}$/, "every PIN entry carries a keyed tag (VER-12)");
    assert.equal(JSON.stringify(entries).includes(`"${PIN}"`), false, "the PIN is never written");
  });

  it("counts malformed, wrong and unknown-subject entries the same way, and locks after the limit", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, "12"), { matched: false, locked: false }, "too short");
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, "123456789"), { matched: false, locked: false }, "too long");
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, "48a6"), { matched: false, locked: true }, "not digits, and the third attempt");
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "even the right PIN is not judged now");
    for (const account of ["99999999", "x"]) {
      const other = await t.engine.startCall();
      await t.engine.beginVerification(other.callId, { accountNumber: account });
      assert.deepEqual(await t.engine.submitPin(other.callId, PIN), { matched: false, locked: false });
    }
  });

  it("refuses a subject that has no PIN on file, and a keypad map as a PIN", async () => {
    const t = setup();
    t.records.putSubject("ws_test", { subjectKey: OWNER, phoneOnFile: "+15555550100", knowledge: {} });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false);
    waitOut(t);
    assert.equal((await t.engine.submitFactor(callId, "pin", { pin: PIN })).matched, false);
    assert.equal((await t.engine.submitFactor(callId, "keypad_knowledge", "19850214")).matched, false, "keypad knowledge is a map of fields");
    assert.equal((await t.engine.state(callId)).factors.length, 3, "each was judged, none refused by a wait");
  });

  it("binds the digest to the subject", async () => {
    const record = pinDigest(TEST_KNOWLEDGE_KEY, "a".repeat(64), PIN);
    assert.equal(await pinOnFile(record, "a".repeat(64), PIN), true);
    assert.equal(await pinOnFile(record, "b".repeat(64), PIN), false, "the same PIN does not match for another subject");
  });

  it("lets a PIN match unlock the photo ID link, as a keypad match does", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, PIN);
    assert.deepEqual(await t.engine.startPhotoId(callId), { sent: true });
  });
});

describe("PIN factor, the host's verifier", () => {
  const verifierConfig = () =>
    testConfig((c) => {
      (c.modules.badge!.settings as { pin: { mode: string } }).pin.mode = "verifier";
    });

  it("asks the host's PIN store every time, with a stand-in for a malformed entry or a non-keypad account (review item 11)", async () => {
    const t = setup({ config: verifierConfig() });
    t.pinVerifier.set("ws_test", OWNER, PIN);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, "0000")).matched, false);
    waitOut(t);
    assert.equal((await t.engine.submitPin(callId, "12")).matched, false);
    waitOut(t);
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.deepEqual(t.pinVerifier.asked, [OWNER, OWNER, OWNER], "the malformed entry was asked too, as a stand-in");
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: "12a" });
    t.pinVerifier.verify = async (input) => {
      t.pinVerifier.asked.push(input.subjectKey);
      return { matched: true }; // a verifier that says yes to a stand-in still never passes it
    };
    assert.equal((await t.engine.submitPin(other.callId, PIN)).matched, false);
    waitOut(t);
    assert.equal((await t.engine.submitPin(other.callId, "1")).matched, false);
    assert.equal(t.pinVerifier.asked.length, 5);
  });

  it("never passes a subject the records do not have, whatever the verifier says", async () => {
    const t = setup({ config: verifierConfig() });
    const ghost = subjectKeyFor(TEST_KNOWLEDGE_KEY, "55555555");
    t.pinVerifier.set("ws_test", ghost, PIN);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: ghost });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false);
    assert.deepEqual(t.pinVerifier.asked, [ghost]);
  });

  it("counts the attempt before asking, so a verifier that fails still uses it", async () => {
    const t = setup({ config: verifierConfig() });
    t.pinVerifier.verify = async () => {
      throw new Error("pin store down");
    };
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    for (let i = 0; i < 3; i++) {
      await assert.rejects(t.engine.submitPin(callId, PIN), /pin store down/);
      waitOut(t);
    }
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true });
    assert.equal((await t.engine.state(callId)).factors.length, 0);
    const subject = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: OWNER };
    assert.equal((await t.counters.get(subject, "2000-01-01T00:00:00.000Z")).length, 3, "each failed verifier call is a failure across calls too");
  });
});

describe("PIN lockout across calls and engines (VER-1)", () => {
  const CALLER = "+15555550142";

  /** Process B: a second engine on the same session store, ledger, records and counters. */
  function secondEngine(t: TestEngine) {
    return createTestEngine({
      config: testConfig(),
      clock: t.clock,
      ids: t.ids,
      adapters: { sessions: t.sessions, ledger: t.ledger, records: t.records, counters: t.counters },
    }).engine;
  }

  it("carries a PIN lock across two calls and two engines, and lifts it only when the window passes or the business resets it", async () => {
    const t = setup();
    const b = secondEngine(t);
    const engines = [t.engine, b];
    let failures = 0;
    // Three wrong PINs per call, alternating engines and calls, the way an attacker calls back.
    for (let c = 0; failures < 10; c++) {
      const { callId } = await engines[c % 2]!.startCall();
      await engines[(c + 1) % 2]!.beginVerification(callId, { subjectKey: OWNER, callingNumber: CALLER });
      for (let i = 0; i < 3 && failures < 10; i++) {
        waitOut(t);
        const result = await engines[(c + i) % 2]!.submitPin(callId, String(1000 + failures).padStart(4, "0"));
        failures++;
        assert.equal(result.matched, false);
        assert.equal(result.locked, i === 2 || failures === 10, `failure ${failures}`);
      }
    }
    // A fresh call, on either engine, from another number: the subject is locked whatever the line.
    for (const engine of engines) {
      waitOut(t);
      const { callId } = await engine.startCall();
      await engine.beginVerification(callId, { subjectKey: OWNER, callingNumber: "+15555550199" });
      assert.deepEqual(await engine.submitPin(callId, PIN), { matched: false, locked: true }, "the right PIN, not judged");
      assert.deepEqual((await engine.state(callId)).factors, []);
    }
    const locks = (await t.ledger.list()).filter((e) => e.event === "verification.locked");
    assert.deepEqual(
      locks.map((e) => [e.detail.scope, e.detail.hard]),
      [["subject", true], ["subject", true], ["subject", true]],
      "the tenth failure locks the subject (its number too), and both refusals name the subject",
    );
    assert.equal(JSON.stringify(locks).includes(PIN) || JSON.stringify(locks).includes(CALLER), false);
    // The business lifts the lock (both counters, as the owner's own number was counted too).
    await t.counters.reset({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: OWNER });
    await t.counters.reset({ workspaceId: "ws_test", factor: "pin", scope: "number", key: numberKeyFor(TEST_KNOWLEDGE_KEY, CALLER) });
    const { callId } = await b.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER, callingNumber: CALLER });
    assert.deepEqual(await b.submitPin(callId, PIN), { matched: true, locked: false });
  });

  it("counts unknown subjects by the calling number, so trying one account after another from one line locks the line", async () => {
    const t = setup();
    const b = secondEngine(t);
    // Ten calls, each to a different account that does not exist, and the last one with no account a keypad could produce.
    for (let i = 0; i < 10; i++) {
      waitOut(t);
      const engine = i % 2 === 0 ? t.engine : b;
      const { callId } = await engine.startCall();
      await engine.beginVerification(callId, { accountNumber: i === 9 ? "not-digits" : `5000000${i}`, callingNumber: CALLER });
      assert.deepEqual(await engine.submitPin(callId, PIN), { matched: false, locked: i === 9 });
    }
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.locked").map((e) => e.detail.scope), ["number"]);
    // The real owner, from that line: refused. From their own line: judged.
    waitOut(t);
    const fromLine = await t.engine.startCall();
    await t.engine.beginVerification(fromLine.callId, { subjectKey: OWNER, callingNumber: CALLER });
    assert.deepEqual(await t.engine.submitPin(fromLine.callId, PIN), { matched: false, locked: true });
    assert.equal((await t.ledger.list()).at(-1)!.detail.scope, "number");
    const fromOwn = await b.startCall();
    await b.beginVerification(fromOwn.callId, { subjectKey: OWNER, callingNumber: "+15555550101" });
    assert.deepEqual(await b.submitPin(fromOwn.callId, PIN), { matched: true, locked: false });
  });

  it("refuses the second of two simultaneous wrong PINs on one call even when both engines read the counters first", async () => {
    const t = setup();
    const b = secondEngine(t);
    const { callId } = await t.engine.startCall();
    await b.beginVerification(callId, { subjectKey: OWNER });
    const results = await Promise.all([t.engine.submitPin(callId, "0000"), b.submitPin(callId, "1111"), t.engine.submitPin(callId, PIN)]);
    assert.equal(results.filter((r) => !r.locked).length, 1, "one judged; the others refused by the wait or the race");
    assert.equal((await t.engine.state(callId)).factors.length, 1);
  });
});

describe("factor plug-ins", () => {
  it("judges a host's own factor with the keyed hash, never the key, and limits its attempts", async () => {
    const seen: FactorJudgeInput[] = [];
    const badge = badgeModule({
      factors: [
        {
          kind: "voice_passphrase",
          summary: "a passphrase the host's speech pipeline normalised",
          maxAttemptsPerCall: 1,
          adapters: [],
          judge: async (input) => {
            seen.push(input);
            return input.entry === "open sesame" && input.subject !== null;
          },
        },
        { kind: "truthy_judge", summary: "returns a non-boolean", maxAttemptsPerCall: 2, adapters: [], judge: async () => "yes" as unknown as boolean },
      ],
    });
    const config = testConfig((c) => {
      c.policy.levels[0] = { level: 1, anyOf: [["voice_passphrase"], ["truthy_judge"]] };
      (c.modules.badge!.settings as { factors: string[] }).factors.push("voice_passphrase", "truthy_judge");
    });
    const t = setup({ config, badge });
    assert.ok(t.engine.registry.factorKinds().includes("voice_passphrase"));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "truthy_judge", "x"), { matched: false, locked: false }, "only true passes");
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "open sesame"), { matched: true, locked: false });
    assert.deepEqual(await t.engine.submitFactor(callId, "voice_passphrase", "open sesame"), { matched: false, locked: true });
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.subjectKey, OWNER);
    assert.match(await seen[0]!.hmac("x"), /^[0-9a-f]{64}$/);
    assert.equal(Object.values(seen[0]!).includes(TEST_KNOWLEDGE_KEY), false);
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    const again = await t.engine.startCall();
    await t.engine.beginVerification(again.callId, { accountNumber: ACCOUNT });
    await t.engine.submitFactor(again.callId, "voice_passphrase", "open sesame");
    await assert.rejects(t.engine.startPhotoId(again.callId), rejects("precondition_failed"), "a plug-in match does not unlock texts to the number on file");
  });
});

describe("factor plug-ins added after the engine is built (MOD-3)", () => {
  const token = (judged: FactorJudgeInput[] = []): FactorPlugin => ({
    kind: "hardware_token",
    summary: "a code from a token the organisation issued",
    maxAttemptsPerCall: 2,
    adapters: [],
    judge: async (input) => {
      judged.push(input);
      return input.entry === "246810" && input.subject !== null;
    },
  });
  /** The test config with hardware_token in the policy at level 1 and, unless told not to, on in Badge's settings. */
  const tokenConfig = (on = true) =>
    testConfig((c) => {
      c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["hardware_token"]] };
      if (on) (c.modules.badge!.settings as { factors: string[] }).factors.push("hardware_token");
    });
  /** An outside module whose manifest provides a factor and supplies its judge. */
  const tokenModule = (plugin: FactorPlugin = token()): AssuranceModule => ({
    manifest: {
      name: "token-check",
      version: "1",
      summary: "hardware tokens",
      provides: { factors: [plugin.kind], steps: [], outcomes: [] },
      scopes: { grants: [], needs: {} },
      adapters: [],
    },
    factorPlugins: [plugin],
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => null,
    enterStep: () => null,
    stepStatus: () => "pending",
  });

  it("useFactor: off under the config in force, known to validateConfig, judged once a config turns it on", async () => {
    const judged: FactorJudgeInput[] = [];
    const t = setup();
    const before = t.engine.config;
    assert.equal(t.engine.useFactor(token(judged)), t.engine);
    assert.ok(t.engine.registry.factorKinds().includes("hardware_token"));
    assert.deepEqual(t.engine.config, before, "the config in force is unchanged");
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitFactor(callId, "hardware_token", "246810"), rejects("precondition_failed", /turned off/));
    // validateConfig sees the new kind with this engine's registry; a registry without it does not.
    assert.deepEqual(validateConfig(tokenConfig(), t.engine.registry), []);
    assert.deepEqual(validateConfig(tokenConfig(), new ModuleRegistry({ adapters: t.engine.registry.adapters, modules: builtInModules() })), [
      "policy: level 1 set [hardware_token]: unknown factor hardware_token",
      "modules.badge.settings: factor hardware_token is not installed",
    ]);
    t.engine.configure(tokenConfig());
    assert.deepEqual(await t.engine.submitFactor(callId, "hardware_token", "000000"), { matched: false, locked: false });
    // A failure starts a wait across calls (VER-1, #71).
    t.clock.advance(900_000);
    assert.deepEqual(await t.engine.submitFactor(callId, "hardware_token", "246810"), { matched: true, locked: false });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal(judged.length, 2);
    assert.equal(Object.values(judged[0]!).includes(TEST_KNOWLEDGE_KEY), false, "the judge gets hmac, never the key");
    const entries = await t.ledger.list();
    assert.equal(JSON.stringify(entries).includes("246810"), false, "the entry is never written");
  });

  it("useFactor: a kind named like an inherited key (constructor) still stops at its attempt limit", async () => {
    const judged: FactorJudgeInput[] = [];
    const t = setup();
    t.engine.useFactor({ ...token(judged), kind: "constructor", maxAttemptsPerCall: 1 });
    t.engine.configure(
      testConfig((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["constructor"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("constructor");
      }),
    );
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "constructor", "000000"), { matched: false, locked: true });
    assert.deepEqual(await t.engine.submitFactor(callId, "constructor", "246810"), { matched: false, locked: true }, "not judged past the limit");
    assert.equal(judged.length, 1);
  });

  it("useFactor: the registry refuses clashes and caller-ID names, and nothing changes", () => {
    const t = setup();
    t.engine.use(tokenModule());
    const kinds = t.engine.registry.factorKinds();
    const badge = t.engine.registry.get("badge");
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "caller_id" }), rejects("invalid_input", /would make caller ID a factor/));
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "pin" }), rejects("invalid_input", /factor kind pin already exists/));
    assert.throws(() => t.engine.useFactor(token()), rejects("invalid_input", /factor hardware_token is already provided by token-check/));
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "ab", maxAttemptsPerCall: 9 }), rejects("invalid_input", /snake_case.*maxAttemptsPerCall/));
    assert.throws(() => t.engine.useFactor({ ...token(), kind: { toString: () => "desk_code" } as unknown as string }), rejects("invalid_input", /factor kind must be a string/));
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "desk_code", adapters: "records" as unknown as [] }), rejects("invalid_input", /adapters must be a list of adapter names/));
    const fob = tokenModule({ ...token(), kind: "key_fob", adapters: "records" as unknown as [] });
    assert.throws(() => t.engine.use({ ...fob, manifest: { ...fob.manifest, name: "fob-check" } }), rejects("invalid_input", /^module fob-check: factor key_fob: adapters must be a list of adapter names$/));
    t.engine.useFactor({ ...token(), kind: "desk_code" });
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "desk_code" }), rejects("invalid_input", /desk_code already exists/));
    // After the built-in kinds (#110's callback among them), before the outside modules' ones.
    assert.deepEqual(t.engine.registry.factorKinds(), [...kinds.slice(0, 7), "desk_code", ...kinds.slice(7)]);
    assert.notEqual(t.engine.registry.get("badge"), badge, "a new build of Badge");
    assert.deepEqual(t.engine.registry.list().map((m) => m.manifest.name), ["badge", "dossier", "paylink", "trace", "gate", "step-up", "token-check"], "in its place");
  });

  it("useFactor on one engine never reaches another engine built with the same Badge", () => {
    const shared = badgeModule();
    const one = setup({ badge: shared });
    const two = setup({ badge: shared });
    one.engine.useFactor(token());
    assert.ok(one.engine.registry.factorKinds().includes("hardware_token"));
    assert.equal(two.engine.registry.factorKinds().includes("hardware_token"), false);
    assert.equal(shared.manifest.provides.factors.includes("hardware_token"), false);
    assert.deepEqual(validateConfig(tokenConfig(), two.engine.registry).length, 2);
  });

  it("useFactor needs Badge installed", () => {
    const t = setup({ config: testConfig((c) => (c.modules.badge = { enabled: false })) });
    t.engine.remove("badge");
    assert.throws(() => t.engine.useFactor(token()), rejects("precondition_failed", /badge module is not installed/));
    // An outside module's factors install without Badge; nothing runs them.
    t.engine.use(tokenModule());
    assert.ok(t.engine.registry.factorKinds().includes("hardware_token"));
    t.engine.remove("token-check");
    assert.equal(t.engine.registry.get("badge"), undefined);
  });

  it("use: an outside module's factor and judge, off until a config turns it on, at construction or later", async () => {
    const judged: FactorJudgeInput[] = [];
    const t = setup();
    t.engine.use(tokenModule(token(judged)));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitFactor(callId, "hardware_token", "246810"), rejects("precondition_failed", /turned off/));
    assert.deepEqual(validateConfig(tokenConfig(), t.engine.registry), []);
    t.engine.configure(tokenConfig());
    assert.deepEqual(await t.engine.submitFactor(callId, "hardware_token", "246810"), { matched: true, locked: false });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal(judged.length, 1);
    // Given at construction, with a config that already turns it on.
    const built = setup({ modules: [tokenModule()], config: tokenConfig() });
    const call = await built.engine.startCall();
    await built.engine.beginVerification(call.callId, { accountNumber: ACCOUNT });
    assert.equal((await built.engine.submitFactor(call.callId, "hardware_token", "246810")).matched, true);
    // The registry refuses an outside module whose factor clashes, is named for caller ID, or has no judge.
    assert.throws(() => t.engine.use({ ...tokenModule(), manifest: { ...tokenModule().manifest, name: "pin-two", provides: { factors: ["pin"], steps: [], outcomes: [] } } }), rejects("invalid_input", /factor pin is already provided by badge/));
    assert.throws(() => t.engine.use(tokenModule({ ...token(), kind: "ani" })), rejects("invalid_input", /factor kind ani would make caller ID a factor/));
    assert.throws(() => t.engine.use({ ...tokenModule(), manifest: { ...tokenModule().manifest, name: "no-judge" }, factorPlugins: [] }), rejects("invalid_input", /factor hardware_token is already provided by token-check; module no-judge: factor hardware_token has no judge/));
    const { factorPlugins: _omitted, ...withoutList } = tokenModule({ ...token(), kind: "desk_code" });
    assert.throws(() => t.engine.use({ ...withoutList, manifest: { ...withoutList.manifest, name: "no-list" } }), rejects("invalid_input", /module no-list: factor desk_code has no judge/));
    assert.equal(t.engine.registry.get("no-list"), undefined);
  });

  it("remove: refuses a module whose factor the config names, then takes its factor away", async () => {
    const t = setup({ modules: [tokenModule()], config: tokenConfig() });
    assert.throws(() => t.engine.remove("token-check"), rejects("precondition_failed", /supplies the factor hardware_token, which the config uses/));
    t.engine.configure(tokenConfig(false));
    assert.throws(() => t.engine.remove("token-check"), rejects("precondition_failed", /which the config uses/), "the policy names it");
    t.engine.configure(testConfig());
    t.engine.remove("token-check");
    assert.equal(t.engine.registry.factorKinds().includes("hardware_token"), false);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitFactor(callId, "hardware_token", "246810"), rejects("invalid_input", /not a factor the caller enters/));
    assert.deepEqual(validateConfig(tokenConfig(), t.engine.registry).length, 2);
    // With Badge off, only the policy counts.
    const off = setup({ modules: [tokenModule()], config: testConfig((c) => (c.modules.badge = { enabled: false })) });
    off.engine.remove("token-check");
    assert.throws(() => off.engine.remove("token-check"), rejects("invalid_input", /no module named token-check/));
  });
});

describe("results that arrive late (CodeRabbit threads on PR 3)", () => {
  it("writes no factor error after the call ended or the verification restarted while a judge was throwing", async () => {
    let during: () => Promise<void> = async () => undefined;
    const t = setup({
      badge: badgeModule({
        factors: [
          {
            kind: "flaky_check",
            summary: "a judge whose store fails after the call moved on",
            maxAttemptsPerCall: 2,
            adapters: [],
            judge: async () => {
              await during();
              throw new Error("store unavailable");
            },
          },
        ],
      }),
      config: testConfig((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["flaky_check"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("flaky_check");
      }),
    });
    const ended = await t.engine.startCall();
    await t.engine.beginVerification(ended.callId, { accountNumber: ACCOUNT });
    during = async () => {
      await t.engine.endCall(ended.callId);
    };
    await assert.rejects(t.engine.submitFactor(ended.callId, "flaky_check", "x"), /store unavailable/);
    const afterEnd = (await t.ledger.list()).filter((e) => e.callId === ended.callId).map((e) => e.event);
    assert.deepEqual(afterEnd.slice(afterEnd.indexOf("call.ended")), ["call.ended", "receipt.issued"], "no factor error after call.ended");

    const restarted = await t.engine.startCall();
    await t.engine.beginVerification(restarted.callId, { accountNumber: ACCOUNT });
    // The first call's failure started a wait across calls (VER-1): waited out first.
    t.clock.advance(900_000);
    during = async () => {
      await t.engine.finishVerification(restarted.callId);
      await t.engine.beginVerification(restarted.callId, { accountNumber: "99999999" });
    };
    await assert.rejects(t.engine.submitFactor(restarted.callId, "flaky_check", "x"), /store unavailable/);
    const afterRestart = (await t.ledger.list()).filter((e) => e.callId === restarted.callId).map((e) => e.event);
    assert.equal(afterRestart.at(-1), "verification.started", "an earlier verification's error is not written into the new one");
  });

  it("never applies a factor judged for a verification that restarted for another subject", async () => {
    const t = setup({
      badge: badgeModule({
        factors: [
          {
            kind: "slow_check",
            summary: "a judge that lets the call move on meanwhile",
            maxAttemptsPerCall: 1,
            adapters: [],
            judge: async () => {
              await t.engine.finishVerification(callId);
              await t.engine.beginVerification(callId, { accountNumber: "99999999" });
              return true;
            },
          },
        ],
      }),
      config: testConfig((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["slow_check"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("slow_check");
      }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.submitFactor(callId, "slow_check", "x"), rejects("precondition_failed", /verification restarted/));
    assert.deepEqual((await t.engine.state(callId)).factors, [], "nothing counts for the other subject");
  });

  it("never stores a carrier report for a subject other than the one it checked", async () => {
    const t = setup();
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "22222222", phoneOnFile: "+15555550199", knowledge: {}, pin: "9999" }));
    t.carrier.set("+15555550100", { identityMatch: "match" });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: "19850214" });
    const check = t.carrier.check.bind(t.carrier);
    t.carrier.check = async (input) => {
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: "22222222" });
      await t.engine.submitPin(callId, "9999");
      return check(input);
    };
    await assert.rejects(t.engine.checkCarrier(callId), rejects("precondition_failed", /verification restarted/));
    assert.deepEqual((await t.engine.state(callId)).factors.map((f) => f.kind), ["pin"]);
  });

  it("drops a pending photo ID check when the subject changes, and resumes a link after a failure", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: "19850214" });
    const create = t.identity.createDocumentCheck.bind(t.identity);
    t.identity.createDocumentCheck = async () => {
      throw new Error("provider down");
    };
    await assert.rejects(t.engine.startPhotoId(callId), /provider down/);
    t.identity.createDocumentCheck = create;
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    await assert.rejects(t.engine.startPhotoId(callId), /carrier down/);
    t.messages.sendText = send;
    assert.deepEqual(await t.engine.startPhotoId(callId), { sent: true }, "resumed, same check");
    assert.equal(t.identity.created.length, 1);
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed", /already sent/));
    // The subject changes: the check sent for the first one no longer counts.
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, "33333333") });
    assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId: t.identity.created[0]!.sessionId, status: "verified" }), { applied: false });
  });

  it("voids a reserved link when the subject changes before it was created", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    await t.engine.submitPin(callId, PIN);
    t.identity.createDocumentCheck = async () => {
      throw new Error("provider down");
    };
    await assert.rejects(t.engine.startPhotoId(callId), /provider down/);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
  });
});

describe("PIN enrolment and reset (VER-6)", () => {
  const NEW_ACCOUNT = "20481937";
  const NEW_PHONE = "+15555550142";
  const NEW_SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, NEW_ACCOUNT);
  const CHOSEN = "5831";
  const pinSettings = (c: FlowConfig) => (c.modules.badge!.settings as { factors: string[]; pin: { mode: string; maxAttemptsPerCall: number } });

  /** A test engine with 5 PIN tries per call, a second subject on file who has no PIN yet, and a carrier that matches their number. */
  function enrolSetup(options: TestEngineOptions = {}): TestEngine {
    const t = setup({ config: testConfig((c) => (pinSettings(c).pin.maxAttemptsPerCall = 5)), ...options });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: NEW_ACCOUNT, phoneOnFile: NEW_PHONE, knowledge: { dob: DOB } }));
    t.carrier.set(NEW_PHONE, { identityMatch: "match" });
    return t;
  }

  /** A call verified by keypad, and by the carrier too unless `level` is 1. */
  async function verified(t: TestEngine, level: 1 | 2 = 2): Promise<string> {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    if (level === 2) await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, level);
    return callId;
  }

  it("needs a verification at level 2 or above on this call, on an open call", async () => {
    const t = enrolSetup();
    const { callId: none } = await t.engine.startCall();
    await assert.rejects(t.engine.enrolPin(none, { pin: CHOSEN, confirm: CHOSEN }), rejects("scope_denied"), "no grant");
    await assert.rejects(t.engine.enrolPin(await verified(t, 1), { pin: CHOSEN, confirm: CHOSEN }), rejects("scope_denied"), "level 1");
    const expired = await verified(t);
    t.clock.advance(900_000);
    await assert.rejects(t.engine.enrolPin(expired, { pin: CHOSEN, confirm: CHOSEN }), rejects("scope_denied"), "the grant expired");
    const verifying = await verified(t);
    await t.engine.beginVerification(verifying, { accountNumber: NEW_ACCOUNT });
    await assert.rejects(t.engine.enrolPin(verifying, { pin: CHOSEN, confirm: CHOSEN }), rejects("invalid_transition"));
    const tainted = await verified(t);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.enrolPin(tainted, { pin: CHOSEN, confirm: CHOSEN }), rejects("scope_denied"));
    const ended = await verified(t);
    await t.engine.endCall(ended);
    await assert.rejects(t.engine.enrolPin(ended, { pin: CHOSEN, confirm: CHOSEN }), rejects("invalid_transition"));
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, undefined, "nothing was stored");
  });

  it("stores the digest submitPin compares, writes pin.enrolled without the digits, and refuses a second PIN", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, NEW_SUBJECT, CHOSEN));
    const entries = await t.ledger.list();
    const enrolled = entries.filter((e) => e.event === "pin.enrolled");
    assert.equal(enrolled.length, 1);
    assert.deepEqual([enrolled[0]!.actor, enrolled[0]!.callId, enrolled[0]!.detail], ["caller", callId, {}]);
    assert.equal(JSON.stringify(entries).includes(`"${CHOSEN}"`), false, "the PIN is never written");
    await assert.rejects(t.engine.enrolPin(callId, { pin: "6094", confirm: "6094" }), rejects("precondition_failed", /only the business/));
    const next = await t.engine.startCall();
    await t.engine.beginVerification(next.callId, { subjectKey: NEW_SUBJECT });
    assert.deepEqual(await t.engine.submitPin(next.callId, CHOSEN), { matched: true, locked: false });
  });

  it("refuses weak, mismatched and malformed PINs, counting each try, and locks after the PIN's limit", async () => {
    const t = enrolSetup();
    const first = await verified(t);
    for (const weak of ["1111", "1234", "4321", "7890"]) {
      assert.deepEqual(await t.engine.enrolPin(first, { pin: weak, confirm: weak }), { enrolled: false, reason: "weak" }, weak);
    }
    assert.deepEqual(await t.engine.enrolPin(first, { pin: DOB, confirm: DOB }), { enrolled: false, reason: "weak" }, "the date of birth on file");
    assert.deepEqual(await t.engine.enrolPin(first, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: false, reason: "locked" }, "even a good PIN after 5 tries");
    const second = await verified(t);
    assert.deepEqual(await t.engine.enrolPin(second, { pin: NEW_ACCOUNT, confirm: NEW_ACCOUNT }), { enrolled: false, reason: "weak" }, "the account number");
    assert.deepEqual(await t.engine.enrolPin(second, { pin: CHOSEN, confirm: "5832" }), { enrolled: false, reason: "mismatch" });
    assert.deepEqual(await t.engine.enrolPin(second, { pin: "583", confirm: "583" }), { enrolled: false, reason: "malformed" }, "below minDigits");
    assert.deepEqual(await t.engine.enrolPin(second, { pin: "583194027", confirm: "583194027" }), { enrolled: false, reason: "malformed" }, "above maxDigits");
    assert.deepEqual(await t.engine.enrolPin(second, { pin: CHOSEN, confirm: "58a1" }), { enrolled: false, reason: "malformed" });
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, undefined);
    assert.equal((await t.ledger.list()).some((e) => e.event === "pin.enrolled"), false);
  });

  it("judges weakness without the engine: one digit, runs both ways, and runs through zero", () => {
    for (const pin of ["0000", "1234", "4321", "7890", "0987", "9012", "23456789"]) assert.equal(isWeakPin(pin), true, pin);
    for (const pin of ["5831", "1235", "1212", "1357", "2468"]) assert.equal(isWeakPin(pin), false, pin);
  });

  it("is refused in verifier mode, with the pin factor off, during a flow and after it", async () => {
    const verifier = enrolSetup({ config: testConfig((c) => (pinSettings(c).pin.mode = "verifier")) });
    await assert.rejects(verifier.engine.enrolPin(await verified(verifier), { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /verifier mode/));
    const off = enrolSetup({ config: testConfig((c) => (pinSettings(c).factors = ["keypad_knowledge", "carrier_identity_match", "photo_id"])) });
    await assert.rejects(off.engine.enrolPin(await verified(off), { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /turned off/));
    await assert.rejects(off.engine.resetPin(NEW_SUBJECT), rejects("precondition_failed", /turned off/));
    const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"] };
    const t = enrolSetup({
      config: testConfig((c) => {
        c.flows = { verify: { steps: [verify] }, intake: { steps: [verify, { type: "dossier.collect", form: "repair" }] } };
      }),
    });
    for (const [flow, message] of [["intake", /outside a flow/], ["verify", /has completed/]] as const) {
      const { callId } = await t.engine.startCall({ flow });
      await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
      await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", message), flow);
    }
  });

  it("refuses a subject that is no longer on file, and stores the PIN even if verification restarted meanwhile", async () => {
    const t = enrolSetup();
    const gone = await verified(t);
    const getSubject = t.records.getSubject.bind(t.records);
    t.records.getSubject = async () => null;
    await assert.rejects(t.engine.enrolPin(gone, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /not on file/));
    t.records.getSubject = getSubject;
    const callId = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
      await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
      return put(workspaceId, subjectKey, digest, enrolmentId);
    };
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, NEW_SUBJECT, CHOSEN));
  });

  it("lets one of two enrolments at once win, and refuses the other without replacing the PIN", async () => {
    const t = enrolSetup();
    const loser = await verified(t);
    const winner = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    let raced = false;
    t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
      if (!raced) {
        raced = true;
        assert.deepEqual(await t.engine.enrolPin(winner, { pin: "6094", confirm: "6094" }), { enrolled: true });
      }
      return put(workspaceId, subjectKey, digest, enrolmentId);
    };
    await assert.rejects(t.engine.enrolPin(loser, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/));
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, NEW_SUBJECT, "6094"));
    assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
  });

  it("finishes an enrolment whose session write failed after the PIN was stored, once, with the same PIN only", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(workspaceId, subjectKey, digest, enrolmentId);
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), /session store down/);
    t.records.putPinDigest = put;
    const stored = (await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest;
    assert.ok(await pinOnFile(stored, NEW_SUBJECT, CHOSEN));
    const enrolledEvents = async () => (await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length;
    assert.equal(await enrolledEvents(), 0);
    await assert.rejects(t.engine.enrolPin(callId, { pin: "6094", confirm: "6094" }), rejects("precondition_failed", /only the business/), "another PIN");
    const other = await verified(t);
    await assert.rejects(t.engine.enrolPin(other, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/), "another call");
    // Two retries at once: both answer enrolled, and pin.enrolled is written once.
    const getSubject = t.records.getSubject.bind(t.records);
    t.records.getSubject = async (workspaceId, subjectKey) => {
      t.records.getSubject = getSubject;
      assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
      return getSubject(workspaceId, subjectKey);
    };
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
    assert.equal(await enrolledEvents(), 1);
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, stored);
    await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/), "already finished");
  });

  it("refuses a retry of the losing enrolment of the same PIN, so pin.enrolled is written once (CodeRabbit, PR 74)", async () => {
    const t = enrolSetup();
    const loser = await verified(t);
    const winner = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    let raced = false;
    t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
      if (!raced) {
        raced = true;
        assert.deepEqual(await t.engine.enrolPin(winner, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
      }
      return put(workspaceId, subjectKey, digest, enrolmentId);
    };
    await assert.rejects(t.engine.enrolPin(loser, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/));
    await assert.rejects(t.engine.enrolPin(loser, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/), "the retry");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
  });

  it("finishes an enrolment stored on the call's last try, and nothing else past the limit (CodeRabbit, PR 74)", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    for (let i = 0; i < 4; i++) assert.deepEqual(await t.engine.enrolPin(callId, { pin: "1111", confirm: "1111" }), { enrolled: false, reason: "weak" });
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
      t.records.putPinDigest = put;
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(workspaceId, subjectKey, digest, enrolmentId);
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), /session store down/, "the fifth and last try");
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: "6094", confirm: "6094" }), { enrolled: false, reason: "locked" }, "another PIN past the limit");
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
    assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: false, reason: "locked" }, "nothing left to finish");
  });

  it("locks past the limit when the last try's store write failed, whatever PIN comes next", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    for (let i = 0; i < 4; i++) await t.engine.enrolPin(callId, { pin: "1111", confirm: "1111" });
    const put = t.records.putPinDigest.bind(t.records);
    t.records.putPinDigest = async () => {
      t.records.putPinDigest = put;
      throw new Error("record store down");
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), /record store down/);
    for (const pin of [CHOSEN, "6094"]) assert.deepEqual(await t.engine.enrolPin(callId, { pin, confirm: pin }), { enrolled: false, reason: "locked" }, pin);
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, undefined);
  });

  for (const [second, label] of [["6094", "another PIN"], [CHOSEN, "the same PIN"]] as const) {
    it(`writes pin.enrolled for the PIN stored when two tries on one call race, the second with ${label} (CodeRabbit, PR 74)`, async () => {
      const t = enrolSetup();
      const callId = await verified(t);
      const put = t.records.putPinDigest.bind(t.records);
      let calls = 0;
      let other: Promise<unknown> = Promise.resolve();
      let reached = (): void => undefined;
      let release = (): void => undefined;
      const atStore = new Promise<void>((resolve) => (reached = resolve));
      t.records.putPinDigest = async (workspaceId, subjectKey, digest, enrolmentId) => {
        calls++;
        if (calls === 1) {
          // The second try records its pending digest and waits at the store while the first one stores.
          other = t.engine.enrolPin(callId, { pin: second, confirm: second });
          // Observed from the start: a second try that settles before the store fails here, not by hanging.
          const early = other.then(
            () => Promise.reject(new Error("the second try finished before it reached the store")),
            (e: unknown) => Promise.reject(new Error(`the second try failed before it reached the store: ${String(e)}`)),
          );
          early.catch(() => undefined);
          await within(Promise.race([atStore, early]), "the second try at the store");
        } else {
          reached();
          await new Promise<void>((resolve) => (release = resolve));
        }
        return put(workspaceId, subjectKey, digest, enrolmentId);
      };
      try {
        assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
      } finally {
        release();
      }
      await assert.rejects(other, rejects("precondition_failed", /only the business/));
      assert.ok(await pinOnFile((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, NEW_SUBJECT, CHOSEN));
      assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1, "the stored PIN is in the ledger, once");
      const stored = (await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { pinPending?: unknown[] } } };
      assert.deepEqual(stored.modules.badge.pinPending, [], "nothing left pending");
    });
  }

  it("is reset by the business only: the digest goes, the PIN counters are cleared, and the old PIN stops working", async () => {
    const resets: unknown[] = [];
    const t = enrolSetup({ adapters: { counters: resetRecorder(resets) } });
    await assert.rejects(t.engine.resetPin("not-hex"), rejects("invalid_input"));
    // A call that began verification before the reset cannot use the old PIN after it.
    const before = await t.engine.startCall();
    await t.engine.beginVerification(before.callId, { subjectKey: OWNER });
    await t.engine.resetPin(OWNER);
    assert.equal((await t.engine.submitPin(before.callId, PIN)).matched, false, "the old PIN no longer works on a call already verifying");
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, undefined);
    assert.deepEqual(
      resets,
      [
        { workspaceId: "ws_test", factor: "pin", scope: "subject", key: OWNER },
        { workspaceId: "ws_test", factor: "duress.hidden.pin", scope: "subject", key: OWNER },
      ],
      "VER-1's own counter key, and VER-12's hidden one",
    );
    const last = (await t.ledger.list()).find((e) => e.event === "pin.reset")!;
    assert.deepEqual([last.event, last.actor, last.callId, last.detail], ["pin.reset", "member", null, { subjectKey: OWNER }]);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, false, "the old PIN no longer works");
    // A subject the store does not have is left alone, and an engine without counters still resets.
    const plain = enrolSetup();
    await plain.engine.resetPin("c".repeat(64));
    assert.equal(await plain.records.getSubject("ws_test", "c".repeat(64)), null);
  });

  it("in verifier mode leaves the PIN to the host's store and still clears the counters", async () => {
    const resets: unknown[] = [];
    const t = enrolSetup({
      config: testConfig((c) => (pinSettings(c).pin.mode = "verifier")),
      adapters: { counters: resetRecorder(resets) },
    });
    await t.engine.resetPin(OWNER);
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", OWNER))!.pinDigest, OWNER, PIN));
    assert.deepEqual(resets, [
      { workspaceId: "ws_test", factor: "pin", scope: "subject", key: OWNER },
      { workspaceId: "ws_test", factor: "duress.hidden.pin", scope: "subject", key: OWNER },
    ]);
    assert.equal((await t.ledger.list()).at(-1)!.event, "pin.reset");
  });
});
