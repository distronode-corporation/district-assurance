// The PIN factor (keyed hash or the host's verifier) and factor plug-ins.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { validateConfig } from "../src/core/config.ts";
import { ModuleRegistry, type AssuranceModule } from "../src/core/module.ts";
import { builtInModules } from "../src/modules.ts";
import { badgeModule } from "../src/verify/badge.ts";
import type { FactorJudgeInput, FactorPlugin } from "../src/verify/factors.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { TEST_KNOWLEDGE_KEY, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, PIN, rejects, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);

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
    assert.deepEqual(entries[2]!.detail, { kind: "pin", passed: true });
    assert.equal(JSON.stringify(entries).includes(`"${PIN}"`), false, "the PIN is never written");
  });

  it("counts malformed, wrong and unknown-subject entries the same way, and locks after the limit", async () => {
    const t = setup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, "12"), { matched: false, locked: false }, "too short");
    assert.deepEqual(await t.engine.submitPin(callId, "123456789"), { matched: false, locked: false }, "too long");
    assert.deepEqual(await t.engine.submitPin(callId, "48a6"), { matched: false, locked: true }, "not digits, and the third attempt");
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
    assert.equal((await t.engine.submitFactor(callId, "pin", { pin: PIN })).matched, false);
    assert.equal((await t.engine.submitFactor(callId, "keypad_knowledge", "19850214")).matched, false, "keypad knowledge is a map of fields");
  });

  it("binds the digest to the subject", () => {
    assert.notEqual(pinDigest(TEST_KNOWLEDGE_KEY, "a".repeat(64), PIN), pinDigest(TEST_KNOWLEDGE_KEY, "b".repeat(64), PIN));
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
    assert.equal((await t.engine.submitPin(callId, "12")).matched, false);
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    assert.deepEqual(t.pinVerifier.asked, [OWNER, OWNER, OWNER], "the malformed entry was asked too, as a stand-in");
    const other = await t.engine.startCall();
    await t.engine.beginVerification(other.callId, { accountNumber: "12a" });
    t.pinVerifier.verify = async (input) => {
      t.pinVerifier.asked.push(input.subjectKey);
      return { matched: true }; // a verifier that says yes to a stand-in still never passes it
    };
    assert.equal((await t.engine.submitPin(other.callId, PIN)).matched, false);
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
    for (let i = 0; i < 3; i++) await assert.rejects(t.engine.submitPin(callId, PIN), /pin store down/);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true });
    assert.equal((await t.engine.state(callId)).factors.length, 0);
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
    assert.match(seen[0]!.hmac("x"), /^[0-9a-f]{64}$/);
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
    t.engine.useFactor({ ...token(), kind: "desk_code" });
    assert.throws(() => t.engine.useFactor({ ...token(), kind: "desk_code" }), rejects("invalid_input", /desk_code already exists/));
    assert.deepEqual(t.engine.registry.factorKinds(), [...kinds.slice(0, 6), "desk_code", ...kinds.slice(6)]);
    assert.notEqual(t.engine.registry.get("badge"), badge, "a new build of Badge");
    assert.deepEqual(t.engine.registry.list().map((m) => m.manifest.name), ["badge", "dossier", "paylink", "trace", "token-check"], "in its place");
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
