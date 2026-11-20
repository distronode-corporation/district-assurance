// The synthetic voice signal (VER-14): a speech vendor's score can only make a call count for less.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import type { CallRecord } from "../src/core/runtime.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const THRESHOLDS = {
  acme: { spokenKnowledgeAbove: 0.5, levelOneAbove: 0.8 },
  "voice-co": { spokenKnowledgeAbove: 0.2, levelOneAbove: 0.4 },
};

function voiceConfig(patch: (config: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    (c.modules.badge!.settings as { syntheticVoice?: unknown }).syntheticVoice = structuredClone(THRESHOLDS);
    patch(c);
  });
}

/** A call verified to level 2 by keypad and a carrier match on the number on file. */
async function levelTwoCall(t: TestEngine): Promise<string> {
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  return callId;
}

/**
 * `spoken_knowledge` cannot be turned on until VER-3 builds it, so these tests record passed
 * factors straight into the call record, as that factor's judge will.
 */
async function recordPassed(t: TestEngine, callId: string, kinds: string[]): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const record = structuredClone(stored.record) as unknown as CallRecord;
  for (const kind of kinds) record.state.factors.push({ kind, passed: true, at: "2026-01-01T00:00:00.000Z" });
  assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as unknown as JsonValue)).ok, true);
}

/** A policy where a spoken answer counts: alone at level 1, with a carrier match at level 2. */
const spokenPolicy = (c: FlowConfig) => {
  // #84 built spoken_knowledge: a policy that counts it names its spoken fields.
  c.policy.spoken = { fields: { postal_code: "ca_postal_code" }, maxAttemptsPerCall: 2 };
  c.policy.levels[0]!.anyOf.push(["spoken_knowledge"], ["carrier_identity_match"]);
  c.policy.levels[1]!.anyOf.push(["spoken_knowledge", "carrier_identity_match"]);
};

describe("synthetic voice: the bands", () => {
  it("changes nothing at or below the vendor's first threshold", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    const before = await t.engine.state(callId);
    await t.engine.reportSyntheticVoice(callId, { score: 0.5, vendor: "acme" });
    const after = await t.engine.state(callId);
    assert.equal(after.syntheticVoice, "clear");
    assert.equal(after.level, 3);
    assert.deepEqual(after.grant, before.grant);
    assert.equal(await t.engine.authorize(callId, "contact.update"), true);
  });

  it("holds the call to level 1 above the second threshold, a grant already issued included", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    assert.equal(await t.engine.authorize(callId, "payment.request"), true);
    await t.engine.reportSyntheticVoice(callId, { score: 0.81, vendor: "acme" });
    const state = await t.engine.state(callId);
    assert.equal(state.syntheticVoice, "level_1");
    assert.equal(state.level, 1);
    assert.equal(state.grant!.level, 1);
    assert.deepEqual(state.grant!.scopes, ["intake.file", "status.read"], "the grant keeps only the scopes level 1 reaches");
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    assert.equal(await t.engine.authorize(callId, "contact.update"), false);
    assert.equal(await t.engine.authorize(callId, "status.read"), true);
  });

  it("judges each vendor against its own thresholds", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await levelTwoCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.45, vendor: "acme" });
    assert.equal((await t.engine.finishVerification(callId)).level, 2, "0.45 is clear for acme");
    await t.engine.reportSyntheticVoice(callId, { score: 0.45, vendor: "voice-co" });
    assert.equal((await t.engine.state(callId)).level, 1, "and above voice-co's second threshold");
  });

  it("stops spoken_knowledge counting above the first threshold, for a grant already issued too", async () => {
    const t = setup({ config: voiceConfig(spokenPolicy) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await recordPassed(t, callId, ["spoken_knowledge"]);
    assert.equal((await t.engine.finishVerification(callId)).level, 1, "a spoken answer alone reaches level 1");
    await t.engine.reportSyntheticVoice(callId, { score: 0.6, vendor: "acme" });
    const state = await t.engine.state(callId);
    assert.equal(state.syntheticVoice, "spoken_off");
    assert.equal(state.level, 0);
    assert.equal(state.grant, null, "the level rested on the spoken answer alone, so the grant is dropped");
    assert.equal(await t.engine.authorize(callId, "status.read"), false);
  });

  it("lowers a grant to what its other methods reach when spoken_knowledge stops counting", async () => {
    const t = setup({ config: voiceConfig(spokenPolicy) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await recordPassed(t, callId, ["spoken_knowledge", "carrier_identity_match"]);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    await t.engine.reportSyntheticVoice(callId, { score: 0.3, vendor: "voice-co" });
    const state = await t.engine.state(callId);
    assert.equal(state.level, 1, "the carrier match alone is level 1");
    assert.deepEqual(state.grant!.scopes, ["intake.file", "status.read"]);
  });

  it("does not count a spoken answer given after the score, and keeps the other factors", async () => {
    const t = setup({ config: voiceConfig(spokenPolicy) });
    const { callId } = await t.engine.startCall();
    await t.engine.reportSyntheticVoice(callId, { score: 0.7, vendor: "acme" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await recordPassed(t, callId, ["spoken_knowledge"]);
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    assert.equal((await t.engine.finishVerification(callId)).level, 1, "keypad knowledge still counts");
  });
});

describe("synthetic voice: nothing lifts or raises", () => {
  it("never lifts a cap with a later, lower score", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" });
    await t.engine.reportSyntheticVoice(callId, { score: 0.6, vendor: "acme" });
    await t.engine.reportSyntheticVoice(callId, { score: 0, vendor: "voice-co" });
    const state = await t.engine.state(callId);
    assert.equal(state.syntheticVoice, "level_1");
    assert.equal(state.level, 1);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] }, "verifying again reaches no higher");
  });

  it("holds a grant issued after the score to the cap, and fails a flow step that needs more", async () => {
    const t = setup({
      config: voiceConfig((c) => {
        c.flows.deposit = { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] }] };
      }),
    });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.reportSyntheticVoice(callId, { score: 0.99, vendor: "acme" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file"] });
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("never raises a level or stands in for a factor, and no score means no cap", async () => {
    const t = setup({ config: voiceConfig() });
    const { callId } = await t.engine.startCall();
    await t.engine.reportSyntheticVoice(callId, { score: 0, vendor: "acme" });
    assert.equal((await t.engine.state(callId)).level, 0);
    assert.equal(await t.engine.authorize(callId, "status.read"), false);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] });
    const unscored = await levelTwoCall(t);
    assert.equal((await t.engine.finishVerification(unscored)).level, 2);
    assert.equal((await t.engine.state(unscored)).syntheticVoice, "clear");
  });

  it("keeps a cap through a taint and a fresh verification", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.95, vendor: "acme" });
    await t.engine.markUntrusted(callId, "endpoint");
    const state = await t.engine.state(callId);
    assert.equal(state.syntheticVoice, "level_1");
    assert.equal(state.grant, null);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 1, "keypad and carrier would be level 2");
  });
});

describe("synthetic voice: the ledger and the receipt", () => {
  it("shows a capped call on its receipt exactly as an honestly lower one, and keeps every method in the ledger", async () => {
    // Capped after it finished: level 2 by keypad and carrier, held to 1 by a score.
    const late = setup({ config: voiceConfig() });
    const lateCall = await levelTwoCall(late);
    assert.equal((await late.engine.finishVerification(lateCall)).level, 2);
    await late.engine.reportSyntheticVoice(lateCall, { score: 0.9, vendor: "acme" });
    // Capped before it finished: the same factors, the score first.
    const early = setup({ config: voiceConfig() });
    const earlyCall = await levelTwoCall(early);
    await early.engine.reportSyntheticVoice(earlyCall, { score: 0.9, vendor: "acme" });
    assert.equal((await early.engine.finishVerification(earlyCall)).level, 1);
    // Honestly level 1: the keypad alone, no score.
    const honest = setup({ config: voiceConfig() });
    const { callId: honestCall } = await honest.engine.startCall();
    await honest.engine.beginVerification(honestCall, { accountNumber: ACCOUNT });
    await honest.engine.submitKeypad(honestCall, { dob: DOB });
    assert.equal((await honest.engine.finishVerification(honestCall)).level, 1);

    const shown = async (t: TestEngine, callId: string) => (await t.engine.endCall(callId))!.body.verification;
    const expected = await shown(honest, honestCall);
    assert.deepEqual(expected, { level: 1, methods: ["keypad_knowledge"], policyVersion: "default-1", configRevision: "default" });
    assert.deepEqual(await shown(late, lateCall), expected, "capped after finishing");
    assert.deepEqual(await shown(early, earlyCall), expected, "capped before finishing");
    for (const t of [late, early]) {
      const finished = (await t.ledger.list()).filter((e) => e.event === "verification.finished").at(-1)!.detail;
      assert.deepEqual(finished.methods, ["carrier_identity_match", "keypad_knowledge"], "the ledger keeps every counted method");
    }
  });


  it("never lists a method the band stopped counting on the receipt, whether the score came before or after the finish", async () => {
    // Level 1 takes a spoken answer alone; the call passes keypad, spoken answer and carrier match.
    const run = async (scoreFirst: boolean) => {
      const t = setup({ config: voiceConfig(spokenPolicy) });
      const callId = await levelTwoCall(t);
      await recordPassed(t, callId, ["spoken_knowledge"]);
      if (scoreFirst) await t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" });
      await t.engine.finishVerification(callId);
      if (!scoreFirst) await t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" });
      return (await t.engine.endCall(callId))!.body.verification as { level: number; methods: string[] };
    };
    const before = await run(true);
    const after = await run(false);
    assert.equal(after.level, 1);
    assert.ok(!after.methods.includes("spoken_knowledge"), `the band stopped spoken_knowledge counting: ${after.methods.join(", ")}`);
    assert.deepEqual(after, before, "the same receipt either way");
  });

  it("records the vendor and the band, never the score, and the receipt carries neither", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    await t.engine.reportSyntheticVoice(callId, { score: 0.8731, vendor: "acme" });
    await t.engine.reportSyntheticVoice(callId, { score: 0.1234, vendor: "voice-co" });
    const entries = (await t.ledger.list()).filter((e) => e.event === "verification.synthetic_voice");
    assert.deepEqual(
      entries.map((e) => [e.actor, e.detail]),
      [
        ["system", { vendor: "acme", band: "level_1" }],
        ["system", { vendor: "voice-co", band: "clear" }],
      ],
    );
    const ledger = JSON.stringify(await t.ledger.list());
    assert.equal(ledger.includes("8731") || ledger.includes("1234"), false, "no raw score");
    const receipt = JSON.stringify(await t.engine.endCall(callId));
    for (const word of ["synthetic", "level_1", "clear", "acme", "voice-co", "8731"]) assert.equal(receipt.includes(word), false, word);
  });

  it("names the vendor whose thresholds set the band, even if the caller changes the input during the update", async () => {
    const t = setup({ config: voiceConfig() });
    const callId = await verifiedCall(t);
    const input = { score: 0.6, vendor: "acme" };
    const pending = t.engine.reportSyntheticVoice(callId, input);
    input.vendor = "voice-co";
    input.score = 0.9;
    await pending;
    const entries = (await t.ledger.list()).filter((e) => e.event === "verification.synthetic_voice");
    assert.deepEqual(
      entries.map((e) => e.detail),
      [{ vendor: "acme", band: "spoken_off" }],
    );
    assert.equal((await t.engine.state(callId)).syntheticVoice, "spoken_off");
  });
});

describe("synthetic voice: refusals", () => {
  it("refuses a vendor without thresholds, a score outside 0 to 1, an ended call and Badge turned off", async () => {
    const t = setup({ config: voiceConfig() });
    const { callId } = await t.engine.startCall();
    for (const bad of [null, undefined, "acme"]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, bad as never), rejects("invalid_input", /score and vendor/), String(bad));
    }
    for (const vendor of ["other", "toString", "__proto__"]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, { score: 0.5, vendor }), rejects("invalid_input", /no synthetic voice thresholds/));
    }
    for (const score of [-0.1, 1.01, Number.NaN, Number.POSITIVE_INFINITY, "0.9" as unknown as number]) {
      await assert.rejects(t.engine.reportSyntheticVoice(callId, { score, vendor: "acme" }), rejects("invalid_input", /score must be/));
    }
    await t.engine.endCall(callId);
    await assert.rejects(t.engine.reportSyntheticVoice(callId, { score: 0.9, vendor: "acme" }), rejects("invalid_transition"));
    const unset = setup();
    const call = await unset.engine.startCall();
    await assert.rejects(unset.engine.reportSyntheticVoice(call.callId, { score: 0.9, vendor: "acme" }), rejects("invalid_input"), "no vendor configured: no score is taken");
    const off = setup({ config: voiceConfig((c) => (c.modules.badge!.enabled = false)) });
    const offCall = await off.engine.startCall();
    await assert.rejects(off.engine.reportSyntheticVoice(offCall.callId, { score: 0.9, vendor: "acme" }), rejects("module_disabled"));
  });

  it("reads a call stored before synthetic voice scores as clear, so a spoken answer still counts", async () => {
    const t = setup({ config: voiceConfig(spokenPolicy) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await recordPassed(t, callId, ["spoken_knowledge"]);
    const stored = (await t.sessions.get("ws_test", callId))!;
    const record = structuredClone(stored.record) as unknown as CallRecord;
    delete (record.state as Partial<CallRecord["state"]>).syntheticVoice;
    assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, record as unknown as JsonValue)).ok, true);
    assert.equal((await t.engine.finishVerification(callId)).level, 1, "no score was ever reported: no cap");
    await t.engine.reportSyntheticVoice(callId, { score: 0.6, vendor: "acme" });
    assert.equal((await t.engine.state(callId)).syntheticVoice, "spoken_off");
    assert.equal((await t.engine.state(callId)).level, 0, "and a score on it caps it as on any call");
  });

  it("checks the thresholds when the config is saved", () => {
    const registry = setup().engine.registry;
    const at = (syntheticVoice: unknown) =>
      validateConfig(
        testConfig((c) => ((c.modules.badge!.settings as { syntheticVoice?: unknown }).syntheticVoice = syntheticVoice as JsonValue)),
        registry,
      );
    assert.deepEqual(at(THRESHOLDS), []);
    assert.deepEqual(at({}), []);
    assert.deepEqual(at({ same: { spokenKnowledgeAbove: 0.7, levelOneAbove: 0.7 } }), [], "equal thresholds skip the middle band");
    assert.deepEqual(at([]), ["modules.badge.settings: syntheticVoice must map each vendor's name to its thresholds"]);
    assert.deepEqual(
      at({
        "Bad Name": 1,
        typed: { spokenKnowledgeAbove: "0.5", levelOneAbove: 2, extra: 0 },
        partial: { levelOneAbove: 0.5 },
        inverted: { spokenKnowledgeAbove: 0.9, levelOneAbove: 0.5 },
      }),
      [
        'modules.badge.settings: syntheticVoice vendor "Bad Name" must be 1 to 32 lower-case letters, digits, "-" or "_", starting with a letter',
        "modules.badge.settings: syntheticVoice.Bad Name must be {spokenKnowledgeAbove, levelOneAbove}",
        "modules.badge.settings: syntheticVoice.typed.extra is not a threshold",
        "modules.badge.settings: syntheticVoice.typed.spokenKnowledgeAbove must be a number from 0 to 1",
        "modules.badge.settings: syntheticVoice.typed.levelOneAbove must be a number from 0 to 1",
        "modules.badge.settings: syntheticVoice.partial.spokenKnowledgeAbove must be a number from 0 to 1",
        "modules.badge.settings: syntheticVoice.inverted.levelOneAbove must not be below spokenKnowledgeAbove",
      ],
    );
  });
});
