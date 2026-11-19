// The PIN factor (keyed hash or the host's verifier) and factor plug-ins.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { badgeModule } from "../src/verify/badge.ts";
import type { FactorJudgeInput } from "../src/verify/factors.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { isWeakPin } from "../src/verify/pin.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { TEST_KNOWLEDGE_KEY, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PIN, rejects, setup, testConfig } from "./helpers.ts";

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
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, pinDigest(TEST_KNOWLEDGE_KEY, NEW_SUBJECT, CHOSEN));
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
    t.records.putPinDigest = async (workspaceId, subjectKey, digest) => {
      await t.engine.beginVerification(callId, { accountNumber: NEW_ACCOUNT });
      return put(workspaceId, subjectKey, digest);
    };
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), { enrolled: true });
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, pinDigest(TEST_KNOWLEDGE_KEY, NEW_SUBJECT, CHOSEN));
  });

  it("lets one of two enrolments at once win, and refuses the other without replacing the PIN", async () => {
    const t = enrolSetup();
    const loser = await verified(t);
    const winner = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    let raced = false;
    t.records.putPinDigest = async (workspaceId, subjectKey, digest) => {
      if (!raced) {
        raced = true;
        assert.deepEqual(await t.engine.enrolPin(winner, { pin: "6094", confirm: "6094" }), { enrolled: true });
      }
      return put(workspaceId, subjectKey, digest);
    };
    await assert.rejects(t.engine.enrolPin(loser, { pin: CHOSEN, confirm: CHOSEN }), rejects("precondition_failed", /only the business/));
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, pinDigest(TEST_KNOWLEDGE_KEY, NEW_SUBJECT, "6094"));
    assert.equal((await t.ledger.list()).filter((e) => e.event === "pin.enrolled").length, 1);
  });

  it("finishes an enrolment whose session write failed after the PIN was stored, once, with the same PIN only", async () => {
    const t = enrolSetup();
    const callId = await verified(t);
    const put = t.records.putPinDigest.bind(t.records);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    t.records.putPinDigest = async (workspaceId, subjectKey, digest) => {
      t.sessions.compareAndSet = async () => {
        t.sessions.compareAndSet = cas;
        throw new Error("session store down");
      };
      return put(workspaceId, subjectKey, digest);
    };
    await assert.rejects(t.engine.enrolPin(callId, { pin: CHOSEN, confirm: CHOSEN }), /session store down/);
    t.records.putPinDigest = put;
    const stored = pinDigest(TEST_KNOWLEDGE_KEY, NEW_SUBJECT, CHOSEN);
    assert.equal((await t.records.getSubject("ws_test", NEW_SUBJECT))!.pinDigest, stored);
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

  it("is reset by the business only: the digest goes, the PIN counters are cleared, and the old PIN stops working", async () => {
    const resets: unknown[] = [];
    const t = enrolSetup({ adapters: { counters: { reset: async (input) => void resets.push(input) } } });
    await assert.rejects(t.engine.resetPin("not-hex"), rejects("invalid_input"));
    // A call that began verification before the reset cannot use the old PIN after it.
    const before = await t.engine.startCall();
    await t.engine.beginVerification(before.callId, { subjectKey: OWNER });
    await t.engine.resetPin(OWNER);
    assert.equal((await t.engine.submitPin(before.callId, PIN)).matched, false, "the old PIN no longer works on a call already verifying");
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, undefined);
    assert.deepEqual(resets, [{ workspaceId: "ws_test", kind: "pin", key: { subject: OWNER } }]);
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
      adapters: { counters: { reset: async (input) => void resets.push(input) } },
    });
    await t.engine.resetPin(OWNER);
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, pinDigest(TEST_KNOWLEDGE_KEY, OWNER, PIN));
    assert.equal(resets.length, 1);
    assert.equal((await t.ledger.list()).at(-1)!.event, "pin.reset");
  });
});
