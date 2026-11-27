// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Spoken answers (VER-3): exact normalisation of postal codes, ZIP codes and references in English
// and French, and the spoken_knowledge factor that compares them like keypad fields.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { defaultVerificationPolicy, validatePolicy as validatePolicyRaw, type SpokenFormat, type VerificationPolicy } from "../src/core/policy.ts";
import { problemMessage } from "../src/core/module.ts";
import type { Locale } from "../src/core/runtime.ts";
import { TEST_KNOWLEDGE_KEY, testSubject } from "../src/testing/index.ts";
import { judgeSpoken } from "../src/verify/factors.ts";
import { knowledgeDigest } from "../src/verify/knowledge.ts";

/** The policy validator's sentences, as the tests read them. */
const validatePolicy = (...args: Parameters<typeof validatePolicyRaw>): string[] => validatePolicyRaw(...args).map(problemMessage);
import { MAX_SPOKEN_TRANSCRIPT, normaliseSpokenAnswer, normaliseSpokenKeypadEntry } from "../src/verify/spoken.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

type Case = [locale: Locale, field: SpokenFormat, transcript: string, expected: string | "unusable"];

/** Transcripts as speech-to-text writes them, and the one value each must come out as. */
const CORPUS: Case[] = [
  // English: as written, digits and letter names, the NATO alphabet, "as in" and "for".
  ["en", "ca_postal_code", "K1A 0B1", "K1A0B1"],
  ["en", "ca_postal_code", "k1a0b1", "K1A0B1"],
  ["en", "ca_postal_code", "K one A zero B one", "K1A0B1"],
  ["en", "ca_postal_code", "Kay one A, zero, bee one.", "K1A0B1"],
  ["en", "ca_postal_code", "kay one ay zero bee one", "K1A0B1"],
  ["en", "ca_postal_code", "ee six jay three tee one", "E6J3T1"],
  ["en", "ca_postal_code", "kilo one alpha zero bravo one", "K1A0B1"],
  ["en", "ca_postal_code", "K as in kilo 1 A as in alpha 0 B for bravo 1", "K1A0B1"],
  ["en", "ca_postal_code", "B as in boy, three see, eight are, two", "B3C8R2"],
  ["en", "ca_postal_code", "aitch two ex, one why four", "H2X1Y4"],
  ["en", "ca_postal_code", "V6B-3K9", "V6B3K9"],
  ["en", "ca_postal_code", "M five vee three sea eight", "M5V3C8"],
  ["en", "ca_postal_code", "tango two juliett one x-ray niner", "T2J1X9"],
  ["en", "ca_postal_code", "T2J 1 zed 9", "T2J1Z9"],
  ["en", "us_zip_code", "90210", "90210"],
  ["en", "us_zip_code", "nine zero two one zero", "90210"],
  ["en", "us_zip_code", "1 0 0 0 1", "10001"],
  ["en", "reference", "alpha bravo one two charlie delta", "AB12CD"],
  ["en", "reference", "double u x ray 4 4", "WX44"],
  ["en", "reference", "double-you, why, zee, 7", "WYZ7"],
  ["en", "reference", "R7 gee 4 queue", "R7G4Q"],
  // French: chiffres, noms des lettres, l'alphabet radio et l'alphabet OTAN, "comme" et "comme dans".
  ["fr", "ca_postal_code", "K1A 0B1", "K1A0B1"],
  ["fr", "ca_postal_code", "K un A zéro B un", "K1A0B1"],
  ["fr", "ca_postal_code", "ka un a zéro bé un", "K1A0B1"],
  ["fr", "ca_postal_code", "Kilo un Alpha zéro Bravo un", "K1A0B1"],
  ["fr", "ca_postal_code", "H comme Henri deux X comme Xavier un i grec quatre", "H2X1Y4"],
  ["fr", "ca_postal_code", "J comme Joseph huit zède deux ka sept", "J8Z2K7"],
  ["fr", "ca_postal_code", "G un R quatre P cinq", "G1R4P5"],
  ["fr", "ca_postal_code", "C comme dans Célestin trois, enne, six, erre, neuf", "C3N6R9"],
  ["fr", "ca_postal_code", "Eugène? Non: E comme Eugène, six ji trois, té un", "unusable"],
  ["fr", "ca_postal_code", "E comme Eugène six ji trois té un", "E6J3T1"],
  ["fr", "us_zip_code", "neuf zéro deux un zéro", "90210"],
  ["fr", "reference", "double vé, ixe, quatre, quatre", "WX44"],
  ["fr", "reference", "Anatole Berthe un deux Célestin Désiré", "AB12CD"],
  ["fr", "reference", "Suzanne Thérèse Ursule Victor William Yvonne Zoé", "STUVWYZ"],
  ["fr", "reference", "effe, gé, ache, elle, emme, pé, ku, esse", "FGHLMPQS"],
  // Misrecognitions and near matches: never guessed, always unusable.
  ["en", "ca_postal_code", "K1A 0B", "unusable"],
  ["en", "ca_postal_code", "K1A 0B1 2", "unusable"],
  ["en", "ca_postal_code", "kay won A zero bee one", "unusable"],
  ["en", "ca_postal_code", "K one O zero B one", "unusable"],
  ["en", "ca_postal_code", "K I A zero B one", "unusable"],
  ["en", "ca_postal_code", "D1A 0B1", "unusable"],
  ["en", "ca_postal_code", "K1A 0B1 please", "unusable"],
  ["en", "ca_postal_code", "my postal code is K1A 0B1", "unusable"],
  ["en", "ca_postal_code", "B as in delta 3 C 8 R 2", "unusable"],
  ["en", "ca_postal_code", "as in kilo 1 A 0 B 1", "unusable"],
  ["en", "ca_postal_code", "K1A 0B1 as in", "unusable"],
  ["en", "ca_postal_code", "K as in 1 1 A 0 B 1", "unusable"],
  ["en", "ca_postal_code", "K1A as in kilo 0B1", "unusable"],
  ["en", "ca_postal_code", "K as in kilo as in kilo 1A0B1", "unusable"],
  ["en", "ca_postal_code", "K un A zero B one", "unusable"],
  ["en", "ca_postal_code", "K1А 0B1", "unusable"],
  ["en", "ca_postal_code", "K1A_0B1", "unusable"],
  ["en", "ca_postal_code", "", "unusable"],
  ["en", "ca_postal_code", "   ", "unusable"],
  ["en", "us_zip_code", "nine oh two one oh", "unusable"],
  ["en", "us_zip_code", "nine for two one zero", "unusable"],
  ["en", "us_zip_code", "ninety two one oh", "unusable"],
  ["en", "us_zip_code", "90210-1234", "unusable"],
  ["en", "us_zip_code", "double five two one zero", "unusable"],
  ["en", "reference", "ABC", "unusable"],
  ["en", "reference", "ABCD", "unusable"],
  ["en", "reference", "one two three four five six seven eight nine one two three four", "unusable"],
  ["fr", "ca_postal_code", "K one A zéro B un", "unusable"],
  ["fr", "ca_postal_code", "B comme Désiré trois C huit R deux", "unusable"],
  ["fr", "ca_postal_code", "B comme Berthe comme Berthe 3C8R2", "unusable"],
  ["fr", "ca_postal_code", "K un A zéro B œuf", "unusable"],
  ["fr", "us_zip_code", "quatre-vingt-dix deux un zéro", "unusable"],
  ["fr", "reference", "double cinq A B", "unusable"],
];

describe("normaliseSpokenAnswer", () => {
  for (const [locale, field, transcript, expected] of CORPUS) {
    it(`${locale} ${field}: ${JSON.stringify(transcript)} is ${expected}`, () => {
      const answer = normaliseSpokenAnswer({ field, transcript, locale });
      assert.deepEqual(answer, expected === "unusable" ? { status: "unusable" } : { status: "normalised", value: expected });
    });
  }

  it("refuses a transcript that is too long or not a string", () => {
    const long = `K1A 0B1${" ".repeat(MAX_SPOKEN_TRANSCRIPT)}`;
    assert.deepEqual(normaliseSpokenAnswer({ field: "ca_postal_code", transcript: long, locale: "en" }), { status: "unusable" });
    assert.deepEqual(normaliseSpokenAnswer({ field: "ca_postal_code", transcript: long.slice(0, MAX_SPOKEN_TRANSCRIPT), locale: "en" }), { status: "normalised", value: "K1A0B1" });
    assert.deepEqual(normaliseSpokenAnswer({ field: "ca_postal_code", transcript: 1 as unknown as string, locale: "en" }), { status: "unusable" });
  });

  it("throws on a field format or a locale it does not know, which is a host's bug", () => {
    assert.throws(() => normaliseSpokenAnswer({ field: "postal" as SpokenFormat, transcript: "K1A 0B1", locale: "en" }), rejects("invalid_input", /ca_postal_code, us_zip_code, reference/));
    assert.throws(() => normaliseSpokenAnswer({ field: "ca_postal_code", transcript: "K1A 0B1", locale: "de" as Locale }), rejects("invalid_input", /en or fr/));
  });
});

describe("normaliseSpokenKeypadEntry", () => {
  it("reads 1 to 32 digits, every value a keypad field can hold, and nothing else", () => {
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "seven", locale: "en" }), { status: "normalised", value: "7" });
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "un deux 3", locale: "fr" }), { status: "normalised", value: "123" });
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "1".repeat(32), locale: "en" }), { status: "normalised", value: "1".repeat(32) });
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "1".repeat(33), locale: "en" }), { status: "unusable" });
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "one oh two", locale: "en" }), { status: "unusable" }, "oh is a letter");
    assert.deepEqual(normaliseSpokenKeypadEntry({ transcript: "", locale: "en" }), { status: "unusable" });
    // Spanish is refused until a reviewed vocabulary exists (decision 6), like any locale without one.
    for (const locale of ["de", "es"] as Locale[]) assert.throws(() => normaliseSpokenKeypadEntry({ transcript: "1", locale }), rejects("invalid_input", /en or fr/), locale);
  });
});

const SPOKEN = { fields: { postal_code: "ca_postal_code" as const }, maxAttemptsPerCall: 2 };

function policy(patch: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return { ...defaultVerificationPolicy(), spoken: SPOKEN, ...patch };
}

describe("the policy's spoken fields", () => {
  it("can use spoken_knowledge alone at level 1, and only with a factor that is not knowledge above it", () => {
    assert.deepEqual(validatePolicy(policy({ levels: [{ level: 1, anyOf: [["spoken_knowledge"]] }] })), []);
    assert.deepEqual(validatePolicy(policy({ levels: [{ level: 2, anyOf: [["spoken_knowledge", "carrier_identity_match"]] }] })), []);
    assert.deepEqual(validatePolicy(policy({ levels: [{ level: 2, anyOf: [["spoken_knowledge"], ["spoken_knowledge", "keypad_knowledge"]] }] })), [
      "level 2 set [spoken_knowledge]: level 2 and above need two different factors",
      "level 2 set [spoken_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
      "level 2 set [spoken_knowledge, keypad_knowledge]: level 2 and above need a factor that is not something the caller knows (text_code, carrier_identity_match, photo_id, callback)",
    ]);
    assert.deepEqual(validatePolicy(policy({ levels: [{ level: 3, anyOf: [["spoken_knowledge", "photo_id"]] }] })), []);
  });

  it("needs spoken fields before a level can count spoken_knowledge", () => {
    const { spoken: _none, ...without } = policy({ levels: [{ level: 1, anyOf: [["spoken_knowledge"]] }] });
    assert.deepEqual(validatePolicy(without), ["level 1 set [spoken_knowledge]: spoken_knowledge needs the policy's spoken fields"]);
  });

  it("checks the fields, their formats and the attempt limit", () => {
    assert.deepEqual(validatePolicy(policy({ spoken: "x" as never })), ["spoken must be { fields, maxAttemptsPerCall }"]);
    assert.deepEqual(validatePolicy(policy({ spoken: { fields: {}, maxAttemptsPerCall: 0, x: 1 } as never })), [
      "spoken.x is not a spoken setting",
      "spoken.fields must map at least one field name to a format (ca_postal_code, us_zip_code, reference)",
      "spoken.maxAttemptsPerCall must be an integer from 1 to 5",
    ]);
    assert.deepEqual(validatePolicy(policy({ spoken: { fields: { dob: "reference", city: "name" }, maxAttemptsPerCall: 6 } as never })), [
      "spoken.fields.dob is also a keypad field",
      "spoken.fields.city must be one of ca_postal_code, us_zip_code, reference",
      "spoken.maxAttemptsPerCall must be an integer from 1 to 5",
    ]);
    assert.deepEqual(validatePolicy(policy({ keypadFields: "dob" as never, spoken: { fields: { dob: "reference" }, maxAttemptsPerCall: 5 } })), ["keypadFields must be a list of field names"]);
  });
});

const POSTAL = "K1A0B1";

function spokenConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.spoken = structuredClone(SPOKEN);
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["spoken_knowledge"]] };
    (c.modules.badge!.settings as { factors: string[] }).factors.push("spoken_knowledge");
    patch(c);
  });
}

function spokenSetup(config: FlowConfig = spokenConfig()) {
  const t = setup({ config });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB, postal_code: POSTAL } }));
  return t;
}

describe("the spoken_knowledge factor", () => {
  it("can be turned on in Badge's settings, and reaches level 1 alone", async () => {
    const t = spokenSetup();
    const { callId } = await t.engine.startCall({ locale: "fr" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "ka un a zéro bé un" }), { matched: true, locked: false });
    assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] });
  });

  it("reads the transcript in the call's language", async () => {
    const t = spokenSetup();
    const { callId } = await t.engine.startCall({ locale: "en" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "ka un a zéro bé un" }), { matched: false, locked: false });
    // A failure starts a wait across calls (VER-1, #71): waited out.
    t.clock.advance(900_000);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "kay one A zero bee one" }), { matched: true, locked: false });
  });

  it("counts an unusable or wrong answer as an attempt, then stops judging, even the right answer", async () => {
    const t = spokenSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B" }), { matched: false, locked: false });
    t.clock.advance(900_000);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B2" }), { matched: false, locked: true });
    t.clock.advance(900_000);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1" }), { matched: false, locked: true });
    assert.equal((await t.engine.finishVerification(callId)).level, 0);
    const entries = await t.ledger.list();
    const factors = entries.filter((e) => e.event === "verification.factor").map((e) => e.detail);
    assert.deepEqual(factors, [{ kind: "spoken_knowledge", passed: false }, { kind: "spoken_knowledge", passed: false }], "unusable and wrong look the same");
    assert.equal(JSON.stringify(entries).includes("K1A"), false, "no transcript or value in the ledger");
  });

  it("gives an unknown account the same answer as a wrong one", async () => {
    const t = spokenSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1" }), { matched: false, locked: false });
  });

  it("does not unlock texts to the number on file", async () => {
    const t = spokenSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1" }), { matched: true, locked: false });
    await assert.rejects(t.engine.startPhotoId(callId), rejects("precondition_failed"));
    assert.deepEqual(t.messages.sent, []);
  });

  it("is never judged when the policy has no spoken fields", async () => {
    const t = spokenSetup(
      spokenConfig((c) => {
        delete c.policy.spoken;
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"]] };
      }),
    );
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: "K1A 0B1" }), { matched: false, locked: true });
    assert.equal((await t.ledger.list()).some((e) => e.event === "verification.factor"), false);
  });

  it("judges every spoken field together, with a keyed digest, and fails closed on anything else", async () => {
    const hmac = async (data: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, data);
    const subject = { subjectKey: "s", phoneOnFile: PHONE_ON_FILE, knowledge: { postal_code: knowledgeDigest(TEST_KNOWLEDGE_KEY, "postal_code", POSTAL), ref: knowledgeDigest(TEST_KNOWLEDGE_KEY, "ref", "AB12") } };
    const input = (entry: string | Record<string, string>, s: typeof subject | null = subject) => ({ workspaceId: "w", subjectKey: "s", subject: s, entry, hmac, locale: "en" as const });
    const both = { fields: { postal_code: "ca_postal_code" as const, ref: "reference" as const }, maxAttemptsPerCall: 1 };
    assert.equal(await judgeSpoken(both, input({ postal_code: "K1A 0B1", ref: "alpha bravo one two" })), true);
    assert.equal(await judgeSpoken(both, input({ postal_code: "K1A 0B1", ref: "alpha bravo one three" })), false, "one field wrong");
    assert.equal(await judgeSpoken(both, input({ postal_code: "K1A 0B1" })), false, "one field missing");
    assert.equal(await judgeSpoken(both, input("K1A 0B1")), false, "a single string is not a set of fields");
    assert.equal(await judgeSpoken(both, input({ postal_code: "K1A 0B1", ref: "AB12" }, null)), false, "unknown subject");
    assert.equal(await judgeSpoken({ fields: {}, maxAttemptsPerCall: 1 }, input({})), false, "no fields is never a pass");
  });
});
