// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Regressions for CodeRabbit's re-review of the L3 integration (#131, 3539bf6): each case failed before its fix.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { IntakeRecord } from "../src/core/adapters.ts";
import { REDACTION_MARKERS, cardNumberRedactor, composeRedactors, healthCardRedactor, sinRedactor, type RedactionKind, type Redactor } from "../src/core/redaction.ts";
import { deliverRecord } from "../src/file/delivery.ts";
import { validateForm, type IntakeForm } from "../src/file/intake.ts";
import { problemMessage } from "../src/core/module.ts";
import { verifySubjectExport } from "../src/prove/subject.ts";
import { LEDGER_PAGE } from "../src/prove/trace.ts";
import { FakeFieldCipher, MemoryConsentStore, MemoryRecordStore } from "../src/testing/fakes.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, heard, rejects, setup, testConfig, verifiedCall } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const request = { workspaceId: "ws_test", subjectKey: SUBJECT };

/** A redactor that replaces every occurrence of any of the words with a kind's marker, in one pass, as the contract asks. */
function wordRedactor(words: string | string[], kind: RedactionKind): Redactor {
  return {
    redact(text) {
      const found = new RegExp([words].flat().join("|"), "g");
      const findings = [...text.matchAll(found)].map((m) => ({ kind, start: m.index, end: m.index + m[0].length }));
      return { text: text.replace(found, REDACTION_MARKERS[kind]), findings };
    },
  };
}

describe("L3 review round 3: redaction", () => {
  it("finds a Quebec health card whose four letters are spread by astral combining marks (the look-back is in UTF-16 units)", () => {
    const s = "\u{1D165}".repeat(8);
    const text = `T${s}R${s}E${s}M${s}75010112`;
    const result = healthCardRedactor.redact(text);
    assert.deepEqual(result.findings, [{ kind: "health_card", start: 0, end: text.length }]);
    assert.equal(result.text, REDACTION_MARKERS.health_card);
    // Ordinary prefixes still count, and a fifth letter before them still does not.
    assert.equal(healthCardRedactor.redact("TREM 7501 0112").findings.length, 1);
    assert.equal(healthCardRedactor.redact("XTREM 7501 0112").findings.length, 0);
  });

  it("keeps the offsets of what follows when a later redactor replaces only part of an earlier marker", () => {
    const text = "4111111111111111 tail";
    const once = composeRedactors(cardNumberRedactor, wordRedactor("card", "sin"), wordRedactor("tail", "bank_account")).redact(text);
    assert.deepEqual(once.findings, [
      { kind: "card_number", start: 0, end: 16 },
      { kind: "sin", start: 0, end: 16 },
      { kind: "bank_account", start: 17, end: 21 },
    ]);
    // Two findings inside one earlier marker, in one pass: the piece between them still maps to the card, and the text after it still lines up.
    const twice = composeRedactors(cardNumberRedactor, wordRedactor(["card", "removed"], "sin"), wordRedactor("tail", "bank_account")).redact(text);
    assert.equal(twice.text, `[${REDACTION_MARKERS.sin} number ${REDACTION_MARKERS.sin}] ${REDACTION_MARKERS.bank_account}`);
    assert.deepEqual(twice.findings, [
      { kind: "card_number", start: 0, end: 16 },
      { kind: "sin", start: 0, end: 16 },
      { kind: "sin", start: 0, end: 16 },
      { kind: "bank_account", start: 17, end: 21 },
    ]);
    const inBetween = composeRedactors(cardNumberRedactor, wordRedactor(["card", "removed"], "sin"), wordRedactor("number", "health_card")).redact(text);
    assert.deepEqual(inBetween.findings.at(-1), { kind: "health_card", start: 0, end: 16 }, "a finding over the piece left between them covers the card");
  });

  it("maps a finding that starts exactly where an inserted marker starts, inside an earlier one, to what that marker replaced", () => {
    const text = "4111111111111111 tail";
    // "[SIN removed]" now stands where "card" was, right after the "[" left of the card marker; "[SIN" starts at it.
    const result = composeRedactors(cardNumberRedactor, wordRedactor("card", "sin"), wordRedactor("\\[SIN", "health_card"), wordRedactor("tail", "bank_account")).redact(text);
    assert.deepEqual(result.findings.slice(2), [
      { kind: "health_card", start: 0, end: 16 },
      { kind: "bank_account", start: 17, end: 21 },
    ]);
    // A finding that starts at a marker in the plain case maps to its start, as before.
    assert.deepEqual(composeRedactors(cardNumberRedactor, wordRedactor("\\[card", "sin")).redact(text).findings[1], { kind: "sin", start: 0, end: 16 });
  });

  it("translates the offsets of many findings over many earlier markers without rescanning them (linear, not quadratic)", () => {
    const composed = composeRedactors(cardNumberRedactor, sinRedactor);
    const time = (n: number) => {
      const text = "4111111111111111 x 046454286 x ".repeat(n);
      const started = performance.now();
      const result = composed.redact(text);
      const took = performance.now() - started;
      assert.equal(result.findings.length, 2 * n);
      assert.deepEqual(result.findings.at(-1), { kind: "sin", start: 31 * (n - 1) + 19, end: 31 * (n - 1) + 28 });
      return took;
    };
    time(500);
    // The fastest of three runs each, so one pause of the process does not decide the ratio.
    const fastest = (n: number) => Math.min(time(n), time(n), time(n));
    const small = Math.max(fastest(2_000), 1);
    const large = fastest(32_000);
    // Sixteen times the input: a quadratic translation took about 56 times as long, a linear one takes about 12.
    assert.ok(large / small < 36, `32,000 pairs took ${Math.round(large)} ms, 2,000 took ${Math.round(small)} ms`);
  });
});

describe("L3 review round 3: deliverRecord", () => {
  it("records and retries an adapter that throws before returning a promise, and an answer whose status cannot be read", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const { recordId } = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: "whsec_delivery_test_not_a_secret" };
    let posts = 0;
    const delivery = {
      post: (() => {
        posts++;
        if (posts === 1) throw new Error("adapter broke before its promise");
        if (posts === 2)
          return Promise.resolve({
            get status(): number {
              throw new Error("status getter broke");
            },
          });
        return Promise.resolve({ status: 200 });
      }) as never,
    };
    const result = await deliverRecord({ destination, workspaceId: "ws_test", recordId, records: t.records, delivery, ledger: t.ledger, clock: t.clock, sleep: async () => undefined });
    assert.deepEqual([result.delivered, result.attempts, result.status], [true, 3, 200]);
    const attempts = (await t.ledger.list()).filter((e) => e.event === "delivery.attempted").map((e) => [e.detail.outcome, e.detail.status]);
    assert.deepEqual(attempts, [
      ["retry", null],
      ["retry", null],
      ["delivered", 200],
    ]);
  });
});

const STEP_UP = [{ name: "intake_flagged", scope: "intake.file", level: 2, signal: "intake_flagged" }];
const secretForm: IntakeForm = { formId: "secret", version: "1", fields: [{ key: "note", label: { en: "Note", fr: "Note" }, type: "text", required: true, sensitive: true }] };

/** A call verified to level 1 by the keypad alone, with a draft on the given form, under the intake step-up rule. */
async function level1Draft(t: TestEngine, formId: string, key: string, value: string): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  assert.equal((await t.engine.finishVerification(callId)).level, 1);
  await t.engine.startIntake(callId, formId);
  await t.engine.setIntakeField(callId, key, value);
  return callId;
}

const stepUpConfig = () =>
  testConfig((c) => {
    c.policy.stepUp = structuredClone(STEP_UP) as never;
    (c.modules.dossier!.settings as unknown as { forms: IntakeForm[] }).forms.push(structuredClone(secretForm));
  });

describe("L3 review round 3: confirmIntake under a step-up rule raised mid-filing", () => {
  it("writes nothing when the signal is raised while the record is sealed: refused at the claim, and abandonIntake releases it", async () => {
    const cipher = new FakeFieldCipher();
    const t = setup({ config: stepUpConfig(), adapters: { fieldCipher: cipher } });
    const callId = await level1Draft(t, "secret", "note", "A1");
    const encrypt = cipher.encrypt.bind(cipher);
    cipher.encrypt = async (plain, context) => {
      await t.engine.raiseSignal(callId, "intake_flagged");
      return encrypt(plain, context);
    };
    const puts: string[] = [];
    const put = t.records.putIntakeRecord.bind(t.records);
    t.records.putIntakeRecord = async (record, seen) => (puts.push(record.recordId), put(record, seen));
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("scope_denied", /intake_flagged/));
    assert.deepEqual(puts, [], "nothing written");
    assert.equal((await t.ledger.list()).some((e) => e.event === "intake.confirmed"), false);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
    await t.engine.abandonIntake(callId);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
  });

  it("files nothing and emits nothing when the signal is raised while the record is written; abandonIntake deletes what the write stored", async () => {
    const t = setup({ config: stepUpConfig(), adapters: { fieldCipher: new FakeFieldCipher() } });
    const callId = await level1Draft(t, "repair", "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    let raise = true;
    t.records.putIntakeRecord = async (record, seen) => {
      if (raise) {
        raise = false;
        await t.engine.raiseSignal(callId, "intake_flagged");
      }
      return put(record, seen);
    };
    const readBack = await heard(t, callId);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("scope_denied", /intake_flagged/));
    assert.equal((await t.ledger.list()).some((e) => e.event === "intake.confirmed"), false);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null, "the row the write stored is deleted at once, so no reader takes it for a confirmed record");
    const stored = (await t.sessions.get("ws_test", callId))!.record as unknown as { modules: { dossier: { intake: { writers?: Record<string, string>; abandoning?: boolean } } } };
    assert.deepEqual([stored.modules.dossier.intake.writers, stored.modules.dossier.intake.abandoning], [{}, true], "the refused write's claim is gone and the filing is being abandoned");
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("scope_denied"));
    await t.engine.abandonIntake(callId);
    assert.equal((await t.ledger.list()).filter((e) => e.event === "intake.abandoned").length, 1);
  });

  it("leaves a row whose delete failed after a refused write to abandonIntake, which deletes it", async () => {
    const t = setup({ config: stepUpConfig(), adapters: { fieldCipher: new FakeFieldCipher() } });
    const callId = await level1Draft(t, "repair", "issue", "leak");
    const put = t.records.putIntakeRecord.bind(t.records);
    t.records.putIntakeRecord = async (record, seen) => (await t.engine.raiseSignal(callId, "intake_flagged"), put(record, seen));
    const del = t.records.deleteIntakeRecords.bind(t.records);
    let fail = true;
    t.records.deleteIntakeRecords = async (ws, ids) => {
      if (fail) {
        fail = false;
        throw new Error("delete down");
      }
      return del(ws, ids);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("scope_denied", /intake_flagged/));
    assert.notEqual(await t.records.getIntakeRecord("ws_test", "rec_1"), null);
    await t.engine.abandonIntake(callId);
    assert.equal(await t.records.getIntakeRecord("ws_test", "rec_1"), null);
  });
});

/** A record store whose next write throws before storing, and whose deletes can be held. */
class HeldStore extends MemoryRecordStore {
  failNext = 0;
  hold: Promise<void> | null = null;
  override async putIntakeRecord(record: IntakeRecord, seen?: number): Promise<void> {
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("store down");
    }
    return super.putIntakeRecord(record, seen);
  }
  override async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
    const held = this.hold;
    this.hold = null;
    if (held !== null) await held;
    return super.deleteIntakeRecords(workspaceId, recordIds);
  }
}

describe("L3 review round 3: abandonIntake", () => {
  it("leaves a new draft alone when another abandonment of the same reservation finished while its delete was in flight", async () => {
    const records = new HeldStore();
    records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const t = setup({ adapters: { records } });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), /store down/);
    let release!: () => void;
    records.hold = new Promise((resolve) => (release = resolve));
    const slow = t.engine.abandonIntake(callId);
    await new Promise((resolve) => setImmediate(resolve));
    await t.engine.abandonIntake(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "burst pipe");
    const fresh = await heard(t, callId);
    release();
    await slow;
    assert.equal(await heard(t, callId), fresh, "the new draft is still there");
    assert.equal((await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: fresh })).values.issue, "burst pipe");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "intake.abandoned").length, 1, "one abandonment recorded");
  });
});

describe("L3 review round 3: abandonIntake against a filing committed before its claim", () => {
  it("leaves the filed record and a draft opened since alone", async () => {
    const records = new HeldStore();
    records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    const t = setup({ adapters: { records } });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    const readBack = await heard(t, callId);
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /store down/);
    const read = t.sessions.get.bind(t.sessions);
    let race = true;
    t.sessions.get = async (ws, id) => {
      const got = await read(ws, id);
      if (race) {
        race = false;
        await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack });
        await t.engine.startIntake(callId, "repair");
        await t.engine.setIntakeField(callId, "issue", "burst pipe");
      }
      return got;
    };
    await t.engine.abandonIntake(callId);
    assert.deepEqual((await t.engine.state(callId)).recordIds, ["rec_1"]);
    assert.notEqual(await records.getIntakeRecord("ws_test", "rec_1"), null);
    assert.equal((await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) })).values.issue, "burst pipe", "the new draft stays");
  });
});

describe("L3 review round 3: validateForm maxLength", () => {
  const form = (maxLength: unknown): IntakeForm => ({
    formId: "f",
    version: "1",
    fields: [{ key: "code", label: { en: "Code", fr: "Code" }, type: "text", required: true, maxLength: maxLength as number, pattern: "(a+)+$" }],
  });
  it("refuses a maxLength that is not a positive whole number, before the pattern's work bound reads it", () => {
    for (const bad of [Number.NaN, 0, -1, 1.5, "10", Number.POSITIVE_INFINITY, null]) {
      assert.ok(validateForm(form(bad)).map(problemMessage).includes("field code: maxLength must be a positive whole number"), String(bad));
    }
    const ok: IntakeForm = { formId: "f", version: "1", fields: [{ key: "code", label: { en: "Code", fr: "Code" }, type: "text", required: true, maxLength: 40, pattern: "[a-z]+" }] };
    assert.deepEqual(validateForm(ok), []);
  });
});

describe("L3 review round 3: subject export", () => {
  async function filed(consents?: MemoryConsentStore) {
    const t = setup(consents === undefined ? {} : { adapters: { consents } });
    const callId = await verifiedCall(t);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "leak");
    await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    await t.engine.endCall(callId);
    return { t, yes };
  }

  it("is refused when the export and the key both omit kid", async () => {
    const { t } = await filed();
    const exported = await t.engine.exportSubject(request);
    const keys = t.engine.receiptKeys();
    assert.equal(verifySubjectExport(exported, keys), true);
    const { kid: _dropped, ...bare } = exported;
    const bareKeys = keys.map(({ kid: _kid, ...k }) => k);
    assert.equal(verifySubjectExport(bare as never, bareKeys), false);
    assert.equal(verifySubjectExport({ ...exported, kid: 7 } as never, keys), false);
  });

  it("carries the ConsentStore's revocation of a listed consent, keeping the original yes", async () => {
    const consents = new MemoryConsentStore();
    const { t, yes } = await filed(consents);
    assert.deepEqual((await t.engine.exportSubject(request)).body.revocations, [], "nothing revoked yet");
    const revoked = await t.engine.revokeConsent({ consentId: yes.consentId, via: "text" });
    const body = (await t.engine.exportSubject(request)).body;
    assert.deepEqual(body.revocations, [revoked]);
    assert.equal(body.consents.find((c) => c.consentId === yes.consentId)!.answer, "yes");
    // A consent the store no longer has, and an engine with no store, carry none.
    consents.getConsent = async () => null;
    assert.deepEqual((await t.engine.exportSubject(request)).body.revocations, []);
    const { t: bare } = await filed();
    assert.deepEqual((await bare.engine.exportSubject(request)).body.revocations, []);
  });
});

describe("L3 review round 3: revokeConsent once the call is gone", () => {
  it("stores and ledgers the withdrawal of a yes the ledger never recorded, marked priorRecord: false", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    const { callId } = await t.engine.startCall();
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    // The store holds a yes for a call another engine (with its own ledger, and no session for the call) never recorded.
    const stray = { ...yes, consentId: "cns_stray" };
    await consents.putConsent("ws_test", stray);
    const later = createTestEngine({ config: testConfig(), adapters: { consents, ledger: t.ledger } });
    const withdrawn = await later.engine.revokeConsent({ consentId: stray.consentId, via: "web" });
    assert.deepEqual((await consents.getConsent("ws_test", stray.consentId))!.revoked, withdrawn);
    assert.deepEqual(await later.engine.revokeConsent({ consentId: stray.consentId, via: "text" }), withdrawn, "the first withdrawal stands");
    // Another workspace's consent.recorded for the same ids, on a shared ledger, proves nothing here.
    const other = createTestEngine({ workspaceId: "ws_other", config: testConfig(), adapters: { consents, ledger: t.ledger } });
    await consents.putConsent("ws_other", yes);
    await other.engine.revokeConsent({ consentId: yes.consentId, via: "web" });
    assert.equal((await later.engine.revokeConsent({ consentId: yes.consentId, via: "web" })).via, "web");
    const revoked = (await t.ledger.list()).filter((e) => e.event === "consent.revoked");
    assert.deepEqual(
      revoked.map((e) => [e.eventId?.startsWith('["ws_other"') === true, e.detail.consentId, e.detail.priorRecord]),
      [
        [false, stray.consentId, false],
        [true, yes.consentId, false],
        [false, yes.consentId, undefined],
      ],
      "every no reaches the ledger once; only the one this workspace recorded carries no priorRecord flag",
    );
    assert.deepEqual(Object.keys(revoked[0]!.detail).sort(), ["consentId", "priorRecord", "purpose", "via", "wordingVersion"], "no personal data added");
  });

  it("finds the consent.recorded entry past the first page of a long ledger, reading page by page", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    for (let i = 0; i < LEDGER_PAGE + 3; i++) await t.ledger.append({ callId: null, actor: "system", event: "signal.raised", at: "2026-01-01T00:00:00.000Z", detail: { signal: `filler_${i}` } });
    const { callId } = await t.engine.startCall();
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const pages: Array<[number | undefined, number | undefined]> = [];
    const list = t.ledger.list.bind(t.ledger);
    t.ledger.list = async (from, limit) => (pages.push([from, limit]), list(from, limit));
    const later = createTestEngine({ config: testConfig(), adapters: { consents, ledger: t.ledger } });
    await later.engine.revokeConsent({ consentId: yes.consentId, via: "web" });
    assert.deepEqual(pages, [
      [1, LEDGER_PAGE],
      [LEDGER_PAGE + 1, LEDGER_PAGE],
    ]);
    assert.equal((await list()).filter((e) => e.event === "consent.revoked").length, 1);
  });

  it("keeps reading past a page shorter than asked: an adapter may cap its pages", async () => {
    const consents = new MemoryConsentStore();
    const t = setup({ adapters: { consents } });
    for (let i = 0; i < 150; i++) await t.ledger.append({ callId: null, actor: "system", event: "signal.raised", at: "2026-01-01T00:00:00.000Z", detail: { signal: `filler_${i}` } });
    const { callId } = await t.engine.startCall();
    const yes = await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const list = t.ledger.list.bind(t.ledger);
    // At most 100 entries a page, whatever the limit asked.
    t.ledger.list = async (from, limit) => (await list(from, limit)).slice(0, 100);
    const later = createTestEngine({ config: testConfig(), adapters: { consents, ledger: t.ledger } });
    await later.engine.revokeConsent({ consentId: yes.consentId, via: "web" });
    const entry = (await list()).find((e) => e.event === "consent.revoked")!;
    assert.equal("priorRecord" in entry.detail, false, "the consent.recorded entry past the first short page was found");
  });
});
