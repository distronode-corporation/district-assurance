// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Regressions for the CodeRabbit review of the L3 integration (#131): each case failed before its fix.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, IntakeRecord } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { DEFAULT_LOCKOUT } from "../src/verify/counters.ts";
import { bankAccountRedactor, cardNumberRedactor, composeRedactors } from "../src/core/redaction.ts";
import { deliverRecord } from "../src/file/delivery.ts";
import { validateForm, type IntakeForm } from "../src/file/intake.ts";
import { problemMessage } from "../src/core/module.ts";
import { FakeFieldCipher, FakeRecordDelivery, MemoryConsentStore, MemoryRecordStore } from "../src/testing/fakes.ts";
import { FakeDuressNotifier, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { hiddenCounterKey } from "../src/verify/duress-flag.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, confirmAmount, heard, rejects, setup, testConfig, verifiedCall, waitOut, wording } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const request = { workspaceId: "ws_test", subjectKey: SUBJECT };
const DURESS = "7391";
const POSTAL = "K1A0B1";

type Stored = { modules: Record<string, Record<string, unknown>> } & Record<string, unknown>;

/** Rewrites a call's stored record in place, as a record saved by an older version would read. */
async function patchStored(t: TestEngine, callId: string, edit: (record: Stored) => void): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const record = structuredClone(stored.record) as unknown as Stored;
  edit(record);
  assert.deepEqual(await t.sessions.compareAndSet("ws_test", callId, stored.version, record as unknown as JsonValue), { ok: true, version: stored.version + 1 });
}

async function drafted(t: TestEngine, formId = "repair", key = "issue", value = "leak"): Promise<string> {
  const callId = await verifiedCall(t);
  await t.engine.startIntake(callId, formId);
  await t.engine.setIntakeField(callId, key, value);
  return callId;
}

/** A record store whose next `failNext` writes throw before storing anything. */
class FailingStore extends MemoryRecordStore {
  failNext = 0;
  failDeletes = 0;
  override async putIntakeRecord(record: IntakeRecord, seen?: number): Promise<void> {
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("store down");
    }
    return super.putIntakeRecord(record, seen);
  }
  override async deleteIntakeRecords(workspaceId: string, recordIds: readonly string[]): Promise<void> {
    if (this.failDeletes > 0) {
      this.failDeletes--;
      throw new Error("delete down");
    }
    return super.deleteIntakeRecords(workspaceId, recordIds);
  }
}

/** An idempotent store that keeps the first write of a record id; its next `lose` writes store and then fail. */
class KeepFirstStore extends MemoryRecordStore {
  lose = 0;
  override async putIntakeRecord(record: IntakeRecord, seen?: number): Promise<void> {
    if ((await this.getIntakeRecord(record.workspaceId, record.recordId)) === null) await super.putIntakeRecord(record, seen);
    if (this.lose > 0) {
      this.lose--;
      throw new Error("answer lost");
    }
  }
}

function seeded<T extends MemoryRecordStore>(store: T): T {
  store.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return store;
}

const note = (formId: string, sensitive: boolean): IntakeForm => ({
  formId,
  version: "1",
  fields: [{ key: "note", label: { en: "Note", fr: "Note" }, type: "text", required: true, ...(sensitive ? { sensitive: true } : {}) }],
});
const twoForms = () => testConfig((c) => (c.modules.dossier = { settings: { forms: [note("plain", false), note("secret", true)] } as unknown as JsonValue }));

describe("L3 review: confirmIntake", () => {
  it("refuses a draft started again on another form between its snapshot and its reservation (the keyed digests follow the form)", async () => {
    const t = setup({ config: twoForms(), adapters: { fieldCipher: new FakeFieldCipher() } });
    const callId = await drafted(t, "secret", "note", "A1");
    const secretReadBack = await heard(t, callId);
    await t.engine.abandonIntake(callId);
    await t.engine.startIntake(callId, "plain");
    await t.engine.setIntakeField(callId, "note", "A1");
    const count = t.records.subjectErasures.bind(t.records);
    let swap = true;
    t.records.subjectErasures = async (ws, key) => {
      if (swap) {
        swap = false;
        await t.engine.abandonIntake(callId);
        await t.engine.startIntake(callId, "secret");
        await t.engine.setIntakeField(callId, "note", "A1");
      }
      return count(ws, key);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: secretReadBack }), rejects("conflict", /draft changed while it was being filed/));
    const filed = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: secretReadBack });
    assert.notEqual(filed.values.note, "A1", "filed again, the value is sealed");
  });

  it("commits and returns the record the store kept, not a retry's fresh ciphertexts", async () => {
    const secure = note("secret", true);
    const records = seeded(new KeepFirstStore());
    const t = setup({ config: testConfig((c) => (c.modules.dossier = { settings: { forms: [secure] } as unknown as JsonValue })), adapters: { fieldCipher: new FakeFieldCipher(), records } });
    const callId = await drafted(t, "secret", "note", "A1");
    const readBack = await heard(t, callId);
    records.lose = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /answer lost/);
    const filed = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack });
    const kept = (await records.getIntakeRecord("ws_test", filed.recordId))!;
    assert.deepEqual(filed, kept);
    assert.deepEqual(await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), kept, "a retried confirmation gets the kept record back");
  });

  it("never files a filing reserved before erasures were counted (no erasuresSeen): refused, and abandonIntake releases it", async () => {
    const records = seeded(new FailingStore());
    const t = setup({ adapters: { records } });
    const callId = await drafted(t);
    const readBack = await heard(t, callId);
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /store down/);
    await patchStored(t, callId, (r) => delete (r.modules.dossier!.intake as Record<string, unknown>).erasuresSeen);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("precondition_failed", /before subject erasures were counted/));
    await t.engine.abandonIntake(callId);
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
  });
});

describe("L3 review: abandonIntake against a confirmation", () => {
  it("leaves the stored record of a confirmation that committed between its read and its delete", async () => {
    const records = seeded(new FailingStore());
    const t = setup({ adapters: { records } });
    const callId = await drafted(t);
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
      }
      return got;
    };
    await t.engine.abandonIntake(callId);
    assert.notEqual(await records.getIntakeRecord("ws_test", "rec_1"), null, "the filed record stays");
    assert.deepEqual((await t.engine.state(callId)).recordIds, ["rec_1"]);
  });

  it("an abandonment whose delete failed keeps any confirmation from writing, until it is finished", async () => {
    const records = seeded(new FailingStore());
    const t = setup({ adapters: { records } });
    const callId = await drafted(t);
    const readBack = await heard(t, callId);
    records.failNext = 1;
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), /store down/);
    records.failDeletes = 1;
    await assert.rejects(t.engine.abandonIntake(callId), /delete down/);
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack }), rejects("precondition_failed", /being abandoned/));
    await t.engine.abandonIntake(callId);
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null);
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
  });

  it("a write in flight when the abandonment claimed the filing files nothing, even when that abandonment's delete failed", async () => {
    const records = seeded(new FailingStore());
    const t = setup({ adapters: { records } });
    const callId = await drafted(t);
    const put = records.putIntakeRecord.bind(records);
    let race = true;
    records.putIntakeRecord = async (record, seen) => {
      if (race) {
        race = false;
        records.failDeletes = 1;
        await assert.rejects(t.engine.abandonIntake(callId), /delete down/);
      }
      return put(record, seen);
    };
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) }), rejects("precondition_failed", /abandoned while it was written/));
    assert.deepEqual((await t.engine.state(callId)).recordIds, []);
    await t.engine.abandonIntake(callId);
    assert.equal(await records.getIntakeRecord("ws_test", "rec_1"), null, "the finished abandonment deletes what the late write stored");
  });
});

describe("L3 review: MemoryRecordStore.putIntakeRecord", () => {
  it("checks the erasure count and stores in one step: an erasure that starts while the write is in the store sees the record", async () => {
    const store = new MemoryRecordStore();
    const record: IntakeRecord = { recordId: "r1", workspaceId: "w", callId: "c1", subjectKey: "s1", formId: "f", formVersion: "1", values: { a: "x" }, digest: "d", confirmedBy: "keypad", confirmedAt: "2026-01-01T00:00:00.000Z" };
    const writing = store.putIntakeRecord(record, 0);
    void store.markSubjectErased("w", "s1");
    const listed = await store.listIntakeRecords("w", "s1");
    await writing;
    assert.equal(listed.length === 1 || (await store.getIntakeRecord("w", "r1")) === null, true, "listed for the erasure, or kept out");
  });
});

describe("L3 review: eraseSubject against another erasure's plan", () => {
  /** Holds the next erasure just before it counts itself, until `release`. */
  function held(t: TestEngine): () => void {
    const mark = t.records.markSubjectErased.bind(t.records);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let first = true;
    t.records.markSubjectErased = async (ws, key) => {
      if (first) {
        first = false;
        await gate;
      }
      return mark(ws, key);
    };
    return release;
  }

  it("takes the next plan number for a record filed after the plan another erasure appended under the same number", async () => {
    const t = setup();
    await drafted(t).then((callId) => heard(t, callId).then((readBack) => t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack })));
    const release = held(t);
    const late = t.engine.eraseSubject(request);
    await new Promise((r) => setImmediate(r));
    await t.engine.eraseSubject(request);
    const callId = await drafted(t, "repair", "issue", "door stuck");
    const record = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    release();
    const result = await late;
    assert.deepEqual([result.erased, result.recordIds], [true, [record.recordId]]);
    assert.equal(await t.records.getIntakeRecord("ws_test", record.recordId), null, "the late record is erased");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "subject.erased").length, 2);
  });

  it("takes the next plan number for a PIN digest put back after a plan that had none", async () => {
    const t = setup();
    await t.records.deletePinDigest("ws_test", SUBJECT);
    await drafted(t).then((callId) => heard(t, callId).then((readBack) => t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack })));
    const release = held(t);
    const late = t.engine.eraseSubject(request);
    await new Promise((r) => setImmediate(r));
    assert.equal((await t.engine.eraseSubject(request)).pinDigest, false);
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    release();
    const result = await late;
    assert.deepEqual([result.erased, result.pinDigest], [true, true]);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, undefined, "the PIN put back is erased");
  });
});

describe("L3 review: validateForm", () => {
  it("refuses a sensitive flag that is not true or false", () => {
    for (const sensitive of ["true", 1, null]) {
      const form = { formId: "f", version: "1", fields: [{ key: "policy", label: { en: "Policy", fr: "Police" }, type: "text", sensitive }] } as unknown as IntakeForm;
      assert.ok(validateForm(form).map(problemMessage).includes("field policy: sensitive must be true or false"), JSON.stringify(sensitive));
    }
    assert.deepEqual(validateForm(note("f", true)), []);
  });
});

describe("L3 review: composed redactors", () => {
  it("keeps the bank word before a card marker, so the account digits after it are removed too", () => {
    const redactor = composeRedactors(cardNumberRedactor, bankAccountRedactor);
    const { text } = redactor.redact("account number 4111 1111 1111 1111 12345678");
    assert.equal(text.includes("12345678"), false, text);
  });

  it("removes a short suffix of the run too, which the bank stage alone would count with the card digits", () => {
    const { text } = composeRedactors(cardNumberRedactor, bankAccountRedactor).redact("account number 4111 1111 1111 1111 12 thanks");
    assert.equal(/\d/.test(text), false, text);
    assert.equal(composeRedactors(cardNumberRedactor, bankAccountRedactor).redact("card 4111 1111 1111 1111 12").text.includes("12"), true, "no bank word, no bank number");
  });
});

describe("L3 review: deliverRecord", () => {
  it("sends every attempt to the destination as it was when the delivery began", async () => {
    const t = setup();
    const callId = await drafted(t);
    const { recordId } = await t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: await heard(t, callId) });
    const destination = { destinationId: "crm", url: "https://hooks.example.test/records", secret: "whsec_delivery_test_not_a_secret" };
    const delivery = new FakeRecordDelivery([503, 200]);
    const sleep = async () => {
      destination.url = "https://elsewhere.example.test/records";
      destination.secret = "whsec_another_secret_not_real";
    };
    const result = await deliverRecord({ destination, workspaceId: "ws_test", recordId, records: t.records, delivery, ledger: t.ledger, clock: t.clock, sleep });
    assert.equal(result.delivered, true);
    assert.deepEqual(delivery.posts.map((p) => p.url), ["https://hooks.example.test/records", "https://hooks.example.test/records"]);
  });
});

describe("L3 review: beginVerification", () => {
  it("keeps no copy of the duress PIN digest on the call", async () => {
    const t = setup();
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN, duressPin: DURESS }));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const subject = ((await t.sessions.get("ws_test", callId))!.record as unknown as Stored).modules.badge!.subject as Record<string, unknown>;
    assert.equal(subject.subjectKey, SUBJECT);
    assert.deepEqual(["pinDigest" in subject, "duressDigest" in subject], [false, false]);
  });
});

describe("L3 review: a spoken answer that carries keypad fields", () => {
  type Badge = { factors: string[]; pin: { duress?: { refuseScopes: string[] } }; accessibility?: { spokenKeypadFields?: string[] } };
  function config(fields: string[] | null, duress = false): FlowConfig {
    return testConfig((c) => {
      c.policy.spoken = { fields: { postal_code: "ca_postal_code" }, maxAttemptsPerCall: 2 };
      c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["spoken_knowledge"]] };
      const settings = c.modules.badge!.settings as unknown as Badge;
      settings.factors.push("spoken_knowledge");
      if (fields !== null) settings.accessibility = { spokenKeypadFields: fields };
      if (duress) {
        c.policy.scopes["owner.command"] = 1;
        c.policy.scopeClasses = { "owner.command": "none" };
        settings.pin.duress = { refuseScopes: ["owner.command"] };
      }
    });
  }
  function engine(c: FlowConfig): TestEngine {
    const t = setup({ config: c, adapters: { duressNotifier: new FakeDuressNotifier() } });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB, postal_code: POSTAL }, pin: PIN }));
    return t;
  }
  async function verifying(t: TestEngine): Promise<string> {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    return callId;
  }
  const hiddenKeypad: AttemptCounterKey = hiddenCounterKey("ws_test", "keypad_knowledge", SUBJECT);
  const since = (t: TestEngine) => new Date(t.clock.now().getTime() - 24 * 3_600_000 + 1).toISOString();

  it("is refused while the hidden keypad_knowledge hard lock holds, and never judged", async () => {
    const t = engine(config(["dob"], true));
    for (let i = 0; i < DEFAULT_LOCKOUT.lockAfterFailures; i++) await t.counters.recordFailure(hiddenKeypad, t.clock.now().toISOString(), since(t));
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: DOB }), { matched: false, locked: true });
  });

  it("counts a failure under the hidden keypad_knowledge counter, and a pass resets it", async () => {
    const t = engine(config(["dob"], true));
    const callId = await verifying(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: "19700101" }), { matched: false, locked: false });
    assert.equal((await t.counters.get(hiddenKeypad, since(t))).length, 1);
    waitOut(t);
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: DOB }), { matched: true, locked: false });
    assert.equal((await t.counters.get(hiddenKeypad, since(t))).length, 0);
  });

  it("is judged with the keypad fields it was charged for, even when the config changes while it waits", async () => {
    const t = engine(config(null));
    const callId = await verifying(t);
    const get = t.counters.get.bind(t.counters);
    let swap = true;
    t.counters.get = async (key, from) => {
      if (swap) {
        swap = false;
        t.engine.configure(config(["dob"]));
      }
      return get(key, from);
    };
    assert.deepEqual(await t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: "19700101" }), { matched: true, locked: false }, "judged without dob, as it was counted");
  });

  it("is refused, never judged, when Badge lists a spoken keypad field the policy does not key", async () => {
    const t = engine(config(["dob", "dobb"]));
    const callId = await verifying(t);
    await assert.rejects(t.engine.submitFactor(callId, "spoken_knowledge", { postal_code: POSTAL, dob: DOB }), rejects("precondition_failed", /dobb is not one of the policy's keypad fields/));
  });
});

// ---- trace: alerts, notices, receipt texts, calls saved before PRV-3 ----

const consentWording = { purpose: "receipt_texts", version: "1", text: { en: "May we text you a receipt?", fr: "Pouvons-nous vous texter un reçu?" } };
function traceConfig(duress = false): FlowConfig {
  return testConfig((c) => {
    c.modules.trace = { settings: { receipts: true, wordings: [structuredClone(wording), consentWording], businessName: "Maple Property Management" } };
    c.policy.levels[0]!.anyOf.push(["pin"]);
    if (duress) {
      c.policy.scopes["owner.command"] = 1;
      c.policy.scopeClasses = { "owner.command": "none" };
      (c.modules.badge!.settings as { pin: { duress?: unknown } }).pin.duress = { refuseScopes: ["owner.command"] };
    }
    c.flows = {
      deposit: {
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
          { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" },
          { type: "trace.consent", purpose: "receipt_texts", require: "answer" },
          { type: "trace.receipt", textLink: { consent: "receipt_texts" } },
        ],
      },
      // The caller is asked twice (a yes, then a change of mind).
      twice: {
        steps: [
          { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
          { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Deposit", amountSource: "price_list" },
          { type: "trace.consent", purpose: "receipt_texts", require: "answer" },
          { type: "trace.consent", purpose: "receipt_texts", require: "answer" },
          { type: "trace.receipt", textLink: { consent: "receipt_texts" } },
        ],
      },
    };
  });
}
const LINK = "https://receipts.example.test/r/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("L3 review: sweepAlerts", () => {
  it("sends a call's duress alert when its contact notice fails", async () => {
    const t = setup({ config: traceConfig(true), adapters: { duressNotifier: { notify: () => new Promise<void>(() => undefined) } } });
    assert.deepEqual(await t.engine.enrolDuressPin(SUBJECT, DURESS), { enrolled: true });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await patchStored(t, callId, (r) => ((r.modules.trace!.texts as { notices: unknown[] }).notices = [{ subjectKey: SUBJECT, to: PHONE_ON_FILE, sent: false }]));
    const notifier = new FakeDuressNotifier();
    const restarted = createTestEngine({ config: traceConfig(true), adapters: { duressNotifier: notifier, sessions: t.sessions, records: t.records, ledger: t.ledger } });
    restarted.messages.sendText = async () => {
      throw new Error("carrier down");
    };
    assert.deepEqual(await restarted.engine.sweepAlerts(), { sent: [], failed: [callId] }, "the notice is still owed");
    assert.equal(notifier.told.length, 1, "the duress alert went");
  });
});

describe("L3 review: sweepAlerts with a messages adapter that never answers", () => {
  it("returns within the notify timeout, and the next sweep sends the duress alert and tries the notice again under its key", async () => {
    const t = setup({ config: traceConfig(true), adapters: { duressNotifier: { notify: () => new Promise<void>(() => undefined) } } });
    assert.deepEqual(await t.engine.enrolDuressPin(SUBJECT, DURESS), { enrolled: true });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await patchStored(t, callId, (r) => ((r.modules.trace!.texts as { notices: unknown[] }).notices = [{ subjectKey: SUBJECT, to: PHONE_ON_FILE, sent: false }]));
    let down = true;
    const notifier = new FakeDuressNotifier();
    const restarted = createTestEngine({
      config: traceConfig(true),
      notifyTimeoutMs: 100,
      adapters: { duressNotifier: { notify: async (a) => (down ? Promise.reject(new Error("down")) : notifier.notify(a)) }, sessions: t.sessions, records: t.records, ledger: t.ledger },
    });
    const keys: string[] = [];
    restarted.messages.sendText = (input) => (keys.push(input.idempotencyKey), new Promise(() => undefined));
    assert.deepEqual(await restarted.engine.sweepAlerts(), { sent: [], failed: [callId] });
    down = false;
    assert.deepEqual(await restarted.engine.sweepAlerts(), { sent: [], failed: [callId] }, "the notice is still owed");
    assert.equal(notifier.told.length, 1, "the duress alert went on the next sweep");
    assert.deepEqual([keys.length, new Set(keys).size], [2, 1], "tried again, under the same key");
  });
});

describe("L3 review: contact notices", () => {
  it("one recipient the adapter refuses never holds back the next one's notice", async () => {
    const t = setup({ config: traceConfig() });
    const { callId } = await t.engine.startCall();
    await patchStored(t, callId, (r) => {
      (r.modules.trace!.texts as { notices: unknown[] }).notices = [
        { subjectKey: SUBJECT, to: "+15555550101", sent: false },
        { subjectKey: SUBJECT, to: "+15555550102", sent: false },
      ];
      r.owesAlerts = true;
    });
    const send = t.messages.sendText.bind(t.messages);
    t.messages.sendText = async (input) => {
      if (input.to === "+15555550101") throw new Error("refused");
      return send(input);
    };
    assert.deepEqual(await t.engine.sweepAlerts(), { sent: [], failed: [callId] });
    assert.deepEqual(t.messages.sent.map((m) => m.to), ["+15555550102"]);
    const notices = ((await t.sessions.get("ws_test", callId))!.record as unknown as Stored).modules.trace!.texts as { notices: Array<{ sent: boolean }> };
    assert.deepEqual(notices.notices.map((n) => n.sent), [false, true], "the refused one stays owed");
  });
});

describe("L3 review: textReceiptLink after a revocation", () => {
  async function texted(store: MemoryConsentStore) {
    const t = setup({ config: traceConfig(), adapters: { consents: store } });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "deposit" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    await confirmAmount(t.engine, callId);
    await t.engine.requestPayment(callId);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
    const consent = await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    assert.notEqual(await t.engine.endCall(callId), null);
    return { t, callId, consent };
  }
  const links = (t: TestEngine) => t.messages.sent.filter((m) => m.purpose === "receipt_link");

  it("sends nothing once the yes is revoked in the store", async () => {
    const { t, callId, consent } = await texted(new MemoryConsentStore());
    await t.engine.revokeConsent({ consentId: consent.consentId, via: "text" });
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    assert.equal(links(t).length, 0);
  });

  it("sends nothing when the store no longer has the consent, or cannot be read", async () => {
    const store = new MemoryConsentStore();
    const { t, callId } = await texted(store);
    store.getConsent = async () => null;
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    store.getConsent = async () => {
      throw new Error("store down");
    };
    await assert.rejects(t.engine.textReceiptLink(callId, LINK), /store down/);
    assert.equal(links(t).length, 0);
  });

  it("sends nothing when a later answer for the purpose was still being stored when the call ended", async () => {
    const store = new MemoryConsentStore();
    const t = setup({ config: traceConfig(), adapters: { consents: store } });
    t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    const { callId } = await t.engine.startCall({ flow: "twice" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    await confirmAmount(t.engine, callId);
    await t.engine.requestPayment(callId);
    await t.engine.applyPaymentOutcome({ kind: "completed", linkId: t.payments.created.at(-1)!.linkId, paymentStatus: "paid" });
    await t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "yes" });
    store.putConsent = async () => {
      throw new Error("store down");
    };
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "receipt_texts", answer: "no" }), /store down/);
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: false });
    assert.equal(links(t).length, 0);
  });

  it("still sends the link for a yes that stands", async () => {
    const { t, callId } = await texted(new MemoryConsentStore());
    assert.deepEqual(await t.engine.textReceiptLink(callId, LINK), { texted: true });
  });
});

describe("L3 review: a call saved before PRV-3", () => {
  it("records a consent and ends with a receipt, with no consent reservation or unrecorded list saved", async () => {
    const t = setup({ config: traceConfig(), adapters: { consents: new MemoryConsentStore() } });
    const { callId } = await t.engine.startCall();
    await patchStored(t, callId, (r) => {
      delete r.modules.trace!.storing;
      delete r.modules.trace!.unrecorded;
    });
    await t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" });
    const ended = await t.engine.startCall();
    await patchStored(t, ended.callId, (r) => {
      delete r.modules.trace!.storing;
      delete r.modules.trace!.unrecorded;
    });
    for (const id of [callId, ended.callId]) assert.notEqual(await t.engine.endCall(id), null);
  });
});
