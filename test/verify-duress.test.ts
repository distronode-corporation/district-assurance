// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The duress PIN (VER-12): a pass to the caller, refused money, contact and access, a told notifier.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AuditEntry, SubjectRecord } from "../src/core/adapters.ts";
import { ConfigError, type FlowConfig } from "../src/core/config.ts";
import type { EngineRuntime } from "../src/core/runtime.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { judgePin, pinTag, type PinSettings } from "../src/verify/factors.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { readPinTag } from "../src/verify/pin.ts";
import { FakeDuressNotifier, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, pinOnFile, rejects, setup, testConfig, waitOut, messages } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";

/** HMAC under the test knowledge key, as the engine computes it. */
const hmacUnderTestKey = (data: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, data);

type Badge = { factors: string[]; pin: PinSettings };
const badgeSettings = (c: FlowConfig) => c.modules.badge!.settings as unknown as Badge;

/** A PIN alone reaches level 1, a PIN and the carrier level 2; `owner.command` is a business scope at level 1. */
function duressConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.levels[1]!.anyOf.push(["pin", "carrier_identity_match"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    badgeSettings(c).pin.duress = { refuseScopes: ["owner.command"] };
    patch(c);
  });
}

/** An engine with the duress PIN on, the subject's duress PIN enrolled by the business, and the carrier matching. */
async function duressSetup(patch?: (c: FlowConfig) => void, notifier = new FakeDuressNotifier()): Promise<TestEngine & { notifier: FakeDuressNotifier }> {
  const t = setup({ config: duressConfig(patch), adapters: { duressNotifier: notifier } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  if (badgeSettings(t.engine.config).pin.mode === "keyed_hash") assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return { ...t, notifier };
}

/** One call: a PIN, the carrier, a level 2 grant, then the end and its receipt. */
async function pinCall(t: TestEngine, pin: string) {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  const answer = await t.engine.submitPin(callId, pin);
  await t.engine.checkCarrier(callId);
  const verification = await t.engine.finishVerification(callId);
  const state = await t.engine.state(callId);
  const scopes: Record<string, boolean> = {};
  for (const scope of ["status.read", "intake.file", "owner.command", "payment.request", "contact.update"]) scopes[scope] = await t.engine.authorize(callId, scope);
  return { callId, answer, verification, state, scopes };
}

/** Lets the alerts sent after a write (off the response path) go out and be acknowledged. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
}

/** The Badge part of a stored call: its duress state and the alerts it still owes. */
async function badgeOf(t: TestEngine, callId: string) {
  return ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { duress?: unknown; duressAlerts?: unknown[] } } }).modules.badge;
}

/** Holds the next `getSubject` (the judge's or an enrolment's store read) until released. */
function holdNextRead(t: TestEngine): () => void {
  const real = t.records.getSubject.bind(t.records);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  t.records.getSubject = async (workspaceId, subjectKey) => {
    t.records.getSubject = real;
    const subject = await real(workspaceId, subjectKey);
    await gate;
    return subject;
  };
  return release;
}

/** A ledger entry without what its keyed tag changes: the tag itself, the hashes over it, and the receipt digest over the head. */
function untagged(entry: AuditEntry) {
  const { tag: _tag, ...detail } = entry.detail;
  if (entry.event === "receipt.issued") detail.digest = "";
  return { ...entry, detail, hash: "", prevHash: "" };
}

describe("Duress PIN: what the caller sees", () => {
  it("gives the same answer, level, grant, events and receipt as the normal PIN", async () => {
    const normal = await duressSetup();
    const duress = await duressSetup();
    const a = await pinCall(normal, PIN);
    const b = await pinCall(duress, DURESS);
    assert.deepEqual(b.answer, { matched: true, locked: false });
    assert.deepEqual(b.answer, a.answer);
    assert.deepEqual(b.verification, { level: 2, scopes: ["intake.file", "owner.command", "payment.request", "status.read"] });
    assert.deepEqual(b.verification, a.verification);
    assert.deepEqual(b.state, a.state, "the same state and grant");
    const receiptA = (await normal.engine.endCall(a.callId))!;
    const receiptB = (await duress.engine.endCall(b.callId))!;
    const ledgerA = await normal.ledger.list();
    const ledgerB = await duress.ledger.list();
    assert.deepEqual(ledgerB.map(untagged), ledgerA.map(untagged), "the same events, in the same order, with the same detail");
    const tagged = (entries: AuditEntry[]) => entries.filter((e) => "tag" in e.detail).map((e) => [e.event, e.detail.kind]);
    assert.deepEqual(tagged(ledgerB), [["verification.factor", "pin"]]);
    assert.deepEqual(tagged(ledgerB), tagged(ledgerA), "both carry the tag field");
    const body = (r: typeof receiptA) => ({ ...r.body, ledger: { seq: r.body.ledger.seq, hash: "" } });
    assert.deepEqual(body(receiptB), body(receiptA), "the same receipt, but for the ledger head the tag changes");
    assert.equal(JSON.stringify(ledgerB).includes(DURESS), false, "the duress PIN is never written");
    // The duress state is in the call record only.
    const slice = async (t: TestEngine, callId: string) => ((await t.sessions.get("ws_test", callId))!.record as { modules: { badge: { duress?: unknown } } }).modules.badge.duress;
    assert.deepEqual(await slice(duress, b.callId), { refuseScopes: ["owner.command"] });
    assert.equal(await slice(normal, a.callId), undefined);
  });

  it("refuses money, contact, access and the business's own scopes, as a scope without a grant", async () => {
    // A contact scope and an access scope a level 2 call is granted, so the normal call can use both.
    const reachable = (c: FlowConfig) => {
      c.policy.scopes["contact.email"] = 2;
      c.policy.scopes["access.door"] = 2;
    };
    const normal = await duressSetup(reachable);
    const duress = await duressSetup(reachable);
    const a = await pinCall(normal, PIN);
    const b = await pinCall(duress, DURESS);
    assert.deepEqual(a.scopes, { "status.read": true, "intake.file": true, "owner.command": true, "payment.request": true, "contact.update": false });
    assert.deepEqual(b.scopes, { "status.read": true, "intake.file": true, "owner.command": false, "payment.request": false, "contact.update": false });
    for (const scope of ["contact.email", "access.door"]) {
      assert.equal(await normal.engine.authorize(a.callId, scope), true, `${scope} on the normal call`);
      assert.equal(await duress.engine.authorize(b.callId, scope), false, `${scope} on the duress call`);
    }
    const request = { amountMinor: 1500, currency: "cad", description: "Deposit", amountSource: "price_list" as const };
    let duressError: unknown;
    await duress.engine.requestPayment(b.callId, request).catch((e: unknown) => (duressError = e));
    const { callId: ungranted } = await duress.engine.startCall();
    let ungrantedError: unknown;
    await duress.engine.requestPayment(ungranted, request).catch((e: unknown) => (ungrantedError = e));
    assert.ok(rejects("scope_denied")(duressError));
    assert.deepEqual(String(duressError), String(ungrantedError), "the same refusal as a call with no grant");
    assert.equal(duress.payments.created.length, 0);
    assert.equal(duress.messages.sent.length, 0, "nothing was texted");
  });

  it("stays a duress call after verification restarts, and the normal PIN still works on a subject with a duress PIN", async () => {
    const t = await duressSetup();
    const a = await pinCall(t, PIN);
    assert.equal(a.scopes["payment.request"], true);
    assert.equal(t.notifier.told.length, 0);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, "0000")).matched, false, "a wrong PIN still fails");
    // Past the wait VER-1 puts after a failure.
    waitOut(t);
    assert.equal((await t.engine.submitPin(callId, DURESS)).matched, true);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, PIN)).matched, true);
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    assert.equal(await t.engine.authorize(callId, "payment.request"), false, "the normal PIN does not undo a duress entry on the same call");
  });

  it("is off by default: a duress digest on file fails like a wrong PIN while the setting is off", async () => {
    const t = setup();
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN, duressPin: DURESS }));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, DURESS), { matched: false, locked: false });
    assert.equal(await t.engine.readPinTag((await t.ledger.list()).at(-1)!), "fail");
    await assert.rejects(t.engine.enrolDuressPin(OWNER, "5038"), rejects("precondition_failed", /turned off/));
  });
});

describe("Duress PIN: a subject's erasure (#105 with #124)", () => {
  it("removes the duress digest with the PIN digest, so neither PIN passes after the erase", async () => {
    const t = await duressSetup();
    const subjectKey = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
    assert.notEqual((await t.records.getSubject("ws_test", subjectKey))!.duressDigest, undefined);
    assert.equal((await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey })).pinDigest, true);
    const onFile = (await t.records.getSubject("ws_test", subjectKey))!;
    assert.deepEqual([onFile.pinDigest, onFile.duressDigest], [undefined, undefined]);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, DURESS)).matched, false, "the duress PIN no longer passes");
    assert.equal(t.notifier.told.length, 0);
  });

  it("erases a duress digest left alone after the PIN digest went", async () => {
    const t = await duressSetup();
    const subjectKey = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
    const subject = (await t.records.getSubject("ws_test", subjectKey))!;
    delete subject.pinDigest;
    t.records.putSubject("ws_test", subject);
    assert.equal((await t.engine.eraseSubject({ workspaceId: "ws_test", subjectKey })).pinDigest, true);
    assert.equal((await t.records.getSubject("ws_test", subjectKey))!.duressDigest, undefined);
  });
});

describe("Duress PIN: the notifier", () => {
  it("is told of every duress entry, after the write and off the response path, with an alert id, the workspace, the subject, the call and the time, never the PIN", async () => {
    const t = await duressSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    assert.equal(t.notifier.told.length, 0, "not on the response path");
    await settle();
    t.clock.advance(1000);
    await t.engine.finishVerification(callId);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await settle();
    assert.deepEqual(t.notifier.told.map(({ alertId: _id, ...alert }) => alert), [
      { workspaceId: "ws_test", subjectKey: OWNER, callId, at: "2026-01-01T00:00:00.000Z" },
      { workspaceId: "ws_test", subjectKey: OWNER, callId, at: "2026-01-01T00:00:01.000Z" },
    ]);
    assert.equal(new Set(t.notifier.told.map((a) => a.alertId)).size, 2, "each entry is its own alert");
    assert.equal(JSON.stringify(t.notifier.told).includes(DURESS), false);
    assert.deepEqual((await badgeOf(t, callId)).duressAlerts, [], "both acknowledged");
  });

  it("sends the alert even when the ledger append fails, and a normal PIN fails the same way (iMac hostile pass, #124)", async () => {
    for (const pin of [DURESS, PIN]) {
      const t = await duressSetup();
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      const append = t.ledger.append.bind(t.ledger);
      t.ledger.append = async (input) => {
        if (input.event === "verification.factor") throw new Error("ledger 503");
        return append(input);
      };
      await assert.rejects(t.engine.submitPin(callId, pin), /ledger 503/, "the same rejection for both");
      await settle();
      assert.equal(t.notifier.told.length, pin === DURESS ? 1 : 0, pin);
      t.ledger.append = append;
      await t.engine.flushLedger(callId);
      await settle();
      assert.equal(t.notifier.told.length, pin === DURESS ? 1 : 0, "sent once, not again");
    }
  });

  it("keeps an alert owed until the notifier answers, and retries it on the next write, on flushLedger and on the host's sweep", async () => {
    const notifier = new FakeDuressNotifier();
    const notify = notifier.notify.bind(notifier);
    let down = true;
    let tries = 0;
    notifier.notify = async (input) => {
      tries++;
      if (down) throw new Error("pager down");
      return notify(input);
    };
    const t = await duressSetup(undefined, notifier);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await settle();
    await t.engine.checkCarrier(callId);
    await settle();
    await t.engine.flushLedger(callId);
    await settle();
    assert.equal(await t.engine.deliverDuressAlerts(callId), 0);
    assert.equal(tries, 4, "after the entry, the next write, flushLedger and the sweep");
    assert.equal((await badgeOf(t, callId)).duressAlerts!.length, 1, "still owed");
    // An engine without a notifier (a config without the duress PIN) leaves it owed for one that has one.
    const other = createTestEngine({ config: testConfig(), clock: t.clock, ids: t.ids, adapters: { sessions: t.sessions, records: t.records, ledger: t.ledger } });
    assert.equal(await other.engine.deliverDuressAlerts(callId), 0);
    down = false;
    assert.equal(await t.engine.deliverDuressAlerts(callId), 1);
    assert.equal(await t.engine.deliverDuressAlerts(callId), 0, "acknowledged once");
    assert.equal(notifier.told.length, 1);
  });

  it("sends an alert again, with the same id, when its acknowledgement could not be written; one in hand waits 30 seconds", async () => {
    const notifier = new FakeDuressNotifier();
    const notify = notifier.notify.bind(notifier);
    const t = await duressSetup(undefined, notifier);
    const cas = t.sessions.compareAndSet.bind(t.sessions);
    let hang = true;
    notifier.notify = async (input) => {
      if (hang) {
        hang = false;
        return new Promise<void>(() => undefined);
      }
      await notify(input);
      if (notifier.told.length === 1) t.sessions.compareAndSet = async () => ({ ok: false });
    };
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitPin(callId, DURESS);
    await settle();
    assert.equal(await t.engine.deliverDuressAlerts(callId), 0, "the first send never answered, and is still in hand");
    t.clock.advance(30_000);
    assert.equal(await t.engine.deliverDuressAlerts(callId), 0, "sent again after 30 seconds; the acknowledgement could not be written");
    t.sessions.compareAndSet = cas;
    assert.equal(await t.engine.deliverDuressAlerts(callId), 1);
    assert.deepEqual(notifier.told.map((a) => a.alertId), [notifier.told[0]!.alertId, notifier.told[0]!.alertId], "at least once, by one id");
  });

  it("leaves the alert owed when the session store cannot be read for the send, with no unhandled rejection", async () => {
    const t = await duressSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const get = t.sessions.get.bind(t.sessions);
    let down = false;
    t.sessions.get = async (workspaceId, id) => {
      // Down for the send after the reply, which is the next read.
      if (down) {
        down = false;
        throw new Error("session store down");
      }
      return get(workspaceId, id);
    };
    await t.engine.submitPin(callId, DURESS);
    down = true;
    await settle();
    assert.equal(t.notifier.told.length, 0);
    assert.equal(await t.engine.deliverDuressAlerts(callId), 1);
  });

  it("never holds the caller's answer for the notifier: a slow notifier runs after the reply", async () => {
    const notifier = new FakeDuressNotifier();
    let called = false;
    notifier.notify = async () => {
      called = true;
      const until = Date.now() + 20;
      while (Date.now() < until) {
        // A notifier that blocks, which it must not; it still runs only after the reply.
      }
    };
    const t = await duressSetup(undefined, notifier);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, DURESS), { matched: true, locked: false });
    assert.equal(called, false);
    await settle();
    assert.equal(called, true);
  });

  it("never changes what the call does when it throws, rejects or never answers", async () => {
    const reference = await pinCall(await duressSetup(), DURESS);
    const failing: Array<() => Promise<void>> = [
      () => {
        throw new Error("notifier down");
      },
      () => Promise.reject(new Error("notifier down")),
      () => new Promise<void>(() => undefined),
    ];
    for (const notify of failing) {
      const notifier = new FakeDuressNotifier();
      notifier.notify = notify;
      const t = await duressSetup(undefined, notifier);
      const run = await pinCall(t, DURESS);
      assert.deepEqual({ ...run, callId: "" }, { ...reference, callId: "" });
    }
  });
});

describe("Duress PIN: the ledger tag", () => {
  it("can be read only by the key holder, on every PIN entry, pass, fail or duress", async () => {
    const t = await duressSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    for (const pin of ["0000", PIN, DURESS]) {
      await t.engine.submitPin(callId, pin);
      // Past the wait VER-1 puts after a failure.
      waitOut(t);
    }
    const entries = (await t.ledger.list()).filter((e) => e.event === "verification.factor");
    assert.deepEqual(
      await Promise.all(entries.map((e) => t.engine.readPinTag(e))),
      [null, "fail", "pass", "duress"],
      "the keypad entry has no tag",
    );
    const other = createTestEngine({ knowledgeKey: "another-workspace-key-0001", config: duressConfig(), adapters: { duressNotifier: new FakeDuressNotifier() } });
    assert.deepEqual(await Promise.all(entries.map((e) => other.engine.readPinTag(e))), [null, null, null, null], "another key reads nothing");
    const tags = entries.slice(1).map((e) => e.detail.tag);
    assert.equal(new Set(tags).size, 3, "each tag is bound to its own entry");
    const duressEntry = entries[3]!;
    assert.equal(await t.engine.readPinTag({ ...duressEntry, eventId: entries[2]!.eventId! }), null, "a tag moved to another entry reads nothing");
    assert.equal(await t.engine.readPinTag({ ...duressEntry, detail: { ...duressEntry.detail, tag: 1 } }), null);
    assert.equal(await t.engine.readPinTag({ event: duressEntry.event, detail: duressEntry.detail }), null, "no event id");
    assert.equal(await t.engine.readPinTag((await t.ledger.list())[0]!), null, "not a factor entry");
    assert.equal(readPinTag(hmacUnderTestKey, duressEntry), "duress", "the exported reader, with the key's HMAC");
    assert.equal(duressEntry.detail.tag, pinTag(hmacUnderTestKey, duressEntry.eventId!, "duress"));
  });
});

describe("Duress PIN: the store decides", () => {
  it("reads the duress digest from the store on every entry, so a removal or a PIN reset counts on a call already verifying", async () => {
    const t = await duressSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.removeDuressPin(OWNER);
    assert.deepEqual(await t.engine.submitPin(callId, DURESS), { matched: false, locked: false }, "removed after verification began");
    const u = await duressSetup();
    const other = await u.engine.startCall();
    await u.engine.beginVerification(other.callId, { accountNumber: ACCOUNT });
    await u.engine.resetPin(OWNER);
    assert.deepEqual(await u.engine.submitPin(other.callId, DURESS), { matched: false, locked: false }, "a PIN reset removes the duress PIN too");
    assert.equal(u.notifier.told.length, 0, "no duress notice");
  });
});

describe("Duress PIN: the same work", () => {
  const keyed: PinSettings = { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3, duress: { refuseScopes: [] } };
  const withDuress = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pin: PIN, duressPin: DURESS });
  const withoutDuress = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pin: PIN });

  /** Judges one entry and counts the keyed hashes it took. */
  /** The store the judge reads both digests from on every entry (VER-6's fix pass): here it holds `subject`. */
  const storeOf = (subject: SubjectRecord | null) => ({ adapter: () => ({ getSubject: async () => subject }) }) as unknown as EngineRuntime;

  async function judge(settings: PinSettings, subject: SubjectRecord | null, entry: string, rt = storeOf(subject)) {
    const hashed: string[] = [];
    const hmac = async (d: string) => {
      hashed.push(d.slice(0, d.indexOf(":")));
      return hmacUnderTestKey(d);
    };
    const outcome = await judgePin(rt, settings, { workspaceId: "ws_test", subjectKey: subject === null ? null : OWNER, subject, entry, hmac, locale: "en" });
    return { outcome, hashed };
  }

  it("compares every entry with both digests, with or without a duress PIN on file or turned on", async () => {
    const off: PinSettings = { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 };
    const cases = [
      [keyed, withDuress, DURESS, "duress"],
      [keyed, withDuress, PIN, "pass"],
      [keyed, withDuress, "0000", "fail"],
      [keyed, withoutDuress, DURESS, "fail"],
      [keyed, withoutDuress, PIN, "pass"],
      [keyed, null, PIN, "fail"],
      [keyed, withDuress, "12", "fail"],
      [off, withDuress, DURESS, "fail"],
      [off, withDuress, PIN, "pass"],
    ] as const;
    for (const [settings, subject, entry, expected] of cases) {
      const { outcome, hashed } = await judge(settings, subject, entry);
      assert.equal(outcome, expected, `${entry}`);
      // An unknown subject's store lookup is keyed too ("subject:"); the PIN and duress hashes are made every time.
      assert.deepEqual(hashed.filter((h) => h !== "subject"), ["pin", "duress"], "the same keyed hashes every time");
    }
  });

  it("asks the host's verifier once per entry, and takes its duress answer only when the setting is on", async () => {
    const t = await duressSetup((c) => (badgeSettings(c).pin.mode = "verifier"));
    t.pinVerifier.set("ws_test", OWNER, PIN);
    t.pinVerifier.setDuress("ws_test", OWNER, DURESS);
    const rt = { adapter: () => t.pinVerifier } as unknown as EngineRuntime;
    const verifier = { ...keyed, mode: "verifier" as const };
    const off: PinSettings = { mode: "verifier", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 };
    assert.equal((await judge(verifier, withDuress, DURESS, rt)).outcome, "duress");
    assert.equal((await judge(verifier, withDuress, PIN, rt)).outcome, "pass");
    assert.equal((await judge(verifier, withDuress, "0000", rt)).outcome, "fail");
    assert.equal((await judge(off, withDuress, DURESS, rt)).outcome, "fail", "duress answers count only while turned on");
    assert.equal((await judge(verifier, null, DURESS, rt)).outcome, "fail", "an unknown subject never passes");
    assert.equal(t.pinVerifier.asked.length, 5);
    // End to end: the host's verifier answers duress, and the call looks like a pass.
    const run = await pinCall(t, DURESS);
    assert.deepEqual(run.answer, { matched: true, locked: false });
    assert.equal(run.scopes["payment.request"], false);
    await settle();
    assert.equal(t.notifier.told.length, 1);
    await assert.rejects(t.engine.enrolDuressPin(OWNER, "5038"), rejects("precondition_failed", /verifier mode/));
    await assert.rejects(t.engine.removeDuressPin(OWNER), rejects("precondition_failed", /verifier mode/));
  });
});

describe("Duress PIN: enrolment by the business", () => {
  it("refuses a duress PIN that is malformed, weak, the PIN itself or a value on file, with one answer for all", async () => {
    const t = await duressSetup();
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, "12"), { enrolled: false, reason: "malformed" });
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, "48a6"), { enrolled: false, reason: "malformed" });
    for (const weak of [PIN, ACCOUNT, DOB, "1111", "6789"]) assert.deepEqual(await t.engine.enrolDuressPin(OWNER, weak), { enrolled: false, reason: "weak" }, weak);
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", OWNER))!.duressDigest, OWNER, DURESS, "duress"), "the earlier duress PIN stands");
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, "5038"), { enrolled: true }, "the business replaces it");
    assert.ok(await pinOnFile((await t.records.getSubject("ws_test", OWNER))!.duressDigest, OWNER, "5038", "duress"));
    assert.equal(JSON.stringify(await t.ledger.list()).includes("5038"), false);
  });

  it("needs the pin factor and the setting on, a well-formed subject key and a subject with a PIN on file", async () => {
    const t = await duressSetup();
    await assert.rejects(t.engine.enrolDuressPin("not-hex", DURESS), rejects("invalid_input"));
    await assert.rejects(t.engine.removeDuressPin("not-hex"), rejects("invalid_input"));
    await assert.rejects(t.engine.enrolDuressPin("a".repeat(64), "5038"), rejects("precondition_failed", /PIN on file/), "not on file");
    const bare = subjectKeyFor(TEST_KNOWLEDGE_KEY, "55555555");
    t.records.putSubject("ws_test", { subjectKey: bare, phoneOnFile: PHONE_ON_FILE, knowledge: {} });
    await assert.rejects(t.engine.enrolDuressPin(bare, "5038"), rejects("precondition_failed", /PIN on file/), "no PIN");
    t.engine.configure(duressConfig((c) => (badgeSettings(c).factors = ["keypad_knowledge"])));
    await assert.rejects(t.engine.enrolDuressPin(OWNER, "5038"), rejects("precondition_failed", /pin factor is turned off/));
  });

  it("is removed by the business, and by a PIN reset, after which the duress PIN is only a wrong PIN", async () => {
    const t = await duressSetup();
    await t.engine.removeDuressPin(OWNER);
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.duressDigest, undefined);
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(callId, DURESS)).matched, false);
    assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
    await t.engine.resetPin(OWNER);
    const subject = (await t.records.getSubject("ws_test", OWNER))!;
    assert.deepEqual([subject.pinDigest, subject.duressDigest], [undefined, undefined]);
    assert.equal(t.notifier.told.length, 0);
  });

  it("never lets a caller choose, as their PIN, a duress PIN on file", async () => {
    const t = await duressSetup();
    const account = "24681357";
    const phone = "+15555550199";
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: account, phoneOnFile: phone, knowledge: { dob: DOB }, duressPin: DURESS }));
    t.carrier.set(phone, { identityMatch: "match" });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: account });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: DURESS, confirm: DURESS }), { enrolled: false, reason: "weak" });
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: "5038", confirm: "5038" }), { enrolled: true });
  });
});

describe("Duress PIN: settings", () => {
  const module = badgeModule();
  const settings = (duress: unknown) => ({ factors: ["pin"], pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3, duress } });

  it("checks the duress settings and needs the duressNotifier adapter while they are on", () => {
    assert.deepEqual(messages(module.validateSettings(settings({ refuseScopes: [] }))), []);
    assert.deepEqual(messages(module.validateSettings(settings(true))), ["pin.duress must be an object with refuseScopes"]);
    assert.deepEqual(messages(module.validateSettings(settings({ refuseScopes: "owner.command", alert: true }))), [
      "pin.duress.alert is not a duress setting",
      "pin.duress.refuseScopes must list scopes (it may be empty)",
    ]);
    assert.deepEqual(messages(module.validateSettings(settings({ refuseScopes: ["a", "a"] }))), ["pin.duress.refuseScopes has duplicates"]);
    assert.deepEqual(module.requiredAdapters(settings({ refuseScopes: [] })), ["records", "counters", "duressNotifier"]);
    assert.deepEqual(module.requiredAdapters({ factors: ["keypad_knowledge"], pin: settings({ refuseScopes: [] }).pin }), ["records", "counters"]);
    assert.throws(
      () => createTestEngine({ config: duressConfig() }),
      (e: unknown) => e instanceof ConfigError && e.problems.includes("modules.badge: needs the duressNotifier adapter, which the engine does not have"),
    );
  });
});

describe("Duress PIN: races and broken subjects (iMac hostile pass, #124)", () => {
  it("keeps a duress entry and its alert when verification restarts while it is judged, with the same error as a normal PIN", async () => {
    const errors: string[] = [];
    for (const pin of [DURESS, PIN]) {
      const t = await duressSetup();
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      const release = holdNextRead(t);
      const submit = t.engine.submitPin(callId, pin).then(() => "ok", (e: unknown) => String(e));
      await settle();
      await t.engine.finishVerification(callId);
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      release();
      errors.push(await submit);
      await settle();
      assert.equal(t.notifier.told.length, pin === DURESS ? 1 : 0, pin);
      assert.deepEqual((await badgeOf(t, callId)).duress, pin === DURESS ? { refuseScopes: ["owner.command"] } : undefined);
      assert.equal((await t.engine.state(callId)).factors.length, 0, "the stale entry is not a factor");
    }
    assert.match(errors[0]!, /verification restarted/);
    assert.equal(errors[0], errors[1]);
  });

  it("keeps a duress entry and its alert when the call ended while it was judged", async () => {
    const t = await duressSetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    const release = holdNextRead(t);
    const submit = t.engine.submitPin(callId, DURESS);
    await settle();
    await t.engine.endCall(callId);
    release();
    await assert.rejects(submit, rejects("invalid_transition"));
    await settle();
    assert.equal(t.notifier.told.length, 1);
  });

  it("refuses a duress PIN when the PIN changed after it was checked, so a reset and a new PIN can never make them equal", async () => {
    const t = await duressSetup();
    await t.engine.removeDuressPin(OWNER);
    const X = "5927";
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    const release = holdNextRead(t);
    const enrolDuress = t.engine.enrolDuressPin(OWNER, X);
    await settle();
    await t.engine.resetPin(OWNER);
    assert.deepEqual(await t.engine.enrolPin(callId, { pin: X, confirm: X }), { enrolled: true });
    release();
    await assert.rejects(enrolDuress, rejects("conflict", /the PIN changed/));
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.duressDigest, undefined);
    const { callId: next } = await t.engine.startCall();
    await t.engine.beginVerification(next, { accountNumber: ACCOUNT });
    assert.equal((await t.engine.submitPin(next, X)).matched, true);
    await settle();
    assert.equal((await badgeOf(t, next)).duress, undefined, "the real PIN is a real login");
    assert.equal(t.notifier.told.length, 0);
    assert.equal(await t.records.putDuressDigest("ws_test", "c".repeat(64), "d".repeat(64), "e".repeat(64)), false, "a subject the store does not have");
  });

  it("refuses an entry that is both the PIN and the duress PIN of an imported subject: neither a login nor an alarm", async () => {
    const t = await duressSetup();
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN, duressPin: PIN }));
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: false });
    await settle();
    assert.equal((await badgeOf(t, callId)).duress, undefined);
    assert.equal(t.notifier.told.length, 0);
  });
});

describe("Duress PIN: the synchronous tag reader (#124 with #72)", () => {
  it("reads nothing from an entry that is not a tagged PIN factor, or whose tag no outcome makes", () => {
    const hmac = () => "0".repeat(64);
    assert.equal(readPinTag(hmac, { event: "call.started", detail: {} }), null);
    assert.equal(readPinTag(hmac, { eventId: "e", event: "verification.factor", detail: { kind: "pin", tag: "1".repeat(64) } }), null, "no outcome matches");
  });
});
