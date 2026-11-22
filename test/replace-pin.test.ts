// Engine.replacePin: the business replaces or removes a PIN in one compare-and-set
// (RecordStore.replacePinDigest), so of two changes at once one lands and the other changes nothing.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { PinChangeUnfinishedError } from "../src/verify/pin.ts";
import * as root from "../src/index.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, PIN, PHONE_ON_FILE, pinOnFile, rejects, setup, testConfig } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const NEXT = "5831";
const COUNTER = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: SUBJECT };
const FOREVER = "1970-01-01T00:00:00.000Z";

/** Makes one method of an adapter fail until the returned function puts it back. */
function failing<T extends object>(adapter: T, method: keyof T & string): () => void {
  const own = adapter as Record<string, unknown>;
  own[method] = async () => {
    throw new Error(`${method} unavailable`);
  };
  return () => delete own[method];
}

describe("Engine.replacePin", () => {
  it("replaces the PIN only from the record on file, writes the number given, and records the change", async () => {
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    const next = pinDigest(TEST_KNOWLEDGE_KEY, SUBJECT, NEXT);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: "$pin1$not-on-file", to: next }), false);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: null, to: next }), false, "not from none while one is on file");
    assert.equal((await t.ledger.list()).length, 0, "a refused change records nothing");
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: next, phoneOnFile: "+15555550177" }), true);
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    assert.equal(await pinOnFile(subject.pinDigest, SUBJECT, NEXT), true);
    assert.equal(subject.phoneOnFile, "+15555550177");
    assert.deepEqual((await t.ledger.list()).map((e) => [e.event, e.detail]), [["pin.reset", { subjectKey: SUBJECT }]]);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: null }), false, "the old record no longer names what is on file");
  });

  it("removes the PIN with a null, keeping the number when none is given, and clears the counters", async () => {
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    const counter = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: SUBJECT };
    await t.counters.recordFailure(counter, "2026-01-01T00:00:00.000Z", "1970-01-01T00:00:00.000Z");
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: null }), true);
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    assert.equal(subject.pinDigest, undefined);
    assert.equal(subject.phoneOnFile, PHONE_ON_FILE);
    assert.deepEqual(await t.counters.get(counter, "1970-01-01T00:00:00.000Z"), []);
  });

  it("stores a first PIN from none, clearing and recording nothing", async () => {
    const t = setup();
    await t.engine.resetPin(SUBJECT);
    const before = (await t.ledger.list()).length;
    const counter = { workspaceId: "ws_test", factor: "pin", scope: "subject" as const, key: SUBJECT };
    await t.counters.recordFailure(counter, "2026-01-01T00:00:00.000Z", "1970-01-01T00:00:00.000Z");
    assert.equal(await t.engine.replacePin(SUBJECT, { from: null, to: pinDigest(TEST_KNOWLEDGE_KEY, SUBJECT, PIN), phoneOnFile: "" }), true);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.phoneOnFile, "");
    assert.equal((await t.ledger.list()).length, before);
    assert.equal((await t.counters.get(counter, "1970-01-01T00:00:00.000Z")).length, 1);
  });

  it("answers false for a subject the store does not have, creating nothing", async () => {
    const t = setup();
    const unknown = "f".repeat(64);
    assert.equal(await t.engine.replacePin(unknown, { from: null, to: "$pin1$x" }), false);
    assert.equal(await t.records.getSubject("ws_test", unknown), null);
  });

  it("reports a change whose cleanup failed after it landed, and finishes it on resume", async () => {
    assert.equal(root.PinChangeUnfinishedError, PinChangeUnfinishedError);
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    const next = pinDigest(TEST_KNOWLEDGE_KEY, SUBJECT, NEXT);
    await t.counters.recordFailure(COUNTER, "2026-01-01T00:00:00.000Z", FOREVER);
    const restore = failing(t.ledger, "append");
    const error = (await t.engine.replacePin(SUBJECT, { from: onFile, to: next, phoneOnFile: "+15555550177" }).catch((e: unknown) => e)) as Error;
    restore();
    assert.ok(error instanceof PinChangeUnfinishedError);
    assert.equal(error.name, "PinChangeUnfinishedError");
    assert.match((error.cause as Error).message, /append unavailable/);
    assert.equal(error.message.includes(NEXT) || error.message.includes(next), false);
    // What the error reports is what is stored: the new PIN and number are on file.
    const subject = (await t.records.getSubject("ws_test", SUBJECT))!;
    assert.equal(subject.pinDigest, next);
    assert.equal(subject.phoneOnFile, "+15555550177");
    assert.equal((await t.ledger.list()).length, 0);
    // The same change again, without resume, is a lost compare-and-set; with it, the cleanup runs alone.
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: next }), false);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: next, resume: true }), true);
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["pin.reset"]);
    assert.deepEqual(await t.counters.get(COUNTER, FOREVER), []);
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, next, "not written again");
  });

  it("finishes a removal whose counter reset failed, on resume, even without the record it removed", async () => {
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    await t.counters.recordFailure(COUNTER, "2026-01-01T00:00:00.000Z", FOREVER);
    const restore = failing(t.counters, "reset");
    await assert.rejects(t.engine.replacePin(SUBJECT, { from: onFile, to: null }), PinChangeUnfinishedError);
    restore();
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, undefined);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: null, to: null, resume: true }), true);
    assert.deepEqual(await t.counters.get(COUNTER, FOREVER), []);
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["pin.reset"]);
  });

  it("with resume, still compares and sets a change that has not landed, and refuses a stale one", async () => {
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    const next = pinDigest(TEST_KNOWLEDGE_KEY, SUBJECT, NEXT);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: "$pin1$stale", to: next, resume: true }), false);
    assert.equal((await t.ledger.list()).length, 0);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: onFile, to: next, resume: true }), true);
    assert.deepEqual((await t.ledger.list()).map((e) => e.event), ["pin.reset"]);
    // A resumed first PIN that landed has nothing to clean up.
    await t.engine.replacePin(SUBJECT, { from: next, to: null });
    const first = pinDigest(TEST_KNOWLEDGE_KEY, SUBJECT, PIN);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: null, to: first }), true);
    assert.equal(await t.engine.replacePin(SUBJECT, { from: null, to: first, resume: true }), true);
    assert.equal((await t.ledger.list()).length, 2);
    // Nothing to resume for a subject the store does not have.
    assert.equal(await t.engine.replacePin("f".repeat(64), { from: null, to: null, resume: true }), false);
  });

  it("refuses hostile input before touching the store", async () => {
    const t = setup();
    const onFile = (await t.records.getSubject("ws_test", SUBJECT))!.pinDigest!;
    for (const key of ["", "A".repeat(64), "1".repeat(63), 7, ["f".repeat(64)]]) {
      await assert.rejects(t.engine.replacePin(key as string, { from: onFile, to: null }), rejects("invalid_input", /subjectKey/));
    }
    const bad: unknown[] = [
      null,
      undefined,
      "change",
      {},
      { from: onFile },
      { from: "", to: null },
      { from: 1, to: null },
      { from: onFile, to: "" },
      { from: onFile, to: {} },
      { from: onFile, to: null, phoneOnFile: "5555550142" },
      { from: onFile, to: null, phoneOnFile: "+0555" },
      { from: onFile, to: null, phoneOnFile: 15555550142 },
      { from: onFile, to: null, phoneOnFile: null },
      { from: onFile, to: null, resume: "yes" },
      { from: onFile, to: null, resume: 1 },
    ];
    for (const change of bad) {
      await assert.rejects(t.engine.replacePin(SUBJECT, change as never), rejects("invalid_input"), JSON.stringify(change));
    }
    assert.equal((await t.records.getSubject("ws_test", SUBJECT))!.pinDigest, onFile);
  });

  it("needs the pin factor on, in keyed_hash mode", async () => {
    const off = setup({ config: testConfig((c) => (c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "photo_id"] } })) });
    await assert.rejects(off.engine.replacePin(SUBJECT, { from: null, to: null }), rejects("precondition_failed", /pin factor/));
    const verifier = setup({
      config: testConfig((c) => (c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"], pin: { mode: "verifier", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 } } })),
    });
    await assert.rejects(verifier.engine.replacePin(SUBJECT, { from: null, to: null }), rejects("precondition_failed", /verifier mode/));
  });
});
