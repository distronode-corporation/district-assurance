// PIN records as Argon2id over the keyed HMAC (ADR-29): hash and verify, a wrong PIN, the earlier
// keyed-HMAC records verifying and then upgraded, tampered and downgraded parameters refused.
import { strict as assert } from "node:assert";
import { argon2Sync } from "node:crypto";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { duressDigest, type PinSettings } from "../src/verify/factors.ts";
import { pinDigest, subjectKeyFor } from "../src/verify/knowledge.ts";
import { readPinTag } from "../src/verify/pin.ts";
import { PIN_HASH_CEILING, PIN_HASH_PARAMETERS, checkPinRecord, hashPinRecord, hashPinRecordSync } from "../src/verify/pin-hash.ts";
import { FakeDuressNotifier, MemoryRecordStore, TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, PHONE_ON_FILE, PIN, pinOnFile, setup, testConfig, waitOut } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const keyedPin = (pin: string, kind = "pin") => hmacSha256Hex(TEST_KNOWLEDGE_KEY, `${kind}:${OWNER}:${pin}`);
const RECORD = /^\$pin1\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/;

/** Unpadded base64, as the record writes it. */
const b64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** A record computed correctly, at any cost, the way an older or a hostile writer could. */
function recordAt(keyed: string, cost: { memory: number; passes: number; parallelism: number }, salt = Buffer.alloc(16, 7)): string {
  const tag = argon2Sync("argon2id", { message: Buffer.from(keyed, "hex"), nonce: salt, tagLength: 32, ...cost });
  return `$pin1$argon2id$v=19$m=${cost.memory},t=${cost.passes},p=${cost.parallelism}$${b64(salt)}$${b64(tag)}`;
}

type Badge = { factors: string[]; pin: PinSettings };
const duressConfig = (): FlowConfig =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    (c.modules.badge!.settings as unknown as Badge).pin.duress = { refuseScopes: [] };
  });

/** A test engine whose subject's PIN (and duress PIN, when given) are records of the earlier format: the bare keyed HMAC. */
function legacySetup(options: { duress?: boolean; records?: MemoryRecordStore } = {}) {
  const records = options.records ?? new MemoryRecordStore();
  const t = setup({ ...(options.duress ? { config: duressConfig() } : {}), adapters: { records, duressNotifier: new FakeDuressNotifier() } });
  const subject = { subjectKey: OWNER, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pinDigest: keyedPin(PIN), ...(options.duress ? { duressDigest: keyedPin(DURESS, "duress") } : {}) };
  records.putSubject("ws_test", subject);
  return { ...t, records };
}

async function login(t: { engine: ReturnType<typeof setup>["engine"] }, pin: string) {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { subjectKey: OWNER });
  return t.engine.submitPin(callId, pin);
}

describe("PIN records: Argon2id over the keyed HMAC", () => {
  it("hashes a keyed PIN into a versioned record that carries its parameters, and verifies it", async () => {
    const record = await hashPinRecord(keyedPin(PIN));
    assert.match(record, RECORD);
    assert.deepEqual(await checkPinRecord(record, keyedPin(PIN)), { match: true, upgrade: false });
    const again = hashPinRecordSync(keyedPin(PIN));
    assert.match(again, RECORD);
    assert.notEqual(again, record, "a fresh salt each time");
    assert.deepEqual(await checkPinRecord(again, keyedPin(PIN)), { match: true, upgrade: false });
    // The public builders give records the PIN factor accepts, for bytes and for an HMAC function.
    const kms = async (data: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, data);
    for (const stored of [pinDigest(TEST_KNOWLEDGE_KEY, OWNER, PIN), await pinDigest(kms, OWNER, PIN)]) {
      assert.match(stored, RECORD);
      assert.equal(await pinOnFile(stored, OWNER, PIN), true);
    }
    assert.equal(await pinOnFile(duressDigest(TEST_KNOWLEDGE_KEY, OWNER, DURESS), OWNER, DURESS, "duress"), true);
    assert.equal(await pinOnFile(duressDigest(TEST_KNOWLEDGE_KEY, OWNER, DURESS), OWNER, DURESS), false, "a duress record is keyed apart from a PIN");
  });

  it("refuses a wrong PIN, another subject's PIN and a record of nothing", async () => {
    const record = await hashPinRecord(keyedPin(PIN));
    assert.deepEqual(await checkPinRecord(record, keyedPin("4827")), { match: false, upgrade: false });
    assert.equal(await pinOnFile(record, "a".repeat(64), PIN), false, "bound to the subject");
    assert.deepEqual(await checkPinRecord(keyedPin(PIN), keyedPin("4827")), { match: false, upgrade: false }, "an earlier record, wrong PIN");
    for (const stored of [undefined, "", 42, null, "not a record"]) assert.deepEqual(await checkPinRecord(stored, keyedPin(PIN)), { match: false, upgrade: false });
    const t = setup();
    assert.deepEqual(await login(t, "4827"), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false }, "the seeded Argon2id record passes");
  });

  it("verifies a record of the earlier format, then replaces it with an Argon2id record on the match", async () => {
    assert.deepEqual(await checkPinRecord(keyedPin(PIN), keyedPin(PIN)), { match: true, upgrade: true });
    const t = legacySetup();
    assert.deepEqual(await login(t, "4827"), { matched: false, locked: false });
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, keyedPin(PIN), "a miss upgrades nothing");
    waitOut(t);
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false });
    const upgraded = (await t.records.getSubject("ws_test", OWNER))!.pinDigest;
    assert.match(upgraded!, RECORD);
    assert.equal(await pinOnFile(upgraded, OWNER, PIN), true);
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false }, "and the upgraded record passes next time");
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, upgraded, "an Argon2id record at today's cost is kept");
  });

  it("upgrades an earlier duress record on a duress entry, and never the other record", async () => {
    const t = legacySetup({ duress: true });
    assert.deepEqual(await login(t, DURESS), { matched: true, locked: false }, "a duress entry looks like a pass");
    const onFile = (await t.records.getSubject("ws_test", OWNER))!;
    assert.match(onFile.duressDigest!, RECORD);
    assert.equal(await pinOnFile(onFile.duressDigest, OWNER, DURESS, "duress"), true);
    assert.equal(onFile.pinDigest, keyedPin(PIN), "the PIN record is left as it was");
  });

  it("still passes when the record changed before the upgrade could be written", async () => {
    class Moved extends MemoryRecordStore {
      upgrades = 0;
      override async upgradePinDigest(): Promise<boolean> {
        this.upgrades++;
        return false;
      }
    }
    const records = new Moved();
    const t = legacySetup({ records });
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false });
    assert.equal(records.upgrades, 1);
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, keyedPin(PIN));
  });

  it("keeps a verified outcome when the upgrade's write fails, and tries again on the next match (CodeRabbit #143)", async () => {
    class Failing extends MemoryRecordStore {
      failing = true;
      override async upgradePinDigest(...args: Parameters<MemoryRecordStore["upgradePinDigest"]>): Promise<boolean> {
        if (this.failing) throw new Error("record store down");
        return super.upgradePinDigest(...args);
      }
    }
    const records = new Failing();
    const t = legacySetup({ duress: true, records });
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false }, "the PIN still passes");
    assert.deepEqual(await login(t, DURESS), { matched: true, locked: false }, "the duress PIN still looks like a pass");
    const tags = (await t.ledger.list()).filter((e) => e.event === "verification.factor").map((e) => readPinTag((d) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, d), e));
    assert.deepEqual(tags, ["pass", "duress"], "and the ledger's keyed tags say a pass, then a duress entry");
    const onFile = (await records.getSubject("ws_test", OWNER))!;
    assert.deepEqual([onFile.pinDigest, onFile.duressDigest], [keyedPin(PIN), keyedPin(DURESS, "duress")], "both records are left as they were");
    records.failing = false;
    assert.deepEqual(await login(t, PIN), { matched: true, locked: false });
    assert.match((await records.getSubject("ws_test", OWNER))!.pinDigest!, RECORD, "the next match upgrades it");
  });

  it("refuses a record whose parameters, salt, tag or spelling were changed", async () => {
    const record = await hashPinRecord(keyedPin(PIN));
    const [, , , , cost, salt, tag] = record.split("$");
    const flip = (s: string) => (s[0] === "A" ? "B" : "A") + s.slice(1);
    const tampered = [
      record.replace("m=19456", "m=19457"),
      record.replace("t=2", "t=3"),
      record.replace("p=1", "p=2"),
      record.replace(salt!, flip(salt!)),
      record.replace(tag!, flip(tag!)),
      record.replace("$argon2id$", "$argon2i$"),
      record.replace("$v=19$", "$v=16$"),
      record.replace("$pin1$", "$pin2$"),
      record.replace("m=19456", "m=019456"),
      `${record}=`,
      record.replace(tag!, tag!.slice(0, -1)),
      record.replace(cost!, "t=2,m=19456,p=1"),
    ];
    for (const stored of tampered) assert.deepEqual(await checkPinRecord(stored, keyedPin(PIN)), { match: false, upgrade: false }, stored);
    // Base64 whose unused low bits are set reads as the same bytes: one spelling per record only.
    const last = salt!.at(-1)!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const sameBytes = alphabet[alphabet.indexOf(last) + 1]!;
    const noncanonical = record.replace(`$${salt}$`, `$${salt!.slice(0, -1)}${sameBytes}$`);
    assert.equal(Buffer.from(noncanonical.split("$")[5]!, "base64").equals(Buffer.from(salt!, "base64")), true, "the same salt bytes");
    assert.deepEqual(await checkPinRecord(noncanonical, keyedPin(PIN)), { match: false, upgrade: false });
    const tagLast = tag!.at(-1)!;
    const noncanonicalTag = record.replace(`$${tag}`, `$${tag!.slice(0, -1)}${alphabet[alphabet.indexOf(tagLast) + 1]!}`);
    assert.deepEqual(await checkPinRecord(noncanonicalTag, keyedPin(PIN)), { match: false, upgrade: false });
  });

  it("refuses a correctly computed record below today's cost, or above the ceiling, and never upgrades it", async () => {
    const floor = { ...PIN_HASH_PARAMETERS };
    assert.deepEqual(await checkPinRecord(recordAt(keyedPin(PIN), floor), keyedPin(PIN)), { match: true, upgrade: false }, "the floor itself passes");
    assert.deepEqual(await checkPinRecord(recordAt(keyedPin(PIN), { ...floor, memory: 65536, passes: 3, parallelism: 2 }), keyedPin(PIN)), { match: true, upgrade: false }, "a dearer record passes");
    for (const weaker of [{ ...floor, memory: 8192 }, { ...floor, passes: 1 }]) {
      assert.deepEqual(await checkPinRecord(recordAt(keyedPin(PIN), weaker), keyedPin(PIN)), { match: false, upgrade: false }, JSON.stringify(weaker));
    }
    // Above the ceiling, refused before any run: the strings are written by hand, never computed.
    const salt = b64(Buffer.alloc(16, 1));
    const tag = b64(Buffer.alloc(32, 2));
    for (const [name, value] of [["m", PIN_HASH_CEILING.memory + 1], ["t", PIN_HASH_CEILING.passes + 1], ["p", PIN_HASH_CEILING.parallelism + 1]] as const) {
      const cost = { m: floor.memory, t: floor.passes, p: floor.parallelism, [name]: value };
      const stored = `$pin1$argon2id$v=19$m=${cost.m},t=${cost.t},p=${cost.p}$${salt}$${tag}`;
      assert.deepEqual(await checkPinRecord(stored, keyedPin(PIN)), { match: false, upgrade: false }, stored);
    }
    // On the PIN factor: a downgraded record fails the right PIN, and stays as it was.
    const t = setup();
    const downgraded = recordAt(keyedPin(PIN), { ...floor, memory: 8192, passes: 1 });
    t.records.putSubject("ws_test", { subjectKey: OWNER, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pinDigest: downgraded });
    assert.deepEqual(await login(t, PIN), { matched: false, locked: false });
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, downgraded);
  });

  it("keeps lockouts as they were: an earlier record's misses count, and the limit locks", async () => {
    const t = legacySetup();
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    assert.deepEqual(await t.engine.submitPin(callId, "1111"), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, "2222"), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, "3333"), { matched: false, locked: true });
    waitOut(t);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: false, locked: true }, "the right PIN is not judged once locked");
    assert.equal((await t.records.getSubject("ws_test", OWNER))!.pinDigest, keyedPin(PIN), "and a locked try upgrades nothing");
  });
});
