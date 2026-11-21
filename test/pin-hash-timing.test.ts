// The PIN record check is timing-insensitive (ADR-29): one Argon2id run per check whatever is on
// file, and every tag or digest compared in constant time over its full length. `node:crypto` is
// watched before the engine is loaded (each test file runs in its own process), so the named
// imports in pin-hash.ts and hash.ts bind to the watching functions.
import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { describe, it, mock } from "node:test";

const runs: Array<{ memory: number; passes: number; parallelism: number }> = [];
const compares: Array<[number, number]> = [];
const realArgon2 = crypto.argon2;
const realEqual = crypto.timingSafeEqual;
/** Which runs, counted from 1 after the last reset, fail as an Argon2id run that cannot get its memory would. */
const failing = new Set<number>();
mock.method(crypto, "argon2", (algorithm: crypto.Argon2Algorithm, parameters: crypto.Argon2Parameters, callback: (err: Error | null, key: Buffer) => void) => {
  runs.push({ memory: parameters.memory, passes: parameters.passes, parallelism: parameters.parallelism });
  if (failing.has(runs.length)) return void setImmediate(() => callback(new Error("argon2 failed"), Buffer.alloc(0)));
  realArgon2(algorithm, parameters, callback);
});
mock.method(crypto, "timingSafeEqual", (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => {
  compares.push([a.byteLength, b.byteLength]);
  return realEqual(a, b);
});
syncBuiltinESMExports();

const { hmacSha256Hex } = await import("../src/core/hash.ts");
const { PIN_HASH_PARAMETERS, checkPinRecord, hashPinRecord } = await import("../src/verify/pin-hash.ts");
const { subjectKeyFor } = await import("../src/verify/knowledge.ts");
const { TEST_KNOWLEDGE_KEY } = await import("../src/testing/index.ts");
const { ACCOUNT, PHONE_ON_FILE, PIN, setup, waitOut } = await import("./helpers.ts");
const { MemoryRecordStore } = await import("../src/testing/index.ts");

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const keyed = (pin: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, `pin:${OWNER}:${pin}`);

function reset(): void {
  runs.length = 0;
  compares.length = 0;
  failing.clear();
}

describe("the PIN record check takes the same work whatever is on file", () => {
  it("runs Argon2id once at today's cost whatever is on file, a dearer record included (#149)", async () => {
    const record = await hashPinRecord(keyed(PIN));
    const cases: Array<[string, unknown, string]> = [
      ["an Argon2id record, the right PIN", record, PIN],
      ["an Argon2id record, a wrong PIN", record, "4827"],
      ["an earlier record, the right PIN", keyed(PIN), PIN],
      ["an earlier record, a wrong PIN", keyed(PIN), "4827"],
      ["no record", undefined, PIN],
      ["a record of nothing", "garbage", PIN],
      ["a downgraded record", record.replace("t=2", "t=1"), PIN],
      // Never run at its own cost: that would take longer than an unknown subject's stand-in.
      ["a dearer record", record.replace("t=2", "t=3"), PIN],
      ["a dearer record by memory", record.replace("m=19456", "m=38912"), PIN],
      ["a dearer record by lanes", record.replace("p=1", "p=2"), PIN],
    ];
    for (const [label, stored, pin] of cases) {
      reset();
      await checkPinRecord(stored, keyed(pin));
      assert.deepEqual(runs, [{ ...PIN_HASH_PARAMETERS }], label);
    }
  });

  it("compares an Argon2id tag over its full 32 bytes, whether it differs first, last or not at all", async () => {
    const record = await hashPinRecord(keyed(PIN));
    const tag = record.split("$").at(-1)!;
    const bytes = Buffer.from(tag, "base64");
    const variant = (i: number) => {
      const changed = Buffer.from(bytes);
      changed[i]! ^= 0x01;
      return record.replace(tag, changed.toString("base64").replace(/=+$/, ""));
    };
    for (const [label, stored, match] of [["the same", record, true], ["first byte", variant(0), false], ["last byte", variant(31), false]] as const) {
      reset();
      assert.equal((await checkPinRecord(stored, keyed(PIN))).match, match, label);
      assert.deepEqual(compares, [[32, 32]], label);
    }
    // An earlier record is compared as a 32-byte digest too.
    reset();
    assert.equal((await checkPinRecord(keyed(PIN), keyed("4827"))).match, false);
    assert.deepEqual(compares, [[32, 32]]);
  });

  it("gives the PIN factor two Argon2id runs per entry (the PIN and the duress PIN), for any subject", async () => {
    const t = setup();
    t.records.putSubject("ws_test", { subjectKey: "b".repeat(64), phoneOnFile: PHONE_ON_FILE, knowledge: {} });
    for (const [label, subject, pin] of [["the PIN", OWNER, PIN], ["a wrong PIN", OWNER, "4827"], ["no PIN on file", "b".repeat(64), PIN], ["an unknown subject", "c".repeat(64), PIN], ["a malformed entry", OWNER, "12"]] as const) {
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { subjectKey: subject });
      reset();
      await t.engine.submitPin(callId, pin);
      assert.equal(runs.length, 2, label);
      waitOut(t);
    }
  });

  it("keeps a verified outcome when hashing the upgraded record fails, and leaves the earlier record (CodeRabbit #143)", async () => {
    const records = new MemoryRecordStore();
    const t = setup({ adapters: { records } });
    records.putSubject("ws_test", { subjectKey: OWNER, phoneOnFile: PHONE_ON_FILE, knowledge: {}, pinDigest: keyed(PIN) });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { subjectKey: OWNER });
    reset();
    // Runs 1 and 2 are the entry's two checks; run 3 hashes the upgraded record, and fails.
    failing.add(3);
    assert.deepEqual(await t.engine.submitPin(callId, PIN), { matched: true, locked: false });
    assert.equal(runs.length, 3);
    assert.equal((await records.getSubject("ws_test", OWNER))!.pinDigest, keyed(PIN), "the earlier record is left for the next match");
  });
});
