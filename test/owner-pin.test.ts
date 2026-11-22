// The owner PIN (ADR-20, ADR-31): the business sets, clears and lifts the owner's PIN over the
// engine's own stores, and a PIN keyed on the line is judged by the engine as any PIN.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { EngineError } from "../src/core/errors.ts";
import * as root from "../src/index.ts";
import { knowledgeHmac, subjectKeyFor } from "../src/verify/knowledge.ts";
import { OwnerPinConflictError, createOwnerPin, ownerSubjectKey, type OwnerPin, type OwnerPinOptions } from "../src/verify/owner-pin.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { pinOnFile, rejects, testConfig, waitOut } from "./helpers.ts";

const WS = "ws_test";
const LINE = "+15555550142";
const OTHER_LINE = "+15555550143";
const OWNER_PIN = "583190";
const NEW_PIN = "720461";
const hmac = knowledgeHmac(TEST_KNOWLEDGE_KEY);

function ownerConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.modules.badge = {
      settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"], pin: { mode: "keyed_hash", minDigits: 6, maxDigits: 12, maxAttemptsPerCall: 3 } },
    };
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"]] };
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    c.flows = { "owner-command": { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] } };
    patch(c);
  });
}

function world(patch?: (c: FlowConfig) => void, options: Partial<OwnerPinOptions> = {}): { t: TestEngine; owner: OwnerPin } {
  const t = createTestEngine({ config: ownerConfig(patch) });
  const owner = createOwnerPin({ engine: t.engine, hmac, records: t.records, counters: t.counters, now: () => t.clock.now(), ...options });
  return { t, owner };
}

/** One phone call on the owner's line keying one PIN, as the host's line does it. */
async function keyOnLine(t: TestEngine, owner: OwnerPin, pin: string, line: string = LINE): Promise<{ matched: boolean; locked: boolean }> {
  const { callId } = await t.engine.startCall({ flow: "owner-command", callingNumber: line });
  await t.engine.beginVerification(callId, { subjectKey: await owner.subjectKey(), callingNumber: line });
  const result = await t.engine.submitPin(callId, pin);
  await t.engine.endCall(callId);
  return result;
}

async function ownerRecord(t: TestEngine) {
  return t.records.getSubject(WS, subjectKeyFor(TEST_KNOWLEDGE_KEY, `owner:${WS}`));
}

/**
 * The test engine's record store, for racing owner PINs: each read waits until `readers` reads are
 * in, so every racer reads what is on file before any of them writes. No timers.
 */
function readBarrier(t: TestEngine, readers: number): TestEngine["records"] {
  let read = 0;
  let open!: () => void;
  const allRead = new Promise<void>((resolve) => (open = resolve));
  return {
    getSubject: async (workspaceId: string, subjectKey: string) => {
      const subject = await t.records.getSubject(workspaceId, subjectKey);
      if (++read === readers) open();
      await allRead;
      return subject;
    },
    createSubject: (workspaceId: string, subject: Parameters<TestEngine["records"]["createSubject"]>[1]) => t.records.createSubject(workspaceId, subject),
  } as unknown as TestEngine["records"];
}

async function events(t: TestEngine, name: string) {
  return (await t.ledger.list()).filter((e) => e.event === name);
}

describe("owner PIN", () => {
  it("is a root export", () => {
    assert.equal(root.createOwnerPin, createOwnerPin);
    assert.equal(root.OwnerPinConflictError, OwnerPinConflictError);
    assert.equal(root.ownerSubjectKey, ownerSubjectKey);
  });

  it("keys the owner as the subject owner:<workspaceId>, apart from any account", async () => {
    const { owner } = world();
    const key = await owner.subjectKey();
    assert.equal(key, subjectKeyFor(TEST_KNOWLEDGE_KEY, `owner:${WS}`));
    assert.equal(await ownerSubjectKey(hmac, WS), key);
    assert.notEqual(key, subjectKeyFor(TEST_KNOWLEDGE_KEY, WS));
    assert.notEqual(await ownerSubjectKey(hmac, "ws_other"), key);
  });

  it("reports no PIN and no lock before anything is set", async () => {
    const { owner } = world();
    assert.deepEqual(await owner.status({ phone: LINE }), { pinSet: false, locked: false, waitSeconds: 0, failures: 0, remaining: 10 });
    assert.deepEqual(await owner.status({ phone: null }), { pinSet: false, locked: false, waitSeconds: 0, failures: 0, remaining: 10 });
  });

  it("sets a PIN the engine then judges on the line, with no digits stored or written", async () => {
    const { t, owner } = world();
    assert.deepEqual(await owner.setPin({ phone: LINE }, OWNER_PIN), { ok: true });
    const record = await ownerRecord(t);
    assert.equal(record!.phoneOnFile, LINE);
    assert.deepEqual(record!.knowledge, {});
    assert.match(record!.pinDigest!, /^\$pin1\$argon2id\$/);
    assert.equal(await pinOnFile(record!.pinDigest, record!.subjectKey, OWNER_PIN), true);
    assert.equal(record!.pinDigest!.includes(OWNER_PIN), false);
    assert.equal((await owner.status({ phone: LINE })).pinSet, true);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN), { matched: true, locked: false });
    // A first PIN resets nothing, and nothing in the ledger holds the digits.
    assert.equal((await events(t, "pin.reset")).length, 0);
    assert.equal(JSON.stringify(await t.ledger.list()).includes(OWNER_PIN), false);
  });

  it("stores the line as no number when there is none", async () => {
    const { t, owner } = world();
    assert.deepEqual(await owner.setPin({ phone: null }, OWNER_PIN), { ok: true });
    assert.equal((await ownerRecord(t))!.phoneOnFile, "");
  });

  it("refuses an empty, short, oversized, non-digit or non-string PIN, storing nothing", async () => {
    const { t, owner } = world();
    const hostile: unknown[] = ["", "58319", "5831904726193", "58319a", " 583190", "583190 ", "５８３１９０", "58-3190", "٥٨٣١٩٠", "5".repeat(100_000), 583190, null, undefined, ["583190"], { toString: () => "583190" }];
    for (const pin of hostile) {
      assert.deepEqual(await owner.setPin({ phone: LINE }, pin as string), { ok: false, reason: "malformed" }, String(pin).slice(0, 20));
    }
    assert.equal(await ownerRecord(t), null);
    assert.equal((await t.ledger.list()).length, 0);
  });

  it("refuses a weak PIN, storing nothing", async () => {
    const { t, owner } = world();
    for (const pin of ["000000", "111111", "123456", "654321", "789012", "123456789012"]) {
      assert.deepEqual(await owner.setPin({ phone: LINE }, pin), { ok: false, reason: "weak" }, pin);
    }
    assert.equal(await ownerRecord(t), null);
  });

  it("counts wrong PINs up to the hard lock, with waits, then refuses even the right one", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    for (let n = 1; n <= 9; n++) {
      assert.deepEqual(await keyOnLine(t, owner, "000001"), { matched: false, locked: false }, `wrong PIN ${n}`);
      const status = await owner.status({ phone: LINE });
      assert.deepEqual([status.locked, status.failures, status.remaining], [false, n, 10 - n]);
      assert.ok(status.waitSeconds > 0, "a wait after each failure");
      waitOut(t);
      assert.equal((await owner.status({ phone: LINE })).waitSeconds, 0);
    }
    // The boundary: the tenth wrong PIN in the window is the hard lock.
    assert.deepEqual(await keyOnLine(t, owner, "000001"), { matched: false, locked: true });
    assert.deepEqual(await owner.status({ phone: LINE }), { pinSet: true, locked: true, waitSeconds: 0, failures: 10, remaining: 0 });
    waitOut(t);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN), { matched: false, locked: true }, "the right PIN is refused under the hard lock");
    assert.equal((await owner.status({ phone: LINE })).locked, true);
  });

  it("reports the first wait exactly, and nothing once it has passed", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    await keyOnLine(t, owner, "000001");
    assert.equal((await owner.status({ phone: LINE })).waitSeconds, 5);
    t.clock.advance(4_001);
    assert.equal((await owner.status({ phone: LINE })).waitSeconds, 1);
    t.clock.advance(999);
    assert.equal((await owner.status({ phone: LINE })).waitSeconds, 0);
  });

  it("ends the hard lock when the oldest failure leaves the window, not a millisecond before", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: null }, OWNER_PIN);
    const first = t.clock.now().getTime();
    for (let n = 0; n < 10; n++) {
      await keyOnLine(t, owner, "000001", OTHER_LINE);
      waitOut(t);
    }
    assert.equal((await owner.status({ phone: null })).locked, true);
    t.clock.advance(first + 24 * 3_600_000 - 1 - t.clock.now().getTime());
    assert.equal((await owner.status({ phone: null })).locked, true);
    t.clock.advance(1);
    const status = await owner.status({ phone: null });
    assert.deepEqual([status.locked, status.failures, status.remaining], [false, 9, 1]);
  });

  it("counts concurrent wrong PINs on separate calls, every one of them", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    const results = await Promise.all(Array.from({ length: 6 }, () => keyOnLine(t, owner, "000001")));
    assert.ok(results.every((r) => !r.matched));
    // Every attempt is recorded on the subject before it is judged: none goes uncounted.
    assert.equal((await owner.status({ phone: null })).failures, 6);
    assert.equal((await owner.status({ phone: LINE })).remaining, 4);
  });

  it("counts a right PIN keyed in a race with wrong ones only as the engine allows", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    const results = await Promise.all([keyOnLine(t, owner, "000001"), keyOnLine(t, owner, OWNER_PIN), keyOnLine(t, owner, "000002")]);
    // At most one is judged; the others meet the wait the first one started.
    assert.ok(results.filter((r) => r.matched).length <= 1);
    assert.equal((await owner.status({ phone: null })).locked, false);
  });

  it("lifts the owner's locks, the subject's and the line's, and the right PIN passes again", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    for (let n = 0; n < 10; n++) {
      await keyOnLine(t, owner, "000001");
      waitOut(t);
    }
    assert.equal((await owner.status({ phone: LINE })).locked, true);
    await owner.liftLock({ phone: LINE }, "member_1");
    assert.deepEqual(await owner.status({ phone: LINE }), { pinSet: true, locked: false, waitSeconds: 0, failures: 0, remaining: 10 });
    const unlocked = await events(t, "verification.unlocked");
    assert.deepEqual(
      unlocked.map((e) => [e.detail.scope, e.detail.memberId]),
      [
        ["subject", "member_1"],
        ["number", "member_1"],
      ],
    );
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN), { matched: true, locked: false });
  });

  it("lifts only the subject's lock when the line is not given, so the line stays locked", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    for (let n = 0; n < 10; n++) {
      await keyOnLine(t, owner, "000001");
      waitOut(t);
    }
    await owner.liftLock({ phone: null }, "member_1");
    assert.equal((await owner.status({ phone: null })).locked, false);
    assert.equal((await owner.status({ phone: LINE })).locked, true);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN), { matched: false, locked: true });
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN, OTHER_LINE), { matched: true, locked: false });
  });

  it("refuses a lift for a member id the engine refuses, lifting nothing", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    await keyOnLine(t, owner, "000001");
    for (const memberId of ["", "owner@example.test", "a b", "x".repeat(65)]) {
      await assert.rejects(owner.liftLock({ phone: LINE }, memberId), rejects("invalid_input"));
    }
    assert.equal((await owner.status({ phone: LINE })).failures, 1);
    assert.equal((await events(t, "verification.unlocked")).length, 0);
  });

  it("changes a PIN in one step: the old PIN fails, the new passes, the subject's counters go", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    for (let n = 0; n < 3; n++) {
      await keyOnLine(t, owner, "000001");
      waitOut(t);
    }
    assert.deepEqual(await owner.setPin({ phone: LINE }, NEW_PIN), { ok: true });
    assert.equal((await events(t, "pin.reset")).length, 1);
    // The subject's counter is cleared; the line's is not the business's PIN change to forgive.
    assert.equal((await owner.status({ phone: null })).failures, 0);
    assert.equal((await owner.status({ phone: LINE })).failures, 3);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN, OTHER_LINE), { matched: false, locked: false });
    waitOut(t);
    assert.deepEqual(await keyOnLine(t, owner, NEW_PIN, OTHER_LINE), { matched: true, locked: false });
  });

  it("keeps the PIN and the number on file when the new record cannot be computed", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    const before = (await ownerRecord(t))!;
    let fail = false;
    const flaky = async (data: string) => {
      if (fail && data.startsWith("pin:")) throw new Error("key store unavailable");
      return hmac(data);
    };
    const second = createOwnerPin({ engine: t.engine, hmac: flaky, records: t.records, counters: t.counters });
    fail = true;
    await assert.rejects(second.setPin({ phone: OTHER_LINE }, NEW_PIN), /key store unavailable/);
    assert.deepEqual(await ownerRecord(t), before);
    assert.equal((await events(t, "pin.reset")).length, 0);
  });

  it("keeps the old PIN and number, never no PIN, when the store fails the replacement", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    const before = (await ownerRecord(t))!;
    const store = t.records as { replacePinDigest: typeof t.records.replacePinDigest };
    const original = store.replacePinDigest;
    store.replacePinDigest = async () => {
      throw new Error("store unavailable");
    };
    const error = (await owner.setPin({ phone: OTHER_LINE }, NEW_PIN).catch((e: unknown) => e)) as Error;
    store.replacePinDigest = original;
    assert.match(error.message, /store unavailable/);
    assert.equal(error.message.includes(NEW_PIN), false);
    assert.deepEqual(await ownerRecord(t), before);
    assert.equal((await events(t, "pin.reset")).length, 0);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN), { matched: true, locked: false });
  });

  it("refuses with a typed conflict, naming no PIN, when the record on file changed since it was read; a retry lands", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    // The read sees a record that is no longer on file, as when another change landed in between.
    const stale = {
      getSubject: async (workspaceId: string, subjectKey: string) => ({ ...(await t.records.getSubject(workspaceId, subjectKey))!, pinDigest: "$pin1$replaced-meanwhile" }),
      createSubject: () => Promise.resolve(false),
    } as unknown as TestEngine["records"];
    const racing = createOwnerPin({ engine: t.engine, hmac, records: stale, counters: t.counters });
    for (const run of [() => racing.setPin({ phone: OTHER_LINE }, NEW_PIN), () => racing.clearPin()]) {
      const error = (await run().catch((e: unknown) => e)) as EngineError;
      assert.ok(error instanceof OwnerPinConflictError);
      assert.equal(error.code, "conflict");
      assert.equal(error.name, "OwnerPinConflictError");
      assert.equal(error.message.includes(OWNER_PIN) || error.message.includes(NEW_PIN), false);
    }
    const record = (await ownerRecord(t))!;
    assert.equal(record.phoneOnFile, LINE, "a failed set leaves the number");
    assert.equal(await pinOnFile(record.pinDigest, record.subjectKey, OWNER_PIN), true);
    assert.equal((await events(t, "pin.reset")).length, 0);
    // The host reads again and retries: it lands.
    assert.deepEqual(await owner.setPin({ phone: OTHER_LINE }, NEW_PIN), { ok: true });
    assert.equal((await ownerRecord(t))!.phoneOnFile, OTHER_LINE);
  });

  it("lands exactly one of two changes that read before either writes, every time, in every pairing", async () => {
    const set = (pin: string, phone: string) => (o: OwnerPin) => o.setPin({ phone }, pin).then(() => `set ${pin} ${phone}`);
    const clear = (o: OwnerPin) => o.clearPin().then(() => "clear");
    const pairings: Array<{ name: string; first: boolean; racers: Array<(o: OwnerPin) => Promise<string>> }> = [
      { name: "two first PINs", first: true, racers: [set(OWNER_PIN, LINE), set(NEW_PIN, OTHER_LINE)] },
      { name: "two changes", first: false, racers: [set(NEW_PIN, OTHER_LINE), set("306418", LINE)] },
      { name: "a change and a clear", first: false, racers: [set(NEW_PIN, OTHER_LINE), clear] },
      { name: "two clears", first: false, racers: [clear, clear] },
    ];
    for (const { name, first, racers } of pairings) {
      for (const order of [0, 1]) {
        for (let round = 0; round < 5; round++) {
          const at = `${name}, order ${order}, round ${round}`;
          const { t, owner } = world();
          if (!first) await owner.setPin({ phone: LINE }, "915273");
          const before = (await ownerRecord(t))?.pinDigest ?? null;
          const barrier = readBarrier(t, racers.length);
          const ordered = order === 0 ? racers : [...racers].reverse();
          const outcomes = await Promise.allSettled(ordered.map((race) => race(createOwnerPin({ engine: t.engine, hmac, records: barrier, counters: t.counters }))));
          const won = outcomes.filter((o): o is PromiseFulfilledResult<string> => o.status === "fulfilled");
          const lost = outcomes.filter((o): o is PromiseRejectedResult => o.status === "rejected");
          assert.equal(won.length, 1, `${at}: one lands`);
          assert.equal(lost.length, 1, `${at}: one conflict`);
          assert.ok(lost[0]!.reason instanceof OwnerPinConflictError, `${at}: the loser is a typed conflict`);
          // What is on file is the winner's alone, and the record read before is gone.
          const record = (await ownerRecord(t))!;
          const winner = won[0]!.value;
          assert.notEqual(record.pinDigest ?? null, before, at);
          if (winner === "clear") assert.equal(record.pinDigest, undefined, at);
          else {
            const [, pin, phone] = winner.split(" ");
            assert.equal(await pinOnFile(record.pinDigest, record.subjectKey, pin!), true, `${at}: the winner's PIN`);
            assert.equal(record.phoneOnFile, phone, `${at}: the winner's number`);
          }
          assert.equal((await events(t, "pin.reset")).length, first ? 0 : 1, `${at}: one pin.reset, for the change that landed`);
        }
      }
    }
  });

  it("refreshes the number on file on every set, and writes no number for a line without one", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    assert.equal((await ownerRecord(t))!.phoneOnFile, LINE);
    await owner.setPin({ phone: OTHER_LINE }, NEW_PIN);
    assert.equal((await ownerRecord(t))!.phoneOnFile, OTHER_LINE);
    await owner.setPin({ phone: null }, OWNER_PIN);
    assert.equal((await ownerRecord(t))!.phoneOnFile, "");
    await owner.setPin({ phone: LINE }, NEW_PIN);
    assert.equal((await ownerRecord(t))!.phoneOnFile, LINE);
    // A refused set leaves the number as it was.
    assert.deepEqual(await owner.setPin({ phone: OTHER_LINE }, "123456"), { ok: false, reason: "weak" });
    assert.deepEqual(await owner.setPin({ phone: OTHER_LINE }, "1"), { ok: false, reason: "malformed" });
    assert.equal((await ownerRecord(t))!.phoneOnFile, LINE);
  });

  it("clears a PIN and its counters; the old PIN then fails, and the number stays", async () => {
    const { t, owner } = world();
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    await keyOnLine(t, owner, "000001");
    await owner.clearPin();
    assert.deepEqual(await owner.status({ phone: null }), { pinSet: false, locked: false, waitSeconds: 0, failures: 0, remaining: 10 });
    assert.equal((await ownerRecord(t))!.phoneOnFile, LINE);
    assert.equal((await events(t, "pin.reset")).length, 1);
    waitOut(t);
    assert.deepEqual(await keyOnLine(t, owner, OWNER_PIN, OTHER_LINE), { matched: false, locked: false });
  });

  it("clears when no PIN is set without failing, changing and recording nothing", async () => {
    const { t, owner } = world();
    await owner.clearPin();
    await owner.clearPin();
    assert.equal((await owner.status({ phone: null })).pinSet, false);
    assert.equal(await ownerRecord(t), null);
    assert.equal((await events(t, "pin.reset")).length, 0);
  });

  it("refuses a line that is not an E.164 number or null", async () => {
    const { owner } = world();
    for (const line of [{ phone: "5555550142" }, { phone: "+0555" }, { phone: "" }, { phone: 15555550142 }, { phone: undefined }, {}, null, undefined, "+15555550142"]) {
      const asLine = line as unknown as { phone: string | null };
      await assert.rejects(owner.status(asLine), rejects("invalid_input"), JSON.stringify(line));
      await assert.rejects(owner.setPin(asLine, OWNER_PIN), rejects("invalid_input"));
      await assert.rejects(owner.liftLock(asLine, "member_1"), rejects("invalid_input"));
    }
  });

  it("needs Badge with the pin factor on in keyed_hash mode", async () => {
    const off = [
      (c: FlowConfig) => {
        c.modules.badge!.enabled = false;
        c.policy.levels[0] = { level: 1, anyOf: [["pin"]] };
        c.flows = {};
      },
      (c: FlowConfig) => {
        c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "photo_id"] } };
        c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"]] };
        c.flows = {};
      },
      (c: FlowConfig) => {
        c.modules.badge = { settings: { factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"], pin: { mode: "verifier", minDigits: 6, maxDigits: 12, maxAttemptsPerCall: 3 } } };
      },
    ];
    for (const patch of off) {
      const { owner } = world(patch);
      for (const run of [() => owner.status({ phone: LINE }), () => owner.setPin({ phone: LINE }, OWNER_PIN), () => owner.clearPin(), () => owner.liftLock({ phone: LINE }, "member_1")]) {
        await assert.rejects(run(), rejects("precondition_failed", /keyed_hash/));
      }
    }
  });

  it("takes the engine's PIN length, as a configure changes it", async () => {
    const { t, owner } = world();
    t.engine.configure(ownerConfig((c) => ((c.modules.badge!.settings as { pin: { minDigits: number } }).pin.minDigits = 8)));
    assert.deepEqual(await owner.setPin({ phone: LINE }, OWNER_PIN), { ok: false, reason: "malformed" });
    assert.deepEqual(await owner.setPin({ phone: LINE }, "58319047"), { ok: true });
  });

  it("reads the facts under the engine's lockout, its only source, as a configure changes it", async () => {
    const stricter = (c: FlowConfig) => ((c.modules.badge!.settings as { lockout?: unknown }).lockout = { lockAfterFailures: 3 });
    const { t, owner } = world(stricter);
    await owner.setPin({ phone: LINE }, OWNER_PIN);
    assert.equal((await owner.status({ phone: LINE })).remaining, 3);
    for (let n = 0; n < 3; n++) {
      await keyOnLine(t, owner, "000001");
      waitOut(t);
    }
    assert.deepEqual(await owner.status({ phone: LINE }), { pinSet: true, locked: true, waitSeconds: 0, failures: 3, remaining: 0 });
    t.engine.configure(ownerConfig());
    assert.deepEqual(await owner.status({ phone: LINE }), { pinSet: true, locked: false, waitSeconds: 0, failures: 3, remaining: 7 });
  });

  it("takes the knowledge key only as an HMAC function, and refuses a malformed answer", async () => {
    const t = createTestEngine({ config: ownerConfig() });
    for (const bad of [TEST_KNOWLEDGE_KEY, new Uint8Array(32), undefined, null]) {
      assert.throws(() => createOwnerPin({ engine: t.engine, hmac: bad as never, records: t.records, counters: t.counters }), rejects("invalid_input", /hmac/));
    }
    const garbage = createOwnerPin({ engine: t.engine, hmac: async () => "not hex", records: t.records, counters: t.counters });
    await assert.rejects(garbage.setPin({ phone: LINE }, OWNER_PIN), rejects("invalid_input", /64 lower-case hex/));
    assert.equal(await t.records.getSubject(WS, subjectKeyFor(TEST_KNOWLEDGE_KEY, `owner:${WS}`)), null);
  });

  it("reads the system clock when no clock is given", async () => {
    const t = createTestEngine({ config: ownerConfig() });
    const counters = new MemoryAttemptCounters();
    const owner = createOwnerPin({ engine: t.engine, hmac, records: t.records, counters });
    const key = await owner.subjectKey();
    await counters.recordFailure({ workspaceId: WS, factor: "pin", scope: "subject", key }, new Date().toISOString(), "1970-01-01T00:00:00.000Z");
    const status = await owner.status({ phone: null });
    assert.deepEqual([status.failures, status.remaining], [1, 9]);
    assert.ok(status.waitSeconds >= 1 && status.waitSeconds <= 5);
  });
});
