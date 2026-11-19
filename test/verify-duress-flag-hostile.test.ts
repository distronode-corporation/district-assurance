// The hostile pass on #124 (VER-12 "flag until cleared"), kept as regressions: each attack asserts
// the safe behaviour. C2 is a todo until Sean decides how the flag survives a failed write.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey, AttemptCounters } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../src/testing/index.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { duressClearedSubject } from "../src/verify/duress-flag.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const DURESS = "7391";
const HOUR = 3_600_000;
const WRONG = ["1357", "2468", "3579", "4680", "5791", "6802", "7913", "8024", "9135", "0246", "1470", "2581"];
const badge = (c: FlowConfig) => c.modules.badge!.settings as unknown as { pin: PinSettings };
const cfg = (patch: (c: FlowConfig) => void = () => undefined) =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    c.policy.levels[1]!.anyOf.push(["pin", "carrier_identity_match"]);
    c.policy.scopes["owner.command"] = 1;
    c.policy.scopeClasses = { "owner.command": "none" };
    badge(c).pin.duress = { refuseScopes: ["owner.command"] };
    patch(c);
  });
const tick = async (n = 10) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

async function mk(options: { counters?: AttemptCounters; workspaceId?: string } = {}): Promise<{ t: TestEngine; n: FakeDuressNotifier }> {
  const n = new FakeDuressNotifier();
  const workspaceId = options.workspaceId ?? "ws_test";
  const t =
    workspaceId === "ws_test"
      ? setup({ config: cfg(), adapters: { duressNotifier: n, ...(options.counters === undefined ? {} : { counters: options.counters }) } })
      : createTestEngine({ workspaceId, config: cfg(), adapters: { duressNotifier: n, ...(options.counters === undefined ? {} : { counters: options.counters }) } });
  if (workspaceId !== "ws_test") t.records.putSubject(workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, DURESS), { enrolled: true });
  return { t, n };
}

/** A call on the owner's account, number withheld, past any wait from an earlier entry. */
async function call(t: TestEngine): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  t.clock.advance(900_000);
  return callId;
}

/** Everything a caller (or the host speaking for them) can see of a passing PIN call. */
async function visible(t: TestEngine, callId: string, pin: string) {
  const answer = await t.engine.submitPin(callId, pin);
  const finished = await t.engine.finishVerification(callId);
  const state = await t.engine.state(callId);
  await tick();
  const receipt = await t.engine.endCall(callId);
  const events = (await t.ledger.list()).filter((e) => e.callId === callId).map((e) => [e.event, e.actor, e.detail]);
  return { answer, finished, state: { ...state, callId: "x", startedAt: "x", endedAt: "x" }, events, receipt: receipt === null ? null : { ...receipt.body, receiptId: "x", callId: "x", ledger: null, startedAt: "x", endedAt: "x", issuedAt: "x" } };
}

/** Counters that let a test fail or hold one call on one key. */
class FaultyCounters extends MemoryAttemptCounters {
  failNext: { op: "get" | "recordFailure" | "reset"; factor: string; times?: number } | null = null;
  holdGet: { factor: string; gate: Promise<void>; reached: () => void } | null = null;
  #maybeFail(op: "get" | "recordFailure" | "reset", key: AttemptCounterKey): void {
    if (this.failNext?.op === op && this.failNext.factor === key.factor) {
      const times = (this.failNext.times ?? 1) - 1;
      this.failNext = times > 0 ? { ...this.failNext, times } : null;
      throw new Error(`counters ${op} 503`);
    }
  }
  override async get(key: AttemptCounterKey, since: string): Promise<string[]> {
    this.#maybeFail("get", key);
    const got = await super.get(key, since);
    const hold = this.holdGet;
    if (hold !== null && hold.factor === key.factor) {
      this.holdGet = null;
      hold.reached();
      await hold.gate;
    }
    return got;
  }
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    this.#maybeFail("recordFailure", key);
    return super.recordFailure(key, at, since);
  }
  override async reset(key: AttemptCounterKey): Promise<void> {
    this.#maybeFail("reset", key);
    return super.reset(key);
  }
}

describe("#124 hostile: a duress-PIN-only attacker, number withheld", () => {
  it("A1 interleaving 2 wrong guesses and the duress PIN over 10 calls hits the hidden lock: the real PIN is refused while it holds, then passes as duress", async () => {
    const { t, n } = await mk();
    for (let c = 0; c < 5; c++) {
      const callId = await call(t);
      for (let g = 0; g < 2; g++) {
        await t.engine.submitPin(callId, WRONG[c * 2 + g]!);
        t.clock.advance(900_000);
      }
      // The fifth call's guesses reach the hidden count's 10: its duress entry is refused like any.
      await t.engine.submitPin(callId, DURESS);
    }
    const owner = await call(t);
    assert.deepEqual(await t.engine.submitPin(owner, PIN), { matched: false, locked: true }, "the owner is refused while the hidden lock holds");
    t.clock.advance(24 * HOUR);
    const later = await call(t);
    const before = n.told.length;
    assert.equal((await t.engine.submitPin(later, PIN)).matched, true);
    await t.engine.finishVerification(later);
    await tick();
    assert.ok(n.told.length > before, "the owner's pass alerts");
    assert.equal(await t.engine.authorize(later, "owner.command"), false);
  });

  it("A2 the hidden lock is no longer than plain wrong guesses give: the same 10 failures lock the same 24 hours", async () => {
    const plain = await mk();
    for (let i = 0; i < 10; i++) await plain.t.engine.submitPin(await call(plain.t), WRONG[i]!);
    const viaDuress = await mk();
    for (let c = 0; c < 5; c++) {
      const callId = await call(viaDuress.t);
      for (let g = 0; g < 2; g++) {
        await viaDuress.t.engine.submitPin(callId, WRONG[c * 2 + g]!);
        viaDuress.t.clock.advance(900_000);
      }
      await viaDuress.t.engine.submitPin(callId, DURESS);
    }
    const plainLock = (await plain.t.ledger.list()).filter((e) => e.event === "verification.locked" && e.detail.hard === true).at(-1)!.detail.until as string;
    const duressLock = (await viaDuress.t.ledger.list()).filter((e) => e.event === "verification.locked" && e.detail.hard === true).at(-1)!.detail.until as string;
    // Both locks end 24 hours after the first of the 10 failures they hold.
    const firstPlain = Date.parse((await plain.t.ledger.list()).find((e) => e.event === "verification.factor")!.at);
    const firstDuress = Date.parse((await viaDuress.t.ledger.list()).find((e) => e.event === "verification.factor")!.at);
    assert.equal(Date.parse(plainLock) - firstPlain, Date.parse(duressLock) - firstDuress);
  });

  it("A3 the duress PIN alone, without a wrong guess, never locks the owner out", async () => {
    const { t } = await mk();
    for (let i = 0; i < 20; i++) assert.equal((await t.engine.submitPin(await call(t), DURESS)).matched, true);
    assert.equal((await t.engine.submitPin(await call(t), PIN)).matched, true, "flagged, but not locked");
  });
});

describe("#124 hostile: can anyone learn that the flag is set?", () => {
  it("B1 a flagged subject's real-PIN pass looks the same as an unflagged one's: answer, level, scopes, state, ledger and receipt", async () => {
    const plain = await mk();
    const flagged = await mk();
    // One earlier call each, so both clocks and id sequences stand in the same place.
    await plain.t.engine.submitPin(await call(plain.t), PIN);
    await flagged.t.engine.submitPin(await call(flagged.t), DURESS);
    await tick();
    const a = await visible(plain.t, await call(plain.t), PIN);
    const b = await visible(flagged.t, await call(flagged.t), PIN);
    assert.deepEqual(b.answer, a.answer);
    assert.deepEqual(b.finished, a.finished);
    assert.deepEqual(b.state, a.state);
    assert.deepEqual(b.receipt, a.receipt);
    // The PIN entry's ledger tag is keyed, so its value differs; its shape and everything else do not.
    // The receipt's digest covers the ledger head, which the keyed tag changes; so it is set aside too.
    const shape = (events: unknown[][]) => JSON.stringify(events).replace(/"tag":"[0-9a-f]{64}"/g, '"tag":"T"').replace(/"digest":"[0-9a-f]{64}"/g, '"digest":"D"');
    assert.equal(shape(b.events), shape(a.events));
  });

  it("B2 after a duress entry, the next wrong guess waits and answers as it would after a pass", async () => {
    const answersAfter = async (first: string) => {
      const { t } = await mk();
      const callId = await call(t);
      await t.engine.submitPin(callId, first);
      const out = [];
      for (let i = 0; i < 2; i++) out.push(await t.engine.submitPin(callId, WRONG[i]!));
      return out;
    };
    assert.deepEqual(await answersAfter(DURESS), await answersAfter(PIN));
  });

  it("B3 the work a flagged pass does on the response path equals an unflagged pass's (store round trips)", async () => {
    const count = async (flag: boolean) => {
      const counters = new MemoryAttemptCounters();
      const ops: string[] = [];
      const proxy = new Proxy(counters, {
        get(target, prop) {
          const value = Reflect.get(target, prop) as unknown;
          return typeof value === "function" ? (...args: unknown[]) => (ops.push(String(prop)), (value as (...a: unknown[]) => unknown).apply(target, args)) : value;
        },
      }) as unknown as AttemptCounters;
      const { t } = await mk({ counters: proxy });
      if (flag) await t.engine.submitPin(await call(t), DURESS);
      const callId = await call(t);
      ops.length = 0;
      await t.engine.submitPin(callId, PIN);
      // A read or a write, one round trip each: which write it is does not change the time.
      return ops.map((op) => (op === "get" ? "read" : "write")).join(",");
    };
    assert.equal(await count(true), await count(false));
  });
});

describe("#124 hostile: store faults on the flag", () => {
  it("C1 the flag read fails: fail closed (no pass, the attempt counted)", async () => {
    const counters = new FaultyCounters();
    const { t } = await mk({ counters });
    await t.engine.submitPin(await call(t), DURESS);
    const callId = await call(t);
    counters.failNext = { op: "get", factor: "duress.flag" };
    await assert.rejects(t.engine.submitPin(callId, PIN), /counters get 503/);
    assert.equal((await t.engine.state(callId)).factors.length, 0, "no factor");
    assert.ok((await counters.get({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: OWNER }, "1970-01-01T00:00:00.000Z")).length > 0, "the attempt stays counted");
  });

  it("C2 the flag write fails after the call's write: the alert's delivery sets it, so the subject still ends up flagged", async () => {
    const counters = new FaultyCounters();
    const { t, n } = await mk({ counters });
    counters.failNext = { op: "recordFailure", factor: "duress.flag" };
    const first = await call(t);
    await assert.rejects(t.engine.submitPin(first, DURESS), /counters recordFailure 503/);
    await tick();
    assert.equal(n.told.length, 1, "the coerced entry's alert still goes out");
    const owner = await call(t);
    assert.equal((await t.engine.submitPin(owner, PIN)).matched, true);
    await t.engine.finishVerification(owner);
    await tick();
    assert.equal(n.told.length, 2, "the next pass is still under duress");
  });

  it("C2b ...but a clearing between the entry and its alert's delivery is never undone", async () => {
    const counters = new FaultyCounters();
    const { t, n } = await mk({ counters });
    // The entry's own write of the flag fails, and so does the first delivery's: the alert stays owed.
    counters.failNext = { op: "recordFailure", factor: "duress.flag", times: 2 };
    await assert.rejects(t.engine.submitPin(await call(t), DURESS), /counters recordFailure 503/);
    await tick();
    assert.equal(n.told.length, 0, "still owed");
    await t.engine.clearDuress(OWNER, "member-7");
    const owing = (await t.sessions.listCallsOwingAlerts!("ws_test"))[0]!;
    assert.equal(await t.engine.deliverDuressAlerts(owing), 1, "the alert itself still goes out");
    const owner = await call(t);
    assert.equal((await t.engine.submitPin(owner, PIN)).matched, true);
    await t.engine.finishVerification(owner);
    await tick();
    assert.equal(n.told.length, 1, "cleared stays cleared: no alert for the owner's pass");
    assert.equal(await t.engine.authorize(owner, "owner.command"), true);
  });
});

describe("#124 hostile: the coordinator's calls on the decisions", () => {
  it("G2 duress.cleared never names the subject: a keyed digest only the business can match", async () => {
    const { t } = await mk();
    await t.engine.submitPin(await call(t), DURESS);
    await tick();
    await t.engine.clearDuress(OWNER, "member-7");
    const entries = await t.ledger.list();
    const cleared = entries.find((e) => e.event === "duress.cleared")!;
    assert.deepEqual(cleared.detail, { subject: duressClearedSubject(TEST_KNOWLEDGE_KEY, OWNER), memberId: "member-7" });
    assert.notEqual(cleared.detail.subject, OWNER);
    const otherPin = entries.filter((e) => e.event !== "pin.reset");
    assert.equal(JSON.stringify(otherPin).includes(OWNER), false, "no entry but a business's own PIN reset names a subject");
  });

  it("G3 memberId is an opaque id: no email address, no whitespace, at most 64 characters", async () => {
    const { t } = await mk();
    for (const memberId of ["jane@example.com", "jane doe", "a\tb", "a\nb", "x".repeat(65), "role:admin", "é"]) {
      await assert.rejects(t.engine.clearDuress(OWNER, memberId), rejects("invalid_input", /opaque id/), memberId);
    }
    await t.engine.clearDuress(OWNER, "x".repeat(64));
    await t.engine.clearDuress(OWNER, "m.7_a-b");
    assert.equal((await t.ledger.list()).filter((e) => e.event === "duress.cleared").length, 2);
  });

  it("G5 a flag set while the duress PIN was on holds after the config turns it off: alerted, every scope refused", async () => {
    const { t, n } = await mk();
    await t.engine.submitPin(await call(t), DURESS);
    await tick();
    t.engine.configure(cfg((c) => delete badge(c).pin.duress));
    const owner = await call(t);
    assert.equal((await t.engine.submitPin(owner, PIN)).matched, true, "the same answer as any pass");
    await t.engine.finishVerification(owner);
    await tick();
    assert.equal(n.told.length, 2, "still alerted");
    for (const scope of ["owner.command", "status.read", "intake.file"]) assert.equal(await t.engine.authorize(owner, scope), false, scope);
    // An unflagged subject on the same config is untouched.
    const plain = setup({ config: cfg((c) => delete badge(c).pin.duress) });
    const { callId } = await plain.engine.startCall();
    await plain.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await plain.engine.submitPin(callId, PIN);
    await plain.engine.finishVerification(callId);
    assert.equal(await plain.engine.authorize(callId, "owner.command"), true);
  });

  it("G1 a flagged subject's passes alert once a call, the first, while every duress PIN entry alerts", async () => {
    const { t, n } = await mk();
    await t.engine.submitPin(await call(t), DURESS);
    await tick();
    assert.equal(n.told.length, 1);
    const owner = await call(t);
    await t.engine.submitPin(owner, PIN);
    await t.engine.finishVerification(owner);
    await t.engine.beginVerification(owner, { accountNumber: ACCOUNT });
    await t.engine.submitPin(owner, PIN);
    await t.engine.submitKeypad(owner, { dob: DOB });
    await t.engine.finishVerification(owner);
    await tick();
    assert.equal(n.told.length, 2, "three passes on one call: one alert");
    await t.engine.beginVerification(owner, { accountNumber: ACCOUNT });
    await t.engine.submitPin(owner, DURESS);
    await tick();
    assert.equal(n.told.length, 3, "a duress PIN entry on the same call alerts again");
    const next = await call(t);
    await t.engine.submitPin(next, PIN);
    await tick();
    assert.equal(n.told.length, 4, "a new call: one more");
    assert.equal(new Set(n.told.map((a) => a.alertId)).size, 4);
  });

  it("G0 a plug-in that passes a subject the line could not name reads no flag and no clearing", async () => {
    const t = setup({
      config: cfg((c) => {
        c.policy.levels[0] = { level: 1, anyOf: [["pin"], ["any_check"]] };
        (c.modules.badge!.settings as { factors: string[] }).factors.push("any_check");
      }),
      adapters: { duressNotifier: new FakeDuressNotifier() },
      badge: badgeModule({ factors: [{ kind: "any_check", summary: "passes anything", maxAttemptsPerCall: 1, adapters: [], judge: async () => true }] }),
    });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: "not digits" });
    assert.deepEqual(await t.engine.submitFactor(callId, "any_check", "x"), { matched: true, locked: false });
  });
});

describe("#124 hostile: clearDuress", () => {
  it("D1 a pass under the old flag, in flight while the business clears it, does not set the flag again", async () => {
    const counters = new FaultyCounters();
    const { t, n } = await mk({ counters });
    await t.engine.submitPin(await call(t), DURESS);
    await tick();
    const owner = await call(t);
    let release!: () => void;
    let reached!: () => void;
    const at = new Promise<void>((r) => (reached = r));
    counters.holdGet = { factor: "duress.flag", gate: new Promise<void>((r) => (release = r)), reached: () => reached() };
    const inFlight = t.engine.submitPin(owner, PIN);
    await at;
    await t.engine.clearDuress(OWNER, "member-7");
    release();
    assert.equal((await inFlight).matched, true);
    await tick();
    const alerts = n.told.length;
    const next = await call(t);
    assert.equal((await t.engine.submitPin(next, PIN)).matched, true);
    await t.engine.finishVerification(next);
    await tick();
    assert.equal(n.told.length, alerts, "cleared stays cleared: the later pass raises no alert");
    assert.equal(await t.engine.authorize(next, "owner.command"), true);
  });

  it("D2 refuses hostile member ids and subject keys before writing anything", async () => {
    const { t } = await mk();
    const before = (await t.ledger.list()).length;
    for (const memberId of ["", "a b", "\ud800", "x".repeat(129), "‮member", 7, null]) {
      await assert.rejects(t.engine.clearDuress(OWNER, memberId as string), rejects("invalid_input", /memberId/), String(memberId));
    }
    for (const memberId of ["x".repeat(65)]) {
      await assert.rejects(t.engine.clearDuress(OWNER, memberId), rejects("invalid_input", /memberId/), memberId);
    }
    for (const subjectKey of ["", OWNER.toUpperCase(), "__proto__", 1]) {
      await assert.rejects(t.engine.clearDuress(subjectKey as string, "m1"), rejects("invalid_input", /subjectKey/), String(subjectKey));
    }
    assert.equal((await t.ledger.list()).length, before);
  });

  it("D3 a ledger that refuses the record leaves the flag set: no clearing goes unrecorded", async () => {
    const { t, n } = await mk();
    await t.engine.submitPin(await call(t), DURESS);
    await tick();
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = async (input) => (input.event === "duress.cleared" ? Promise.reject(new Error("ledger 503")) : append(input));
    await assert.rejects(t.engine.clearDuress(OWNER, "m1"), /ledger 503/);
    t.ledger.append = append;
    const before = n.told.length;
    const owner = await call(t);
    await t.engine.submitPin(owner, PIN);
    await t.engine.finishVerification(owner);
    await tick();
    assert.equal(n.told.length, before + 1, "still under duress");
  });
});

describe("#124 hostile: the business's own unlocks", () => {
  async function hiddenLocked() {
    const r = await mk();
    for (let c = 0; c < 5; c++) {
      const callId = await call(r.t);
      for (let g = 0; g < 2; g++) {
        await r.t.engine.submitPin(callId, WRONG[c * 2 + g]!);
        r.t.clock.advance(900_000);
      }
      await r.t.engine.submitPin(callId, DURESS);
    }
    assert.deepEqual(await r.t.engine.submitPin(await call(r.t), PIN), { matched: false, locked: true });
    return r;
  }

  it("E1 a PIN reset lifts the hidden lock as it lifts the visible one", async () => {
    const { t } = await hiddenLocked();
    await t.engine.resetPin(OWNER);
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    assert.deepEqual(await t.engine.submitPin(await call(t), PIN), { matched: true, locked: false });
  });
});

describe("#124 hostile: tenants and races", () => {
  it("F1 one workspace's flag never touches another's subject with the same key, on a shared counters store", async () => {
    const counters = new MemoryAttemptCounters();
    const a = await mk({ counters, workspaceId: "ws_a" });
    const b = await mk({ counters, workspaceId: "ws_b" });
    await a.t.engine.submitPin(await call(a.t), DURESS);
    await tick();
    const callId = await call(b.t);
    await b.t.engine.submitPin(callId, PIN);
    await b.t.engine.finishVerification(callId);
    await tick();
    assert.equal(b.n.told.length, 0);
    assert.equal(await b.t.engine.authorize(callId, "owner.command"), true);
  });

  it("F2 two engines on shared stores: a duress entry on one flags the subject for the other", async () => {
    const one = await mk();
    const n2 = new FakeDuressNotifier();
    const two = createTestEngine({ config: cfg(), adapters: { duressNotifier: n2, sessions: one.t.sessions, records: one.t.records, ledger: one.t.ledger, counters: one.t.counters }, clock: one.t.clock });
    await one.t.engine.submitPin(await call(one.t), DURESS);
    await tick();
    const { callId } = await two.engine.startCall({ callId: "call_on_two" });
    await two.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    one.t.clock.advance(900_000);
    assert.equal((await two.engine.submitPin(callId, PIN)).matched, true);
    await two.engine.finishVerification(callId);
    await tick();
    assert.equal(n2.told.length, 1);
  });
});
