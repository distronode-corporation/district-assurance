// Hostile-pass regressions for #100 (GAT-3): one-time access codes, texted to the number on file, redeemed once.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { ReceiptSigner } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { verifyAccessGrant } from "../src/gate/access.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { MemoryAccessCodeStore, accessCodeDigest, accessCodes, type AccessCodeStore } from "../src/gate/codes.ts";
import { FakeAccessController, FakeMessageSender, FixedClock, MemoryCodeStore, generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, setup, testConfig } from "./helpers.ts";

const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] };
const keypadTarget = { id: "side-door", controller: "keypad", ref: "keypad-1" };
const door = { workspaceId: "ws_test", audience: "keypad", target: "keypad-1" };
const TEXT = /door code: (\d{8})/;

function world(options: { signer?: ReceiptSigner; store?: AccessCodeStore; workspaceId?: string; clock?: FixedClock; newCode?: () => string; maxWrongGuesses?: number; limits?: MemoryCodeStore } = {}) {
  const clock = options.clock ?? new FixedClock();
  const texts = new FakeMessageSender();
  const store = options.store ?? new MemoryAccessCodeStore();
  const accessSigner = generateTestSigner("gate-key-1");
  const ledger = new MemoryAuditLedger();
  const limits = options.limits ?? new MemoryCodeStore();
  const codes = accessCodes({
    key: "access-code-key-not-a-secret",
    signer: options.signer ?? accessSigner,
    store,
    ledger,
    messages: texts,
    limits,
    clock,
    ...(options.newCode === undefined ? {} : { newCode: options.newCode }),
    ...(options.maxWrongGuesses === undefined ? {} : { maxWrongGuesses: options.maxWrongGuesses }),
  });
  const config: FlowConfig = testConfig((c) => {
    c.policy.scopes["entry.open"] = 2;
    c.modules.gate = { settings: { targets: [keypadTarget] } };
    c.flows = { "code-entry": { steps: [verify as never, { type: "gate.grant", target: "side-door", lifetimeSeconds: 600 }] } };
  });
  const t = setup({ clock, config, adapters: { access: { lobby: new FakeAccessController(), keypad: codes.controller }, accessSigner, ledger }, ...(options.workspaceId === undefined ? {} : { workspaceId: options.workspaceId }) });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, ledger, clock, codes, texts, store, accessSigner };
}

async function issued(w: ReturnType<typeof world>): Promise<{ callId: string; code: string }> {
  const { callId } = await w.engine.startCall({ flow: "code-entry" });
  await w.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await w.engine.submitKeypad(callId, { dob: DOB });
  await w.engine.checkCarrier(callId);
  await w.engine.finishVerification(callId);
  await w.codes.issue(w.engine, callId);
  return { callId, code: TEXT.exec(w.texts.sent.at(-1)!.body)![1]! };
}

function deferred() {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  return { gate, release };
}

describe("hostile #100: redeem", () => {
  it("two keypads offering one code at once: one grant between them, however their signing interleaves", async () => {
    const real = generateTestSigner("gate-key-1");
    const held = deferred();
    let calls = 0;
    const signer: ReceiptSigner = {
      keyId: real.keyId,
      algorithm: real.algorithm,
      publicJwk: () => real.publicJwk(),
      sign: async (data) => (++calls === 1 ? held.gate.then(() => real.sign(data)) : real.sign(data)),
    };
    const w = world({ signer });
    const { code } = await issued(w);
    const first = w.codes.redeem({ ...door, code });
    const second = await w.codes.redeem({ ...door, code });
    held.release();
    const results = [await first, second];
    assert.equal(results.filter((r) => r.ok).length, 1, JSON.stringify(results.map((r) => r.ok)));
    assert.deepEqual(await w.codes.redeem({ ...door, code }), { ok: false });
  });

  it("refuses a code at another door, another controller, or in another workspace with the same ids", async () => {
    const w = world();
    const { code } = await issued(w);
    for (const other of [{ ...door, target: "keypad-2" }, { ...door, audience: "lobby" }, { ...door, workspaceId: "ws_other" }]) {
      assert.deepEqual(await w.codes.redeem({ ...other, code }), { ok: false }, JSON.stringify(other));
    }
    const b = world({ workspaceId: "ws_other", store: w.store });
    assert.deepEqual(await b.codes.redeem({ ...door, workspaceId: "ws_other", code }), { ok: false }, "a second workspace sharing the store");
    assert.equal((await w.codes.redeem({ ...door, code })).ok, true, "still redeemable at its own door");
  });

  it("never throws, and never matches, on hostile codes", async () => {
    const bad = (code: string) => [` ${code}`, `${code} `, `${code}\u0000`, [...code].map((d) => String.fromCharCode(0x0660 + Number(d))).join(""), code.slice(0, 7), `${code}0`, "\ud800", "x".repeat(1_000_000), null, 12345678, Number(code), ["1"], { toString: () => code }, "__proto__"];
    for (let i = 0; i < bad("00000000").length; i++) {
      // One guess per code, so the wrong-guess limit never ends it first.
      const w = world();
      const { code } = await issued(w);
      const guess = bad(code)[i];
      assert.deepEqual(await w.codes.redeem({ ...door, code: guess as never }), { ok: false }, String(guess).slice(0, 20));
      assert.equal((await w.codes.redeem({ ...door, code })).ok, true, "the real code survives the guess");
    }
  });

  it("keeps the code when signing fails, and refuses it after a revoke that lands mid-redeem", async () => {
    const real = generateTestSigner("gate-key-1");
    let fail = true;
    const signer: ReceiptSigner = {
      keyId: real.keyId,
      algorithm: real.algorithm,
      publicJwk: () => real.publicJwk(),
      sign: async (d) => {
        if (!fail) return real.sign(d);
        fail = false;
        throw new Error("hsm down");
      },
    };
    const w = world({ signer });
    const { code } = await issued(w);
    await assert.rejects(w.codes.redeem({ ...door, code }), /hsm down/);
    const store = w.store as MemoryAccessCodeStore;
    assert.notEqual(await store.get("ws_test", accessCodeDigest("access-code-key-not-a-secret", door, code)), null, "a failed signature leaves the code live");
    const take = store.take.bind(store);
    store.take = async (ws, digest, id) => {
      await w.codes.revoke(ws, id!);
      return take(ws, digest, id);
    };
    assert.deepEqual(await w.codes.redeem({ ...door, code }), { ok: false }, "revoked between the signature and the take");
    store.take = take;
    assert.deepEqual(await w.codes.redeem({ ...door, code }), { ok: false }, "and stays gone");
  });

  it("refuses a code at its grant's expiry exactly, and a redeemed grant fails the relay's check once expired", async () => {
    const w = world();
    const { code } = await issued(w);
    w.clock.advance(600_000);
    assert.deepEqual(await w.codes.redeem({ ...door, code }), { ok: false });
    const w2 = world();
    const second = await issued(w2);
    w2.clock.advance(599_999);
    const r = await w2.codes.redeem({ ...door, code: second.code });
    assert.equal(r.ok, true);
    const keys = w2.engine.accessKeys();
    assert.equal(verifyAccessGrant(r.ok && r.grant, keys, { workspaceId: "ws_test", audience: "keypad", now: new Date(w2.clock.now().getTime() + 1) }).ok, false);
  });

  it("the code is in the text and nowhere else: not the ledger, the session, the store or the signed grant", async () => {
    const w = world();
    const { callId, code } = await issued(w);
    const puts: string[] = [];
    const store = w.store as MemoryAccessCodeStore;
    const put = store.put.bind(store);
    store.put = async (entry, now) => (puts.push(JSON.stringify(entry)), put(entry, now));
    const again = await issued(w);
    for (const blob of [JSON.stringify(await w.ledger.list()), JSON.stringify(await w.sessions.get("ws_test", callId)), ...puts]) {
      assert.equal(blob.includes(code), false);
      assert.equal(blob.includes(again.code), false);
    }
    const r = await w.codes.redeem({ ...door, code });
    assert.equal(JSON.stringify(r).includes(code), false, "the signed grant carries no code");
  });
});

describe("hostile #100: wrong guesses spend a code", () => {
  it("five wrong guesses at its door spend the code, recorded without the guess; four do not", async () => {
    const w = world();
    const { callId, code } = await issued(w);
    for (let i = 0; i < 4; i++) assert.deepEqual(await w.codes.redeem({ ...door, code: "00000000" === code ? "11111111" : "00000000" }), { ok: false });
    assert.equal((await w.codes.redeem({ ...door, code })).ok, true, "four wrong guesses leave it");
    const v = world();
    const second = await issued(v);
    // A guess with no run of zeros: the ledger's genesis hash is all zeros.
    const wrong = second.code === "13572468" ? "24681357" : "13572468";
    for (let i = 0; i < 5; i++) assert.deepEqual(await v.codes.redeem({ ...door, code: wrong }), { ok: false });
    assert.deepEqual(await v.codes.redeem({ ...door, code: second.code }), { ok: false }, "spent: the right code no longer opens");
    const spent = (await v.ledger.list()).filter((e) => e.event === "access.code_spent");
    assert.deepEqual(spent.map((e) => [e.callId, e.detail]), [[second.callId, { grantId: "acc_1", reason: "wrong_guesses", guesses: 5 }]]);
    const text = JSON.stringify(await v.ledger.list());
    assert.equal(text.includes(wrong), false, "never the guess");
    assert.equal(text.includes(second.code), false, "never the code");
    assert.equal(callId, second.callId);
  });

  it("counts only guesses at the code's own door and workspace, each of two at once, and spends every code live there", async () => {
    const w = world();
    const first = await issued(w);
    for (let i = 0; i < 6; i++) {
      await w.codes.redeem({ ...door, target: "keypad-2", code: "1" });
      await w.codes.redeem({ ...door, workspaceId: "ws_other", code: "1" });
    }
    assert.equal((await w.codes.redeem({ ...door, code: first.code })).ok, true, "other doors and workspaces did not count");
    const v = world({ maxWrongGuesses: 2 });
    const a = await issued(v);
    v.clock.advance(61_000); // past the per-subject send interval, so a second code is texted
    const b = await issued(v);
    await Promise.all([v.codes.redeem({ ...door, code: "x" }), v.codes.redeem({ ...door, code: "y" })]);
    assert.deepEqual([(await v.codes.redeem({ ...door, code: a.code })).ok, (await v.codes.redeem({ ...door, code: b.code })).ok], [false, false]);
    assert.equal((await v.ledger.list()).filter((e) => e.event === "access.code_spent").length, 2, "one entry per spent code");
  });

  it("takes a limit from 1 to 10, and refuses anything else when the codes are made", () => {
    for (const bad of [0, 11, 1.5, Number.NaN, -1, Number.POSITIVE_INFINITY]) {
      assert.throws(() => world({ maxWrongGuesses: bad }), rejects("invalid_input", /maxWrongGuesses/), String(bad));
    }
    for (const ok of [1, 10]) assert.ok(world({ maxWrongGuesses: ok }));
  });
});

describe("hostile #100: the host's code generator", () => {
  it("fails the issue before anything is reserved, counted, stored or texted when newCode is not 8 digits", async () => {
    for (const bad of ["", "1234", "abcdefgh", "123456789", "1234567 ", "\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18", 12345678, null]) {
      const limits = new MemoryCodeStore();
      const w = world({ newCode: () => bad as never, limits });
      const { callId } = await w.engine.startCall({ flow: "code-entry" });
      await w.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await w.engine.submitKeypad(callId, { dob: DOB });
      await w.engine.checkCarrier(callId);
      await w.engine.finishVerification(callId);
      await assert.rejects(w.codes.issue(w.engine, callId), rejects("invalid_input", /newCode/), String(bad));
      assert.deepEqual(await w.engine.accessGrants(callId), [], "no grant reserved");
      assert.equal((w.store as MemoryAccessCodeStore).size, 0, "nothing stored");
      assert.equal(w.texts.sent.length, 0, "nothing texted");
      assert.ok(await limits.take({ workspaceId: "ws_test", key: { scope: "subject", key: "k" }, at: w.clock.now().toISOString(), max: 1, windowSeconds: 60, minIntervalSeconds: 0 }));
    }
  });
});
