// Hostile-pass regressions for #101 (GAT-4): web sign-in step-up tokens, issued on a verified call, exchanged once.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import type { ReceiptSigner } from "../src/core/adapters.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { MAX_STEP_UP_TOKEN_BYTES } from "../src/gate/step-up.ts";
import { TEST_KNOWLEDGE_KEY, generateTestSigner, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, setup, testConfig } from "./helpers.ts";

const PORTAL = "https://portal.example.test";
const NONCE = "482913";
const SUBJECT_KEY = hmacSha256Hex(TEST_KNOWLEDGE_KEY, `subject:${ACCOUNT}`);
const portal = { audience: PORTAL, subjectKey: SUBJECT_KEY, nonce: NONCE };

class StoppingStore extends MemorySessionStore {
  stopWhen: (() => boolean) | null = null;
  override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
    if (this.stopWhen?.() === true) {
      this.stopWhen = null;
      throw new Error("store down");
    }
    return super.compareAndSet(w, c, v, r);
  }
}

function config(): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["entry.sign_in"] = 2;
    c.modules["step-up"] = { settings: { issuer: "https://verify.example.test", sites: [{ id: "portal", audience: PORTAL }] } };
    c.flows = { web: { steps: [{ type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.sign_in"] } as never, { type: "step-up.issue", site: "portal" }] } };
  });
}

function world(options: { signer?: ReceiptSigner; workspaceId?: string; sessions?: StoppingStore } = {}) {
  const sessions = options.sessions ?? new StoppingStore();
  const t = setup({ config: config(), adapters: { sessions, stepUpSigner: options.signer ?? generateTestSigner("step-up-key-1") }, ...(options.workspaceId === undefined ? {} : { workspaceId: options.workspaceId }) });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  if (options.workspaceId !== undefined) t.records.putSubject(options.workspaceId, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return { ...t, sessions };
}

async function verified(t: ReturnType<typeof world>): Promise<string> {
  const { callId } = await t.engine.startCall({ flow: "web" });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  await t.engine.finishVerification(callId);
  return callId;
}

function heldSigner() {
  const real = generateTestSigner("step-up-key-1");
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let reached!: () => void;
  const started = new Promise<void>((r) => (reached = r));
  const signer: ReceiptSigner = { keyId: real.keyId, algorithm: real.algorithm, publicJwk: () => real.publicJwk(), sign: async (d) => (reached(), await gate, real.sign(d)) };
  return { signer, release, started };
}

describe("hostile #101: exchange", () => {
  it("two exchanges of one token at once: one succeeds, the other is refused, and one entry each", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    const answers = await Promise.all([t.engine.exchangeStepUpToken(token, portal), t.engine.exchangeStepUpToken(token, portal), t.engine.exchangeStepUpToken(token, portal)]);
    assert.equal(answers.filter((a) => a.ok).length, 1, JSON.stringify(answers));
    assert.equal((await t.ledger.list()).filter((e) => e.event === "stepup.exchanged").length, 1);
  });

  it("a token from one workspace never exchanges in another with the same call and token ids", async () => {
    const a = world();
    const b = world({ workspaceId: "ws_b" });
    const ca = await verified(a);
    const cb = await verified(b);
    assert.equal(ca, cb, "the same call id in both");
    const fromA = await a.engine.issueStepUpToken(ca, { nonce: NONCE });
    const fromB = await b.engine.issueStepUpToken(cb, { nonce: NONCE });
    assert.equal(fromA.tokenId, fromB.tokenId, "and the same token id");
    assert.deepEqual(await b.engine.exchangeStepUpToken(fromA.token, portal), { ok: false, reason: "unknown" });
    assert.equal((await b.engine.exchangeStepUpToken(fromB.token, portal)).ok, true, "B's own token is untouched");
  });

  it("untrusted content after the token was issued refuses it", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    await t.engine.markUntrusted(callId, "transcript");
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "tainted" });
  });

  it("never throws on hostile tokens, and a tampered byte is unknown", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
    const hostile: unknown[] = [null, 42, {}, [], "", "a.b", "a.b.c.d", "\ud800.\ud800.\ud800", "x".repeat(1_000_000), `e30.${b64({ sid: "__proto__", jti: "constructor", nonce: NONCE })}.c2ln`, `e30.${b64({ sid: callId, jti: "stu_1", nonce: NONCE })}.c2ln`];
    const parts = token.split(".");
    hostile.push(`${parts[0]}.${parts[1]}.${parts[2]!.slice(0, -2)}AA`, `${parts[0]}.${parts[1]}x.${parts[2]}`);
    for (const bad of hostile) {
      const answer = await t.engine.exchangeStepUpToken(bad, portal);
      assert.equal(answer.ok, false, String(bad).slice(0, 30));
    }
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true, "none of them used the real token up");
  });
});

describe("hostile #101: issue", () => {
  it("endCall while the token is being signed: it is never handed out, and never exchanges", async () => {
    const held = heldSigner();
    const t = world({ signer: held.signer });
    const callId = await verified(t);
    const pending = t.engine.issueStepUpToken(callId, { nonce: NONCE });
    await held.started;
    await t.engine.endCall(callId);
    held.release();
    await assert.rejects(pending, /not issued/);
    assert.deepEqual((await t.engine.stepUpTokens(callId)).map((x) => x.status), ["failed"]);
  });

  it("a lost write after signing hands nothing out, and the stale reservation fails before the next one", async () => {
    const t = world();
    const callId = await verified(t);
    let writes = 0;
    t.sessions.stopWhen = () => ++writes === 2;
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE }), /store down/);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE }), /being issued/);
    t.clock.advance(121_000);
    const next = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    assert.equal((await t.engine.exchangeStepUpToken(next.token, portal)).ok, true);
    assert.deepEqual((await t.engine.stepUpTokens(callId)).map((x) => x.status), ["failed", "exchanged"]);
  });

  it("keeps the nonce, the token and the subject key out of the ledger", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: "90817263" });
    await t.engine.exchangeStepUpToken(token, { ...portal, nonce: "90817263" });
    const text = JSON.stringify(await t.ledger.list());
    for (const secret of ["90817263", token, token.split(".")[2]!, SUBJECT_KEY]) assert.equal(text.includes(secret), false, secret.slice(0, 12));
  });

  it("a mismatched nonce uses the token up: the right one cannot follow (one shot, by design)", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, { ...portal, nonce: "000000" }), { ok: false, reason: "mismatch" });
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, false);
  });
});

describe("hostile #101: token size", () => {
  it("refuses a token over 4 KiB as malformed, without parsing it or reading any call", async () => {
    const t = world();
    const callId = await verified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    assert.ok(Buffer.byteLength(token) < 1024, "an issued token is well under the cap");
    const claims = Buffer.from(JSON.stringify({ sid: callId, jti: "stu_1", nonce: NONCE, pad: "x".repeat(MAX_STEP_UP_TOKEN_BYTES) })).toString("base64url");
    const parse = JSON.parse;
    let parses = 0;
    let reads = 0;
    const get = t.sessions.get.bind(t.sessions);
    t.sessions.get = async (w, c) => (reads++, get(w, c));
    JSON.parse = ((text: string, reviver?: never) => (parses++, parse(text, reviver))) as typeof JSON.parse;
    try {
      for (const big of [`e30.${claims}.c2ln`, "\u00e9".repeat(MAX_STEP_UP_TOKEN_BYTES / 2 + 1)]) {
        assert.deepEqual(await t.engine.exchangeStepUpToken(big, portal), { ok: false, reason: "malformed" });
      }
    } finally {
      JSON.parse = parse;
    }
    assert.deepEqual([parses, reads], [0, 0], "no parse, no read");
    const exact = "a".repeat(MAX_STEP_UP_TOKEN_BYTES);
    assert.deepEqual(await t.engine.exchangeStepUpToken(exact, portal), { ok: false, reason: "malformed" }, "at the cap it is read, and is not a token");
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true);
  });
});
