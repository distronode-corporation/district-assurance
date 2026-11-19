// Web sign-in step-up (GAT-4, ADR-24, ADR-25): a short-lived ES256 JWT, bound to the site's nonce,
// the verified subject and the call's verification grant, issued by the engine and exchanged once,
// through the engine, by the host's web sign-in. No module code can write a token or its outcome.
import { strict as assert } from "node:assert";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import { hmacSha256Hex, sha256Hex } from "../src/core/hash.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { stepUpAcr, stepUpModule, stepUpSubject } from "../src/gate/step-up.ts";
import { builtInModules } from "../src/modules.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { TEST_KNOWLEDGE_KEY, generateTestSigner, testSubject } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, PIN, rejects, setup, testConfig } from "./helpers.ts";

const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] };

/** A session store that can be told to refuse one write. */
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

// Web sign-in step-up (GAT-4): a short-lived ES256 JWT, bound to the site's nonce, the verified
// subject and the call's verification grant, exchanged once by the host's web sign-in.
const ISSUER = "https://verify.example.test";
const PORTAL = "https://portal.example.test";
const NONCE = "482913";
const SUBJECT_KEY = hmacSha256Hex(TEST_KNOWLEDGE_KEY, `subject:${ACCOUNT}`);
const webVerify = { ...verify, scopes: ["entry.sign_in"] };
const sites = [
  { id: "portal", audience: PORTAL },
  { id: "shop", audience: "shop-client-1" },
];

function stepUpConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["entry.sign_in"] = 2;
    c.modules["step-up"] = { settings: { issuer: ISSUER, sites: structuredClone(sites) } };
    c.flows = { web: { steps: [webVerify as never, { type: "step-up.issue", site: "portal" }] } };
    patch(c);
  });
}

function stepUpSetup(options: { patch?: (c: FlowConfig) => void; signer?: ReturnType<typeof generateTestSigner> } = {}) {
  const sessions = new StoppingStore();
  const t = setup({ config: stepUpConfig(options.patch), adapters: { sessions, stepUpSigner: options.signer ?? generateTestSigner("step-up-key-1") } });
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { ...t, sessions };
}

async function webVerified(t: ReturnType<typeof stepUpSetup>, flow: string | null = "web"): Promise<string> {
  const { callId } = await t.engine.startCall(flow === null ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
const stepUpTokens = (t: ReturnType<typeof stepUpSetup>, callId: string) => t.engine.stepUpTokens(callId);
const stepUpEvents = async (t: ReturnType<typeof stepUpSetup>) => (await t.ledger.list()).filter((e) => e.event.startsWith("stepup.")).map((e) => [e.event, e.detail] as const);
const portal = { audience: PORTAL, subjectKey: SUBJECT_KEY, nonce: NONCE };
/** A compact token with these claims and a junk signature: the shape of a step-up token, never one the engine issued. */
const forged = (claims: unknown) => `${Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln`;

describe("step-up: config", () => {
  const registry = (adapters = ["ledger", "records", "carrier", "identity", "messages", "payments", "signer", "stepUpSigner"]) => new ModuleRegistry({ adapters, modules: builtInModules() });
  const stepUp = stepUpModule;

  it("needs an https issuer", () => {
    for (const issuer of ["http://verify.example.test", "https://verify.example.test/?x=1", "https://verify.example.test/?", "https://verify.example.test/#", "https://user@verify.example.test", "https://", "https:///", "https://verify .example.test", "not a url", 7, undefined]) {
      assert.deepEqual(stepUp.validateSettings({ issuer, sites }), ["issuer must be an https URL without a query, a fragment or credentials"], String(issuer));
    }
    assert.deepEqual(stepUp.validateSettings({ issuer: "https://verify.example.test/ws_test", sites }), []);
  });

  it("needs the stepUpSigner adapter", () => {
    assert.deepEqual(validateConfig(stepUpConfig(), registry(["ledger", "records", "carrier", "identity", "messages", "payments", "signer"])), [
      "modules.step-up: needs the stepUpSigner adapter, which the engine does not have",
    ]);
  });

  it("checks every step-up setting", () => {
    assert.deepEqual(stepUp.validateSettings({ issuer: ISSUER, sites, maxTokensPerCall: 5 }), []);
    assert.deepEqual(stepUp.validateSettings(null), ["must be an object with the issuer and the sites"]);
    assert.deepEqual(stepUp.validateSettings({ issuer: ISSUER, sites: [], maxTokensPerCall: 0, x: 1 }), [
      "x is not a step-up setting",
      "maxTokensPerCall must be an integer from 1 to 5",
      "sites must list at least one site",
    ]);
    const sparse: unknown[] = [];
    sparse[1] = sites[0];
    assert.deepEqual(stepUp.validateSettings({ issuer: ISSUER, sites: sparse }), ["sites must list at least one site"], "a hole is not a site");
    assert.deepEqual(stepUp.validateSettings({ issuer: ISSUER, sites: ["portal", { id: "Portal", audience: "a b", y: 1 }, { id: "a", audience: "x".repeat(201) }, { id: "a", audience: 1 }] }), [
      "sites[0] must be { id, audience }",
      "sites[1].y is not a site field",
      "sites[1].id must be lower-case letters, digits and hyphens, at most 64",
      "sites[1].audience must be 1 to 200 characters, no spaces",
      "sites[2].audience must be 1 to 200 characters, no spaces",
      "sites[3].audience must be 1 to 200 characters, no spaces",
      "two sites have the same id",
    ]);
  });

  it("checks step-up.issue steps, and holds them to entry.sign_in at level 2", () => {
    const problems = (c: FlowConfig) => validateConfig(c, registry());
    assert.deepEqual(problems(stepUpConfig()), []);
    const step = (s: Record<string, unknown>) => problems(stepUpConfig((c) => (c.flows = { web: { steps: [webVerify as never, s as never] } })));
    assert.deepEqual(step({ type: "step-up.issue", site: "shop", lifetimeSeconds: 300 }), []);
    assert.deepEqual(step({ type: "step-up.issue", site: "bank", lifetimeSeconds: 119, x: 1 }), [
      "flows.web.steps[1] (step-up.issue): x is not a field of this step",
      "flows.web.steps[1] (step-up.issue): lifetimeSeconds must be an integer from 120 to 300",
      "flows.web.steps[1] (step-up.issue): no site bank in the step-up settings",
    ]);
    assert.deepEqual(step({ type: "step-up.issue", lifetimeSeconds: 301 }), [
      "flows.web.steps[1] (step-up.issue): lifetimeSeconds must be an integer from 120 to 300",
      "flows.web.steps[1] (step-up.issue): site must name a site in the step-up settings",
    ]);
    assert.deepEqual(problems(stepUpConfig((c) => (c.modules["step-up"] = { settings: { issuer: ISSUER, sites: [] } }))), ["modules.step-up.settings: sites must list at least one site"]);
    assert.deepEqual(problems(stepUpConfig((c) => (c.policy.scopes["entry.sign_in"] = 1))), ["policy: scope entry.sign_in is access, and below its floor of level 2"]);
    assert.deepEqual(
      problems(stepUpConfig((c) => (c.flows = { web: { steps: [{ ...webVerify, scopes: ["payment.request"] } as never, { type: "step-up.issue", site: "portal" }] } }))),
      ["flows.web.steps[1] (step-up.issue): needs the scope entry.sign_in, which the last verification step does not grant"],
    );
  });

  it("keeps the sites a call started with when the config changes", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    t.engine.configure(
      stepUpConfig((c) => {
        c.modules["step-up"] = { settings: { issuer: "https://other.example.test", sites: [{ id: "bank", audience: "bank-1" }] } };
        c.flows = { bank: { steps: [webVerify as never, { type: "step-up.issue", site: "bank" }] } };
      }),
    );
    await assert.rejects(t.engine.startFlow(callId, "bank"), rejects("precondition_failed", /no site bank/));
  });
});

describe("step-up: tokens", () => {
  it("runs a web flow: an ES256 JWT for an OpenID Connect acr step-up, checked against the JWKS, exchanged once", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    t.clock.advance(1_500);
    const issued = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    assert.deepEqual({ ...issued, token: "" }, { token: "", tokenId: "stu_1", expiresAt: "2026-01-01T00:02:01.000Z" });
    assert.equal((await t.engine.flowPosition(callId))!.status, "completed");

    const [header, payload, signature] = issued.token.split(".") as [string, string, string];
    assert.deepEqual(decode(header), { alg: "ES256", kid: "step-up-key-1", typ: "JWT" });
    const claims = {
      iss: ISSUER,
      aud: PORTAL,
      sub: stepUpSubject(SUBJECT_KEY, PORTAL),
      iat: 1767225601,
      exp: 1767225721,
      auth_time: 1767225600,
      jti: "stu_1",
      acr: "urn:district-assurance:level:2",
      nonce: NONCE,
      sid: callId,
      grant: "grant_1",
    };
    assert.deepEqual(decode(payload), claims);
    assert.equal(claims.acr, stepUpAcr(2));
    assert.notEqual(stepUpSubject(SUBJECT_KEY, "shop-client-1"), claims.sub, "a handle per site");
    // What any JOSE library does with the JWKS: find the key by kid, check ES256 over header.payload.
    const jwks = t.engine.stepUpKeys();
    assert.deepEqual(jwks.keys.map((k) => [k.kid, k.alg, k.use, k.kty, k.crv]), [["step-up-key-1", "ES256", "sig", "EC", "P-256"]]);
    const key = createPublicKey({ key: jwks.keys.find((k) => k.kid === "step-up-key-1")!, format: "jwk" });
    assert.ok(cryptoVerify("sha256", Buffer.from(`${header}.${payload}`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature, "base64url")));
    assert.ok(!cryptoVerify("sha256", Buffer.from(`${header}.${payload}x`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature, "base64url")));

    // The call ended before the web sign-in got there: the token is still exchanged, once.
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.exchangeStepUpToken(issued.token, portal), { ok: true, claims });
    assert.deepEqual(await t.engine.exchangeStepUpToken(issued.token, portal), { ok: false, reason: "unknown" }, "used once");
    const order = (await t.ledger.list()).map((e) => e.event);
    assert.ok(order.indexOf("stepup.exchanged") > order.indexOf("receipt.issued"), "an exchange after the end follows the receipt");

    const digest = sha256Hex(issued.token);
    assert.deepEqual(await stepUpEvents(t), [
      ["stepup.issued", { tokenId: "stu_1", site: "portal", scope: "entry.sign_in", level: 2, verificationGrantId: "grant_1", expiresAt: "2026-01-01T00:02:01.000Z" }],
      ["stepup.exchanged", { tokenId: "stu_1", digest, kid: "step-up-key-1" }],
    ]);
    const ledger = JSON.stringify(await t.ledger.list());
    assert.ok(!ledger.includes(NONCE) && !ledger.includes(signature) && !ledger.includes(claims.sub), "never the nonce, the token or the subject");
    assert.deepEqual((await stepUpTokens(t, callId)), [
      {
        tokenId: "stu_1",
        site: "portal",
        audience: PORTAL,
        subject: claims.sub,
        level: 2,
        verificationGrantId: "grant_1",
        authTime: "2026-01-01T00:00:00.000Z",
        issuedAt: "2026-01-01T00:00:01.000Z",
        expiresAt: "2026-01-01T00:02:01.000Z",
        status: "exchanged",
        digest,
        kid: "step-up-key-1",
      },
    ]);
    assert.ok(!JSON.stringify(await t.sessions.get("ws_test", callId)).includes(NONCE), "the call record keeps no nonce");
  });

  it("refuses without a verification grant covering entry.sign_in, or while a verification runs", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall({ flow: "web" });
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE }), rejects("precondition_failed", /on step badge.verify/));
    const open = await t.engine.startCall();
    await assert.rejects(t.engine.issueStepUpToken(open.callId, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /entry.sign_in/));
    const tainted = await webVerified(t, null);
    await t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.issueStepUpToken(tainted, { nonce: NONCE, site: "portal" }), rejects("scope_denied"));
    const expired = await webVerified(t, null);
    t.clock.advance(900_000);
    await assert.rejects(t.engine.issueStepUpToken(expired, { nonce: NONCE, site: "portal" }), rejects("scope_denied"));
    // Verified, then a new verification started (maybe for another account): its subject is not the grant's.
    const again = await webVerified(t, null);
    await t.engine.beginVerification(again, { accountNumber: "99999999" });
    await assert.rejects(t.engine.issueStepUpToken(again, { nonce: NONCE, site: "portal" }), rejects("precondition_failed", /verification is running/));
    assert.deepEqual(await stepUpEvents(t), []);
  });

  it("takes the site from the step in a flow and from the host outside one, and the nonce always from the keypad", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { issuer: ISSUER, sites: structuredClone(sites), maxTokensPerCall: 2 }) });
    const inFlow = await webVerified(t);
    await assert.rejects(t.engine.issueStepUpToken(inFlow, { nonce: NONCE, site: "shop" }), rejects("invalid_input", /pass only the nonce/));
    await assert.rejects(t.engine.issueStepUpToken(inFlow, { nonce: NONCE, lifetimeSeconds: 300 }), rejects("invalid_input", /pass only the nonce/));
    for (const nonce of ["12345", "1234567890123", "48291a", 482913]) {
      await assert.rejects(t.engine.issueStepUpToken(inFlow, { nonce: nonce as never }), (e: unknown) => rejects("invalid_input", /6 to 12 digits/)(e) && !String(e).includes(String(nonce)));
    }
    const outside = await webVerified(t, null);
    await assert.rejects(t.engine.issueStepUpToken(outside, { nonce: NONCE }), rejects("invalid_input", /site is required/));
    await assert.rejects(t.engine.issueStepUpToken(outside, { nonce: NONCE, site: "bank" }), rejects("invalid_input", /no site bank/));
    await assert.rejects(t.engine.issueStepUpToken(outside, { nonce: NONCE, site: "shop", lifetimeSeconds: 600 }), rejects("invalid_input", /lifetimeSeconds/));
    const shop = await t.engine.issueStepUpToken(outside, { nonce: "123456789012", site: "shop", lifetimeSeconds: 300 });
    assert.equal(shop.expiresAt, "2026-01-01T00:05:00.000Z");
    assert.equal(decode(shop.token.split(".")[1]!).aud, "shop-client-1");
    await t.engine.issueStepUpToken(outside, { nonce: NONCE, site: "portal" });
    await assert.rejects(t.engine.issueStepUpToken(outside, { nonce: NONCE, site: "portal" }), rejects("precondition_failed", /every step-up token/));
  });

  it("never outlives the verification grant", async () => {
    const t = stepUpSetup({ patch: (c) => (c.flows.web!.steps[1] = { type: "step-up.issue", site: "portal", lifetimeSeconds: 300 }) });
    const callId = await webVerified(t);
    t.clock.advance(800_500);
    const issued = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    assert.equal(issued.expiresAt, "2026-01-01T00:15:00.000Z", "the verification grant's own expiry");
    assert.equal(decode(issued.token.split(".")[1]!).exp, Date.parse("2026-01-01T00:15:00.000Z") / 1000);
  });

  it("refuses an exchange after the call is tainted, and that uses the token up", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    await t.engine.markUntrusted(callId, "crm_note");
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "tainted" });
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "unknown" });
    assert.deepEqual((await stepUpEvents(t)).at(-1), ["stepup.refused", { tokenId: "stu_1", digest: sha256Hex(token), reason: "tainted" }]);
    assert.equal((await stepUpTokens(t, callId))[0]!.status, "refused");
  });

  it("refuses an expired token, and one for another site, subject or nonce, each using it up", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { issuer: ISSUER, sites: structuredClone(sites), maxTokensPerCall: 5 }) });
    const callId = await webVerified(t, null);
    const issue = async () => (await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" })).token;
    const expired = await issue();
    t.clock.advance(119_000);
    const live = [await issue(), await issue(), await issue()];
    t.clock.advance(1_000);
    assert.deepEqual(await t.engine.exchangeStepUpToken(expired, portal), { ok: false, reason: "expired" });
    for (const [i, wrong] of [{ audience: "shop-client-1" }, { subjectKey: "a".repeat(64) }, { nonce: "482914" }].entries()) {
      assert.deepEqual(await t.engine.exchangeStepUpToken(live[i]!, { ...portal, ...wrong }), { ok: false, reason: "mismatch" }, JSON.stringify(wrong));
      assert.deepEqual(await t.engine.exchangeStepUpToken(live[i]!, portal), { ok: false, reason: "unknown" }, "the first refusal used it up");
    }
    const fresh = await issue();
    assert.equal((await t.engine.exchangeStepUpToken(fresh, portal)).ok, true);
    assert.deepEqual((await stepUpTokens(t, callId)).map((s) => s.status), ["refused", "refused", "refused", "refused", "exchanged"]);
  });

  it("refuses a token whose call was verified again since", async () => {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { issuer: ISSUER, sites: structuredClone(sites), maxTokensPerCall: 5 }) });
    const callId = await webVerified(t, null);
    const first = (await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" })).token;
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.engine.exchangeStepUpToken(first, portal), { ok: false, reason: "not_authorized" }, "a new grant");
    const second = (await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" })).token;
    assert.equal(decode(second.split(".")[1]!).grant, "grant_2");
    // Verified again and failed: the call holds no grant.
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    assert.deepEqual(await t.engine.exchangeStepUpToken(second, portal), { ok: false, reason: "not_authorized" });
  });

  it("refuses anything that is not a token this call issued, without using up the real one", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t, null);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" });
    for (const bad of [null, 7, "a.b", "a.b.c.d", forged({ sid: callId, jti: "stu_1" }), forged({ sid: callId, jti: 1, nonce: NONCE }), forged([]), "a.bm90IGpzb24.c"]) {
      assert.deepEqual(await t.engine.exchangeStepUpToken(bad, portal), { ok: false, reason: "malformed" }, String(bad));
    }
    const claims = decode(token.split(".")[1]!);
    for (const bad of [forged(claims), forged({ ...claims, sid: "call_unknown" }), forged({ ...claims, jti: "stu_9" }), `${token.slice(0, -2)}${token.endsWith("AA") ? "BB" : "AA"}`]) {
      assert.deepEqual(await t.engine.exchangeStepUpToken(bad, portal), { ok: false, reason: "unknown" });
    }
    // No module code can reach step-up's part of a call, to write a token or read one (ADR-25).
    await assert.rejects(t.engine.updateModule(callId, "step-up", (s) => s), rejects("precondition_failed", /built in/));
    await assert.rejects(t.engine.moduleState(callId, "step-up"), rejects("precondition_failed", /built in/));
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => r.status), ["issued"], "nothing was settled");
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true, "the real token was never used up");
  });

  it("throws a failed write as it is", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE });
    t.sessions.stopWhen = () => true;
    await assert.rejects(t.engine.exchangeStepUpToken(token, portal), /store down/);
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true);
  });

  it("fails a token whose signing failed, hands out nothing, and fails the step at the limit", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let broken = true;
    const t = stepUpSetup({
      signer: { ...signer, sign: (payload) => (broken ? Promise.reject(new Error("kms down")) : signer.sign(payload)) },
      patch: (c) => (c.modules["step-up"]!.settings = { issuer: ISSUER, sites: structuredClone(sites), maxTokensPerCall: 2 }),
    });
    const callId = await webVerified(t);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE }), /kms down/);
    assert.equal((await t.engine.flowPosition(callId))!.status, "running");
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE }), /kms down/);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed", "every token used, none valid");
    assert.deepEqual((await stepUpEvents(t)).map(([e, d]) => [e, (d as { reason?: string }).reason ?? null]), [
      ["stepup.issued", null],
      ["stepup.failed", "signing"],
      ["stepup.issued", null],
      ["stepup.failed", "signing"],
    ]);
    broken = false;
    const outside = await webVerified(t, null);
    assert.equal((await t.engine.issueStepUpToken(outside, { nonce: NONCE, site: "portal" })).tokenId, "stu_3");
  });

  it("issues nothing when the call was tainted, verified again or the token expired while it was signed", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let during: () => Promise<unknown> = async () => undefined;
    const t = stepUpSetup({ signer: { ...signer, sign: async (payload) => (await during(), signer.sign(payload)) } });
    const tainted = await webVerified(t, null);
    during = () => t.engine.markUntrusted(tainted, "crm_note");
    await assert.rejects(t.engine.issueStepUpToken(tainted, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    const again = await webVerified(t, null);
    during = () => t.engine.beginVerification(again, { accountNumber: ACCOUNT });
    await assert.rejects(t.engine.issueStepUpToken(again, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    const slow = await webVerified(t, null);
    during = async () => t.clock.advance(120_000);
    await assert.rejects(t.engine.issueStepUpToken(slow, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /it expired/));
    for (const callId of [tainted, again, slow]) {
      assert.deepEqual((await stepUpTokens(t, callId)).map((s) => [s.status, s.digest]), [["failed", null]]);
    }
    const reasons = (await stepUpEvents(t)).filter(([e]) => e === "stepup.failed").map(([, d]) => (d as { reason: string }).reason);
    assert.deepEqual(reasons, ["not_authorized", "not_authorized", "expired"]);
  });

  it("allows one token being signed per call", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let nested: Promise<unknown> | null = null;
    let call = { t: null as ReturnType<typeof stepUpSetup> | null, id: "" };
    const t = stepUpSetup({
      signer: {
        ...signer,
        sign: async (payload) => {
          nested ??= call.t!.engine.issueStepUpToken(call.id, { nonce: NONCE, site: "shop" });
          await assert.rejects(nested, rejects("precondition_failed", /being issued/));
          return signer.sign(payload);
        },
      },
    });
    call = { t, id: await webVerified(t, null) };
    assert.equal((await t.engine.issueStepUpToken(call.id, { nonce: NONCE, site: "portal" })).tokenId, "stu_1");
    assert.ok(nested !== null);
  });

  it("fails a token still being signed when the call ends, and hands it out to no one", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let during: () => Promise<unknown> = async () => undefined;
    const t = stepUpSetup({ signer: { ...signer, sign: async (payload) => (await during(), signer.sign(payload)) } });
    const callId = await webVerified(t, null);
    during = () => t.engine.endCall(callId);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => [r.status, r.digest]), [["failed", null]]);
    const entries = await t.ledger.list();
    const events = entries.map((e) => e.event);
    assert.deepEqual(entries.filter((e) => e.event === "stepup.failed").map((e) => e.detail), [{ tokenId: "stu_1", reason: "call_ended" }]);
    assert.ok(events.indexOf("stepup.failed") < events.indexOf("call.ended"), "settled in the write that ended the call");
    assert.equal(events.at(-1), "receipt.issued", "nothing follows the receipt");
    // A signer that fails after the call ended: the token stays as the end settled it.
    const other = await webVerified(t, null);
    during = async () => {
      await t.engine.endCall(other);
      throw new Error("kms down");
    };
    await assert.rejects(t.engine.issueStepUpToken(other, { nonce: NONCE, site: "portal" }), /kms down/);
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "stepup.failed").map((e) => e.detail.reason), ["call_ended", "call_ended"]);
  });

  it("issues nothing when the call was verified again for the same subject while it was signed", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let during: () => Promise<unknown> = async () => undefined;
    const t = stepUpSetup({ signer: { ...signer, sign: async (payload) => (await during(), signer.sign(payload)) } });
    const callId = await webVerified(t, null);
    during = async () => {
      during = async () => undefined;
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      await t.engine.checkCarrier(callId);
      await t.engine.finishVerification(callId);
    };
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" }), rejects("scope_denied", /no longer authorized/));
    assert.equal((await t.engine.state(callId)).grant!.grantId, "grant_2");
    assert.equal((await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" })).tokenId, "stu_2", "a new token, bound to the new grant");
  });

  it("refuses an exchange while a new verification runs on the call, and that uses the token up", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t, null);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" });
    // Another verification starts (maybe for another account): the old grant is still held while it runs.
    await t.engine.beginVerification(callId, { accountNumber: "99999999" });
    assert.equal((await t.engine.state(callId)).grant!.grantId, "grant_1");
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "not_authorized" });
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "unknown" });
  });

  it("fails a token left reserved past its expiry, so the call's next request is not blocked for good", async () => {
    const signer = generateTestSigner("step-up-key-1");
    let stop = true;
    const t = stepUpSetup({
      signer: {
        ...signer,
        sign: async (payload) => {
          // The process stops right after signing, before the write that makes the token valid.
          if (stop) t.sessions.stopWhen = () => true;
          return signer.sign(payload);
        },
      },
    });
    const callId = await webVerified(t, null);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" }), /store down/);
    stop = false;
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => r.status), ["reserved"]);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" }), rejects("precondition_failed", /being issued/), "a live signing still blocks");
    t.clock.advance(120_000);
    assert.equal((await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" })).tokenId, "stu_2");
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => r.status), ["failed", "issued"]);
    assert.deepEqual((await stepUpEvents(t)).find(([e]) => e === "stepup.failed")![1], { tokenId: "stu_1", reason: "not_issued_in_time" });
  });

  it("signs the nonce it checked, even when the caller changes its input object meanwhile", async () => {
    const t = stepUpSetup();
    const callId = await webVerified(t, null);
    const input = { nonce: NONCE, site: "portal" };
    const append = t.ledger.append.bind(t.ledger);
    t.ledger.append = async (...args: Parameters<typeof append>) => {
      if (args[0].event === "stepup.issued") Object.assign(input, { nonce: "not checked", site: "shop" });
      return append(...args);
    };
    const { token } = await t.engine.issueStepUpToken(callId, input);
    assert.equal(input.nonce, "not checked", "the object did change during the reservation");
    assert.deepEqual([decode(token.split(".")[1]!).nonce, decode(token.split(".")[1]!).aud], [NONCE, PORTAL]);
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true);
    await assert.rejects(t.engine.issueStepUpToken(callId, null as never), rejects("invalid_input", /6 to 12 digits/));
  });

  it("answers unknown for a token naming a call that started with step-up off", async () => {
    const t = stepUpSetup();
    const { callId } = await t.engine.startCall();
    const claims = { sid: callId, jti: "stu_1", nonce: NONCE };
    assert.deepEqual(await t.engine.exchangeStepUpToken(forged(claims), portal), { ok: false, reason: "unknown" });
    const off = setup();
    const call = await off.engine.startCall();
    assert.deepEqual(await off.engine.exchangeStepUpToken(forged({ ...claims, sid: call.callId }), portal), { ok: false, reason: "unknown" });
    assert.deepEqual(await off.engine.stepUpTokens(call.callId), []);
    assert.deepEqual(setup({ adapters: { stepUpSigner: undefined } }).engine.stepUpKeys(), { keys: [] });
  });
});

describe("step-up: its own key", () => {
  it("refuses a step-up signer that shares a key with the receipt or the access signer", () => {
    const shared = generateTestSigner("shared-1");
    assert.throws(() => setup({ adapters: { signer: shared, stepUpSigner: shared } }), /stepUpSigner must have its own key id, not the receipt signer's/);
    assert.throws(() => setup({ adapters: { accessSigner: shared, stepUpSigner: shared } }), /stepUpSigner must have its own key id, not the accessSigner's/);
    assert.throws(() => setup({ adapters: { signer: shared, stepUpSigner: { ...shared, keyId: "other-id" } } }), /stepUpSigner must be its own key, not the receipt signer's/);
    assert.throws(() => setup({ adapters: { accessSigner: shared, stepUpSigner: { ...shared, keyId: "other-id" } } }), /stepUpSigner must be its own key, not the accessSigner's/);
    assert.ok(setup({ adapters: { stepUpSigner: generateTestSigner("own-1") } }).engine.stepUpKeys().keys[0]!.kid === "own-1");
  });
});

// Hostile review of 8580ae6 (iMac): hanging up must never revive a token its call no longer vouches for.
describe("step-up: the end of the call", () => {
  const OTHER = "87654321";
  async function verifyAs(t: ReturnType<typeof stepUpSetup>, callId: string, account: string) {
    await t.engine.beginVerification(callId, { accountNumber: account });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    return t.engine.finishVerification(callId);
  }
  function endSetup() {
    const t = stepUpSetup({ patch: (c) => (c.modules["step-up"]!.settings = { issuer: ISSUER, sites: structuredClone(sites), maxTokensPerCall: 5 }) });
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OTHER, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
    return t;
  }
  async function issued(t: ReturnType<typeof endSetup>) {
    const { callId } = await t.engine.startCall();
    await verifyAs(t, callId, ACCOUNT);
    const { token } = await t.engine.issueStepUpToken(callId, { nonce: NONCE, site: "portal" });
    return { callId, token };
  }
  const refusedAtEnd = async (t: ReturnType<typeof endSetup>, callId: string, token: string) => {
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "not_authorized" });
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "not_authorized" }, "and stays refused");
    const entries = await t.ledger.list();
    const events = entries.map((e) => e.event);
    assert.ok(events.indexOf("stepup.refused") < events.indexOf("call.ended"), "refused in the write that ended the call");
    assert.ok(!events.includes("stepup.exchanged"));
    assert.equal(events.at(-1), "receipt.issued", "nothing follows the receipt");
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => [r.status, r.refusedAtEnd]), [["refused", "not_authorized"]]);
  };

  it("A: refuses a token whose call ended while a new verification was running", async () => {
    const t = endSetup();
    const { callId, token } = await issued(t);
    await t.engine.beginVerification(callId, { accountNumber: OTHER });
    await refusedAtEnd(t, callId, token);
  });

  it("B: refuses a token whose call verified again (its grant replaced), then ended", async () => {
    const t = endSetup();
    const { callId, token } = await issued(t);
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.finishVerification(callId);
    assert.equal((await t.engine.state(callId)).grant!.grantId, "grant_2");
    await refusedAtEnd(t, callId, token);
  });

  it("C: refuses subject A's token once the caller verified as another subject and hung up", async () => {
    const t = endSetup();
    const { callId, token } = await issued(t);
    assert.equal((await verifyAs(t, callId, OTHER)).level, 2);
    await refusedAtEnd(t, callId, token);
    const other = { ...portal, subjectKey: hmacSha256Hex(TEST_KNOWLEDGE_KEY, `subject:${OTHER}`) };
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, other), { ok: false, reason: "not_authorized" }, "nor for the new subject");
  });

  it("refuses at the end a token whose call was tainted, and says so", async () => {
    const t = endSetup();
    const { callId, token } = await issued(t);
    await t.engine.markUntrusted(callId, "crm_note");
    assert.equal((await t.engine.state(callId)).grant, null, "a taint drops the grant");
    await t.engine.endCall(callId);
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "tainted" });
    assert.deepEqual((await stepUpTokens(t, callId)).map((r) => [r.status, r.refusedAtEnd]), [["refused", "tainted"]]);
  });

  it("keeps a token for the grant the call still held as it ended, exchangeable once", async () => {
    const t = endSetup();
    const { callId, token } = await issued(t);
    await t.engine.endCall(callId);
    assert.equal((await t.engine.exchangeStepUpToken(token, portal)).ok, true);
    assert.deepEqual(await t.engine.exchangeStepUpToken(token, portal), { ok: false, reason: "unknown" });
  });

  it("G: lists the call's tokens on the receipt as they stood at the end, still at version 1", async () => {
    const t = endSetup();
    const { callId } = await issued(t);
    await assert.rejects(t.engine.issueStepUpToken(callId, { nonce: "1", site: "portal" }), rejects("invalid_input"));
    const receipt = (await t.engine.endCall(callId))!;
    assert.equal(receipt.body.v, 1);
    assert.deepEqual(receipt.body.stepUp, [{ tokenId: "stu_1", expiresAt: "2026-01-01T00:02:00.000Z", status: "issued" }]);
    assert.ok(verifyReceipt(receipt, t.engine.receiptKeys()));
    // A call that issued none carries no stepUp part at all.
    const plain = await t.engine.startCall();
    assert.ok(!("stepUp" in (await t.engine.endCall(plain.callId))!.body));
  });

  it("H: publishes only public key members, whatever a signer's publicJwk returns", () => {
    const leaky = (kid: string) => {
      const s = generateTestSigner(kid);
      return { ...s, publicJwk: () => ({ ...s.publicJwk(), d: "SECRET", p: "x", k: "y" }) };
    };
    const t = setup({ adapters: { signer: leaky("r-1"), accessSigner: leaky("a-1"), stepUpSigner: leaky("s-1") } });
    for (const key of [...t.engine.receiptKeys(), ...t.engine.accessKeys(), ...t.engine.stepUpKeys().keys]) {
      assert.deepEqual(Object.keys(key).sort(), ["alg", "crv", "kid", "kty", "use", "x", "y"].filter((k) => k in key).sort());
      assert.ok(!("d" in key) && !JSON.stringify(key).includes("SECRET"));
    }
    assert.deepEqual(t.engine.stepUpKeys().keys.map((k) => (k as { kid?: string }).kid), ["s-1"]);
  });
});

