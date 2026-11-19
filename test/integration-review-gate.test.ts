// L1 integration review (PR #129), Gate: each case is a finding from the review of the integrated
// branch, and each test failed before its fix.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AccessController, ReceiptSigner, UnlockResult } from "../src/core/adapters.ts";
import type { JsonValue } from "../src/core/canonical.ts";
import { validateConfig, type FlowConfig } from "../src/core/config.ts";
import { MemorySessionStore } from "../src/core/session-store.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { verifyAccessGrant, type SignedAccessGrant } from "../src/gate/access.ts";
import { seamAccessController } from "../src/gate/seam.ts";
import { vendorAccessController } from "../src/gate/vendors.ts";
import { builtInModules } from "../src/modules.ts";
import { ModuleRegistry } from "../src/core/module.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import { FakeAccessController, FixedClock, TEST_KNOWLEDGE_KEY, generateTestSigner } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, setup, testConfig } from "./helpers.ts";

const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] };
const targets = [{ id: "front-door", controller: "lobby", ref: "door-1" }];

function gateConfig(patch: (c: FlowConfig) => void = () => undefined): FlowConfig {
  return testConfig((c) => {
    c.policy.scopes["entry.open"] = 2;
    c.modules.gate = { settings: { targets: structuredClone(targets) } };
    c.flows = { entry: { steps: [verify as never, { type: "gate.grant", target: "front-door" }] } };
    patch(c);
  });
}

/** A signer whose public key carries no `kid`: the ReceiptSigner contract does not require one. */
function signerWithoutKid(keyId: string): ReceiptSigner {
  const inner = generateTestSigner(keyId);
  return {
    keyId: inner.keyId,
    algorithm: inner.algorithm,
    sign: (payload) => inner.sign(payload),
    publicJwk: () => {
      const { kid: _kid, ...rest } = inner.publicJwk() as ReturnType<ReceiptSigner["publicJwk"]> & { kid?: string };
      return { ...rest, kid: "not-the-key-id" } as ReturnType<ReceiptSigner["publicJwk"]>;
    },
  };
}

async function verifiedCall(t: ReturnType<typeof setup>, flow: string | null = null): Promise<string> {
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  const { callId } = await t.engine.startCall(flow === null ? {} : { flow });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.checkCarrier(callId);
  assert.equal((await t.engine.finishVerification(callId)).level, 2);
  return callId;
}

describe("L1 review: Gate", () => {
  it("publishes the access and receipt key sets under the signer's keyId, whatever its JWK says (T0)", async () => {
    const door = new FakeAccessController();
    const t = setup({ config: gateConfig(), adapters: { access: { lobby: door }, accessSigner: signerWithoutKid("gate-key-1"), signer: signerWithoutKid("receipt-key-1") } });
    assert.deepEqual(t.engine.accessKeys().map((k) => (k as { kid?: string }).kid), ["gate-key-1"]);
    assert.deepEqual(t.engine.receiptKeys().map((k) => (k as { kid?: string }).kid), ["receipt-key-1"]);
    const callId = await verifiedCall(t);
    assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    const grant = door.received[0]!.grant;
    const check = verifyAccessGrant(grant, t.engine.accessKeys(), { workspaceId: t.engine.workspaceId, audience: "lobby", now: t.clock.now() });
    assert.equal(check.ok, true, "a relay finds the key by the grant's kid");
    const receipt = (await t.engine.endCall(callId))!;
    assert.ok(verifyReceipt(receipt, t.engine.receiptKeys()), "and a receipt verifies against its key set");
  });

  it("refuses a flow with more gate.grant steps than maxGrantsPerCall, since it could never complete (T2)", () => {
    const registry = new ModuleRegistry({ adapters: ["ledger", "records", "carrier", "identity", "messages", "payments", "signer", "pinVerifier", "access", "accessSigner"], modules: builtInModules() });
    const flow = (max: number | undefined, grants: number) =>
      gateConfig((c) => {
        c.modules.gate = { settings: { targets: structuredClone(targets), ...(max === undefined ? {} : { maxGrantsPerCall: max }) } };
        c.flows = { entry: { steps: [verify as never, ...Array.from({ length: grants }, () => ({ type: "gate.grant", target: "front-door" }) as never)] } };
      });
    assert.deepEqual(validateConfig(flow(1, 1), registry), []);
    assert.deepEqual(validateConfig(flow(undefined, 3), registry), []);
    assert.deepEqual(validateConfig(flow(1, 2), registry), ["flows.entry (gate): 2 gate.grant steps, but a call may have at most 1 access grant (maxGrantsPerCall)"]);
    assert.deepEqual(validateConfig(flow(undefined, 4), registry), ["flows.entry (gate): 4 gate.grant steps, but a call may have at most 3 access grants (maxGrantsPerCall)"]);
    // A step that is not an object is its own problem, and is not counted.
    const junk = flow(1, 1);
    junk.flows.entry!.steps.push("gate.grant" as never);
    assert.deepEqual(validateConfig(junk, registry), ["flows.entry.steps[2]: a step is an object with a type"]);
  });

  it("never sends a grant once a taint committed after the write that checked it (T3)", async () => {
    // A store that runs a hook right after the write that checks the grant and records its digest.
    class Hooked extends MemorySessionStore {
      after: (() => Promise<void>) | null = null;
      override async compareAndSet(w: string, c: string, v: number, r: JsonValue) {
        const out = await super.compareAndSet(w, c, v, r);
        const g = (r as unknown as { modules: { gate?: { grants: Array<{ digest: string | null; status: string }> } } }).modules.gate?.grants.at(-1);
        const run = this.after;
        if (out.ok && run !== null && typeof g?.digest === "string" && g.status === "reserved") {
          this.after = null;
          await run();
        }
        return out;
      }
    }
    const sessions = new Hooked();
    const door = new FakeAccessController();
    const t = setup({ config: gateConfig(), adapters: { sessions, access: { lobby: door }, accessSigner: generateTestSigner("gate-key-1") } });
    const callId = await verifiedCall(t);
    sessions.after = () => t.engine.markUntrusted(callId, "webhook");
    await assert.rejects(t.engine.grantAccess(callId, { target: "front-door" }), (e: unknown) => (e as { code?: string }).code === "scope_denied");
    assert.deepEqual(door.received, [], "the controller was never asked");
    assert.equal((await t.engine.accessGrants(callId))[0]!.status, "failed");
  });

  it("records a malformed controller answer as unknown, never as refused, and never leaves the grant reserved (T4)", async () => {
    const answers: unknown[] = [undefined, { outcome: "opened", reason: "door_offline" }, { outcome: "delivered", providerRef: 7, confirmed: true }, { outcome: "delivered", providerRef: "p", confirmed: "yes" }, { outcome: "refused", reason: 3 }, null, "delivered"];
    for (const answer of answers) {
      const odd: AccessController = { unlock: async () => answer as UnlockResult };
      const t = setup({ config: gateConfig((c) => (c.modules.gate = { settings: { targets: structuredClone(targets), maxGrantsPerCall: 1 } })), adapters: { access: { lobby: odd }, accessSigner: generateTestSigner("gate-key-1") } });
      const callId = await verifiedCall(t);
      assert.deepEqual(await t.engine.grantAccess(callId, { target: "front-door" }), { grantId: "acc_1", status: "unknown", confirmed: false }, JSON.stringify(answer));
      const last = (await t.ledger.list()).filter((e) => e.event.startsWith("access.")).at(-1)!;
      assert.equal(last.event, "access.unknown");
      assert.equal((last.detail as { reason: string }).reason, "malformed_answer");
    }
    // A well-formed refusal and delivery are kept as they are.
    for (const [answer, status] of [
      [{ outcome: "refused", reason: "door_offline" }, "refused"],
      [{ outcome: "delivered", providerRef: "p", confirmed: false }, "delivered"],
    ] as const) {
      const t = setup({ config: gateConfig(), adapters: { access: { lobby: { unlock: async () => answer } }, accessSigner: generateTestSigner("gate-key-1") } });
      const callId = await verifiedCall(t);
      assert.equal((await t.engine.grantAccess(callId, { target: "front-door" })).status, status);
    }
  });

  it("exchanges a step-up token against the sign-in it was asked for, even if the host reuses its object meanwhile (T7)", async () => {
    const ISSUER = "https://verify.example.test";
    const PORTAL = "https://portal.example.test";
    class Reading extends MemorySessionStore {
      onGet: (() => void) | null = null;
      override async get(w: string, c: string) {
        const out = await super.get(w, c);
        const run = this.onGet;
        this.onGet = null;
        run?.();
        return out;
      }
    }
    const sessions = new Reading();
    const t = setup({
      config: testConfig((c) => {
        c.policy.scopes["entry.sign_in"] = 2;
        c.modules["step-up"] = { settings: { issuer: ISSUER, sites: [{ id: "portal", audience: PORTAL }] } };
      }),
      adapters: { sessions, stepUpSigner: generateTestSigner("step-up-key-1") },
    });
    const callId = await verifiedCall(t);
    const issued = await t.engine.issueStepUpToken(callId, { nonce: "482913", site: "portal" });
    const subjectKey = hmacSha256Hex(TEST_KNOWLEDGE_KEY, `subject:${ACCOUNT}`);
    // The first sign-in is someone else's; the host reuses the object for the right one while the read waits.
    const expect = { audience: PORTAL, subjectKey: "someone-else", nonce: "482913" };
    sessions.onGet = () => {
      expect.subjectKey = subjectKey;
    };
    assert.deepEqual(await t.engine.exchangeStepUpToken(issued.token, expect), { ok: false, reason: "mismatch" });
  });
});

describe("L1 review: door adapters", () => {
  const grant = (target: string): SignedAccessGrant => ({
    body: { v: 1, kind: "access", grantId: "acc_1", workspaceId: "w", audience: "lobby", target, action: "unlock", scope: "entry.open", level: 2, issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-01T00:01:00.000Z" },
    alg: "ES256",
    kid: "k1",
    signature: "sig",
  });
  const unreadable = { now: () => new Date(Number.NaN) };

  /** A fetch that answers every request as Seam would for a lock that unlocks, and records the paths. */
  function seamFetch(paths: string[]): typeof fetch {
    return (async (url: URL) => {
      paths.push(url.pathname);
      const body =
        url.pathname === "/devices/get"
          ? { device: { device_id: "dev-ok", can_remotely_unlock: true, properties: { online: true } } }
          : { action_attempt: { action_attempt_id: "aa_1", status: "success", result: { was_confirmed_by_device: true } } };
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof fetch;
  }

  it("Seam refuses a grant signed for another door, before anything is sent (T5)", async () => {
    const paths: string[] = [];
    const seam = seamAccessController({ apiKey: "seam_test_notASecret_0000", fetch: seamFetch(paths), clock: new FixedClock() });
    assert.deepEqual(await seam.unlock({ grant: grant("dev-other"), target: "dev-ok", idempotencyKey: "k" }), { outcome: "refused", reason: "target_mismatch" });
    assert.deepEqual(paths, [], "not even the device check");
    assert.equal((await seam.unlock({ grant: grant("dev-ok"), target: "dev-ok", idempotencyKey: "k" })).outcome, "delivered");
  });

  it("Seam refuses the unlock when the clock or the expiry cannot be read (T6)", async () => {
    const paths: string[] = [];
    const seam = seamAccessController({ apiKey: "seam_test_notASecret_0000", fetch: seamFetch(paths), clock: unreadable });
    assert.deepEqual(await seam.unlock({ grant: grant("dev-ok"), target: "dev-ok", idempotencyKey: "k" }), { outcome: "refused", reason: "grant_expiring" });
    assert.deepEqual(paths, ["/devices/get"], "the unlock itself was never sent");
    // Exactly the timeout left is still enough.
    const exact = seamAccessController({ apiKey: "seam_test_notASecret_0000", fetch: seamFetch([]), clock: { now: () => new Date("2026-01-01T00:00:55.000Z") } });
    assert.equal((await exact.unlock({ grant: grant("dev-ok"), target: "dev-ok", idempotencyKey: "k" })).outcome, "delivered");
  });

  it("Kisi and Verkada refuse the unlock when the clock or the expiry cannot be read (T8)", async () => {
    for (const [vendor, target] of [
      ["kisi", "48213"],
      ["verkada", "8f6a1b2c-3d4e-4f50-8a6b-7c8d9e0f1a2b"],
    ] as const) {
      const sent: string[] = [];
      const fetcher = (async (url: URL) => {
        sent.push(url.pathname);
        return new Response(JSON.stringify({ token: "t" }), { status: 200 });
      }) as unknown as typeof fetch;
      const door = vendorAccessController({ vendor, apiKey: "test-key-not-a-secret", fetch: fetcher, clock: unreadable });
      assert.deepEqual(await door.unlock({ grant: grant(target), target, idempotencyKey: "k" }), { outcome: "refused", reason: "grant_expiring" }, vendor);
      assert.deepEqual(sent, [], `${vendor}: nothing was sent`);
      const exact = vendorAccessController({ vendor, apiKey: "test-key-not-a-secret", fetch: fetcher, clock: { now: () => new Date("2026-01-01T00:00:55.000Z") } });
      assert.equal((await exact.unlock({ grant: grant(target), target, idempotencyKey: "k" })).outcome, "delivered", `${vendor}: exactly the timeout left`);
    }
  });
});
