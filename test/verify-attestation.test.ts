// Caller ID attestation (VER-10): recorded on every call, never a factor, and only ever a cap.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { Attestation, AssuranceLevel } from "../src/core/policy.ts";
import { verifyReceipt } from "../src/prove/receipt.ts";
import type { TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, rejects, setup, testConfig } from "./helpers.ts";

const ALL: Attestation[] = ["A", "B", "C", "failed", "none"];

/** A test engine whose policy caps levels by attestation. */
function capped(caps: Partial<Record<Attestation, AssuranceLevel>>): TestEngine {
  const t = setup();
  t.engine.configure(testConfig((c) => (c.policy.attestationCaps = caps)));
  return t;
}

/** Keypad and photo ID, which reach level 3 when nothing caps them. */
async function strongCall(t: TestEngine, attestation?: Attestation): Promise<string> {
  const { callId } = await t.engine.startCall(attestation === undefined ? {} : { attestation });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  await t.engine.submitKeypad(callId, { dob: DOB });
  await t.engine.startPhotoId(callId);
  await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
  return callId;
}

async function finished(t: TestEngine): Promise<{ [key: string]: unknown }> {
  return (await t.ledger.list()).findLast((e) => e.event === "verification.finished")!.detail;
}

describe("Caller ID attestation", () => {
  it("is none by default, recorded in call.started and the receipt, and changes nothing without caps", async () => {
    for (const attestation of [undefined, ...ALL]) {
      const t = setup();
      const callId = await strongCall(t, attestation);
      assert.deepEqual(await t.engine.finishVerification(callId), {
        level: 3,
        scopes: ["contact.update", "intake.file", "payment.request", "payout.update", "status.read"],
      });
      const expected = attestation ?? "none";
      assert.deepEqual((await t.ledger.list())[0]!.detail, { locale: "en", revision: "default", attestation: expected });
      assert.equal((await finished(t)).capped, false);
      const receipt = (await t.engine.endCall(callId))!;
      assert.equal(receipt.body.attestation, expected);
      assert.deepEqual(receipt.body.verification, { level: 3, methods: ["keypad_knowledge", "photo_id"] });
      assert.equal(receipt.body.v, 1, "an optional field: the format stays version 1");
      assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
      assert.equal(verifyReceipt({ ...receipt, body: { ...receipt.body, attestation: "A" } }, t.engine.receiptKeys()), expected === "A");
    }
  });

  it("caps the level, the grant and the scopes at each value's cap, and never appears in methods", async () => {
    const caps = { A: 3, B: 2, C: 2, none: 1, failed: 0 } as const;
    const scopes: Record<AssuranceLevel, string[]> = {
      0: [],
      1: ["intake.file", "status.read"],
      2: ["intake.file", "payment.request", "status.read"],
      3: ["contact.update", "intake.file", "payment.request", "payout.update", "status.read"],
    };
    for (const attestation of ALL) {
      const t = capped(caps);
      const callId = await strongCall(t, attestation);
      const cap = caps[attestation];
      assert.deepEqual(await t.engine.finishVerification(callId), { level: cap, scopes: scopes[cap] }, attestation);
      const state = await t.engine.state(callId);
      assert.equal(state.level, cap);
      assert.equal(state.grant?.level ?? 0, cap);
      assert.equal(await t.engine.authorize(callId, "payout.update"), cap === 3);
      assert.equal(await t.engine.authorize(callId, "payment.request"), cap >= 2);
      assert.deepEqual(await finished(t), { level: cap, methods: ["keypad_knowledge", "photo_id"], discounted: [], capped: cap < 3 });
      const receipt = (await t.engine.endCall(callId))!;
      assert.equal(receipt.body.attestation, attestation);
      assert.deepEqual(receipt.body.verification, { level: cap, methods: cap === 0 ? [] : ["keypad_knowledge", "photo_id"] });
    }
  });

  it("never raises a level and never stands in for a factor", async () => {
    for (const attestation of ALL) {
      const t = capped({ A: 3, B: 3, C: 3, failed: 3, none: 3 });
      const { callId } = await t.engine.startCall({ attestation });
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      assert.deepEqual(await t.engine.finishVerification(callId), { level: 0, scopes: [] }, "no factor, no level");
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      assert.deepEqual(await t.engine.finishVerification(callId), { level: 1, scopes: ["intake.file", "status.read"] }, "keypad alone stays at level 1");
      assert.deepEqual(await finished(t), { level: 1, methods: ["keypad_knowledge"], discounted: [], capped: false });
    }
  });

  it("is set once: a second value for the call, or a value that is not an attestation, is refused", async () => {
    const t = setup();
    await t.engine.startCall({ callId: "c1", attestation: "A" });
    await assert.rejects(t.engine.startCall({ callId: "c1", attestation: "failed" }), rejects("invalid_input", /exists/));
    await assert.rejects(t.engine.startCall({ callId: "c2", attestation: "D" as Attestation }), rejects("invalid_input", /attestation must be A, B, C, failed or none/));
    await assert.rejects(t.engine.state("c2"), rejects("unknown_call"));
    await assert.rejects(t.engine.startCall({ callId: "c3", attestation: null as unknown as Attestation }), rejects("invalid_input", /attestation must be A, B, C, failed or none/));
    await assert.rejects(t.engine.state("c3"), rejects("unknown_call"));
    const started = (await t.ledger.list()).filter((e) => e.event === "call.started");
    assert.deepEqual(started.map((e) => e.detail.attestation), ["A"]);
    const receipt = (await t.engine.endCall("c1"))!;
    assert.equal(receipt.body.attestation, "A");
  });

  it("fails a flow step whose level the cap keeps the call from reaching", async () => {
    const t = setup();
    t.engine.configure(
      testConfig((c) => {
        c.policy.attestationCaps = { C: 1 };
        c.flows = { strong: { steps: [{ type: "badge.verify", level: 3, factors: ["keypad_knowledge", "photo_id"] }, { type: "trace.receipt" }] } };
      }),
    );
    const { callId } = await t.engine.startCall({ flow: "strong", attestation: "C" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.startPhotoId(callId);
    await t.engine.applyIdentityOutcome({ sessionId: t.identity.created.at(-1)!.sessionId, status: "verified" });
    assert.equal((await t.engine.finishVerification(callId)).level, 1);
    assert.equal((await t.engine.flowPosition(callId))!.status, "failed");
  });

  it("caps a grant already issued once the config turns caps on", async () => {
    const t = setup();
    const callId = await strongCall(t, "failed");
    await t.engine.finishVerification(callId);
    assert.equal(await t.engine.authorize(callId, "payment.request"), true);
    t.engine.configure(testConfig((c) => (c.policy.attestationCaps = { failed: 1 })));
    assert.equal(await t.engine.authorize(callId, "payment.request"), false);
    assert.equal(await t.engine.authorize(callId, "status.read"), true);
  });

  it("reads a call stored before attestations existed as none: capped as none, and its receipt still signs", async () => {
    const t = capped({ none: 1 });
    // A record written before VER-10 has no attestation field.
    const strip = async (callId: string) => {
      const stored = (await t.sessions.get("ws_test", callId))!;
      const { attestation: _, ...old } = stored.record as { attestation: string };
      assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, old as never)).ok, true);
    };
    // Verified at level 3 as A, then read back as a stored call: the grant is held to the none cap.
    const verified = await strongCall(t, "A");
    assert.equal((await t.engine.finishVerification(verified)).level, 3);
    assert.equal(await t.engine.authorize(verified, "payment.request"), true);
    await strip(verified);
    assert.equal(await t.engine.authorize(verified, "payment.request"), false, "the none cap holds, not no cap at all");

    const callId = await strongCall(t, "A");
    await strip(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 1, "capped as none when it finishes");
    const receipt = (await t.engine.endCall(callId))!;
    assert.equal(receipt.body.attestation, "none");
    assert.equal(verifyReceipt(receipt, t.engine.receiptKeys()), true);
  });
});
