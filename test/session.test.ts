// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { EngineError } from "../src/core/errors.ts";
import { forwardingFor } from "../src/core/forwarding.ts";
import { ALLOWED_PHASES, canApply, newSession, reduce, snapshot, type SessionEvent, type SessionPhase, type SessionState } from "../src/core/session.ts";

const at = "2026-01-01T00:00:00.000Z";
const factor = { kind: "keypad_knowledge" as const, passed: true, at };
const grant = { grantId: "g1", level: 1 as const, scopes: ["status.read"], policyVersion: "p1", configRevision: "r1", issuedAt: at, expiresAt: at };

/** One sample of every event type. */
const SAMPLES: Record<SessionEvent["type"], SessionEvent> = {
  verification_started: { type: "verification_started", reset: false },
  factor_recorded: { type: "factor_recorded", factor },
  verification_finished: { type: "verification_finished", level: 1, grant },
  intake_started: { type: "intake_started" },
  intake_confirmed: { type: "intake_confirmed", recordId: "r1" },
  intake_abandoned: { type: "intake_abandoned" },
  sensitive_opened: { type: "sensitive_opened", reason: "keypad" },
  sensitive_closed: { type: "sensitive_closed" },
  payment_requested: { type: "payment_requested", paymentId: "p1" },
  payment_settled: { type: "payment_settled", paymentId: "p1" },
  untrusted_content: { type: "untrusted_content", source: "endpoint" },
  synthetic_voice_scored: { type: "synthetic_voice_scored", band: "level_1", ceiling: 1, scopes: ["status.read"] },
  call_ended: { type: "call_ended", at },
};

const PHASES: SessionPhase[] = ["open", "verifying", "filing", "paying", "ended"];

function inPhase(phase: SessionPhase): SessionState {
  return { ...newSession("c1", "w1", at), phase };
}

describe("session state machine", () => {
  it("starts open, unverified and untainted", () => {
    const s = newSession("c1", "w1", at);
    assert.equal(s.phase, "open");
    assert.equal(s.level, 0);
    assert.equal(s.grant, null);
    assert.equal(s.tainted, false);
    assert.equal(s.endedAt, null);
  });

  it("allows each event only in its listed phases, in every phase", () => {
    for (const [type, phases] of Object.entries(ALLOWED_PHASES) as Array<[SessionEvent["type"], readonly SessionPhase[]]>) {
      for (const phase of PHASES) {
        const event = SAMPLES[type];
        const allowed = phases.includes(phase);
        assert.equal(canApply(inPhase(phase), event), allowed, `${type} in ${phase}`);
        if (allowed) reduce(inPhase(phase), event);
        else {
          assert.throws(
            () => reduce(inPhase(phase), event),
            (e: unknown) => e instanceof EngineError && e.code === "invalid_transition" && e.message === `${type} is not allowed while ${phase}`,
          );
        }
      }
    }
  });

  it("runs a whole call", () => {
    let s = newSession("c1", "w1", at);
    s = reduce(s, SAMPLES.verification_started);
    s = reduce(s, SAMPLES.sensitive_opened);
    assert.equal(s.sensitive, "keypad");
    s = reduce(s, SAMPLES.sensitive_closed);
    assert.equal(s.sensitive, null);
    s = reduce(s, SAMPLES.factor_recorded);
    s = reduce(s, { ...SAMPLES.sensitive_opened });
    s = reduce(s, SAMPLES.verification_finished);
    assert.equal(s.phase, "open");
    assert.equal(s.sensitive, null, "finishing verification closes the keypad segment");
    assert.equal(s.level, 1);
    assert.deepEqual(s.grant, grant);
    s = reduce(s, SAMPLES.intake_started);
    assert.equal(s.phase, "filing");
    s = reduce(s, SAMPLES.intake_confirmed);
    assert.deepEqual(s.recordIds, ["r1"]);
    s = reduce(reduce(s, SAMPLES.intake_started), SAMPLES.intake_abandoned);
    assert.equal(s.phase, "open");
    s = reduce(s, SAMPLES.payment_requested);
    assert.equal(s.phase, "paying");
    assert.equal(s.sensitive, "payment");
    assert.deepEqual(s.paymentIds, ["p1"]);
    s = reduce(s, SAMPLES.payment_settled);
    assert.equal(s.phase, "open");
    assert.equal(s.sensitive, null);
    s = reduce(reduce(s, SAMPLES.payment_requested), SAMPLES.call_ended);
    assert.equal(s.phase, "ended");
    assert.equal(s.sensitive, null);
    assert.equal(s.grant, null);
    assert.equal(s.endedAt, at);
  });

  it("keeps factors across a step-up and drops them on reset or after taint", () => {
    let s = reduce(reduce(newSession("c1", "w1", at), SAMPLES.verification_started), SAMPLES.factor_recorded);
    s = reduce(s, SAMPLES.verification_finished);
    s = reduce(s, SAMPLES.verification_started);
    assert.equal(s.factors.length, 1, "a step-up keeps earlier factors");
    s = reduce(s, SAMPLES.verification_finished);
    assert.equal(reduce(s, { type: "verification_started", reset: true }).factors.length, 0);
    s = reduce(s, SAMPLES.untrusted_content);
    assert.equal(s.tainted, true);
    assert.equal(s.level, 0);
    assert.equal(s.grant, null);
    assert.equal(reduce(s, SAMPLES.verification_started).factors.length, 0);
  });

  it("snapshots are copies", () => {
    const s = newSession("c1", "w1", at);
    const copy = snapshot(s);
    copy.recordIds.push("x");
    assert.deepEqual(s.recordIds, []);
  });
});

describe("forwardingFor", () => {
  const all = { transcript: true, speechToText: true, model: true, listenIn: true, heldFor: null };
  const none = { transcript: false, speechToText: false, model: false, listenIn: false };

  it("forwards everything while nothing is sensitive, tainted or not", () => {
    const s = newSession("c1", "w1", at);
    assert.deepEqual(forwardingFor(s), all);
    assert.deepEqual(forwardingFor(reduce(s, SAMPLES.untrusted_content)), all);
    for (const phase of ["open", "verifying", "filing"] as const) assert.deepEqual(forwardingFor(inPhase(phase)), all, phase);
    // Paying without the payment hold is not a state the engine writes (see test/forwarding-hostile.test.ts).
    assert.deepEqual(forwardingFor(inPhase("paying")), { ...none, heldFor: "unknown" });
  });

  it("holds the transcript, both audio paths and listen-in through keypad entry and payment, and after the call", () => {
    let s = reduce(newSession("c1", "w1", at), SAMPLES.verification_started);
    s = reduce(s, SAMPLES.sensitive_opened);
    assert.deepEqual(forwardingFor(s), { ...none, heldFor: "keypad" });
    s = reduce(s, SAMPLES.sensitive_closed);
    assert.deepEqual(forwardingFor(s), all);
    s = reduce(reduce(s, SAMPLES.sensitive_opened), SAMPLES.verification_finished);
    assert.deepEqual(forwardingFor(s), all, "finishing verification releases the keypad hold");
    s = reduce(s, SAMPLES.payment_requested);
    assert.deepEqual(forwardingFor(s), { ...none, heldFor: "payment" });
    s = reduce(s, SAMPLES.payment_settled);
    assert.deepEqual(forwardingFor(s), all);
    s = reduce(reduce(s, SAMPLES.payment_requested), SAMPLES.call_ended);
    assert.deepEqual(forwardingFor(s), { ...none, heldFor: "ended" });
  });

  it("keeps the payment hold: sensitive_closed is refused while paying", () => {
    const s = reduce(newSession("c1", "w1", at), SAMPLES.payment_requested);
    assert.equal(s.phase, "paying");
    assert.throws(() => reduce(s, SAMPLES.sensitive_closed), (e: unknown) => e instanceof EngineError && e.code === "invalid_transition");
    assert.deepEqual(forwardingFor(s), { ...none, heldFor: "payment" });
  });

  it("fails closed with no state, or one the engine never writes", () => {
    const held = { ...none, heldFor: "unknown" };
    const s = newSession("c1", "w1", at);
    for (const bad of [null, undefined, "open" as unknown, { ...s, sensitive: undefined }, { ...s, sensitive: "microphone" }, { ...s, phase: "closing" }, { ...s, phase: undefined }]) {
      assert.deepEqual(forwardingFor(bad as SessionState), held, JSON.stringify(bad));
    }
  });

  it("is exported from the package root", async () => {
    const root = await import("../src/index.ts");
    assert.equal(root.forwardingFor, forwardingFor);
  });
});
