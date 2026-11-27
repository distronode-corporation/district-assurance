// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #96 (INT-2, forwardingFor and the payment hold). W1 to W3 failed
// before forwardingFor read each field once as the state's own and required the hold while paying.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { forwardingFor } from "../src/core/forwarding.ts";
import { newSession, type SessionState } from "../src/core/session.ts";
import { confirmAmount, setup, verifiedCall } from "./helpers.ts";

const NONE = { transcript: false, speechToText: false, model: false, listenIn: false };
const live = (patch: Partial<Record<keyof SessionState, unknown>>) => ({ ...newSession("c", "w", "2026-01-01T00:00:00.000Z"), ...patch }) as SessionState;

describe("hostile #96: states forwardingFor is handed", () => {
  it("W1: a paying call without the payment hold (stored before #96 made it impossible) forwards nothing", () => {
    assert.deepEqual(forwardingFor(live({ phase: "paying", sensitive: null })), { ...NONE, heldFor: "unknown" });
    assert.deepEqual(forwardingFor(live({ phase: "paying", sensitive: "keypad" })), { ...NONE, heldFor: "unknown" });
    assert.deepEqual(forwardingFor(live({ phase: "paying", sensitive: "payment" })), { ...NONE, heldFor: "payment" });
  });

  it("W2: a state whose fields answer differently on each read is judged on one read", () => {
    let phaseReads = 0;
    let sensitiveReads = 0;
    const shifty = {
      ...live({}),
      get phase() {
        return phaseReads++ === 0 ? "verifying" : "open";
      },
      get sensitive() {
        return sensitiveReads++ === 0 ? null : "keypad";
      },
    } as unknown as SessionState;
    const answer = forwardingFor(shifty);
    // Whatever it decides, it decided on the values it read once each.
    assert.equal(phaseReads, 1);
    assert.equal(sensitiveReads, 1);
    assert.deepEqual(answer, { transcript: true, speechToText: true, model: true, listenIn: true, heldFor: null });
  });

  it("W3: shapes the engine never writes fail closed", () => {
    for (const state of [[], "open", 1, true, { phase: "OPEN", sensitive: null }, { phase: "open" }, { phase: "open", sensitive: "Keypad" }, { phase: ["open"], sensitive: null }, Object.create({ phase: "open", sensitive: null })]) {
      assert.equal(forwardingFor(state as SessionState).transcript, false, JSON.stringify(state));
    }
  });
});

describe("hostile #96: the payment hold on a real call", () => {
  it("W4: nothing the host can call while paying lifts the hold before the payment settles", async () => {
    const t = setup();
    const callId = await verifiedCall(t);
    await confirmAmount(t.engine, callId, { amountMinor: 1000, currency: "cad", description: "Deposit", amountSource: "price_list" });
    await t.engine.requestPayment(callId, { amountMinor: 1000, currency: "cad", description: "Deposit", amountSource: "price_list" });
    const held = async () => forwardingFor(await t.engine.state(callId)).heldFor;
    assert.equal(await held(), "payment");
    await assert.rejects(t.engine.closeSensitive(callId));
    await assert.rejects(t.engine.openSensitive(callId, "keypad"));
    await t.engine.markUntrusted(callId, "document");
    assert.equal(await held(), "payment", "a taint keeps the hold");
    await t.engine.endCall(callId).catch(() => undefined);
    assert.notEqual(await held(), null);
  });
});
