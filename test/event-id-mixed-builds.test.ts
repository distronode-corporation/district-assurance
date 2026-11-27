// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// #124 cross-review item 1: ledger event ids numbered by the writes that queue entries must never
// equal the version-numbered ids an older build writes on the same call, or the ledger drops the
// newer build's entry as a replay. Both builds run on one session store and one ledger (a rolling
// deploy). The older build is simulated: one write of its own, its entry appended under
// [workspaceId, callId, version, index], exactly as main and every build before #124 forms it.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { JsonValue } from "../src/core/canonical.ts";
import { createTestEngine, type TestEngine } from "../src/testing/index.ts";
import { testConfig } from "./helpers.ts";

/** One write by an older build: the next version, one entry under the version-numbered id. */
async function olderBuildWrite(t: TestEngine, callId: string, event: string): Promise<void> {
  const stored = (await t.sessions.get("ws_test", callId))!;
  const version = stored.version + 1;
  await t.ledger.append({ eventId: JSON.stringify(["ws_test", callId, version, 0]), callId, actor: "system", event: event as never, at: "2026-01-01T00:00:00.000Z", detail: { by: "older build" } });
  assert.equal((await t.sessions.compareAndSet("ws_test", callId, stored.version, stored.record as JsonValue)).ok, true);
}

describe("#124: ledger event ids across builds on one store", () => {
  it("E1 an older build's version-numbered ids never take a newer build's entry: nothing is lost", async () => {
    const t = createTestEngine({ config: testConfig() });
    const { callId } = await t.engine.startCall();
    await olderBuildWrite(t, callId, "module.event");
    await olderBuildWrite(t, callId, "module.event");
    await t.engine.markUntrusted(callId, "crm_note");
    await olderBuildWrite(t, callId, "module.event");
    await t.engine.endCall(callId);
    const entries = (await t.ledger.list()).filter((e) => e.callId === callId);
    const events = entries.map((e) => e.event);
    for (const name of ["call.started", "session.tainted", "call.ended"]) assert.ok(events.includes(name as never), `${name} is on the ledger`);
    assert.equal(entries.filter((e) => e.detail.by === "older build").length, 3);
    assert.equal(new Set(entries.map((e) => e.eventId)).size, entries.length);
    const stored = (await t.sessions.get("ws_test", callId))!.record as { outbox: unknown[] };
    assert.deepEqual(stored.outbox, [], "nothing left pending");
  });

  it("E2 the newer ids have their own shape: [workspaceId, callId, \"w\", n, index]", async () => {
    const t = createTestEngine({ config: testConfig() });
    const { callId } = await t.engine.startCall();
    await t.engine.markUntrusted(callId, "crm_note");
    const ids = (await t.ledger.list()).filter((e) => e.callId === callId).map((e) => JSON.parse(e.eventId!) as unknown[]);
    assert.deepEqual(ids, [["ws_test", callId, "w", 1, 0], ["ws_test", callId, "w", 2, 0]]);
  });
});
