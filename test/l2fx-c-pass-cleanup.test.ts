// L2 fix T13 (PR #130 review): a pass's counters cleanup is safe to replay. The subject forgets only
// the failures up to the pass, so a cleanup run again (its owed marker not cleared) erases nothing
// recorded since.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { DEFAULT_LOCKOUT, forgetPass } from "../src/verify/counters.ts";
import { MemoryAttemptCounters } from "../src/testing/index.ts";

const LONG_AGO = "1970-01-01T00:00:00.000Z";
const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();
const subject = (): AttemptCounterKey => ({ workspaceId: "ws_test", factor: "pin", scope: "subject", key: "b".repeat(64) });

describe("T13: pass cleanup is safe to replay", () => {
  it("the subject forgets only the failures up to the pass, run once or twice", async () => {
    const counters = new MemoryAttemptCounters();
    for (const ms of [T0 - 5, T0 - 5, T0, T0 + 7]) await counters.recordFailure(subject(), iso(ms), LONG_AGO);
    await forgetPass(counters, [subject()], new Date(T0));
    assert.deepEqual(await counters.get(subject(), LONG_AGO), [iso(T0 + 7)], "a failure recorded after the pass stays");
    await counters.recordFailure(subject(), iso(T0 + 9), LONG_AGO);
    await forgetPass(counters, [subject()], new Date(T0));
    assert.deepEqual(await counters.get(subject(), LONG_AGO), [iso(T0 + 7), iso(T0 + 9)], "a replay erases nothing recorded since");
  });

  it("forgets failures older than the window too, as a reset did", async () => {
    const counters = new MemoryAttemptCounters();
    await counters.recordFailure(subject(), iso(T0 - DEFAULT_LOCKOUT.windowHours * 7 * 3_600_000), LONG_AGO);
    await forgetPass(counters, [subject()], new Date(T0));
    assert.deepEqual(await counters.get(subject(), LONG_AGO), []);
  });
});
