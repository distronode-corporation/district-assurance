// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// L2 fix V7 (PR #130 review, round 4): a flag write taken back after a clearing takes back only its
// own write, never a newer entry's flag written in the same millisecond.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { clearsSoFar, duressFlagKey, flagDuressUnlessCleared, isUnderDuress, recordClear } from "../src/verify/duress-flag.ts";
import { MemoryAttemptCounters } from "../src/testing/index.ts";

const WS = "ws_test";
const SUBJECT = "a".repeat(64);
const flag = duressFlagKey(WS, SUBJECT);
const T = new Date("2026-11-19T12:00:00.000Z");

/** Runs `after` once, right after the next flag write. */
class Racing extends MemoryAttemptCounters {
  after: (() => Promise<void>) | null = null;
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    const got = await super.recordFailure(key, at, since);
    const run = key.factor === flag.factor ? this.after : null;
    if (run !== null) {
      this.after = null;
      await run();
    }
    return got;
  }
}

describe("V7: the rollback of a flag write removes only that write", () => {
  it("a newer entry's flag in the same millisecond stays after the older entry takes its own back", async () => {
    const counters = new Racing();
    const older = await clearsSoFar(counters, WS, SUBJECT);
    counters.after = async () => {
      // clearDuress: the clearing is counted, then the flag cleared.
      await recordClear(counters, WS, SUBJECT, T);
      await counters.reset(flag);
      // A new duress entry, judged in the same millisecond, after the clearing.
      await flagDuressUnlessCleared(counters, WS, SUBJECT, await clearsSoFar(counters, WS, SUBJECT));
    };
    await flagDuressUnlessCleared(counters, WS, SUBJECT, older);
    assert.equal(await isUnderDuress(counters, flag), true, "the newer entry's flag stands");
  });

  it("the older entry's write is still taken back when it landed after the clearing", async () => {
    const counters = new MemoryAttemptCounters();
    const read = counters.get.bind(counters);
    let reads = 0;
    // The clearing lands between the older entry's check and its write.
    counters.get = async (key, since) => {
      const got = await read(key, since);
      if (key.factor === "duress.clears" && reads++ === 0) {
        await recordClear(counters, WS, SUBJECT, T);
        await counters.reset(flag);
      }
      return got;
    };
    await flagDuressUnlessCleared(counters, WS, SUBJECT, 0);
    assert.equal(await isUnderDuress(counters, flag), false);
  });
});
