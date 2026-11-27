// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// monthlyReport reads its input once: a getter can never pass the checks with one workspace or
// month and filter entries by, or name, another.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { monthlyReport } from "../src/prove/report.ts";
import { setup } from "./helpers.ts";

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

describe("report: monthlyReport reads its input once", () => {
  it("counts and names the workspace and month it checked", async () => {
    const t = setup();
    await t.engine.endCall((await t.engine.startCall()).callId);
    const plain = await monthlyReport({ ledger: t.ledger, workspaceId: "ws_test", month: "2026-01" });
    const ws = await monthlyReport(flipping({ ledger: t.ledger, month: "2026-01" }, "workspaceId", "ws_test", "ws_other", 2) as never);
    assert.deepEqual(ws, plain);
    const month = await monthlyReport(flipping({ ledger: t.ledger, workspaceId: "ws_test" }, "month", "2026-01", "1999-12") as never);
    assert.deepEqual(month, plain);
  });
});
