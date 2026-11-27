// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// startCall reads its input once: the access checked is the access stored on the call.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { setup } from "./helpers.ts";

describe("startCall reads its input once", () => {
  it("stores the access it checked, never a value swapped in after the check", async () => {
    const t = setup();
    let reads = 0;
    const input = {
      get access() {
        reads += 1;
        return reads === 1 ? "relay" : "+15555550100";
      },
    };
    const { callId } = await t.engine.startCall(input as never);
    const record = (await t.sessions.get("ws_test", callId))!.record as { access?: string };
    assert.equal(record.access, "relay");
  });
});
