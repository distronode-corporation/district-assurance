// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The demo world's door relay, from the #50 hostile pass (W1): close() while the relay is starting.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { createDemoWorld } from "../examples/reference-server/src/script.ts";

const post = (url: string) =>
  fetch(url, { method: "POST", body: "{}", signal: AbortSignal.timeout(2000) }).then(
    (r) => r.status,
    () => "refused" as const,
  );

describe("the demo world's door relay", () => {
  it("close() while the relay is still starting leaves nothing listening, and no later call hangs", async () => {
    const world = createDemoWorld();
    const starting = world.relayUrl();
    await world.close();
    const url = await Promise.race([starting, new Promise<string>((_, reject) => setTimeout(() => reject(new Error("relayUrl never settled")), 2000).unref())]);
    assert.equal(await post(url), "refused", "the relay still answered after close()");
    await assert.rejects(world.relayUrl(), /closed/, "a later start is refused, never left pending");
  });

  it("close() after the relay started stops it, and close() twice is harmless", async () => {
    const world = createDemoWorld();
    const url = await world.relayUrl();
    assert.notEqual(await post(url), "refused");
    await world.close();
    await world.close();
    assert.equal(await post(url), "refused");
  });

  it("close() on a world whose relay never started does nothing", async () => {
    const world = createDemoWorld();
    await world.close();
    await assert.rejects(world.relayUrl(), /closed/);
  });
});
