// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Slot 2's double-read sweep on #47: every host or relay input is read once, so a getter cannot
// change a value after it was checked.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { SeenGrants, verifyAccessGrant, type AccessGrantBody, type SignedAccessGrant } from "../src/gate/access.ts";
import { signDocument } from "../src/prove/receipt.ts";
import { generateTestSigner } from "../src/testing/index.ts";
import { setup } from "./helpers.ts";

const body: AccessGrantBody = {
  v: 1,
  kind: "access",
  grantId: "acc_1",
  workspaceId: "ws_test",
  audience: "lobby",
  target: "door-1",
  action: "unlock",
  scope: "entry.open",
  level: 2,
  issuedAt: "2026-01-01T00:00:00.000Z",
  expiresAt: "2026-01-01T00:01:00.000Z",
};
const now = new Date("2026-01-01T00:00:10.000Z");

/** An object whose `key` is `first` on its first read and `then` after, counting reads. */
function swapping<T extends object>(base: T, key: string, first: unknown, then: unknown): T & { reads: () => number } {
  let reads = 0;
  const out = { ...base } as Record<string, unknown>;
  Object.defineProperty(out, key, {
    enumerable: true,
    get() {
      reads++;
      return reads === 1 ? first : then;
    },
  });
  Object.defineProperty(out, "reads", { value: () => reads });
  return out as T & { reads: () => number };
}

describe("#47 double reads", () => {
  it("D1 startCall reads callId, locale and flow once each", async () => {
    const t = setup();
    for (const [key, first, then] of [
      ["callId", "call_ok", "\ud800"],
      ["locale", "en", "xx"],
    ] as const) {
      const input = swapping({}, key, first, then);
      const state = await t.engine.startCall(input as never);
      assert.equal(input.reads(), 1, key);
      if (key === "callId") assert.equal(state.callId, "call_ok");
    }
    const flowInput = swapping({}, "flow", undefined, "nope");
    await t.engine.startCall(flowInput as never);
    assert.equal(flowInput.reads(), 1, "flow");
  });

  it("D2 verifyAccessGrant checks, verifies and returns one copy of the grant: a body swapped after the signature is never seen", async () => {
    const signer = generateTestSigner("k1");
    const keys = [signer.publicJwk()];
    const good = (await signDocument(signer, body)) as SignedAccessGrant;
    const forged = { ...body, target: "vault", grantId: "acc_forged" };
    const grant = swapping(good, "body", good.body, forged);
    const check = verifyAccessGrant(grant, keys, { workspaceId: "ws_test", audience: "lobby", now });
    assert.equal(grant.reads(), 1);
    assert.equal(check.ok, true);
    assert.deepEqual(check.ok && check.body, body, "the body that was verified");
    const expect = swapping({ workspaceId: "ws_test", audience: "lobby", now }, "workspaceId", "ws_test", "ws_other");
    assert.equal(verifyAccessGrant(good, keys, expect).ok, true);
    assert.equal(expect.reads(), 1);
    const clock = swapping({ workspaceId: "ws_test", audience: "lobby", now }, "now", now, "later");
    assert.equal(verifyAccessGrant(good, keys, clock).ok, true);
    assert.equal(clock.reads(), 1);
    const throwing = { ...good, get body(): unknown {
      throw new Error("boom");
    } };
    assert.deepEqual(verifyAccessGrant(throwing, keys, { workspaceId: "ws_test", audience: "lobby", now }), { ok: false, reason: "malformed" });
  });

  it("D3 SeenGrants reads a grant's id and expiry once each", () => {
    const seen = new SeenGrants();
    const id = swapping(body, "grantId", "acc_1", "acc_other");
    assert.equal(seen.accept(id, now), true);
    assert.equal(id.reads(), 1);
    assert.equal(seen.accept({ ...body, grantId: "acc_1" }, now), false, "the id it kept is the one it checked");
    const exp = swapping({ ...body, grantId: "acc_2" }, "expiresAt", body.expiresAt, "2099-01-01T00:00:00.000Z");
    assert.equal(seen.accept(exp, now), true);
    assert.equal(exp.reads(), 1);
  });
});
