// Hostile pass on #47's commits after 6e48b37 (be29022, 66c439d, 5930120), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { SeenGrants, verifyAccessGrant, type AccessGrantBody } from "../src/gate/access.ts";
import { webhookRelay } from "../src/gate/relay.ts";
import { FakeAccessController, createTestEngine, generateTestSigner, testSubject, TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, rejects, testConfig } from "./helpers.ts";

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

describe("#47 hostile: the relay's idempotency key (be29022)", () => {
  const seen: IncomingHttpHeaders[] = [];
  let base = "";
  const server = createServer((req, res) => {
    seen.push(req.headers);
    req.resume();
    req.on("end", () => res.writeHead(200, { "content-type": "application/json" }).end("{}"));
  });
  before(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(() => server.close());

  it("H1 keys that differ only in an escape and the character it names stay apart, and every key reads back as its own tuple", async () => {
    const tuples = [
      ["w", "é", "acc_1", "unlock"],
      ["w", "\\u00e9", "acc_1", "unlock"],
      ["w", "\\\\u00e9", "acc_1", "unlock"],
      ["w", "😀", "acc_1", "unlock"],
      ["w", " ‮\u0000\t\"", "acc_1", "unlock"],
      ["w", String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i)), "acc_1", "unlock"],
    ];
    const headers = new Set<string>();
    for (const tuple of tuples) {
      const grant = { kid: "k", signature: "s", body };
      await webhookRelay({ url: `${base}/u` }).unlock({ grant: grant as never, target: "door-1", idempotencyKey: JSON.stringify(tuple) });
      const header = seen.at(-1)!["idempotency-key"] as string;
      assert.match(header, /^[\x20-\x7e]*$/);
      assert.deepEqual(JSON.parse(header), tuple);
      headers.add(header);
    }
    assert.equal(headers.size, tuples.length, "no two keys share a header");
  });
});

describe("#47 hostile: SeenGrants used without the verifier", () => {
  it("H2 refuses a grant whose expiry it cannot read, and a clock reading it cannot use, and keeps forgetting afterwards", () => {
    const seen = new SeenGrants();
    const now = new Date("2026-01-01T00:00:00.000Z");
    assert.equal(seen.accept({ ...body, grantId: "bad", expiresAt: "never" }, now), false, "an unreadable expiry is not a fresh grant");
    assert.equal(seen.accept({ ...body, grantId: "bad2" }, new Date(Number.NaN)), false, "an unusable clock accepts nothing");
    assert.equal(seen.accept(body, now), true);
    // Forgetting still works: after the first grant expired, the clock set back never revives it.
    assert.equal(seen.accept({ ...body, grantId: "acc_2", issuedAt: "2026-01-01T00:05:00.000Z", expiresAt: "2026-01-01T00:06:00.000Z" }, new Date("2026-01-01T00:05:00.000Z")), true);
    assert.equal(seen.accept(body, new Date("2026-01-01T00:00:30.000Z")), false);
    assert.equal(seen.accept({ ...body, grantId: "acc_3", expiresAt: "2026-01-01T00:00:59.000Z" }, new Date("2026-01-01T00:00:30.000Z")), false, "a grant expiring before the forget point is refused");
  });
});

describe("#47 hostile: grantAccess and endCall", () => {
  const verify = { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["entry.open"] };
  const config = (): FlowConfig =>
    testConfig((c) => {
      c.policy.scopes["entry.open"] = 2;
      c.modules.gate = { settings: { targets: [{ id: "front-door", controller: "lobby", ref: "door-1" }] } };
      c.flows = { entry: { steps: [verify as never, { type: "gate.grant", target: "front-door" }] } };
    });

  function pair() {
    const door = new FakeAccessController("confirm");
    const accessSigner = generateTestSigner("gate-key-1");
    const one = createTestEngine({ config: config(), adapters: { access: { lobby: door }, accessSigner } });
    one.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB } }));
    one.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
    // A second engine on the same stores, with its own id generator: its ids repeat the first's.
    const two = createTestEngine({
      config: config(),
      adapters: { access: { lobby: door }, accessSigner, sessions: one.sessions, records: one.records, ledger: one.ledger, carrier: one.carrier },
      clock: one.clock,
    });
    return { one, two, door };
  }

  async function verified(t: ReturnType<typeof pair>["one"]): Promise<string> {
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.checkCarrier(callId);
    assert.equal((await t.engine.finishVerification(callId)).level, 2);
    return callId;
  }

  it("H3 a second engine whose id generator repeats a grant id on the same call is refused, sends nothing, and leaves nothing in flight", async () => {
    const { one, two, door } = pair();
    const callId = await verified(one);
    assert.equal((await one.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    await assert.rejects(two.engine.grantAccess(callId, { target: "front-door" }), rejects("conflict"));
    assert.equal(door.received.length, 1, "no grant with a used id reaches the door");
    const ids = new Set(door.received.map((r) => r.grant.body.grantId));
    assert.equal(ids.size, door.received.length);
    // The call is not left waiting on a phantom reservation: another grant goes out at once, and the call ends.
    assert.equal((await one.engine.grantAccess(callId, { target: "front-door" })).status, "delivered");
    assert.notEqual(await one.engine.endCall(callId), null);
  });

  it("H4 the engine ends the call at the same instant the relay starts refusing the grant, never before", async () => {
    const { one, door } = pair();
    door.mode = "lose";
    const callId = await verified(one);
    assert.equal((await one.engine.grantAccess(callId, { target: "front-door" })).status, "unknown");
    const grant = door.received[0]!.grant;
    const expires = Date.parse(grant.body.expiresAt);
    one.clock.advance(expires - one.clock.now().getTime() - 1);
    assert.equal(verifyAccessGrant(grant, one.engine.accessKeys(), { workspaceId: "ws_test", audience: "lobby", now: one.clock.now() }).ok, true, "1 ms before: a relay still accepts");
    await assert.rejects(one.engine.endCall(callId), rejects("precondition_failed"), "so the end is refused");
    one.clock.advance(1);
    assert.deepEqual(verifyAccessGrant(grant, one.engine.accessKeys(), { workspaceId: "ws_test", audience: "lobby", now: one.clock.now() }), { ok: false, reason: "expired" });
    assert.notEqual(await one.engine.endCall(callId), null, "at the expiry both agree: refused, and the call ends");
  });
});
