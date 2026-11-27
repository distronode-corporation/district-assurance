// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The host allowlist, from the iMac's //host re-check: every case held, kept as regressions.
import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import type { SignedAccessGrant } from "../src/gate/access.ts";
import { seamAccessController } from "../src/gate/seam.ts";
import { FixedClock } from "../src/testing/index.ts";

const KEY = "seam_test_KEY_0000";
const clock = new FixedClock();
const grant = (target: string): SignedAccessGrant => ({
  body: { v: 1, kind: "access", grantId: "acc_1", workspaceId: "w", audience: "lobby", target, action: "unlock", scope: "entry.open", level: 2, issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-01T00:01:00.000Z" },
  alg: "ES256", kid: "k1", signature: "sig",
});
const input = (target: string) => ({ grant: grant(target), target, idempotencyKey: "k" });

type Seen = { url: string; host: string; headers: Record<string, string>; body: string; redirect: unknown };
function stub(attemptId = "aa_1") {
  const seen: Seen[] = [];
  const f = (async (u: URL | string, init: RequestInit) => {
    const url = new URL(String(u));
    seen.push({ url: url.href, host: url.host, headers: init.headers as Record<string, string>, body: String(init.body), redirect: init.redirect });
    const id = JSON.parse(String(init.body)).device_id;
    if (url.pathname.endsWith("/devices/get")) return Response.json({ device: { device_id: id, can_remotely_unlock: true, properties: { online: true } } });
    if (url.pathname.endsWith("/locks/unlock_door")) return Response.json({ action_attempt: { action_attempt_id: attemptId, status: "pending" } });
    return Response.json({ action_attempt: { action_attempt_id: attemptId, status: "success", result: { was_confirmed_by_device: true } } });
  }) as typeof fetch;
  return { seen, f };
}

const BASES = [
  "//evil.example", "\\\\evil.example", "/\\evil.example", "https:evil.example", "https:/evil.example", "https:\\\\evil.example",
  "https://connect.getseam.com@evil.example", "https://connect.getseam.com:x@evil.example", "https://evil.example#@connect.getseam.com",
  "https://evil.example?@connect.getseam.com", "https://connect.getseam.com//evil.example", "https://connect.getseam.com/\\evil.example",
  "https://connect.getseam.com/%2F%2Fevil.example", "https://connect.getseam.com/..//evil.example", "https://connect.getseam.com/../../evil.example",
  "https://connect.getseam.com/%2e%2e/%2e%2e//evil.example", "https://conn\tect.get\nseam.co\rm//evil.example", " https://connect.getseam.com",
  "https://connect.getseam.com。evil.example", "https://connect.getseam.com.evil.example", "https://xn--cnnect-6ve.getseam.com",
  "https://[::ffff:7f00:1]", "https://2130706433", "https://0x7f.1", "http://2130706433//evil.example", "http://0x7f000001//evil.example",
  "http://[::1]//evil.example", "http://localhost.evil.example", "http://localhost//evil.example", "http://127.0.0.1:1@evil.example",
  "http://127.0.0.1//evil.example/x//y", "HTTP://LOCALHOST//evil.example", "http://127.1//evil.example", "http://[0:0:0:0:0:0:0:1]//evil.example",
];

describe("seamAccessController: the key goes only to Seam (//host re-check)", () => {
  it("previous bypass bases and new ones: only connect.getseam.com on https:443 is accepted", async () => {
    const extra = [
      "https://connect.getseam.com.", "https://CONNECT.GETSEAM.COM", "https://Connect.GetSeam.com/", "https://connect.getseam.com:443",
      "https://connect.getseam.com:8443", "https://connect.getseam.com:0443", "https://user@connect.getseam.com", "https://:p@connect.getseam.com",
      "https://connect.getseam.com?x=1", "https://connect.getseam.com/?", "https://connect.getseam.com#", "https://connect.getseam.com/#x",
      "https://xn--connect-getseam-com", "https://xn--cnnect-6ve.getseam.com", "https://conneсt.getseam.com", "https://connect.getseam.com%2e",
      "https://connect.getseam.com\u3002", "https://connect\uff0egetseam\uff0ecom", "http://connect.getseam.com", "wss://connect.getseam.com",
      "https://connect.getseam.co", "https://getseam.com", "https://evil.connect.getseam.com", "https://127.0.0.1", "http://127.0.0.1", "http://localhost",
    ].map((u) => JSON.parse(`"${u.replace(/\\(?!u)/g, "\\\\")}"`) as string);
    const report: string[] = [];
    for (const b of [...BASES, ...extra]) {
      let s = stub();
      try {
        const c = seamAccessController({ apiKey: KEY, baseUrl: b, fetch: s.f, clock, confirmWithinMs: 50, pollIntervalMs: 10 });
        await c.unlock(input("dev-1"));
      } catch {
        report.push(`REJECT ${JSON.stringify(b)}`);
        continue;
      }
      const hosts = [...new Set(s.seen.map((x) => new URL(x.url).host))];
      report.push(`ACCEPT ${JSON.stringify(b)} -> ${hosts.join(",")}`);
      assert.deepEqual(hosts, ["connect.getseam.com"], b);
      for (const x of s.seen) assert.equal(new URL(x.url).protocol, "https:");
    }
  });

  it("allowLoopbackForTests: only the boolean true enables loopback", () => {
    for (const v of ["true", 1, "1", {}, [], new Boolean(true), "yes"] as unknown[]) {
      for (const b of ["http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9", "https://127.0.0.1"]) {
        assert.throws(() => seamAccessController({ apiKey: KEY, baseUrl: b, allowLoopbackForTests: v as boolean }), TypeError, `${b} with ${typeof v}`);
      }
    }
    assert.doesNotThrow(() => seamAccessController({ apiKey: KEY, baseUrl: "http://127.0.0.1:9", allowLoopbackForTests: true }));
    // With the flag, still no non-loopback host and no query on loopback.
    assert.throws(() => seamAccessController({ apiKey: KEY, baseUrl: "https://evil.example", allowLoopbackForTests: true }), TypeError);
    assert.throws(() => seamAccessController({ apiKey: KEY, baseUrl: "http://127.0.0.1:9/?x", allowLoopbackForTests: true }), TypeError);
    assert.throws(() => seamAccessController({ apiKey: KEY, baseUrl: "http://u@127.0.0.1:9", allowLoopbackForTests: true }), TypeError);
  });

  it("a JSON-sourced options object cannot inherit the flag from the prototype chain", () => {
    const opts = JSON.parse('{"apiKey":"k","baseUrl":"http://127.0.0.1:9","__proto__":{"allowLoopbackForTests":true}}');
    const r = (() => { try { seamAccessController(opts); return "ACCEPTED"; } catch { return "REJECTED"; } })();
    assert.equal(r, "REJECTED");
  });

  it("device ids and vendor attempt ids never reach the URL", async () => {
    for (const id of ["//evil.example", "../../..//evil.example", "\\\\evil.example", "@evil.example", "%2F%2Fevil", "a\r\nHost: evil.example"]) {
      const s = stub(id);
      const c = seamAccessController({ apiKey: KEY, fetch: s.f, clock, confirmWithinMs: 50, pollIntervalMs: 10 });
      await c.unlock(input(id));
      for (const x of s.seen) assert.equal(x.host, "connect.getseam.com", x.url);
      assert.deepEqual(s.seen.map((x) => new URL(x.url).pathname), ["/devices/get", "/locks/unlock_door", "/action_attempts/get"]);
    }
  });

  it("a real 3xx to another host is not followed with the key (real fetch)", async () => {
    let evilHits = 0; const evilHeaders: unknown[] = [];
    const evil = createServer((req, res) => { evilHits++; evilHeaders.push(req.headers); res.end("{}"); });
    await new Promise<void>((r) => evil.listen(0, "127.0.0.1", r));
    const evilPort = (evil.address() as AddressInfo).port;
    const front = createServer((req, res) => res.writeHead(307, { location: `http://localhost:${evilPort}${req.url}` }).end());
    await new Promise<void>((r) => front.listen(0, "127.0.0.1", r));
    try {
      const c = seamAccessController({ apiKey: KEY, baseUrl: `http://127.0.0.1:${(front.address() as AddressInfo).port}`, allowLoopbackForTests: true, clock, confirmWithinMs: 0 });
      const r = await c.unlock(input("dev-1"));
      assert.deepEqual(r, { outcome: "refused", reason: "seam_unavailable" });
      assert.equal(evilHits, 0, JSON.stringify(evilHeaders));
    } finally { front.close(); evil.close(); }
  });

  it("a key the header layer rejects never surfaces in a result or error (real fetch)", async () => {
    const srv = createServer((_q, res) => res.end("{}"));
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      for (const bad of ["seam_SECRET\r\nX: y", "seam_SECRET ", "seam_SECRETÿĀ", " seam_SECRET\0"]) {
        const c = seamAccessController({ apiKey: bad, baseUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, allowLoopbackForTests: true, clock, confirmWithinMs: 0 });
        let out = "";
        try { out = JSON.stringify(await c.unlock(input("dev-1"))); } catch (e) { out = `THROW ${(e as Error).message} ${(e as Error).stack}`; }
        assert.ok(!out.includes("SECRET"), out);
      }
    } finally { srv.close(); }
  });

  it("constructor errors never echo the key", () => {
    for (const b of ["notaurl", "ftp://x", "https://u:p@x"]) {
      try { seamAccessController({ apiKey: "seam_SECRET", baseUrl: b }); assert.fail("accepted"); }
      catch (e) { assert.ok(!String((e as Error).message).includes("SECRET")); }
    }
  });
});
