// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The host allowlist, from the iMac's //host re-check: every case held, kept as regressions.
import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import type { SignedAccessGrant } from "../src/gate/access.ts";
import { vendorAccessController } from "../src/gate/vendors.ts";
import { FixedClock } from "../src/testing/index.ts";

const KEY = "vendorKEY0000";
const clock = new FixedClock();
const LOCK = "48213";
const DOOR = "8f6a1b2c-3d4e-4f50-8a6b-7c8d9e0f1a2b";
const grant = (target: string): SignedAccessGrant => ({
  body: { v: 1, kind: "access", grantId: "acc_1", workspaceId: "w", audience: "lobby", target, action: "unlock", scope: "entry.open", level: 2, issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-01T00:01:00.000Z" },
  alg: "ES256", kid: "k1", signature: "sig",
});
const input = (target: string, grantTarget = target) => ({ grant: grant(grantTarget), target, idempotencyKey: "k" });

type Seen = { url: string; host: string; headers: Record<string, string>; redirect: unknown };
function stub(token = "tok") {
  const seen: Seen[] = [];
  const f = (async (u: URL | string, init: RequestInit) => {
    const url = new URL(String(u));
    seen.push({ url: url.href, host: url.host, headers: init.headers as Record<string, string>, redirect: init.redirect });
    if (url.pathname.endsWith("/token")) return Response.json({ token });
    return Response.json({ ok: true });
  }) as typeof fetch;
  return { seen, f };
}

const BASES = [
  "//evil.example", "\\\\evil.example", "/\\evil.example", "https:evil.example", "https:\\\\evil.example",
  "https://api.kisi.io@evil.example", "https://evil.example#@api.kisi.io", "https://evil.example?@api.kisi.io",
  "https://api.kisi.io//evil.example", "https://api.kisi.io/\\evil.example", "https://api.kisi.io/%2F%2Fevil.example",
  "https://api.kisi.io/../..//evil.example", "https://api.kisi.io/%2e%2e//evil.example", "https://api.ki\tsi.io\n//evil.example",
  " https://api.kisi.io", "https://api.kisi.io。evil.example", "https://api.kisi.io.evil.example", "https://2130706433",
  "http://2130706433//evil.example", "http://[::1]//evil.example", "http://localhost.evil.example", "http://127.0.0.1//evil.example/a//b",
];

describe("vendorAccessController: each key goes only to its vendor (//host re-check)", () => {
  const ALLOWED = { kisi: ["api.kisi.io"], verkada: ["api.verkada.com", "api.eu.verkada.com", "api.au.verkada.com"] } as const;
  const EXTRA = [
    "https://api.kisi.io.", "https://API.KISI.IO", "https://api.kisi.io:443", "https://api.kisi.io:8443", "https://u@api.kisi.io", "https://:p@api.kisi.io",
    "https://api.kisi.io?x", "https://api.kisi.io#x", "https://api.kisi.io/?", "https://аpi.kisi.io", "https://xn--pi-7kc.kisi.io", "http://api.kisi.io",
    "https://api.verkada.com.", "https://API.EU.VERKADA.COM", "https://api.au.verkada.com:443", "https://api.us.verkada.com", "https://eu.verkada.com",
    "https://api.verkada.com:444", "https://user:pw@api.verkada.com", "https://api.verkada.com?x=1", "https://api.verkada.com#f", "https://api.vеrkada.com",
    "https://api．verkada．com", "https://api.verkada.com.evil.example", "https://evil.api.verkada.com", "https://127.0.0.1", "http://localhost",
  ];
  for (const vendor of ["kisi", "verkada"] as const) {
    it(`${vendor}: only its own hosts on https:443 are accepted (previous bypasses plus new)`, async () => {
      const report: string[] = [];
      for (const b of [...BASES, ...EXTRA]) {
        const s = stub();
        try {
          const c = vendorAccessController({ vendor, apiKey: KEY, baseUrl: b, fetch: s.f, clock });
          await c.unlock(input(vendor === "kisi" ? LOCK : DOOR));
        } catch {
          continue;
        }
        const hosts = [...new Set(s.seen.map((x) => new URL(x.url).host))];
        report.push(`ACCEPT ${JSON.stringify(b)} -> ${hosts.join(",")}`);
        for (const x of s.seen) {
          assert.ok((ALLOWED[vendor] as readonly string[]).includes(new URL(x.url).host), `${b} sent ${vendor} key to ${x.url}`);
          assert.equal(new URL(x.url).protocol, "https:");
        }
      }
    });
  }

  it("cross-vendor: a Kisi key never goes to Verkada's hosts and the reverse", () => {
    for (const b of ALLOWED.verkada) assert.throws(() => vendorAccessController({ vendor: "kisi", apiKey: KEY, baseUrl: `https://${b}`, clock }), TypeError);
    for (const b of ALLOWED.kisi) assert.throws(() => vendorAccessController({ vendor: "verkada", apiKey: KEY, baseUrl: `https://${b}`, clock }), TypeError);
  });

  it("vendor names from the prototype chain are refused", () => {
    for (const v of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      assert.throws(() => vendorAccessController({ vendor: v as "kisi", apiKey: KEY, clock }), TypeError);
    }
  });

  it("allowLoopbackForTests: only boolean true", () => {
    for (const vendor of ["kisi", "verkada"] as const) {
      for (const v of ["true", 1, {}, [], new Boolean(true)] as unknown[]) {
        for (const b of ["http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9", "https://127.0.0.1"]) {
          assert.throws(() => vendorAccessController({ vendor, apiKey: KEY, baseUrl: b, allowLoopbackForTests: v as boolean, clock }), TypeError, `${vendor} ${b} ${typeof v}`);
        }
      }
      assert.doesNotThrow(() => vendorAccessController({ vendor, apiKey: KEY, baseUrl: "http://127.0.0.1:9", allowLoopbackForTests: true, clock }));
      assert.throws(() => vendorAccessController({ vendor, apiKey: KEY, baseUrl: "https://evil.example", allowLoopbackForTests: true, clock }), TypeError);
      assert.throws(() => vendorAccessController({ vendor, apiKey: KEY, baseUrl: "http://127.0.0.1:9/?q", allowLoopbackForTests: true, clock }), TypeError);
    }
  });

  it("kisi: lock ids that try to escape the path are refused before any send", async () => {
    for (const id of ["//evil.example", "1/../../evil", "1%2F..", "1\n", "1?x=//evil", "١٢٣", "1".repeat(21), "48213\n"]) {
      const s = stub();
      const r = await vendorAccessController({ vendor: "kisi", apiKey: KEY, fetch: s.f, clock }).unlock(input(id));
      assert.equal(s.seen.length, 0, `${JSON.stringify(id)} sent ${s.seen.map((x) => x.url)}`);
      assert.equal(r.outcome, "refused");
    }
  });

  it("verkada: a hostile token from the vendor stays in a header and on the base host", async () => {
    for (const t of ["//evil.example", "a\r\nHost: evil.example", "https://evil.example/"]) {
      const s = stub(t);
      const r = await vendorAccessController({ vendor: "verkada", apiKey: KEY, fetch: s.f, clock }).unlock(input(DOOR));
      for (const x of s.seen) assert.equal(x.host, "api.verkada.com", x.url);
      if (t.includes("\r")) assert.deepEqual(r, { outcome: "refused", reason: "token_unavailable" });
    }
  });

  for (const vendor of ["kisi", "verkada"] as const) {
    it(`${vendor}: a real 3xx to another host is not followed with the key (real fetch)`, async () => {
      let evilHits = 0;
      const evil = createServer((_q, res) => { evilHits++; res.end('{"token":"t"}'); });
      await new Promise<void>((r) => evil.listen(0, "127.0.0.1", r));
      const ep = (evil.address() as AddressInfo).port;
      const front = createServer((req, res) => res.writeHead(308, { location: `http://localhost:${ep}${req.url}` }).end());
      await new Promise<void>((r) => front.listen(0, "127.0.0.1", r));
      try {
        const c = vendorAccessController({ vendor, apiKey: KEY, baseUrl: `http://127.0.0.1:${(front.address() as AddressInfo).port}`, allowLoopbackForTests: true, clock });
        let out: string;
        try { out = JSON.stringify(await c.unlock(input(vendor === "kisi" ? LOCK : DOOR))); } catch (e) { out = `THROW ${(e as Error).message}`; }
        assert.equal(evilHits, 0);
        assert.ok(!out.includes(KEY), out);
      } finally { front.close(); evil.close(); }
    });
  }

  it("errors and results never echo the key (5xx, network error, real fetch)", async () => {
    const srv = createServer((_q, res) => res.writeHead(500).end(`key ${KEY}`));
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    try {
      for (const baseUrl of [`http://127.0.0.1:${port}`, "http://127.0.0.1:1"]) {
        let out: string;
        try { out = JSON.stringify(await vendorAccessController({ vendor: "kisi", apiKey: KEY, baseUrl, allowLoopbackForTests: true, clock }).unlock(input(LOCK))); }
        catch (e) { out = `THROW ${(e as Error).message} ${JSON.stringify((e as Error).cause ?? null)} ${(e as Error).stack}`; }
        assert.ok(!out.includes(KEY), out);
      }
    } finally { srv.close(); }
  });
});
