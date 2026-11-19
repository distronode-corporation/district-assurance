// Hostile-pass regressions for #94 (SRV-3, receipt links by capability token, the receipt page). X1
// failed before the page looked its words up by own key; the rest held.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import { ReceiptLinks, createReferenceServer } from "../examples/reference-server/src/app.ts";
import { signReceipt, type Engine, type FactorKind, type ReceiptBody, type SignedReceipt } from "../src/index.ts";
import { FixedClock, generateTestSigner } from "../src/testing/index.ts";

const signer = generateTestSigner("page-key");
const body: ReceiptBody = {
  v: 1,
  receiptId: "rcpt_1",
  callId: "call_1",
  workspaceId: "ws_test",
  startedAt: "2026-01-01T00:00:00.000Z",
  endedAt: "2026-01-01T00:05:00.000Z",
  issuedAt: "2026-01-01T00:05:00.000Z",
  verification: { level: 2, methods: ["keypad_knowledge"] },
  records: [],
  payments: [{ paymentId: "pay_1", status: "paid", amountMinor: 100, currency: "cad", providerRef: "cs_1" }],
  consents: [{ purpose: "texts", wordingVersion: "1", wordingDigest: "b".repeat(64), answer: "yes" }],
  ledger: { seq: 3, hash: "d".repeat(64) },
};

async function serve(receipt: SignedReceipt | null, run: (base: string, links: ReceiptLinks) => Promise<void>): Promise<void> {
  const links = new ReceiptLinks();
  const engine = { receipt: async () => receipt, receiptKeys: () => [signer.publicJwk()] } as unknown as Engine;
  const server = createReferenceServer({ engine, stripeSecrets: { identity: [], payments: [] }, clock: new FixedClock(), receiptLinks: links });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, links);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe("hostile #94: the receipt page's own words", () => {
  it("X1: a plug-in factor or status named like an Object.prototype member shows its name, never a function", async () => {
    const receipt = await signReceipt(signer, {
      ...body,
      verification: { level: 2, methods: ["constructor" as FactorKind, "keypad_knowledge"] },
      payments: [{ ...body.payments[0]!, status: "constructor" }],
    });
    await serve(receipt, async (base, links) => {
      for (const lang of ["en", "fr"]) {
        const html = await (await fetch(`${base}/r/${links.issue("call_1")}?lang=${lang}`)).text();
        assert.equal(html.includes("function"), false, lang);
        assert.equal(html.includes("native code"), false, lang);
        assert.ok(html.includes("constructor"), lang);
      }
    });
  });
});

describe("hostile #94: tokens", () => {
  it("X2: every spelling but the issued one is the same 404: aliases of the last character, encodings, case, suffixes", async () => {
    const receipt = await signReceipt(signer, body);
    await serve(receipt, async (base, links) => {
      const token = links.issue("call_1");
      assert.equal((await fetch(`${base}/r/${token}`)).status, 200);
      // 43 base64url characters carry 258 bits: other last characters decode to the same 32 bytes.
      const last = "AQgw".includes(token.at(-1)!) ? "AQgw" : token.at(-1)!;
      const aliases = [...last].filter((c) => c !== token.at(-1)).map((c) => token.slice(0, -1) + c);
      const spellings = [
        ...aliases,
        `${token}/`,
        `${token}.JSON`,
        `${token}.json/`,
        `%${token.charCodeAt(0).toString(16)}${token.slice(1)}`,
        token.toUpperCase() === token ? token.toLowerCase() : token.toUpperCase(),
        `${token}%00`,
        `${token.slice(0, -1)}`,
      ];
      const notFound = await (await fetch(`${base}/r/${"A".repeat(43)}`)).text();
      for (const s of spellings) {
        const res = await fetch(`${base}/r/${s}`);
        assert.equal(res.status, 404, s);
        assert.equal(await res.text(), notFound, s);
      }
      assert.equal((await fetch(`${base}/receipts/call_1`)).status, 404, "no route by call id");
    });
  });

  it("X3: a token issued for a call without a receipt yet answers exactly as an unknown token", async () => {
    await serve(null, async (base, links) => {
      const token = links.issue("call_1");
      const [known, unknown] = await Promise.all([fetch(`${base}/r/${token}`), fetch(`${base}/r/${"B".repeat(43)}`)]);
      assert.deepEqual([known.status, await known.text()], [unknown.status, await unknown.text()]);
      assert.deepEqual([...known.headers.keys()].filter((k) => k !== "date").sort(), [...unknown.headers.keys()].filter((k) => k !== "date").sort());
    });
  });

  it("X4: the page and its JSON never leave the token in a Referer, a cache or an index, and refuse every other method", async () => {
    const receipt = await signReceipt(signer, body);
    await serve(receipt, async (base, links) => {
      const token = links.issue("call_1");
      for (const path of [`/r/${token}`, `/r/${token}.json`]) {
        const res = await fetch(`${base}${path}`);
        assert.equal(res.headers.get("cache-control"), "no-store", path);
        assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/, path);
        for (const method of ["POST", "PUT", "DELETE", "HEAD"]) assert.equal((await fetch(`${base}${path}`, { method })).status, 405, `${method} ${path}`);
      }
      const page = await fetch(`${base}/r/${token}`);
      assert.equal(page.headers.get("referrer-policy"), "no-referrer");
      assert.equal(page.headers.get("x-robots-tag"), "noindex, nofollow");
    });
  });

  it("X5: a hostile language choice never reaches the page unescaped and falls back to English", async () => {
    const receipt = await signReceipt(signer, body);
    await serve(receipt, async (base, links) => {
      const token = links.issue("call_1");
      for (const [query, header, expected] of [
        ["?lang=%3Cscript%3E", "fr", "fr"],
        ["?lang=FR", "", "en"],
        ["?lang=fr&lang=en", "", "fr"],
        ["", "fr-CA,en;q=0.5", "fr"],
        ["", "en-CA,fr;q=0.9", "en"],
        ["", "\"><script>", "en"],
      ] as const) {
        const html = await (await fetch(`${base}/r/${token}${query}`, { headers: header === "" ? {} : { "accept-language": header } })).text();
        assert.ok(html.includes(`<html lang="${expected}">`), `${query} ${header}`);
        assert.equal(html.includes("<script>"), false);
      }
    });
  });
});
