// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The SDK path and `fetchStripeClient` send Stripe the same bytes: the same Checkout Session create
// body (form-encoded), the same v2 Account create body (JSON), the same v2 retrieve query, and the
// same `Stripe-Version`, `Stripe-Account` and `Idempotency-Key` headers. Both talk to one local
// fake; nothing leaves the machine.
import { strict as assert } from "node:assert";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import Stripe from "stripe";

import {
  CONNECT_ACCOUNT_INCLUDE,
  STRIPE_API_VERSION,
  connectAccountCreateParams,
  fetchStripeClient,
  stripeFormEncode,
  type CheckoutSessionCreateParams,
  type StripeClientLike,
} from "../src/stripe/index.ts";

const KEY = ["sk", "test", "BYTESBYTESBYTES0123456789"].join("_");
interface Seen {
  method: string;
  url: string;
  body: string;
  headers: Record<string, string | undefined>;
}

let server: Server;
let base: string;
const seen: Seen[] = [];

before(async () => {
  server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const h = (name: string) => {
        const v = req.headers[name];
        return Array.isArray(v) ? v.join(",") : v;
      };
      seen.push({
        method: req.method ?? "",
        url: req.url ?? "",
        body: Buffer.concat(chunks).toString("utf8"),
        headers: { "stripe-version": h("stripe-version"), "stripe-account": h("stripe-account"), "idempotency-key": h("idempotency-key"), "content-type": h("content-type") },
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "cs_test_bytes", object: "checkout.session", livemode: false }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

const PARAMS: CheckoutSessionCreateParams = {
  mode: "payment",
  line_items: [{ quantity: 1, price_data: { currency: "cad", unit_amount: 100, product_data: { name: "Deposit (1/2) for Café & Co. *now* (it's 'paid')!" } } }],
  allowed_payment_method_types: ["card", "link"],
  expires_at: 1_800_000_000,
  client_reference_id: "pay 1/é",
  metadata: { payment_id: "pay 1/é", call_id: "call+1=2&3" },
  success_url: "https://example.com/thanks?x=1&y=[2]",
};

function sdkClient(): StripeClientLike {
  const port = Number(new URL(base).port);
  return new Stripe(KEY, { apiVersion: STRIPE_API_VERSION, host: "127.0.0.1", port, protocol: "http", maxNetworkRetries: 0, telemetry: false });
}

async function both(run: (client: StripeClientLike) => Promise<unknown>): Promise<[Seen, Seen]> {
  seen.length = 0;
  await run(sdkClient());
  await run(fetchStripeClient(KEY, { mode: "test", apiBase: base }));
  assert.equal(seen.length, 2);
  return [seen[0]!, seen[1]!];
}

describe("fetchStripeClient and the SDK send the same bytes", () => {
  it("Checkout Session create: the form body and the headers", async () => {
    const [sdk, ours] = await both((c) => c.checkout.sessions.create(PARAMS, { stripeAccount: "acct_1Bytes", idempotencyKey: "call_1:pay_1" }));
    assert.equal(ours.method, sdk.method);
    assert.equal(ours.url, sdk.url);
    assert.equal(ours.body, sdk.body, "byte-identical form body");
    assert.equal(ours.headers["stripe-version"], STRIPE_API_VERSION);
    for (const name of ["stripe-version", "stripe-account", "idempotency-key", "content-type"]) {
      assert.equal(ours.headers[name], sdk.headers[name], name);
    }
    assert.equal(stripeFormEncode({ ...PARAMS }), sdk.body);
  });

  it("v2 Account create: the JSON body", async () => {
    const params = connectAccountCreateParams({ country: "CA", metadata: { ref: "a".repeat(64) } });
    const [sdk, ours] = await both((c) => c.v2.core.accounts.create(params, { idempotencyKey: "acct-key" }));
    assert.equal(ours.url, sdk.url);
    assert.deepEqual(JSON.parse(ours.body), JSON.parse(sdk.body));
    assert.equal(ours.body, sdk.body, "byte-identical JSON body");
    assert.equal(ours.headers["idempotency-key"], sdk.headers["idempotency-key"]);
  });

  it("v2 Account retrieve and Checkout retrieve: the query and path", async () => {
    let [sdk, ours] = await both((c) => c.v2.core.accounts.retrieve("acct_1Bytes", { include: [...CONNECT_ACCOUNT_INCLUDE] }));
    assert.equal(ours.method, "GET");
    assert.equal(ours.url, sdk.url);
    [sdk, ours] = await both((c) => c.checkout.sessions.retrieve("cs_test_bytes", {}, { stripeAccount: "acct_1Bytes" }));
    assert.equal(ours.url, sdk.url);
    assert.equal(ours.headers["stripe-account"], sdk.headers["stripe-account"]);
    [sdk, ours] = await both((c) => c.checkout.sessions.expire("cs_test_bytes", {}, { idempotencyKey: "close" }));
    assert.equal(ours.url, sdk.url);
    assert.equal(ours.body, sdk.body);
  });
});
