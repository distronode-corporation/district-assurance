// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Compile-time proof that a real stripe-node client on endive is a `StripeClientLike` as it is: the
// assignment below is checked by `npm run typecheck`, which fails if the SDK's shapes drift from the
// package's. stripe is a development dependency only; the package never imports it (ADR-3).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import Stripe from "stripe";

import { STRIPE_API_VERSION, type StripeClientLike } from "../src/stripe/index.ts";

describe("StripeClientLike", () => {
  it("is satisfied by a stripe-node Stripe instance on endive, unchanged", () => {
    const sdk = new Stripe(["sk", "test", "TYPECHECKONLY0123456789"].join("_"), { apiVersion: STRIPE_API_VERSION });
    const client: StripeClientLike = sdk;
    assert.equal(typeof client.checkout.sessions.create, "function");
    assert.equal(typeof client.v2.core.accounts.retrieve, "function");
    assert.equal(typeof client.v2.core.accountLinks.create, "function");
  });
});
