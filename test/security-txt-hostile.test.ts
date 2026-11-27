// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Hostile-pass regressions for #103 (SRV-9): security.txt and its guard against this project's own addresses.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import { createReferenceServer, securityTxt } from "../examples/reference-server/src/app.ts";
import { FixedClock, createTestEngine } from "../src/testing/index.ts";

const now = new Date("2026-01-01T00:00:00.000Z");
const expires = new Date("2026-06-01T00:00:00.000Z");
const make = (contact: string) => () => securityTxt({ contact: [contact], expires }, now, () => {});

describe("hostile #103: this project's addresses", () => {
  for (const address of [
    "mailto:opensource+security@distronode.com",
    "mailto:OpenSource+x@Distronode.COM",
    "mailto:%6Fpensource@distronode.com",
    "https://github.com/distronode-corporation/district-assurance.git",
    "https://github.com//distronode-corporation/district-assurance/security",
    "https://github.com/distronode-corporation//district-assurance",
    "HTTPS://GITHUB.COM/distronode-corporation/district-assurance",
  ]) {
    it(`refuses ${address}`, () => assert.throws(make(address), /this project's address/));
  }

  it("still takes look-alikes that are someone else's", () => {
    for (const address of ["mailto:opensource@distronode.com.example.org", "https://github.com/distronode-corporation/district-assurance-fork", "mailto:security@example.org"]) {
      assert.doesNotThrow(make(address), address);
    }
  });
});

describe("hostile #103: the file once the server runs", () => {
  it("is fixed at creation: changing the settings' Date afterwards changes neither the file, the expiry nor the warnings", async () => {
    const clock = new FixedClock("2026-01-01T00:00:00.000Z");
    const when = new Date("2026-06-01T00:00:00.000Z");
    const warnings: string[] = [];
    const t = createTestEngine();
    const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock, securityTxt: { contact: ["mailto:security@example.org"], expires: when }, warn: (m) => warnings.push(m) });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/security.txt`;
    try {
      const first = await (await fetch(url)).text();
      when.setTime(Date.parse("2030-01-01T00:00:00.000Z"));
      assert.equal(await (await fetch(url)).text(), first);
      clock.advance(Date.parse("2026-05-15T00:00:00.000Z") - clock.now().getTime());
      await fetch(url);
      clock.advance(30 * 86_400_000);
      assert.equal((await fetch(url)).status, 404, "not served once expired");
      assert.equal(warnings.some((w) => w.includes("2030")), false, warnings.join(" | "));
      assert.equal((await fetch(url, { method: "POST" })).status, 404);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
