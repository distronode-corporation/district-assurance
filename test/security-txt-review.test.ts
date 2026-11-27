// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// security.txt: a tel: contact is a global number under RFC 3966, and a warn sink that throws or
// rejects never turns the route into a 500 or repeats its warning on every request.
import { strict as assert } from "node:assert";
import type { AddressInfo } from "node:net";
import { describe, it, type TestContext } from "node:test";

import { createReferenceServer, securityTxt } from "../examples/reference-server/src/app.ts";
import { FixedClock, createTestEngine } from "../src/testing/index.ts";

const DAY = 24 * 60 * 60 * 1000;
const now = new Date("2026-01-01T00:00:00.000Z");
const expires = new Date("2026-06-01T00:00:00.000Z");
const make = (contact: string) => () => securityTxt({ contact: [contact], expires }, now, () => {});

describe("security.txt tel: contacts (RFC 3966 global numbers)", () => {
  for (const contact of ["tel:", "tel:+", "tel:+-", "tel:+()-.", "tel:555-0100", "tel:+1 555 0100", "tel:+1-555-0100;ext=1", "tel:+1/555", "tel:+1-555-0100x", "tel:%2B15550100"]) {
    it(`refuses ${JSON.stringify(contact)}`, () => assert.throws(make(contact), /contact must be a mailto: or tel: or https: URI/));
  }
  for (const contact of ["tel:+1-555-0100", "tel:+15550100", "tel:+1.(555).0100", "TEL:+1-555-0100", "tel:+4"]) {
    it(`takes ${contact}`, () => assert.doesNotThrow(make(contact)));
  }
});

describe("security.txt warn sink failures", () => {
  async function start(ctx: TestContext, warn: (m: string) => void) {
    const clock = new FixedClock();
    // 60 days out: no warning at start, so the first one is the running server's.
    const server = createReferenceServer({
      engine: createTestEngine().engine,
      stripeSecrets: { identity: [], payments: [] },
      clock,
      warn,
      securityTxt: { contact: ["mailto:security@example.test"], expires: new Date(clock.now().getTime() + 60 * DAY) },
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    ctx.after(
      () =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    );
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/security.txt`;
    return { clock, get: async () => (await fetch(url)).status };
  }

  for (const [label, fails] of [
    ["throws", () => {
      throw new Error("sink down");
    }],
    ["rejects", () => Promise.reject(new Error("sink down"))],
  ] as const) {
    it(`serves 200 before expiry and 404 after, warning once each, when the sink ${label}`, async (ctx) => {
      const calls: string[] = [];
      const s = await start(ctx, (m) => {
        calls.push(m);
        return fails() as never;
      });
      s.clock.advance(30 * DAY);
      assert.deepEqual([await s.get(), await s.get()], [200, 200]);
      assert.equal(calls.length, 1, "the last-30-days warning is given once");
      s.clock.advance(30 * DAY);
      assert.deepEqual([await s.get(), await s.get()], [404, 404]);
      assert.equal(calls.length, 2, "the expiry warning is given once");
      assert.match(calls[1]!, /expired/);
    });
  }

  it("starts when the sink throws or rejects on the start-up warning", () => {
    const clock = new FixedClock();
    for (const warn of [
      () => {
        throw new Error("sink down");
      },
      () => Promise.reject(new Error("sink down")) as never,
    ]) {
      assert.ok(
        createReferenceServer({
          engine: createTestEngine().engine,
          stripeSecrets: { identity: [], payments: [] },
          clock,
          warn,
          securityTxt: { contact: ["mailto:security@example.test"], expires: new Date(clock.now().getTime() + 7 * DAY) },
        }),
      );
    }
  });
});
