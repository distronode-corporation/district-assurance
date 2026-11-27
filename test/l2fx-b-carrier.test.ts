// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Twilio Lookup adapter: the deadline covers the identity on file, and an identity score outside
// Twilio's 0 to 100 is not an answer. A stubbed fetch replays the vendor; never the network.
import { strict as assert } from "node:assert";
import { afterEach, describe, it } from "node:test";

import { TwilioLookupSignals, uncheckedReport, type CarrierLookupFailure, type TwilioLookupOptions } from "../examples/reference-server/src/carrier-adapters.ts";
import { FixedClock } from "../src/testing/index.ts";

const realFetch = globalThis.fetch;
let fetches = 0;
afterEach(() => {
  globalThis.fetch = realFetch;
  fetches = 0;
});

function answer(body: unknown): void {
  globalThis.fetch = (async () => {
    fetches += 1;
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

const failures: CarrierLookupFailure[] = [];
const twilio = (extra: Partial<TwilioLookupOptions>) => {
  failures.length = 0;
  return new TwilioLookupSignals(
    { username: "SK_test_not_a_secret", password: "not_a_secret" },
    { countries: ["US"], clock: new FixedClock("2026-01-01T00:00:00.000Z"), onUnavailable: (f) => void failures.push(f), ...extra },
  );
};
const identity = async () => ({ firstName: "Ada" });
const scored = (summaryScore: unknown) => ({
  valid: true,
  country_code: "US",
  sim_swap: { last_sim_swap: { swapped_in_period: false, swapped_period: "P30D" }, error_code: null },
  identity_match: { summary_score: summaryScore, error_code: null },
});

describe("Twilio Lookup: the deadline covers the identity on file (T16)", () => {
  it("an identity lookup that never settles times out, and the vendor is never asked", async () => {
    answer(scored(100));
    const report = await twilio({ timeoutMs: 30, identityFor: () => new Promise(() => undefined) }).check({ phoneNumber: "+15555550100" });
    assert.deepEqual(report, uncheckedReport());
    assert.deepEqual(failures, [{ vendor: "twilio", reason: "timeout" }]);
    assert.equal(fetches, 0);
  });

  it("an identity lookup that answers in time still gets the vendor's answer", async () => {
    answer(scored(100));
    const report = await twilio({ timeoutMs: 1000, identityFor: identity }).check({ phoneNumber: "+15555550100" });
    assert.equal(report.identityMatch, "match");
    assert.equal(fetches, 1);
  });

  it("an identity lookup that rejects before the deadline is identity_on_file", async () => {
    answer(scored(100));
    await twilio({ identityFor: () => Promise.reject(new Error("db down")) }).check({ phoneNumber: "+15555550100" });
    assert.deepEqual(failures, [{ vendor: "twilio", reason: "identity_on_file" }]);
    assert.equal(fetches, 0);
  });
});

describe("Twilio Lookup: an identity score outside 0 to 100 is bad_response", () => {
  it("refuses 101, -1 and other out-of-range scores, and keeps 0 and 100", async () => {
    for (const score of [101, -1, 100.5, -0.5, 1e9]) {
      answer(scored(score));
      assert.deepEqual(await twilio({ identityFor: identity }).check({ phoneNumber: "+15555550100" }), uncheckedReport(), String(score));
      assert.deepEqual(failures, [{ vendor: "twilio", reason: "bad_response" }], String(score));
    }
    answer(scored(0));
    assert.equal((await twilio({ identityFor: identity }).check({ phoneNumber: "+15555550100" })).identityMatch, "no_match");
    answer(scored(100));
    assert.equal((await twilio({ identityFor: identity }).check({ phoneNumber: "+15555550100" })).identityMatch, "match");
  });
});
