// VER-4 carrier signals under attack (a hostile pass on #85): vendor answers that must never trust
// a texted code, and hostile answers and input. A stubbed fetch replays them; never the network.
import { strict as assert } from "node:assert";
import { afterEach, describe, it } from "node:test";

import { TelnyxNumberLookupSignals, TwilioLookupSignals, type CarrierLookupFailure } from "../examples/reference-server/src/carrier-adapters.ts";
import { defaultVerificationPolicy, textCodeTrusted, type CarrierSignalReport } from "../src/index.ts";
import { FixedClock } from "../src/testing/index.ts";

const NOW = "2026-01-01T00:00:00.000Z";
const realFetch = globalThis.fetch;
const seen: Array<{ url: string; init: RequestInit | undefined }> = [];
afterEach(() => {
  globalThis.fetch = realFetch;
  seen.length = 0;
});

/** Every fetch answers `body` (JSON unless a string) with `status`. */
function answer(body: unknown, status = 200): void {
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url, init });
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

const failures: CarrierLookupFailure[] = [];
const options = () => {
  failures.length = 0;
  return { countries: ["US"], clock: new FixedClock(NOW), onUnavailable: (f: CarrierLookupFailure) => void failures.push(f) };
};
const twilio = () => new TwilioLookupSignals({ username: "SK_test_not_a_secret", password: "not_a_secret" }, options());
const telnyx = () => new TelnyxNumberLookupSignals("KEY_test_not_a_secret", options());
const swapBody = (last: unknown) => ({ valid: true, country_code: "US", sim_swap: { last_sim_swap: last, error_code: null } });
const trusted = (report: CarrierSignalReport) => textCodeTrusted(defaultVerificationPolicy(), report);

describe("attack: SIM swap answers that should never trust a texted code", () => {
  it("a recent change Twilio flags in its period is never outweighed by an old date beside it", async () => {
    answer(swapBody({ last_sim_swap_date: "2020-01-01T00:00:00Z", swapped_period: "PT24H", swapped_in_period: true }));
    const report = await twilio().check({ phoneNumber: "+15555550100" });
    assert.equal(trusted(report), false, JSON.stringify(report));
  });

  it("a date that is not an ISO 8601 time (which Date.parse still reads as a year long ago) is not an answer", async () => {
    for (const date of ["1", "0", "Jan 1", "2001", "12/31/1999"]) {
      answer(swapBody({ last_sim_swap_date: date, swapped_in_period: true, swapped_period: "PT1H" }));
      const report = await twilio().check({ phoneNumber: "+15555550100" });
      assert.equal(trusted(report), false, `${date}: ${JSON.stringify(report)}`);
    }
  });

  it("a change dated in the future (clock skew, or a bad answer) counts as just now", async () => {
    answer(swapBody({ last_sim_swap_date: "2030-01-01T00:00:00Z" }));
    const report = await twilio().check({ phoneNumber: "+15555550100" });
    assert.equal(report.lastSimSwapHoursAgo, 0);
    assert.equal(trusted(report), false);
  });

  it("a period shorter than the policy window, with no change in it, is not enough", async () => {
    answer(swapBody({ swapped_in_period: false, swapped_period: "PT24H" }));
    assert.equal(trusted(await twilio().check({ phoneNumber: "+15555550100" })), false);
    answer(swapBody({ swapped_in_period: false, swapped_period: "P30D" }));
    assert.equal(trusted(await twilio().check({ phoneNumber: "+15555550100" })), true, "a long enough period is");
  });

  it("Telnyx never trusts a texted code, whatever its port answer, a garbage date included", async () => {
    for (const ported of [{ ported_status: "N" }, { ported_status: "Y", ported_date: "1" }, { ported_status: "Y", ported_date: "2001-01-01" }]) {
      answer({ data: { country_code: "US", portability: ported, carrier: null } });
      assert.equal(trusted(await telnyx().check({ phoneNumber: "+15555550100" })), false, JSON.stringify(ported));
    }
  });
});

describe("attack: hostile answers and input", () => {
  it("prototype keys, wrong types and a huge answer give an unchecked report, never a throw", async () => {
    for (const body of [
      '{"__proto__": {"valid": true, "country_code": "US"}}',
      JSON.stringify({ valid: true, country_code: "US", sim_swap: { last_sim_swap: { swapped_in_period: "false", swapped_period: "P30D" }, error_code: null } }),
      JSON.stringify({ valid: true, country_code: ["US"], sim_swap: null }),
      JSON.stringify({ valid: true, country_code: "US", sim_swap: { last_sim_swap: { swapped_in_period: false, swapped_period: "P".padEnd(100_000, "9") + "D" }, error_code: null } }),
      "null",
      "[]",
    ]) {
      answer(body);
      const report = await twilio().check({ phoneNumber: "+15555550100" });
      assert.equal(report.checked === false || trusted(report) === false, true, body.slice(0, 60));
    }
  });

  it("a number that is not a string, or not E.164, is never sent", async () => {
    answer(swapBody({ swapped_in_period: false, swapped_period: "P30D" }));
    for (const phoneNumber of [Symbol("x"), 15555550100, "+1 555 555 0100", "+15555550100\n", "+1555555⁦"]) {
      const report = await twilio().check({ phoneNumber: phoneNumber as never });
      assert.equal(report.checked, false);
    }
    assert.equal(seen.length, 0);
  });

  it("never follows a redirect with the credentials, and the listener never hears the number or a credential", async () => {
    answer({ code: 20003, message: "auth +15555550100 SK_test_not_a_secret" }, 401);
    const report = await twilio().check({ phoneNumber: "+15555550100" });
    assert.equal(report.checked, false);
    assert.equal(seen[0]!.init!.redirect, "error");
    assert.equal(JSON.stringify(failures).includes("5555550100") || JSON.stringify(failures).includes("SK_test"), false, JSON.stringify(failures));
  });

  it("refuses a base URL that only looks like a loopback host (0x7f000001 and 2130706433 are 127.0.0.1, so allowed)", () => {
    for (const baseUrl of ["http://127.0.0.1.example.test", "http://localhost.example.test", "http://[::ffff:127.0.0.1]"]) {
      assert.throws(() => new TwilioLookupSignals({ username: "u", password: "p" }, { ...options(), baseUrl }), /https/, baseUrl);
    }
  });
});
