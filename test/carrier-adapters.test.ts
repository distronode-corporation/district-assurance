// The carrier signal adapters (VER-4) against a local fake HTTP server that replays fixture
// responses shaped after Twilio Lookup v2 and Telnyx Number Lookup. Never the network.
import { strict as assert } from "node:assert";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";

import {
  TelnyxNumberLookupSignals,
  TwilioLookupSignals,
  durationHours,
  telnyxLookupFromEnv,
  twilioLookupFromEnv,
  uncheckedReport,
  type CarrierLookupFailure,
  type TwilioLookupOptions,
} from "../examples/reference-server/src/carrier-adapters.ts";
import { FixedClock } from "../src/testing/index.ts";
import { ACCOUNT, DOB, PHONE_ON_FILE, setup } from "./helpers.ts";

// Test credentials, not secrets.
const TWILIO = { username: "SK_test_not_a_secret", password: "twilio_test_not_a_secret" };
const TELNYX_KEY = "KEY_test_not_a_secret";

/** The fixed clock reads 2026-01-01T00:00:00Z. */
const NOW = "2026-01-01T00:00:00.000Z";

interface Reply {
  status?: number;
  /** A string is sent as is; anything else as JSON. */
  body: unknown;
  delayMs?: number;
}

const twilioBody = (fields: Record<string, unknown>) => ({
  calling_country_code: "1",
  country_code: "US",
  phone_number: "+15555550100",
  national_format: "(555) 555-0100",
  valid: true,
  validation_errors: [],
  caller_name: null,
  sim_swap: null,
  call_forwarding: null,
  line_type_intelligence: null,
  identity_match: null,
  url: "https://lookups.twilio.com/v2/PhoneNumbers/+15555550100",
  ...fields,
});

const simSwap = (last: Record<string, unknown> | null, errorCode: number | null = null) => ({
  last_sim_swap: last,
  carrier_name: "Example Mobile",
  mobile_country_code: "310",
  mobile_network_code: "260",
  error_code: errorCode,
});

const identityMatch = (summaryScore: number | null, errorCode: number | null = null) => ({
  first_name_match: "exact_match",
  last_name_match: "high_partial_match",
  address_lines_match: "no_match",
  city_match: "no_match",
  state_match: "high_partial_match",
  postal_code_match: "no_data_available",
  address_country_match: "exact_match",
  national_id_match: "no_data_available",
  date_of_birth_match: "exact_match",
  summary_score: summaryScore,
  error_code: errorCode,
  error_message: errorCode === null ? null : "not available",
});

const telnyxBody = (data: Record<string, unknown>) => ({
  data: {
    record_type: "number_lookup",
    country_code: "US",
    national_format: "(555) 555-0100",
    phone_number: "+15555550100",
    fraud: null,
    caller_name: null,
    carrier: { mobile_country_code: "310", mobile_network_code: "260", name: "Example Mobile", type: "mobile", error_code: null, normalized_carrier: "Example" },
    portability: { lrn: "5555550000", ported_status: "N", ported_date: "", ocn: "0000", line_type: "wireless", spid: "0000", spid_carrier_name: "Example Mobile", spid_carrier_type: "wireless", altspid: "", altspid_carrier_name: "", altspid_carrier_type: "", city: "Example", state: "Example" },
    ...data,
  },
});

const portability = (status: string, date: string) => ({ ...telnyxBody({}).data.portability, ported_status: status, ported_date: date });

describe("carrier adapters", () => {
  let server: Server;
  let base = "";
  const replies = new Map<string, Reply>();
  const requests: Array<{ path: string; query: URLSearchParams; authorization: string | undefined }> = [];

  before(async () => {
    server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://fake.example.test");
      const number = decodeURIComponent(url.pathname.split("/").pop() ?? "");
      requests.push({ path: url.pathname, query: url.searchParams, authorization: req.headers.authorization });
      const reply = replies.get(number) ?? { status: 404, body: { code: 20404, message: "not found", status: 404 } };
      const send = () => {
        if (res.destroyed) return;
        res.writeHead(reply.status ?? 200, { "content-type": "application/json" });
        res.end(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body));
      };
      if (reply.delayMs === undefined) send();
      else setTimeout(send, reply.delayMs).unref();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  beforeEach(() => {
    replies.clear();
    requests.length = 0;
  });

  const failures: CarrierLookupFailure[] = [];
  const common = () => {
    failures.length = 0;
    return { countries: ["US"], baseUrl: base, clock: new FixedClock(NOW), onUnavailable: (f: CarrierLookupFailure) => void failures.push(f) };
  };
  const twilio = (options: Partial<TwilioLookupOptions> = {}) => new TwilioLookupSignals(TWILIO, { ...common(), ...options });
  const telnyx = (options: Partial<TwilioLookupOptions> = {}) => new TelnyxNumberLookupSignals(TELNYX_KEY, { ...common(), ...options });
  const identity = async () => ({ firstName: "Test", lastName: "Caller", postalCode: "", dateOfBirth: "19850214" });

  describe("Twilio Lookup", () => {
    it("maps SIM Swap to hours since the last change, with basic auth and only sim_swap asked", async () => {
      replies.set("+15555550101", {
        body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-12-31T18:30:00Z", swapped_period: "PT5H30M0S", swapped_in_period: true }) }),
      });
      assert.deepEqual(await twilio().check({ phoneNumber: "+15555550101" }), {
        checked: true,
        lastSimSwapHoursAgo: 5,
        lastPortHoursAgo: null,
        identityMatch: "unavailable",
      });
      assert.equal(requests.length, 1);
      assert.equal(requests[0]!.path, "/v2/PhoneNumbers/%2B15555550101");
      assert.equal(requests[0]!.query.get("Fields"), "sim_swap");
      assert.equal(requests[0]!.query.get("FirstName"), null);
      assert.equal(requests[0]!.authorization, `Basic ${Buffer.from(`${TWILIO.username}:${TWILIO.password}`).toString("base64")}`);
      assert.deepEqual(failures, []);
    });

    it("asks Identity Match with the identity on file and maps the summary score", async () => {
      const swap = simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z", swapped_period: "PT2208H", swapped_in_period: false });
      replies.set("+15555550102", { body: twilioBody({ sim_swap: swap, identity_match: identityMatch(90) }) });
      replies.set("+15555550103", { body: twilioBody({ sim_swap: swap, identity_match: identityMatch(40) }) });
      const adapter = twilio({ identityFor: identity });
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550102" }), {
        checked: true,
        lastSimSwapHoursAgo: 2208,
        lastPortHoursAgo: null,
        identityMatch: "match",
      });
      assert.equal((await adapter.check({ phoneNumber: "+15555550103" })).identityMatch, "no_match");
      const q = requests[0]!.query;
      assert.deepEqual(
        [q.get("Fields"), q.get("FirstName"), q.get("LastName"), q.get("DateOfBirth"), q.has("PostalCode"), q.has("City")],
        ["sim_swap,identity_match", "Test", "Caller", "19850214", false, false],
        "empty and missing values are not sent",
      );
      assert.equal((await twilio({ identityFor: identity, identityMinScore: 30 }).check({ phoneNumber: "+15555550103" })).identityMatch, "match");
    });

    it("skips Identity Match when the host has no identity on file", async () => {
      replies.set("+15555550104", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: null, swapped_period: "PT120H", swapped_in_period: false }) }) });
      const report = await twilio({ identityFor: async () => null }).check({ phoneNumber: "+15555550104" });
      assert.deepEqual(report, { checked: true, lastSimSwapHoursAgo: 120, lastPortHoursAgo: null, identityMatch: "unavailable" });
      assert.equal(requests[0]!.query.get("Fields"), "sim_swap");
    });

    it("reads a change with no date or period as just now, and nothing usable as no answer", async () => {
      replies.set("+15555550105", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "not a date", swapped_period: "bogus", swapped_in_period: true }) }) });
      replies.set("+15555550106", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: null, swapped_period: null, swapped_in_period: false }) }) });
      replies.set("+15555550107", { body: twilioBody({ sim_swap: simSwap(null) }) });
      replies.set("+15555550108", { body: twilioBody({ sim_swap: { last_sim_swap: { last_sim_swap_date: "2026-01-02T00:00:00Z" }, error_code: null } }) });
      const adapter = twilio();
      assert.equal((await adapter.check({ phoneNumber: "+15555550105" })).lastSimSwapHoursAgo, 0);
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550106" }), uncheckedReport());
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550107" }), uncheckedReport());
      assert.equal((await adapter.check({ phoneNumber: "+15555550108" })).lastSimSwapHoursAgo, 0, "a date after now is never negative");
      assert.deepEqual(failures, [
        { vendor: "twilio", reason: "bad_response" },
        { vendor: "twilio", reason: "bad_response" },
      ]);
    });

    it("fails closed on a feature the account is not approved for, in either field", async () => {
      replies.set("+15555550109", { body: twilioBody({ sim_swap: simSwap(null, 60606) }) });
      replies.set("+15555550110", {
        body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" }), identity_match: identityMatch(null, 60617) }),
      });
      replies.set("+15555550111", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" }), identity_match: null }) });
      replies.set("+15555550112", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" }), identity_match: identityMatch(null) }) });
      const adapter = twilio({ identityFor: identity });
      for (const n of ["+15555550109", "+15555550110", "+15555550111", "+15555550112"]) {
        assert.deepEqual(await adapter.check({ phoneNumber: n }), uncheckedReport(), n);
      }
      assert.deepEqual(failures, [
        { vendor: "twilio", reason: "feature_unavailable", code: "60606" },
        { vendor: "twilio", reason: "feature_unavailable", code: "60617" },
        { vendor: "twilio", reason: "bad_response" },
        { vendor: "twilio", reason: "bad_response" },
      ]);
    });

    it("fails closed on an unsupported country, an invalid number and malformed answers", async () => {
      const swap = simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" });
      replies.set("+15555550113", { body: twilioBody({ country_code: "CA", sim_swap: swap }) });
      replies.set("+15555550114", { body: twilioBody({ valid: false, sim_swap: null }) });
      replies.set("+15555550115", { body: "<html>not json</html>" });
      replies.set("+15555550116", { body: twilioBody({ sim_swap: "yes" }) });
      replies.set("+15555550117", { body: twilioBody({ country_code: null, sim_swap: swap }) });
      const adapter = twilio();
      for (const n of ["+15555550113", "+15555550114", "+15555550115", "+15555550116", "+15555550117"]) {
        assert.deepEqual(await adapter.check({ phoneNumber: n }), uncheckedReport(), n);
      }
      assert.deepEqual(
        failures.map((f) => f.reason),
        ["unsupported_country", "invalid_number", "bad_response", "bad_response", "unsupported_country"],
      );
    });

    it("fails closed on HTTP errors, keeping the vendor's status and code", async () => {
      replies.set("+15555550118", { status: 401, body: { code: 20003, message: "Authenticate", more_info: "https://www.twilio.com/docs/errors/20003", status: 401 } });
      replies.set("+15555550119", { status: 503, body: "Service Unavailable" });
      replies.set("+15555550121", { status: 429, body: { code: "too_many", status: 429 } });
      const adapter = twilio();
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550118" }), uncheckedReport());
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550119" }), uncheckedReport());
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550121" }), uncheckedReport());
      assert.deepEqual(failures, [
        { vendor: "twilio", reason: "http_status", status: 401, code: "20003" },
        { vendor: "twilio", reason: "http_status", status: 503 },
        { vendor: "twilio", reason: "http_status", status: 429, code: "too_many" },
      ]);
    });

    it("never asks for a number that is not E.164, and never throws when the host's lookup does", async () => {
      const adapter = twilio({
        identityFor: async () => {
          throw new Error("records down");
        },
      });
      assert.deepEqual(await adapter.check({ phoneNumber: "5555550100" }), uncheckedReport());
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550120" }), uncheckedReport());
      assert.deepEqual(requests, []);
      assert.deepEqual(failures, [
        { vendor: "twilio", reason: "invalid_number" },
        { vendor: "twilio", reason: "identity_on_file" },
      ]);
    });
  });

  describe("Telnyx Number Lookup", () => {
    it("maps a port to hours from the end of its day, and returns the carrier", async () => {
      replies.set("+15555550201", { body: telnyxBody({ portability: portability("Y", "2025-12-30") }) });
      const adapter = telnyx();
      assert.deepEqual(await adapter.lookup({ phoneNumber: "+15555550201" }), {
        report: { checked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: 24, identityMatch: "unavailable" },
        carrier: { name: "Example Mobile", type: "mobile" },
      });
      assert.equal(requests[0]!.path, "/v2/number_lookup/%2B15555550201");
      assert.equal(requests[0]!.query.get("type"), "carrier");
      assert.equal(requests[0]!.authorization, `Bearer ${TELNYX_KEY}`);
      assert.equal((await adapter.check({ phoneNumber: "+15555550201" })).lastPortHoursAgo, 24);
    });

    it("reads not ported as none known, a port with a time as is, and a port with no date as just now", async () => {
      replies.set("+15555550202", { body: telnyxBody({}) });
      replies.set("+15555550203", { body: telnyxBody({ portability: portability("y", "2025-12-31T12:00:00Z") }) });
      replies.set("+15555550204", { body: telnyxBody({ portability: { ported_status: "Y" } }) });
      replies.set("+15555550205", { body: telnyxBody({ portability: portability("Y", "2026-01-01") }) });
      const adapter = telnyx();
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550202" }), { checked: true, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" });
      assert.equal((await adapter.check({ phoneNumber: "+15555550203" })).lastPortHoursAgo, 12);
      assert.equal((await adapter.check({ phoneNumber: "+15555550204" })).lastPortHoursAgo, 0);
      assert.equal((await adapter.check({ phoneNumber: "+15555550205" })).lastPortHoursAgo, 0, "a port today is just now");
    });

    it("drops a carrier it cannot read without dropping the report", async () => {
      replies.set("+15555550206", { body: telnyxBody({ carrier: { name: "", type: "", error_code: null } }) });
      replies.set("+15555550207", { body: telnyxBody({ carrier: { name: "X", type: "mobile", error_code: "10001" } }) });
      replies.set("+15555550208", { body: telnyxBody({ carrier: { name: "Example Mobile", type: null, error_code: null } }) });
      const adapter = telnyx();
      assert.equal((await adapter.lookup({ phoneNumber: "+15555550206" })).carrier, null);
      assert.equal((await adapter.lookup({ phoneNumber: "+15555550207" })).carrier, null);
      assert.deepEqual((await adapter.lookup({ phoneNumber: "+15555550208" })).carrier, { name: "Example Mobile", type: null });
      assert.equal((await adapter.lookup({ phoneNumber: "+15555550208" })).report.checked, true);
    });

    it("fails closed on Canadian numbers until the account may look them up", async () => {
      replies.set("+15555550209", { body: telnyxBody({ country_code: "CA", portability: portability("Y", "2025-12-30") }) });
      assert.deepEqual(await telnyx().lookup({ phoneNumber: "+15555550209" }), { report: uncheckedReport(), carrier: null });
      assert.deepEqual(failures, [{ vendor: "telnyx", reason: "unsupported_country" }]);
      assert.equal((await telnyx({ countries: ["US", "ca"] }).check({ phoneNumber: "+15555550209" })).lastPortHoursAgo, 24, "once allowed");
    });

    it("fails closed on errors, unknown porting status and malformed answers", async () => {
      replies.set("+15555550210", { status: 403, body: { errors: [{ code: "10010", title: "Authorization failed", detail: "not enabled" }] } });
      replies.set("+15555550211", { status: 422, body: { errors: [{ code: 10015 }] } });
      replies.set("+15555550212", { status: 500, body: { errors: [] } });
      replies.set("+15555550213", { body: telnyxBody({ portability: portability("", "") }) });
      replies.set("+15555550214", { body: telnyxBody({ portability: null }) });
      replies.set("+15555550215", { body: { data: null } });
      replies.set("+15555550216", { body: telnyxBody({ portability: { ported_status: null } }) });
      replies.set("+15555550217", { body: [1, 2] });
      replies.set("+15555550218", { status: 502, body: { message: "bad gateway" } });
      const adapter = telnyx();
      for (let n = 210; n <= 218; n += 1) {
        assert.deepEqual(await adapter.lookup({ phoneNumber: `+15555550${n}` }), { report: uncheckedReport(), carrier: null }, String(n));
      }
      assert.deepEqual(await adapter.lookup({ phoneNumber: "not a number" }), { report: uncheckedReport(), carrier: null });
      assert.deepEqual(failures, [
        { vendor: "telnyx", reason: "http_status", status: 403, code: "10010" },
        { vendor: "telnyx", reason: "http_status", status: 422, code: "10015" },
        { vendor: "telnyx", reason: "http_status", status: 500 },
        { vendor: "telnyx", reason: "feature_unavailable" },
        { vendor: "telnyx", reason: "bad_response" },
        { vendor: "telnyx", reason: "bad_response" },
        { vendor: "telnyx", reason: "feature_unavailable" },
        { vendor: "telnyx", reason: "bad_response", status: 200 },
        { vendor: "telnyx", reason: "http_status", status: 502 },
        { vendor: "telnyx", reason: "invalid_number" },
      ]);
    });
  });

  describe("timeouts and the network", () => {
    it("gives up after the timeout and answers that nothing is known", async () => {
      replies.set("+15555550301", { body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" }) }), delayMs: 2000 });
      replies.set("+15555550302", { body: telnyxBody({}), delayMs: 2000 });
      const started = Date.now();
      assert.deepEqual(await twilio({ timeoutMs: 50 }).check({ phoneNumber: "+15555550301" }), uncheckedReport());
      assert.deepEqual(failures, [{ vendor: "twilio", reason: "timeout" }]);
      assert.deepEqual(await telnyx({ timeoutMs: 50 }).check({ phoneNumber: "+15555550302" }), uncheckedReport());
      assert.deepEqual(failures, [{ vendor: "telnyx", reason: "timeout" }]);
      assert.ok(Date.now() - started < 1500, "both gave up well before the reply");
    });

    it("answers that nothing is known when the vendor cannot be reached, even if the listener throws", async () => {
      const closed = createServer();
      await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
      const port = (closed.address() as AddressInfo).port;
      await new Promise((resolve) => closed.close(resolve));
      const adapter = new TwilioLookupSignals(TWILIO, {
        countries: ["US"],
        baseUrl: `http://127.0.0.1:${port}/`,
        onUnavailable: () => {
          throw new Error("listener broke");
        },
      });
      assert.deepEqual(await adapter.check({ phoneNumber: "+15555550303" }), uncheckedReport());
    });
  });

  describe("in the engine", () => {
    it("records the identity match and a recent SIM change, and writes no number to the ledger", async () => {
      replies.set(PHONE_ON_FILE, {
        body: twilioBody({ sim_swap: simSwap({ last_sim_swap_date: "2025-12-31T21:00:00Z" }), identity_match: identityMatch(95) }),
      });
      const t = setup({ adapters: { carrier: twilio({ identityFor: identity }) } });
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: false });
      assert.deepEqual((await t.engine.finishVerification(callId)).level, 2);
      const entries = JSON.stringify(await t.ledger.list());
      assert.equal(entries.includes("5555550100"), false);
      assert.equal(entries.includes("Caller"), false);
    });

    it("keeps the call going when the carrier times out, with nothing recorded", async () => {
      replies.set(PHONE_ON_FILE, { body: twilioBody({}), delayMs: 2000 });
      const t = setup({ adapters: { carrier: telnyx({ timeoutMs: 50 }) } });
      const { callId } = await t.engine.startCall();
      await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
      await t.engine.submitKeypad(callId, { dob: DOB });
      assert.deepEqual(await t.engine.checkCarrier(callId), { textCodeTrusted: false });
      assert.deepEqual(
        (await t.engine.state(callId)).factors.map((f) => f.kind),
        ["keypad_knowledge"],
      );
      const checked = (await t.ledger.list()).find((e) => e.event === "verification.carrier_checked");
      assert.deepEqual(checked?.detail, { checked: false, textCodeTrusted: false, identityMatch: "unavailable" });
    });
  });

  describe("credentials from the environment", () => {
    it("builds Twilio from an API key, else the account SID, and refuses without both halves", () => {
      assert.equal(twilioLookupFromEnv({}), null);
      assert.equal(twilioLookupFromEnv({ TWILIO_API_KEY: "SK_test_not_a_secret" }), null);
      assert.equal(twilioLookupFromEnv({ TWILIO_ACCOUNT_SID: "AC_test_not_a_secret" }), null);
      assert.ok(twilioLookupFromEnv({ TWILIO_API_KEY: "SK_test_not_a_secret", TWILIO_API_SECRET: "test_not_a_secret" }) instanceof TwilioLookupSignals);
      assert.ok(twilioLookupFromEnv({ TWILIO_ACCOUNT_SID: "AC_test_not_a_secret", TWILIO_AUTH_TOKEN: "test_not_a_secret" }) instanceof TwilioLookupSignals);
    });

    it("builds Telnyx from its API key", () => {
      assert.equal(telnyxLookupFromEnv({}), null);
      assert.ok(telnyxLookupFromEnv({ TELNYX_API_KEY: TELNYX_KEY }) instanceof TelnyxNumberLookupSignals);
    });

    it("reads the country allow-lists, US by default", async () => {
      replies.set("+15555550401", { body: telnyxBody({ country_code: "CA" }) });
      replies.set("+15555550402", { body: twilioBody({ country_code: "CA", sim_swap: simSwap({ last_sim_swap_date: "2025-10-01T00:00:00Z" }) }) });
      const clock = new FixedClock(NOW);
      const tx = (countries?: string) => telnyxLookupFromEnv({ TELNYX_API_KEY: TELNYX_KEY, TELNYX_LOOKUP_COUNTRIES: countries }, { baseUrl: base, clock })!;
      const tw = (countries?: string) => twilioLookupFromEnv({ TWILIO_API_KEY: "SK_test_not_a_secret", TWILIO_API_SECRET: "test_not_a_secret", TWILIO_LOOKUP_COUNTRIES: countries }, { baseUrl: base, clock })!;
      assert.equal((await tx().check({ phoneNumber: "+15555550401" })).checked, false);
      assert.equal((await tx(" , ").check({ phoneNumber: "+15555550401" })).checked, false);
      assert.equal((await tx("us, ca").check({ phoneNumber: "+15555550401" })).checked, true);
      assert.equal((await tw().check({ phoneNumber: "+15555550402" })).checked, false);
      assert.equal((await tw("CA").check({ phoneNumber: "+15555550402" })).checked, true);
    });
  });
});

describe("durationHours", () => {
  it("reads ISO 8601 durations in whole hours, rounded down", () => {
    assert.equal(durationHours("PT15282H33M44S"), 15282);
    assert.equal(durationHours("P3DT4H"), 76);
    assert.equal(durationHours("PT59M60S"), 1);
    assert.equal(durationHours("P2D"), 48);
    assert.equal(durationHours("PT0.5S"), 0);
    for (const bad of ["P", "PT", "P1DT", "bogus", "PT-1H", ""]) assert.equal(durationHours(bad), null, bad);
  });
});
