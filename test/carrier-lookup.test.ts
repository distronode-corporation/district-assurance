// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// district-assurance/carrier: the Lookup field parsers, pure. The reference server's adapters that
// fetch the answers are tested in carrier-adapters*.test.ts.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { durationHours, isCarrierAnswer, telnyxPortHours, twilioIdentityMatch, twilioSimSwapHours, uncheckedReport } from "../src/carrier/index.ts";

const NOW = new Date("2026-11-22T12:00:00.000Z");
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3_600_000).toISOString();

describe("durationHours", () => {
  it("reads ISO 8601 durations in whole hours, and refuses anything else", () => {
    assert.equal(durationHours("PT15282H33M44S"), 15282);
    assert.equal(durationHours("P3DT4H"), 76);
    assert.equal(durationHours("PT90M"), 1);
    assert.equal(durationHours("PT3600.5S"), 1);
    for (const value of ["P", "PT", "P1DT", "15H", "PT-1H"]) assert.equal(durationHours(value), null, value);
    assert.equal(durationHours(`P${"9".repeat(400)}D`), null);
  });
});

describe("twilioSimSwapHours", () => {
  const swap = (last: Record<string, unknown>) => ({ last_sim_swap: last, error_code: null });

  it("dates a change, caps a flagged one at its period, and bounds an unflagged one below by the period", () => {
    assert.equal(twilioSimSwapHours(swap({ last_sim_swap_date: hoursAgo(10), swapped_period: "PT24H", swapped_in_period: true }), NOW), 10);
    assert.equal(twilioSimSwapHours(swap({ last_sim_swap_date: hoursAgo(48), swapped_period: "PT24H", swapped_in_period: true }), NOW), 0);
    assert.equal(twilioSimSwapHours(swap({ swapped_in_period: true }), NOW), 0);
    assert.equal(twilioSimSwapHours(swap({ last_sim_swap_date: hoursAgo(500) }), NOW), 500);
    assert.equal(twilioSimSwapHours(swap({ last_sim_swap_date: new Date(NOW.getTime() + 3_600_000).toISOString() }), NOW), 0);
    assert.equal(twilioSimSwapHours(swap({ swapped_period: "PT15282H", swapped_in_period: false }), NOW), 15282);
  });

  it("⛔ is no answer for a vendor error, a missing field, a date Date.parse would guess at, or nothing usable", () => {
    assert.deepEqual(twilioSimSwapHours({ error_code: 60606 }, NOW), { reason: "feature_unavailable", code: "60606" });
    assert.deepEqual(twilioSimSwapHours({ error_code: "E1" }, NOW), { reason: "feature_unavailable", code: "E1" });
    // ⛔ A code that is not a string or a number is no answer, never converted (a hostile toString cannot throw here).
    for (const error_code of [{ toString: null }, [1], Number.NaN, true]) assert.deepEqual(twilioSimSwapHours({ error_code }, NOW), { reason: "bad_response" });
    assert.deepEqual(twilioIdentityMatch({ error_code: { toString: null } }, 80), { reason: "bad_response" });
    assert.deepEqual(twilioSimSwapHours(null, NOW), { reason: "bad_response" });
    assert.deepEqual(twilioSimSwapHours({ last_sim_swap: "x" }, NOW), { reason: "bad_response" });
    assert.deepEqual(twilioSimSwapHours(swap({ last_sim_swap_date: "Jan 1" }), NOW), { reason: "bad_response" });
    assert.deepEqual(twilioSimSwapHours(swap({ swapped_period: 7, swapped_in_period: false }), NOW), { reason: "bad_response" });
  });
});

describe("twilioIdentityMatch", () => {
  it("matches at the minimum score or more, and refuses anything that is not a score", () => {
    assert.equal(twilioIdentityMatch({ summary_score: 80, error_code: null }, 80), "match");
    assert.equal(twilioIdentityMatch({ summary_score: 79 }, 80), "no_match");
    assert.deepEqual(twilioIdentityMatch({ error_code: "60617" }, 80), { reason: "feature_unavailable", code: "60617" });
    for (const field of [null, { summary_score: 101 }, { summary_score: "90" }]) assert.deepEqual(twilioIdentityMatch(field, 80), { reason: "bad_response" });
    for (const minScore of [0, 101, Number.NaN, "80"]) assert.throws(() => twilioIdentityMatch({ summary_score: 90 }, minScore as number), /minScore/);
  });
});

describe("telnyxPortHours", () => {
  it("reads a port's age from the last moment its date ends anywhere; null when not ported", () => {
    assert.equal(telnyxPortHours({ ported_status: "N" }, NOW), null);
    assert.equal(telnyxPortHours({ ported_status: "y", ported_date: "2026-11-20" }, NOW), 24);
    assert.equal(telnyxPortHours({ ported_status: "Y", ported_date: hoursAgo(5) }, NOW), 5);
    assert.equal(telnyxPortHours({ ported_status: "Y", ported_date: "1" }, NOW), 0);
    assert.equal(telnyxPortHours({ ported_status: "Y" }, NOW), 0);
  });

  it("⛔ is no answer for an unknown status or a field that is not an object", () => {
    assert.deepEqual(telnyxPortHours({ ported_status: "?" }, NOW), { reason: "feature_unavailable" });
    assert.deepEqual(telnyxPortHours({}, NOW), { reason: "feature_unavailable" });
    assert.deepEqual(telnyxPortHours([], NOW), { reason: "bad_response" });
  });
});

describe("isCarrierAnswer and uncheckedReport", () => {
  it("tells an answer from a failure, and starts a report at nothing known", () => {
    for (const value of [0, 12, null, "match", "no_match"]) assert.equal(isCarrierAnswer(value), true);
    assert.equal(isCarrierAnswer({ reason: "bad_response" }), false);
    const report = uncheckedReport();
    assert.deepEqual(report, { checked: false, simSwapChecked: false, lastSimSwapHoursAgo: null, lastPortHoursAgo: null, identityMatch: "unavailable" });
    report.checked = true;
    assert.equal(uncheckedReport().checked, false);
  });
});
