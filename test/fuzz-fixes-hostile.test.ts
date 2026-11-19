// Hostile-pass regressions for #56 (SRV-7, the property and fuzz suites): what its fixes must hold
// for. F1 failed before verifyChain took an entry that is not an object as a break; the rest held.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import type { AuditEntry } from "../src/core/adapters.ts";
import { MemoryAuditLedger, verifyChain } from "../src/prove/ledger.ts";
import { parseStripeEvent } from "../src/webhooks/stripe.ts";

async function stored(): Promise<AuditEntry[]> {
  const ledger = new MemoryAuditLedger();
  for (let n = 1; n <= 3; n++) await ledger.append({ callId: "c1", actor: "code", event: "call.started", at: "2026-01-01T00:00:00.000Z", detail: { n } });
  return JSON.parse(JSON.stringify(await ledger.list())) as AuditEntry[];
}

describe("hostile #56: verifyChain on what storage hands back", () => {
  it("F1: an entry that is not an object (null, a number, a string, a list) is a break, never a crash", async () => {
    const entries = await stored();
    for (const bad of [null, 42, "entry", [], true]) {
      const damaged = [entries[0]!, bad as unknown as AuditEntry, entries[2]!];
      assert.doesNotThrow(() => verifyChain(damaged), String(bad));
      assert.deepEqual(verifyChain(damaged), { ok: false, seq: 2, reason: "seq" }, JSON.stringify(bad));
    }
  });

  it("F2: an entry with a field added, or a number written another way, is a hash break; one written the same way still verifies", async () => {
    const entries = await stored();
    const extra = structuredClone(entries);
    (extra[1] as unknown as Record<string, unknown>).note = "added";
    assert.deepEqual(verifyChain(extra), { ok: false, seq: 2, reason: "hash" });
    const text = JSON.stringify(entries);
    assert.equal(verifyChain(JSON.parse(text.replace('"n":2', '"n":2.0'))).ok, true, "2.0 is the number 2");
    assert.equal(verifyChain(JSON.parse(text.replace('"n":2', '"n":-0'))).ok, false, "-0 is not 2");
    assert.deepEqual(verifyChain(JSON.parse(text.replace('"n":2', '"n":1e999'))), { ok: false, seq: 2, reason: "hash" });
  });
});

describe("hostile #56: parseStripeEvent and Object.prototype", () => {
  it("F3: event types named like Object.prototype members are ignored events, never outcomes", () => {
    for (const type of ["constructor", "__proto__", "hasOwnProperty", "toString", "valueOf", "isPrototypeOf"]) {
      const event = parseStripeEvent(JSON.stringify({ id: "evt_1", type, livemode: false, data: { object: { id: "cs_1", payment_status: "paid" } } }));
      assert.deepEqual(event, { eventId: "evt_1", livemode: false, kind: "ignored", type }, type);
    }
  });
});

describe("hostile #56: the harness's settings", () => {
  const harness = fileURLToPath(new URL("./fuzz/harness.ts", import.meta.url));
  const load = (env: Record<string, string>) => spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(harness)})`], { env: { ...process.env, ...env }, encoding: "utf8" });

  it("F4: refuses a budget or seed that is not an integer, however it is written", () => {
    for (const [name, value] of [["DA_FUZZ_MS", "1e3"], ["DA_FUZZ_MS", "-1"], ["DA_FUZZ_MS", " 5"], ["DA_FUZZ_MS", "0x10"], ["DA_FUZZ_MS", "60000; rm -rf /"], ["DA_FUZZ_SEED", "1.5"], ["DA_FUZZ_SEED", "9".repeat(20)]]) {
      const r = load({ [name!]: value! });
      assert.notEqual(r.status, 0, `${name}=${value}`);
    }
    assert.equal(load({ DA_FUZZ_MS: "0", DA_FUZZ_SEED: "-7" }).status, 0);
  });
});
