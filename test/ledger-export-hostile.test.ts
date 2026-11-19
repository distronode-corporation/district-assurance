// Hostile pass on #90 (PRV-4 ledger export), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import { EngineError } from "../src/core/errors.ts";
import { exportLedger, verifyLedgerExport, type LedgerExportInput } from "../src/prove/export.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { FixedClock, generateTestSigner } from "../src/testing/fakes.ts";

const clock = new FixedClock("2026-11-18T12:00:00.000Z");

async function ledgerOf(n: number): Promise<MemoryAuditLedger> {
  const ledger = new MemoryAuditLedger();
  for (let i = 1; i <= n; i++) await ledger.append({ callId: "c", actor: "code", event: "module.event", at: "2026-01-01T00:00:00.000Z", detail: { i } });
  return ledger;
}

async function collect(lines: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const line of lines) out += line;
  return out;
}

describe("#90 hostile: the trailer's signer", () => {
  it("X1 a signer whose 64 bytes do not verify against its own key yields nothing, so no export goes out with a trailer no key set checks", async () => {
    const good = generateTestSigner("k1");
    const other = generateTestSigner("k1");
    const ledger = await ledgerOf(2);
    for (const signer of [
      { keyId: "k1", algorithm: "ES256" as const, sign: async () => randomBytes(64), publicJwk: () => good.publicJwk() },
      { keyId: "k1", algorithm: "ES256" as const, sign: (p: Uint8Array) => other.sign(p), publicJwk: () => good.publicJwk() },
    ]) {
      const lines: string[] = [];
      await assert.rejects(
        (async () => {
          for await (const line of exportLedger({ ledger, signer, clock, ledgerId: "ws_1", fromSeq: 1 })) lines.push(line);
        })(),
        (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /does not verify/.test(e.message),
      );
      assert.deepEqual(lines, [], "nothing yielded");
    }
    const text = await collect(exportLedger({ ledger, signer: good, clock, ledgerId: "ws_1", fromSeq: 1 }));
    assert.equal(verifyLedgerExport(text, [good.publicJwk()]).ok, true);
  });
});

describe("#90 hostile: the export input", () => {
  it("X2 each input is read once: a getter cannot pass the checks and then run with another value", async () => {
    const ledger = await ledgerOf(3);
    const signer = generateTestSigner("k1");
    const reads: Record<string, number> = {};
    const input = { ledger, signer, clock } as Record<string, unknown>;
    for (const [key, first, then] of [
      ["fromSeq", 1, -5],
      ["limit", 2, -100],
      ["ledgerId", "ws_1", { not: "a string" }],
    ] as const) {
      Object.defineProperty(input, key, {
        enumerable: true,
        get() {
          reads[key] = (reads[key] ?? 0) + 1;
          return reads[key] === 1 ? first : then;
        },
      });
    }
    const text = await collect(exportLedger(input as unknown as LedgerExportInput));
    assert.deepEqual(reads, { fromSeq: 1, limit: 1, ledgerId: 1 });
    const check = verifyLedgerExport(text, [signer.publicJwk()]);
    assert.equal(check.ok, true);
    assert.deepEqual(check.ok && [check.trailer.ledgerId, check.trailer.count], ["ws_1", 2]);
  });

  it("X3 a line with a field added after the fact fails the chain, even though the rest of the line is untouched", async () => {
    const ledger = await ledgerOf(2);
    const signer = generateTestSigner("k1");
    const text = await collect(exportLedger({ ledger, signer, clock, ledgerId: "ws_1", fromSeq: 1 }));
    const lines = text.split("\n");
    lines[0] = lines[0]!.replace(/^\{/, '{"note":"+15555550100",');
    assert.deepEqual(verifyLedgerExport(lines.join("\n"), [signer.publicJwk()]), { ok: false, reason: "chain", seq: 1 });
  });
});
