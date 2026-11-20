// CodeRabbit's review of 4edbcb2 on #135: SPEC states one `fromSeq` boundary for the ledger export,
// the one the code enforces (at most the head plus one, so an empty ledger exports from 1).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { EngineError } from "../src/core/errors.ts";
import { exportLedger, verifyLedgerExport } from "../src/prove/export.ts";
import { MemoryAuditLedger } from "../src/prove/ledger.ts";
import { FixedClock, generateTestSigner } from "../src/testing/fakes.ts";

const spec = readFileSync(new URL("../SPEC.md", import.meta.url), "utf8").replace(/\s+/g, " ");
const clock = new FixedClock("2026-11-20T12:00:00.000Z");

async function collect(lines: AsyncIterable<string>): Promise<string> {
  let out = "";
  for await (const line of lines) out += line;
  return out;
}

describe("ledger export: the fromSeq boundary (#135 review)", () => {
  it("SPEC refuses only a fromSeq past the head plus one, as its start rule allows the head plus one", () => {
    assert.match(spec, /A run starts at `fromSeq` \(1 or more, at most the head plus one\)/);
    assert.doesNotMatch(spec, /a `fromSeq` past the head, an empty `ledgerId`/);
    assert.match(spec, /a `fromSeq` past the head plus one \(on an empty ledger, more than 1\), an empty `ledgerId`/);
  });

  it("an empty ledger exports from 1 and refuses 2", async () => {
    const ledger = new MemoryAuditLedger();
    const signer = generateTestSigner("k1");
    const text = await collect(exportLedger({ ledger, signer, clock, ledgerId: "ws_1", fromSeq: 1 }));
    assert.equal(verifyLedgerExport(text, [signer.publicJwk()]).ok, true);
    await assert.rejects(
      collect(exportLedger({ ledger, signer, clock, ledgerId: "ws_1", fromSeq: 2 })),
      (e: unknown) => e instanceof EngineError && e.code === "invalid_input" && /past the ledger head/.test(e.message),
    );
  });
});
