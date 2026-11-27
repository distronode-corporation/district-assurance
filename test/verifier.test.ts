// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The stand-alone receipt verifier (scripts/verify-receipt.mjs, PRV-2), run as a child process the
// way a receipt holder runs it: on files, on standard input and on the reference server's key set.
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import type { JsonWebKey } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { receiptKeyRing, type SignedReceipt } from "../src/index.ts";
import { FixedClock, createTestEngine, generateTestSigner } from "../src/testing/index.ts";

/** When k1 stopped signing: after the test clock's receipts (2026-01-01), so they predate it. */
const RETIRED_AT = "2026-06-01T00:00:00.000Z";
const SCRIPT = fileURLToPath(new URL("../scripts/verify-receipt.mjs", import.meta.url));

/** Past the verifier's own 10 s bound on fetching a key set, so only a verifier that stalls reaches it. */
const RUN_DEADLINE_MS = 20_000;

function run(args: string[], stdin = "", deadlineMs = RUN_DEADLINE_MS): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT, ...args]);
    // A child that cannot start rejects this run, rather than throwing out of the test.
    child.on("error", reject);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    // A stalled verifier is killed, so it never outlives the test, and the run rejects with its case.
    const deadline = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, deadlineMs);
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("close", (code, signal) => {
      clearTimeout(deadline);
      if (timedOut) reject(new Error(`the verifier did not exit within ${deadlineMs} ms and was killed (${signal}): ${JSON.stringify(args)}`));
      else resolve({ code, stdout, stderr });
    });
    child.stdin.end(stdin);
  });
}

describe("stand-alone receipt verifier (PRV-2)", () => {
  let dir = "";
  let receipt: SignedReceipt;
  let fresh: SignedReceipt;
  let late: SignedReceipt;
  let keys: JsonWebKey[] = [];
  let keysFile = "";
  let base = "";
  let close: (() => Promise<void>) | undefined;
  let padded = "";
  let closePadded: (() => Promise<void>) | undefined;
  const file = (name: string, value: unknown): string => {
    const path = join(dir, name);
    writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
    return path;
  };

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "verify-receipt-"));
    // A receipt signed by k1, checked after k1 was retired and k2 took over.
    const k1 = generateTestSigner("k1");
    const earlier = createTestEngine({ adapters: { signer: k1 } });
    receipt = (await earlier.engine.endCall((await earlier.engine.startCall()).callId))!;
    const later = createTestEngine({ adapters: { signer: receiptKeyRing({ signers: [generateTestSigner("k2")], active: "k2", retired: [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }] }) } });
    keys = later.engine.receiptKeys();
    keysFile = file("keys.json", { keys });
    fresh = (await later.engine.endCall((await later.engine.startCall()).callId))!;
    // k1 signing again after its retirement: a key that leaked, or a host that kept using it.
    const leaked = createTestEngine({ adapters: { signer: k1 }, clock: new FixedClock("2026-07-01T00:00:00.000Z") });
    late = (await leaked.engine.endCall((await leaked.engine.startCall()).callId))!;
    const server = createReferenceServer({ engine: later.engine, stripeSecrets: { identity: [], payments: [] }, clock: later.clock });
    close = () => new Promise((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    // A valid key set padded with multi-byte characters past 1 MiB of UTF-8.
    const big = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys, padding: "é".repeat(600_000) }));
    });
    closePadded = () => new Promise((resolve) => big.close(() => resolve()));
    await new Promise<void>((resolve) => big.listen(0, "127.0.0.1", resolve));
    padded = `http://127.0.0.1:${(big.address() as AddressInfo).port}`;
  });
  // Each handle is set as soon as it is acquired, so a setup that failed part way still cleans up.
  after(async () => {
    try {
      await close?.();
      await closePadded?.();
    } finally {
      if (dir !== "") rmSync(dir, { recursive: true, force: true });
    }
  });

  it("prints valid for a receipt and its key set, from a file, standard input or the key set URL", async () => {
    const VALID = `valid, signed with a retired key (retired ${RETIRED_AT})\n`;
    const receiptFile = file("receipt.json", receipt);
    assert.deepEqual(await run([receiptFile, keysFile]), { code: 0, stdout: VALID, stderr: "" });
    assert.deepEqual(await run(["-", keysFile], JSON.stringify(receipt)), { code: 0, stdout: VALID, stderr: "" });
    assert.deepEqual(await run([receiptFile, `${base}/.well-known/receipt-keys.json`]), { code: 0, stdout: VALID, stderr: "" });
    // Key order and whitespace do not matter: the signature is over the canonical JSON.
    const reordered = file("reordered.json", `{"signature":"${receipt.signature}","kid":"k1","alg":"ES256",\n "body": ${JSON.stringify(receipt.body, null, 2)}}`);
    assert.deepEqual(await run([reordered, keysFile]), { code: 0, stdout: VALID, stderr: "" });
    // A bare list of keys works as well as a JWK set; an empty one verifies nothing.
    assert.deepEqual(await run([reordered, file("bare-keys.json", keys)]), { code: 0, stdout: VALID, stderr: "" });
    assert.deepEqual(await run([reordered, file("no-keys.json", [])]), { code: 1, stdout: 'invalid: no key with kid "k1" in the key set\n', stderr: "" });
    // The active key's receipt is plainly valid; one the retired key signed after its retirement is not.
    assert.deepEqual(await run([file("fresh.json", fresh), keysFile]), { code: 0, stdout: "valid\n", stderr: "" });
    assert.deepEqual(await run([file("late.json", late), keysFile]), { code: 1, stdout: `invalid: signed with a key retired at ${RETIRED_AT}, at or after its retirement\n`, stderr: "" });
    const badTime = keys.map((k) => (k.kid === "k1" ? { ...k, retiredAt: "June" } : k));
    assert.deepEqual(await run([receiptFile, file("bad-time.json", badTime)]), { code: 1, stdout: "invalid: the key's retiredAt is not an ISO 8601 UTC time\n", stderr: "" });
  });

  it("prints invalid, and exits 1, for a tampered receipt or one the key set cannot verify", async () => {
    const tampered = structuredClone(receipt);
    tampered.body.endedAt = "2026-01-01T00:00:01.000Z";
    const cases: Array<[unknown, string]> = [
      [tampered, "invalid: the signature does not match the body\n"],
      [{ ...receipt, body: { ...receipt.body, verification: { level: 3, methods: ["photo_id"] } } }, "invalid: the signature does not match the body\n"],
      [{ ...receipt, kid: "k9" }, 'invalid: no key with kid "k9" in the key set\n'],
      [{ ...receipt, alg: "HS256" }, "invalid: an algorithm other than ES256\n"],
      [{ ...receipt, signature: `${receipt.signature.slice(0, 85)}B` }, "invalid: a malformed signature\n"],
      [{ ...receipt, signature: receipt.signature.slice(4) }, "invalid: a malformed signature\n"],
      [{ ...receipt, body: { ...receipt.body, v: 2 } }, "invalid: an unknown receipt version\n"],
      [{ ...receipt, kid: 1 }, "invalid: not a receipt\n"],
      [{ body: null }, "invalid: not a receipt\n"],
      [[], "invalid: not a receipt\n"],
      [{ ...receipt, body: { ...receipt.body, callId: "\ud800" } }, "invalid: a body that is not canonical JSON (a lone surrogate)\n"],
    ];
    const receiptFile = file("receipt.json", receipt);
    const otherKey = { ...generateTestSigner("k1").publicJwk() };
    const keyCases: Array<[unknown[], string]> = [
      [[otherKey], "invalid: the signature does not match the body\n"],
      [[null, { ...otherKey, kty: "RSA" }], "invalid: the key is not a public P-256 key\n"],
      [[{ ...otherKey, d: "x" }], "invalid: the key is not a public P-256 key\n"],
      [[{ ...otherKey, y: otherKey.x }], "invalid: the key is not a public P-256 key\n"],
    ];
    // Each case is its own process; they run side by side.
    await Promise.all([
      ...cases.map(async ([value, expected], i) => {
        assert.deepEqual(await run([file(`bad-${i}.json`, value), keysFile]), { code: 1, stdout: expected, stderr: "" }, expected);
      }),
      ...keyCases.map(async ([set, expected], i) => {
        assert.deepEqual(await run([receiptFile, file(`other-keys-${i}.json`, set)]), { code: 1, stdout: expected, stderr: "" }, expected);
      }),
    ]);
  });

  it("exits 2 without a verdict when it cannot run the check", async () => {
    const receiptFile = file("receipt.json", receipt);
    const failures: Array<[string[], RegExp]> = [
      [[receiptFile], /usage: node verify-receipt\.mjs/],
      [[join(dir, "missing.json"), keysFile], /cannot read the receipt from /],
      [[file("garbage.json", "{"), keysFile], /the receipt is not JSON/],
      [[receiptFile, file("not-a-set.json", { keys: {} })], /the key set must be/],
      [[receiptFile, file("null-set.json", "null")], /the key set must be/],
      [[receiptFile, file("big.json", " ".repeat(1024 * 1024 + 1))], /larger than 1 MiB/],
      [[receiptFile, "http://example.test/.well-known/receipt-keys.json"], /must be https/],
      [[receiptFile, "https://"], /is not a URL/],
      [[receiptFile, `${base}/nope`], /answered 404/],
      [[receiptFile, "http://127.0.0.1:1/keys.json"], /cannot fetch the key set/],
      // 600,000 characters but 1.2 MB: the limit is on bytes, not string length.
      [[receiptFile, `${padded}/keys.json`], /the key set is larger than 1 MiB/],
    ];
    await Promise.all(
      failures.map(async ([args, message]) => {
        const result = await run(args);
        assert.equal(result.code, 2, String(message));
        assert.equal(result.stdout, "");
        assert.match(result.stderr, message);
      }),
    );
  });

  it("kills a verifier that stalls, and names the case it was running", async () => {
    // A key set URL that accepts the connection and never answers: the verifier waits on it.
    const stalled = createServer(() => undefined);
    await new Promise<void>((resolve) => stalled.listen(0, "127.0.0.1", resolve));
    try {
      const args = [file("receipt.json", receipt), `http://127.0.0.1:${(stalled.address() as AddressInfo).port}/keys.json`];
      await assert.rejects(run(args, "", 300), (e: unknown) => e instanceof Error && e.message === `the verifier did not exit within 300 ms and was killed (SIGKILL): ${JSON.stringify(args)}`);
    } finally {
      stalled.closeAllConnections();
      await new Promise((resolve) => stalled.close(resolve));
    }
  });

  it("stops reading standard input past 1 MiB, without waiting for it to end", { timeout: 30_000 }, async (t) => {
    // A stream that never ends (a pipe left open, /dev/zero): the limit must cut it off while reading.
    // The test's signal kills the child if the test times out, so a verifier that waits for the end
    // of input fails the test without leaving the child behind.
    const child = spawn(process.execPath, [SCRIPT, "-", keysFile], { signal: t.signal });
    try {
      const exited = new Promise<number | null>((resolve, reject) => {
        child.on("error", reject);
        child.on("close", resolve);
      });
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
      child.stdin.on("error", () => undefined);
      // Standard input stays open until the verifier exits.
      child.stdin.write(Buffer.alloc(2 * 1024 * 1024, 0x20));
      assert.equal(await exited, 2);
      assert.match(stderr, /the receipt is larger than 1 MiB/);
    } finally {
      child.stdin.destroy();
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  });
});
