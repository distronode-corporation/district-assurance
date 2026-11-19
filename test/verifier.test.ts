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
import { createTestEngine, generateTestSigner } from "../src/testing/index.ts";

const SCRIPT = fileURLToPath(new URL("../scripts/verify-receipt.mjs", import.meta.url));

function run(args: string[], stdin = ""): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

describe("stand-alone receipt verifier (PRV-2)", () => {
  let dir = "";
  let receipt: SignedReceipt;
  let keys: JsonWebKey[] = [];
  let keysFile = "";
  let base = "";
  let close: () => Promise<void>;
  let padded = "";
  let closePadded: () => Promise<void>;
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
    const later = createTestEngine({ adapters: { signer: receiptKeyRing({ signers: [generateTestSigner("k2")], active: "k2", retired: [k1.publicJwk()] }) } });
    keys = later.engine.receiptKeys();
    keysFile = file("keys.json", { keys });
    const server = createReferenceServer({ engine: later.engine, stripeSecrets: { identity: [], payments: [] }, clock: later.clock });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    close = () => new Promise((resolve) => server.close(() => resolve()));
    // A valid key set padded with multi-byte characters past 1 MiB of UTF-8.
    const big = createServer((_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys, padding: "é".repeat(600_000) }));
    });
    await new Promise<void>((resolve) => big.listen(0, "127.0.0.1", resolve));
    padded = `http://127.0.0.1:${(big.address() as AddressInfo).port}`;
    closePadded = () => new Promise((resolve) => big.close(() => resolve()));
  });
  after(async () => {
    await close();
    await closePadded();
    rmSync(dir, { recursive: true, force: true });
  });

  it("prints valid for a receipt and its key set, from a file, standard input or the key set URL", async () => {
    const receiptFile = file("receipt.json", receipt);
    assert.deepEqual(await run([receiptFile, keysFile]), { code: 0, stdout: "valid\n", stderr: "" });
    assert.deepEqual(await run(["-", keysFile], JSON.stringify(receipt)), { code: 0, stdout: "valid\n", stderr: "" });
    assert.deepEqual(await run([receiptFile, `${base}/.well-known/receipt-keys.json`]), { code: 0, stdout: "valid\n", stderr: "" });
    // Key order and whitespace do not matter: the signature is over the canonical JSON.
    const reordered = file("reordered.json", `{"signature":"${receipt.signature}","kid":"k1","alg":"ES256",\n "body": ${JSON.stringify(receipt.body, null, 2)}}`);
    assert.equal((await run([reordered, keysFile])).stdout, "valid\n");
    // A bare list of keys works as well as a JWK set; an empty one verifies nothing.
    assert.equal((await run([reordered, file("bare-keys.json", keys)])).stdout, "valid\n");
    assert.deepEqual(await run([reordered, file("no-keys.json", [])]), { code: 1, stdout: 'invalid: no key with kid "k1" in the key set\n', stderr: "" });
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

  it("stops reading standard input past 1 MiB, without waiting for it to end", { timeout: 30_000 }, async () => {
    // A stream that never ends (a pipe left open, /dev/zero): the limit must cut it off while reading.
    const child = spawn(process.execPath, [SCRIPT, "-", keysFile]);
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.stdin.on("error", () => undefined);
    child.stdin.write(Buffer.alloc(2 * 1024 * 1024, 0x20));
    const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
    child.stdin.destroy();
    assert.equal(code, 2);
    assert.match(stderr, /the receipt is larger than 1 MiB/);
  });
});
