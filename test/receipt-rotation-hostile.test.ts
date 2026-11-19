// Hostile-pass regressions for #75 (PRV-1 key rotation, PRV-2 stand-alone verifier). K1, K2, K6
// and K7 failed before their fixes (no throw on bad input, the taint always lands, no raw bidi in the
// verifier's output); K3 to K5 held.
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { checkReceipt, receiptKeyRing, verifyReceipt, type SignedReceipt } from "../src/index.ts";
import { createTestEngine, generateTestSigner } from "../src/testing/index.ts";

// The page's own check, loaded as the page loads it (a plain .js module without types).
const page = (await import(new URL("../examples/reference-server/public/receipt-check.js", import.meta.url).href)) as {
  checkReceipt(receipt: unknown, keys: unknown): Promise<{ ok: boolean }>;
};
const pageCheck = page.checkReceipt;

const SCRIPT = fileURLToPath(new URL("../scripts/verify-receipt.mjs", import.meta.url));
const RETIRED_AT = "2026-01-01T00:00:00.000Z";

async function signedReceipt(): Promise<{ receipt: SignedReceipt; k1: ReturnType<typeof generateTestSigner> }> {
  const k1 = generateTestSigner("k1");
  const t = createTestEngine({ adapters: { signer: k1 } });
  // The default flow signs a receipt at endCall.
  const { callId } = await t.engine.startCall();
  const receipt = (await t.engine.endCall(callId))!;
  assert.ok(receipt !== null);
  return { receipt, k1 };
}

function run(args: string[]): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT, ...args]);
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c.toString()));
    child.stderr.on("data", (c: Buffer) => (out += c.toString()));
    child.on("close", (code) => resolve({ code, out }));
  });
}

describe("hostile #75: checkReceipt and verifyReceipt never throw on bad input", () => {
  it("K1: a null or non-object receipt, body or key, and a non-array key set, answer invalid", async () => {
    const { receipt, k1 } = await signedReceipt();
    const retiredSet = [{ ...k1.publicJwk(), retiredAt: RETIRED_AT }];
    const cases: Array<[unknown, unknown]> = [
      [null, [k1.publicJwk()]],
      [undefined, [k1.publicJwk()]],
      ["receipt", [k1.publicJwk()]],
      [{ ...receipt, body: null }, retiredSet],
      [{ ...receipt, body: "x" }, retiredSet],
      [receipt, [null, k1.publicJwk()]],
      [receipt, null],
      [receipt, { keys: [k1.publicJwk()] }],
      [{ ...receipt, signature: 42 }, [k1.publicJwk()]],
    ];
    for (const [r, keys] of cases) {
      const label = JSON.stringify([r === receipt ? "receipt" : r, keys === null ? null : "keys"]).slice(0, 80);
      assert.doesNotThrow(() => verifyReceipt(r as SignedReceipt, keys as never), label);
      assert.equal(verifyReceipt(r as SignedReceipt, keys as never), r === receipt && Array.isArray(keys) && keys.at(-1) !== null ? true : false, label);
      assert.doesNotThrow(() => checkReceipt(r as SignedReceipt, keys as never), label);
    }
  });

  it("K2: a key set whose matching entry has a throwing getter answers invalid", async () => {
    const { receipt, k1 } = await signedReceipt();
    const trap = Object.defineProperty({ ...k1.publicJwk() }, "retiredAt", {
      get() {
        throw new Error("trap");
      },
    });
    assert.doesNotThrow(() => checkReceipt(receipt, [trap]));
    assert.equal(checkReceipt(receipt, [trap]).valid, false);
  });
});

describe("hostile #75: rotation", () => {
  it("K3: a receipt that names a retired key and claims an issue time before retirement fails when the body was signed later", async () => {
    // The retirement check reads the body's issuedAt; the signature covers it, so moving it back breaks the signature.
    const { receipt, k1 } = await signedReceipt();
    const keys = [{ ...k1.publicJwk(), retiredAt: "2099-01-01T00:00:00.000Z" }];
    assert.deepEqual(checkReceipt(receipt, keys), { valid: true, retiredAt: "2099-01-01T00:00:00.000Z" });
    const backdated = structuredClone(receipt);
    backdated.body.issuedAt = "2000-01-01T00:00:00.000Z";
    assert.equal(checkReceipt(backdated, keys).valid, false);
    const atRetirement = [{ ...k1.publicJwk(), retiredAt: receipt.body.issuedAt }];
    assert.equal(checkReceipt(receipt, atRetirement).valid, false, "issued at the retirement instant: invalid");
  });

  it("K4: retiredAt forms that are not the engine's ISO UTC time are refused everywhere, the same way", async () => {
    const { receipt, k1 } = await signedReceipt();
    for (const at of ["2099-01-01", "2099-01-01T00:00:00Z", "2099-01-01T00:00:00.000+00:00", " 2099-01-01T00:00:00.000Z", 4102444800000, null, "", "Invalid Date"]) {
      const keys = [{ ...k1.publicJwk(), retiredAt: at }];
      assert.equal(checkReceipt(receipt, keys as never).valid, false, String(at));
      assert.equal((await pageCheck(receipt, keys as never)).ok, false, `page ${String(at)}`);
      assert.throws(() => receiptKeyRing({ signers: [generateTestSigner("k2")], active: "k2", retired: keys as never }), TypeError, `ring ${String(at)}`);
    }
  });

  it("K5: a ring refuses a retired key that shares a kid with a signer, a private key, and a signer naming another kid", () => {
    const k1 = generateTestSigner("k1");
    const k2 = generateTestSigner("k2");
    assert.throws(() => receiptKeyRing({ signers: [k1], active: "k1", retired: [{ ...k2.publicJwk(), kid: "k1", retiredAt: RETIRED_AT }] }), /two keys/);
    assert.throws(() => receiptKeyRing({ signers: [k1], active: "k1", retired: [{ ...k2.publicJwk(), d: "x", retiredAt: RETIRED_AT }] }), /private part/);
    const liar = { ...k1, keyId: "k3", publicJwk: k1.publicJwk };
    assert.throws(() => receiptKeyRing({ signers: [liar], active: "k3" }), /publishes a key named/);
    assert.throws(() => receiptKeyRing({ signers: [k1, { ...k1 }], active: "k1" }), /two keys/);
    const ring = receiptKeyRing({ signers: [k1], active: "k1", retired: [{ ...k2.publicJwk(), retiredAt: RETIRED_AT }] });
    const set = ring.keySet();
    (set[0] as { kid?: string }).kid = "changed";
    assert.equal(ring.keySet()[0]!.kid, "k1", "keySet hands out copies");
  });
});

describe("hostile #75: markUntrusted", () => {
  it("K6: a label whose toString throws still taints the call", async () => {
    const t = createTestEngine();
    const { callId } = await t.engine.startCall();
    const label = {
      toString() {
        throw new Error("no");
      },
    };
    await t.engine.markUntrusted(callId, label as never).catch(() => undefined);
    assert.equal((await t.engine.state(callId)).tainted, true, "the taint landed");
  });
});

describe("hostile #75: the stand-alone verifier", () => {
  it("K7: a receipt kid with a bidi override or control characters is never printed raw", async () => {
    const { receipt, k1 } = await signedReceipt();
    const dir = mkdtempSync(join(tmpdir(), "zz75-"));
    try {
      const forged = { ...receipt, kid: "k9\u202e\u0007\u001b[2Kvalid" };
      writeFileSync(join(dir, "r.json"), JSON.stringify(forged));
      writeFileSync(join(dir, "k.json"), JSON.stringify({ keys: [k1.publicJwk()] }));
      const { code, out } = await run([join(dir, "r.json"), join(dir, "k.json")]);
      assert.equal(code, 1);
      assert.match(out, /^invalid: /);
      const raw = [...out.trimEnd()].some((c) => {
        const n = c.codePointAt(0)!;
        return n < 0x20 || n === 0x7f || (n >= 0x202a && n <= 0x202e) || (n >= 0x2066 && n <= 0x2069);
      });
      assert.equal(raw, false, JSON.stringify(out));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
