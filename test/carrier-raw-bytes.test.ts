// The carrier checks run over the bytes on the wire: a body that is not valid UTF-8 is never
// decoded (with replacement characters) before it is checked, so two different bodies never verify
// under one signature. And a key list with entries that are not strings skips them.
import { strict as assert } from "node:assert";
import { createHash, createHmac, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import { describe, it, type TestContext } from "node:test";

import { createReferenceServer } from "../examples/reference-server/src/app.ts";
import { verifyTelnyxSignature, verifyTwilioSignature } from "../src/webhooks/carrier.ts";
import { createTestEngine } from "../src/testing/index.ts";

const PRIVATE = generateKeyPairSync("ed25519").privateKey;
const KEY = Buffer.from(createPublicKey(PRIVATE).export({ format: "jwk" }).x!, "base64url").toString("base64");
const now = new Date("2026-01-01T00:00:00Z");
const stamp = `${Math.floor(now.getTime() / 1000)}`;
const TOKEN = "twilio_token_not_a_secret";

// The same JSON text, once with a real U+FFFD (EF BF BD) and once with a lone 0xFF byte, which a
// UTF-8 decoder with replacement turns into the same U+FFFD.
const SIGNED = Buffer.from('{"name":"\u{fffd}"}', "utf8");
const FORGED = Buffer.concat([Buffer.from('{"name":"'), Buffer.from([0xff]), Buffer.from('"}')]);

describe("carrier signatures over raw bytes", () => {
  it("the two bodies differ on the wire and decode to one string", () => {
    assert.notDeepEqual(SIGNED, FORGED);
    assert.equal(SIGNED.toString("utf8"), FORGED.toString("utf8"));
  });

  it("Telnyx: verifies the bytes it was given, and refuses other bytes under that signature", () => {
    const signature = sign(null, Buffer.concat([Buffer.from(`${stamp}|`), SIGNED]), PRIVATE).toString("base64");
    const check = (payload: Uint8Array) => verifyTelnyxSignature({ payload, signatureHeader: signature, timestampHeader: stamp, publicKeys: [KEY], now });
    assert.deepEqual(check(SIGNED), { ok: true, timestamp: Number(stamp) });
    assert.deepEqual(check(FORGED), { ok: false, reason: "no_matching_signature" });
    const own = sign(null, Buffer.concat([Buffer.from(`${stamp}|`), FORGED]), PRIVATE).toString("base64");
    assert.deepEqual(
      verifyTelnyxSignature({ payload: FORGED, signatureHeader: own, timestampHeader: stamp, publicKeys: [KEY], now }),
      { ok: true, timestamp: Number(stamp) },
      "invalid UTF-8 signed as sent verifies as sent",
    );
  });

  it("Twilio: takes bodySHA256 over the bytes, and refuses other bytes with the same hash in the URL", () => {
    const url = `https://voice.example.test/webhooks/twilio?bodySHA256=${createHash("sha256").update(SIGNED).digest("hex")}`;
    const header = createHmac("sha1", TOKEN).update(url).digest("base64");
    const check = (payload: Uint8Array) => verifyTwilioSignature({ url, payload, header, authTokens: [TOKEN] });
    assert.deepEqual(check(SIGNED), { ok: true });
    assert.deepEqual(check(FORGED), { ok: false, reason: "body_hash_mismatch" });
  });

  it("Twilio: still decodes a form body given as bytes to sign its parameters", () => {
    const url = "https://voice.example.test/webhooks/twilio";
    const header = createHmac("sha1", TOKEN).update(`${url}CallSidCA1Digits1234`).digest("base64");
    assert.deepEqual(verifyTwilioSignature({ url, payload: Buffer.from("Digits=1234&CallSid=CA1"), header, authTokens: [TOKEN] }), { ok: true });
  });
});

describe("Telnyx key lists", () => {
  it("skips an entry that is not a string, and tries the valid key after it", () => {
    const body = '{"data":{}}';
    const signature = sign(null, Buffer.from(`${stamp}|${body}`), PRIVATE).toString("base64");
    const publicKeys = [[KEY], { toString: () => KEY }, 42, null, KEY] as never;
    assert.deepEqual(verifyTelnyxSignature({ payload: body, signatureHeader: signature, timestampHeader: stamp, publicKeys, now }), { ok: true, timestamp: Number(stamp) });
    assert.deepEqual(verifyTelnyxSignature({ payload: body, signatureHeader: signature, timestampHeader: stamp, publicKeys: [[KEY]] as never, now }), { ok: false, reason: "no_secret" });
  });
});

describe("the reference server's carrier routes check the bytes received", () => {
  async function serve(ctx: TestContext) {
    const t = createTestEngine();
    const server = createReferenceServer({
      engine: t.engine,
      stripeSecrets: { identity: [], payments: [] },
      clock: t.clock,
      carriers: { twilio: { authTokens: [TOKEN], publicOrigin: "https://voice.example.test" }, telnyx: { publicKeys: [KEY] } },
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    ctx.after(
      () =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    );
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    return { t, post: async (path: string, body: Uint8Array, headers: Record<string, string>) => {
      const res = await fetch(`${base}${path}`, { method: "POST", body, headers });
      return [res.status, await res.json()];
    } };
  }

  it("Telnyx: a body that is not valid UTF-8 never verifies under another body's signature", async (ctx) => {
    const s = await serve(ctx);
    const at = `${Math.floor(s.t.clock.now().getTime() / 1000)}`;
    const signature = sign(null, Buffer.concat([Buffer.from(`${at}|`), SIGNED]), PRIVATE).toString("base64");
    const headers = { "content-type": "application/json", "telnyx-signature-ed25519": signature, "telnyx-timestamp": at };
    assert.deepEqual(await s.post("/webhooks/telnyx", SIGNED, headers), [200, { received: true }]);
    assert.deepEqual(await s.post("/webhooks/telnyx", FORGED, headers), [400, { error: "signature", reason: "no_matching_signature" }]);
    const own = sign(null, Buffer.concat([Buffer.from(`${at}|`), FORGED]), PRIVATE).toString("base64");
    assert.deepEqual(await s.post("/webhooks/telnyx", FORGED, { ...headers, "telnyx-signature-ed25519": own }), [200, { received: true }], "signed as sent");
  });

  it("Twilio: bodySHA256 is taken over the bytes received", async (ctx) => {
    const s = await serve(ctx);
    const path = `/webhooks/twilio?bodySHA256=${createHash("sha256").update(SIGNED).digest("hex")}`;
    const header = createHmac("sha1", TOKEN).update(`https://voice.example.test${path}`).digest("base64");
    const headers = { "content-type": "application/json", "x-twilio-signature": header };
    assert.deepEqual(await s.post(path, SIGNED, headers), [200, { received: true }]);
    assert.deepEqual(await s.post(path, FORGED, headers), [400, { error: "signature", reason: "body_hash_mismatch" }]);
  });

  it("Twilio: a form body is still signed by its parameters", async (ctx) => {
    const s = await serve(ctx);
    const header = createHmac("sha1", TOKEN).update("https://voice.example.test/webhooks/twilioCallSidCA1Digits1234").digest("base64");
    const headers = { "content-type": "application/x-www-form-urlencoded", "x-twilio-signature": header };
    assert.deepEqual(await s.post("/webhooks/twilio", Buffer.from("Digits=1234&CallSid=CA1"), headers), [200, { received: true }]);
  });
});
