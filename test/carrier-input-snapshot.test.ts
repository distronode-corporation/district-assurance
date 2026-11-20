// verifyTwilioSignature reads its input once: the URL whose bodySHA256 is taken is the URL whose
// signature is checked, and the header checked present is the header compared.
import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";

import { verifyTwilioSignature } from "../src/webhooks/carrier.ts";

const TOKEN = "12345";
const JSON_BODY = '{"property": "value", "boolean": true}';
const JSON_URL = "https://mycompany.com/myapp.php?foo=1&bar=2&bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

describe("verifyTwilioSignature reads its input once", () => {
  const header = createHmac("sha1", TOKEN).update(JSON_URL).digest("base64");

  it("checks the signature over the URL it took the body hash from", () => {
    const input = flipping({ payload: JSON_BODY, header, authTokens: [TOKEN] }, "url", JSON_URL, "https://mycompany.com/other.php");
    assert.deepEqual(verifyTwilioSignature(input as never), { ok: true });
  });

  it("compares the header it checked was present", () => {
    // Valid on the first read only: a check that reads the header again compares null, and fails.
    const input = flipping({ url: JSON_URL, payload: JSON_BODY, authTokens: [TOKEN] }, "header", header, null);
    assert.deepEqual(verifyTwilioSignature(input as never), { ok: true });
  });
});
