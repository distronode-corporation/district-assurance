// judgeKeypadWith compares the fields it hashed: a field the caller adds while the HMACs are
// pending is neither hashed nor compared (cr-main, knowledge.ts:107).
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { TEST_KNOWLEDGE_KEY, testSubject } from "../src/testing/index.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { judgeKeypadWith } from "../src/verify/knowledge.ts";

describe("judgeKeypadWith: the field list is read once", () => {
  it("a field added while the HMACs are pending changes nothing", async () => {
    const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214", zip: "12345" } });
    const fields = ["dob"];
    const hmac = async (data: string): Promise<string> => {
      fields.push("zip");
      return hmacSha256Hex(TEST_KNOWLEDGE_KEY, data);
    };
    assert.equal(await judgeKeypadWith(hmac, subject, fields, { dob: "19850214" }), true, "judged on dob, as it was asked");
  });
});
