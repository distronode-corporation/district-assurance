// Hostile pass on #84 (VER-3 spoken answers), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { hmacSha256Hex } from "../src/core/hash.ts";
import type { SpokenPolicy } from "../src/core/policy.ts";
import { judgeSpoken } from "../src/verify/factors.ts";
import { normaliseSpokenAnswer } from "../src/verify/spoken.ts";
import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";

const read = (transcript: unknown, field: "ca_postal_code" | "us_zip_code" | "reference" = "ca_postal_code", locale: "en" | "fr" = "en") =>
  normaliseSpokenAnswer({ field, transcript: transcript as string, locale });

describe("#84 hostile: transcripts", () => {
  it("S1 look-alike characters never pass as the letters or digits they resemble", () => {
    for (const t of ["Ｋ１Ａ ０Ｂ１", "K1A 0B١", "K1A 0B¹", "K1A 0B1x"]) assert.deepEqual(read(t), { status: "unusable" }, JSON.stringify(t));
    // The Kelvin sign lower-cases to k: it is read as K, which is what it says.
    assert.deepEqual(read("K1A 0B1"), { status: "normalised", value: "K1A0B1" });
  });

  it("S2 a digit heard as 'for' next to a letter is never guessed: K for A is unusable", () => {
    assert.deepEqual(read("K for A 0 B 1"), { status: "unusable" });
    assert.deepEqual(read("K 4 A"), { status: "unusable" }, "not a postal code either way");
    assert.deepEqual(read("for K 1 A 0 B 1"), { status: "unusable" }, "a connector with nothing before it");
  });

  it("S3 non-strings, huge and control-laden transcripts are unusable, never a throw", () => {
    for (const t of [null, undefined, 12345, ["K1A0B1"], { toString: () => "K1A0B1" }, "K1A 0B1".repeat(40), "K1A\u00000B1", "K1A‮0B1"]) {
      assert.deepEqual(read(t), { status: "unusable" }, String(t));
    }
  });
});

describe("#84 hostile: the judge", () => {
  const hmac = (d: string) => hmacSha256Hex(TEST_KNOWLEDGE_KEY, d);
  const subject = (knowledge: Record<string, string>) => ({ subjectKey: "a".repeat(64), phoneOnFile: "+15555550100", knowledge });

  it("S4 an unusable answer never matches a value on file that is the digest of an empty answer", async () => {
    const spoken: SpokenPolicy = { fields: { postal_code: "ca_postal_code" }, maxAttemptsPerCall: 3 };
    const input = { workspaceId: "w", subjectKey: "a".repeat(64), subject: subject({ postal_code: hmac("field:postal_code:") }), entry: { postal_code: "nonsense" }, hmac, locale: "en" as const };
    assert.equal(await judgeSpoken(spoken, input as never), false);
  });

  it("S5 field names that are prototype keys judge like any other field, and an entry without them fails", async () => {
    const spoken = JSON.parse('{"fields": {"constructor": "us_zip_code", "__proto__": "us_zip_code"}, "maxAttemptsPerCall": 3}') as SpokenPolicy;
    const knowledge = JSON.parse(`{"constructor": "${hmac("field:constructor:90210")}", "__proto__": "${hmac("field:__proto__:10001")}"}`) as Record<string, string>;
    const base = { workspaceId: "w", subjectKey: "a".repeat(64), subject: subject(knowledge), hmac, locale: "en" as const };
    const entry = JSON.parse('{"constructor": "9 0 2 1 0", "__proto__": "1 0 0 0 1"}') as Record<string, string>;
    assert.equal(await judgeSpoken(spoken, { ...base, entry } as never), true);
    assert.equal(await judgeSpoken(spoken, { ...base, entry: {} } as never), false);
    assert.equal(await judgeSpoken(spoken, { ...base, subject: subject({}), entry } as never), false, "nothing on file");
  });
});
