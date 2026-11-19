import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { canonicalJson } from "../src/core/canonical.ts";
import { randomIds, systemClock } from "../src/core/clock.ts";
import { EngineError, NotImplementedError } from "../src/core/errors.ts";
import { hexDigestsEqual, hmacSha256Hex, sha256Hex } from "../src/core/hash.ts";

describe("canonicalJson", () => {
  it("sorts keys, drops whitespace and serialises like JSON.stringify", () => {
    assert.equal(canonicalJson({ b: 1, a: [true, false, null, "x"], c: { z: 1.5, y: -0 } }), '{"a":[true,false,null,"x"],"b":1,"c":{"y":0,"z":1.5}}');
    assert.equal(canonicalJson("é\u2028\n"), '"é\u2028\\n"');
    assert.equal(canonicalJson(1e21), "1e+21");
    assert.equal(canonicalJson([]), "[]");
    assert.equal(canonicalJson({}), "{}");
  });

  it("sorts by UTF-16 code units", () => {
    assert.equal(canonicalJson({ "\u20ac": 1, "\r": 2, "\ud83d\ude00": 3, a: 4 }), '{"\\r":2,"a":4,"\u20ac":1,"\ud83d\ude00":3}');
  });

  it("accepts null-prototype objects", () => {
    const value = Object.create(null) as Record<string, number>;
    value.k = 1;
    assert.equal(canonicalJson(value), '{"k":1}');
  });

  it("refuses a lone UTF-16 surrogate in a string or a key, as RFC 8785 requires, and keeps valid pairs", () => {
    assert.throws(() => canonicalJson({ a: "x\ud800" }), /lone surrogate in a string at \$\.a/);
    assert.throws(() => canonicalJson(["\udc00y"]), /lone surrogate in a string at \$\[0\]/);
    assert.throws(() => canonicalJson({ ["k\ud83d"]: 1 }), /lone surrogate in a string at \$/, "in a key");
    assert.throws(() => canonicalJson("\ud800\ud800\udc00"), /lone surrogate/, "a high surrogate followed by a pair");
    assert.equal(canonicalJson({ "\ud83d\ude00": "\ud83d\ude00" }), '{"\ud83d\ude00":"\ud83d\ude00"}', "a valid pair passes");
  });

  it("refuses values JSON cannot carry faithfully, naming the path", () => {
    assert.throws(() => canonicalJson({ a: undefined }), /unsupported undefined at \$\.a/);
    assert.throws(() => canonicalJson([1, () => 1]), /unsupported function at \$\[1\]/);
    assert.throws(() => canonicalJson(Symbol("s")), /unsupported symbol/);
    assert.throws(() => canonicalJson(1n), /unsupported bigint/);
    assert.throws(() => canonicalJson({ n: Number.NaN }), /non-finite number at \$\.n/);
    assert.throws(() => canonicalJson(Number.POSITIVE_INFINITY), /non-finite/);
    assert.throws(() => canonicalJson({ d: new Date(0) }), /not a plain object at \$\.d/);
    assert.throws(() => canonicalJson(new Map()), /not a plain object/);
    // eslint-disable-next-line no-sparse-arrays
    assert.throws(() => canonicalJson([1, , 2]), /unsupported undefined at \$\[1\]/);
  });
});

describe("hash", () => {
  it("hashes and keys to lower-case hex", () => {
    assert.equal(sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert.equal(sha256Hex(new Uint8Array([0x61, 0x62, 0x63])), sha256Hex("abc"));
    // RFC 4231 test case 2.
    assert.equal(hmacSha256Hex("Jefe", "what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  });

  it("compares digests in constant time and refuses anything that is not lower-case hex", () => {
    const a = sha256Hex("a");
    assert.equal(hexDigestsEqual(a, a), true);
    assert.equal(hexDigestsEqual(a, sha256Hex("b")), false);
    assert.equal(hexDigestsEqual(a, a.slice(2)), false);
    assert.equal(hexDigestsEqual(a.toUpperCase(), a.toUpperCase()), false);
    assert.equal(hexDigestsEqual("zz", "zz"), false);
    assert.equal(hexDigestsEqual("ab", "zz"), false);
    assert.equal(hexDigestsEqual("", ""), true);
  });
});

describe("clock and ids", () => {
  it("reads the system clock", () => {
    const before = Date.now();
    const now = systemClock.now().getTime();
    assert.ok(now >= before && now <= Date.now());
  });

  it("mints distinct prefixed url-safe ids", () => {
    const a = randomIds.next("call");
    assert.match(a, /^call_[A-Za-z0-9_-]{16}$/);
    assert.notEqual(a, randomIds.next("call"));
  });
});

describe("errors", () => {
  it("names the feature and the roadmap issue", () => {
    const e = new NotImplementedError("thing", "VER-9");
    assert.equal(e.name, "NotImplementedError");
    assert.equal(e.feature, "thing");
    assert.equal(e.issue, "VER-9");
    assert.match(e.message, /thing is not implemented yet \(ROADMAP\.md, VER-9\)/);
    assert.ok(e instanceof Error);
  });

  it("carries a stable code", () => {
    const e = new EngineError("scope_denied", "no");
    assert.equal(e.name, "EngineError");
    assert.equal(e.code, "scope_denied");
    assert.equal(e.message, "no");
  });
});
