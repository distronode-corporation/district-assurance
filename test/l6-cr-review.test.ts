// CodeRabbit's review of 31ebecf on #136: three claims in the docs, each held to the code.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import type { AttemptCounterKey } from "../src/core/adapters.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { MemoryAttemptCounters, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, setup } from "./helpers.ts";

const flat = (name: string): string => readFileSync(new URL(`../${name}`, import.meta.url), "utf8").replace(/\s+/g, " ");
const spec = flat("SPEC.md");
const model = flat("SECURITY-MODEL.md");

const LONG_AGO = "2000-01-01T00:00:00.000Z";
const subjectPin: AttemptCounterKey = { workspaceId: "ws_test", factor: "pin", scope: "subject", key: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT) };

async function call(t: TestEngine, callingNumber: string): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT, callingNumber });
  return callId;
}

/** Runs `onFirst` once, right after the first failure is recorded, before that entry is judged. */
class AfterFirstRecord extends MemoryAttemptCounters {
  onFirst: (() => Promise<void>) | null = null;
  override async recordFailure(key: AttemptCounterKey, at: string, since: string): Promise<string[]> {
    const failures = await super.recordFailure(key, at, since);
    const next = this.onFirst;
    this.onFirst = null;
    if (next !== null) await next();
    return failures;
  }
}

describe("docs held to the code (#136 review)", () => {
  it("SECURITY-MODEL keeps the call's duress state apart from the subject's flag", () => {
    assert.doesNotMatch(model, /the duress state is kept only in the call record/);
    assert.match(model, /the call's duress state is kept in the call record, and the subject's flag \(below\) in the attempt counters store/);
  });

  it("SECURITY-MODEL scopes the access code odds to a uniformly random newCode, the host's when it supplies one", () => {
    assert.match(model, /8 digits from the default generator \(`randomInt` from node:crypto\) give one chance in 100 million/);
    assert.match(model, /a host that supplies `newCode` must draw each code uniformly at random/);
  });

  it("SPEC tells apart a lock seen on the first read from one seen in recordFailure's list", () => {
    assert.doesNotMatch(spec, /once; if it fails, both failures stand and the second waits the longer wait for two\./);
    assert.match(spec, /A second that saw the first's failure when it read the counters recorded none of its own/);
    assert.match(spec, /one that saw it only in the list `recordFailure` returned has its own failure recorded too, unjudged/);
  });

  it("a second entry that sees the first's failure on its first read records none, so one failure stands when the first fails", async () => {
    const counters = new AfterFirstRecord();
    const t = setup({ adapters: { counters } });
    const one = await call(t, "+15555550142");
    const two = await call(t, "+15555550143");
    let second: unknown = null;
    counters.onFirst = async () => {
      second = await t.engine.submitPin(two, "4826");
    };
    assert.deepEqual(await t.engine.submitPin(one, "0000"), { matched: false, locked: false });
    assert.deepEqual(second, { matched: false, locked: true }, "the second met the first's provisional failure and waited, unjudged");
    assert.equal((await t.counters.get(subjectPin, LONG_AGO)).length, 1, "only the first's failure stands on the subject");
    t.clock.advance(5_000);
    assert.deepEqual(await t.engine.submitPin(two, "4826"), { matched: true, locked: false }, "the wait for one failure is enough");
  });
});
