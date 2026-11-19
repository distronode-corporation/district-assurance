// Hostile pass on #79 (VER-2 texted codes), kept as regressions: each attack asserts the safe behaviour.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import { MemoryCodeStore, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, DOB, setup, testConfig } from "./helpers.ts";

const CALLING = "+15555550199";

function codeSetup(codes: unknown = new MemoryCodeStore(), patch: (c: FlowConfig) => void = () => undefined): TestEngine {
  const config = testConfig((c) => {
    c.modules.badge = { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "text_code"] } };
    c.policy.textCodeCountryCodes = ["1"];
    c.modules.trace = { settings: { receipts: true, wordings: [] } };
    patch(c);
  });
  return setup({ config, adapters: { codes: codes as MemoryCodeStore } });
}

async function matchedCall(t: TestEngine, callingNumber?: string): Promise<string> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, callingNumber === undefined ? { accountNumber: ACCOUNT } : { accountNumber: ACCOUNT, callingNumber });
  assert.equal((await t.engine.submitKeypad(callId, { dob: DOB })).matched, true);
  return callId;
}

const settle = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

describe("#79 hostile: can a caller tell a refused send?", () => {
  it("C1 with a calling number, a send refused by the subject's limit makes the same store calls before the reply as a sent one", async () => {
    const trace = async (refuseSubject: boolean) => {
      const steps: string[] = [];
      const store = new MemoryCodeStore();
      const codes = {
        take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => {
          steps.push(`codes.take`);
          return refuseSubject && input.key.scope === "subject" ? false : store.take(input);
        },
      };
      const t = codeSetup(codes);
      const callId = await matchedCall(t, CALLING);
      steps.length = 0;
      t.messages.sendText = () => new Promise(() => undefined);
      assert.deepEqual(await t.engine.sendTextCode(callId), { sent: true });
      return steps;
    };
    assert.deepEqual(await trace(true), await trace(false));
  });

  it("C1b ...and that refused send is counted on the number too", async () => {
    const store = new MemoryCodeStore();
    const codes = { take: async (input: Parameters<MemoryCodeStore["take"]>[0]) => (input.key.scope === "subject" ? false : store.take(input)) };
    const t = codeSetup(codes);
    const callId = await matchedCall(t, CALLING);
    await t.engine.sendTextCode(callId);
    await settle();
    assert.deepEqual((await t.ledger.list()).filter((e) => e.event === "verification.code_refused").map((e) => e.detail), [{ reason: "subject_limit" }]);
    const numberKey = (await t.sessions.get("ws_test", callId))!.record as unknown as { modules: { badge: { numberKey: string } } };
    assert.equal(await store.take({ workspaceId: "ws_test", key: { scope: "number", key: numberKey.modules.badge.numberKey }, at: t.clock.now().toISOString(), max: 10, windowSeconds: 86_400, minIntervalSeconds: 60 }), false, "the number already has a send within 60 seconds");
  });
});

describe("#79 hostile: the ledger after the receipt", () => {
  /** An SMS adapter that holds each answer until told. */
  function holding(t: TestEngine) {
    const answers: Array<() => void> = [];
    t.messages.sendText = () => new Promise((r) => answers.push(() => r({ messageId: "m" })));
    return answers;
  }
  const after = async (t: TestEngine, callId: string) => {
    const ledger = (await t.ledger.list()).filter((e) => e.callId === callId);
    return ledger.slice(ledger.findIndex((e) => e.event === "receipt.issued") + 1).map((e) => e.event);
  };

  it("C2 the call does not end while a send is with the SMS adapter, so code_sent lands before receipt.issued", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    const answers = holding(t);
    await t.engine.sendTextCode(callId);
    await settle();
    await assert.rejects(t.engine.endCall(callId), (e: unknown) => (e as { code?: string }).code === "precondition_failed");
    answers[0]!();
    await settle();
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await after(t, callId), []);
    assert.ok((await t.ledger.list()).some((e) => e.event === "verification.code_sent"));
  });

  it("C3 a refused send's entry, saved and still being appended when the call ends, lands before the receipt", async () => {
    const t = codeSetup(undefined, (c) => (c.policy.textCodeCountryCodes = ["44"]));
    const callId = await matchedCall(t);
    holding(t);
    const held = t.ledger.append.bind(t.ledger);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let once = true;
    t.ledger.append = async (input) => {
      if (once && input.event === "verification.code_refused") {
        once = false;
        await gate;
      }
      return held(input);
    };
    await t.engine.sendTextCode(callId);
    await settle();
    // The entry is in the call's outbox: the end appends it first, then its own.
    assert.notEqual(await t.engine.endCall(callId), null);
    release();
    await settle();
    assert.deepEqual(await after(t, callId), []);
    assert.ok((await t.ledger.list()).some((e) => e.event === "verification.code_refused"));
  });

  it("C4 past the hold the call ends, and an answer after it writes nothing", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    const answers = holding(t);
    await t.engine.sendTextCode(callId);
    await settle();
    t.clock.advance(30_000);
    assert.notEqual(await t.engine.endCall(callId), null);
    answers[0]!();
    await settle();
    assert.deepEqual(await after(t, callId), []);
  });

  it("C5 a second send while the first is with the adapter keeps holding until its own entry is written", async () => {
    const t = codeSetup();
    const callId = await matchedCall(t);
    const answers = holding(t);
    await t.engine.sendTextCode(callId);
    await settle();
    t.clock.advance(61_000);
    await t.engine.sendTextCode(callId);
    await settle();
    answers[0]!();
    await settle();
    await assert.rejects(t.engine.endCall(callId), (e: unknown) => (e as { code?: string }).code === "precondition_failed", "the second send still holds");
    answers[1]!();
    await settle();
    assert.notEqual(await t.engine.endCall(callId), null);
    assert.deepEqual(await after(t, callId), []);
  });
});

describe("#79 hostile: where a code may go", () => {
  it("C6 textCodeCountryCodes takes only assigned E.164 country codes, or longer prefixes of one", async () => {
    const { validatePolicy, defaultVerificationPolicy, E164_COUNTRY_CODES } = await import("../src/core/policy.ts");
    const errors = (codes: unknown) => validatePolicy({ ...defaultVerificationPolicy(), textCodeCountryCodes: codes } as never).filter((e) => e.includes("textCodeCountryCodes"));
    for (const bad of [["4"], ["42"], ["0"], ["2"], ["999"], ["800"], ["881"], ["1", "4"], ["+1"], ["1234567"]]) assert.notDeepEqual(errors(bad), [], JSON.stringify(bad));
    for (const good of [["1"], ["44"], ["33", "1"], ["1204"], ["4420"], ["383"], ["7"]]) assert.deepEqual(errors(good), [], JSON.stringify(good));
    for (const a of E164_COUNTRY_CODES) for (const b of E164_COUNTRY_CODES) if (a !== b) assert.equal(b.startsWith(a), false, `${a} is a prefix of ${b}`);
  });

  it("C7 global-service codes are refused, with longer prefixes, and SPEC and the list's comment name every one", async () => {
    const { readFile } = await import("node:fs/promises");
    const { validatePolicy, defaultVerificationPolicy, isAssignedCountryPrefix } = await import("../src/core/policy.ts");
    const globalService = ["800", "808", "870", "878", "881", "882", "883", "888", "979"];
    const errors = (codes: unknown) => validatePolicy({ ...defaultVerificationPolicy(), textCodeCountryCodes: codes } as never).filter((e) => e.includes("textCodeCountryCodes"));
    for (const code of globalService) {
      for (const prefix of [code, `${code}1`, `${code}12`]) {
        assert.equal(isAssignedCountryPrefix(prefix), false, prefix);
        assert.notDeepEqual(errors([prefix]), [], prefix);
        assert.notDeepEqual(errors(["1", prefix]), [], `1 and ${prefix}`);
      }
    }
    const spec = await readFile(new URL("../SPEC.md", import.meta.url), "utf8");
    const policySource = await readFile(new URL("../src/core/policy.ts", import.meta.url), "utf8");
    const listComment = policySource.slice(0, policySource.indexOf("export const E164_COUNTRY_CODES"));
    for (const code of globalService) {
      assert.match(spec, new RegExp(`\\b${code}\\b`), `SPEC names ${code}`);
      assert.match(listComment, new RegExp(`\\b${code}\\b`), `the list's comment names ${code}`);
    }
    assert.match(listComment, /not been checked against ITU-T/, "the list's comment says it is unverified");
  });
});
