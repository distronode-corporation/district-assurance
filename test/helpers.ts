// Shared test fixtures: a config with every built-in module on, a form, a wording and the PIN factor.
import { strict as assert } from "node:assert";

import type { JsonValue } from "../src/core/canonical.ts";
import type { FlowConfig } from "../src/core/config.ts";
import { EngineError, type EngineErrorCode } from "../src/core/errors.ts";
import type { Engine } from "../src/engine.ts";
import type { IntakeForm } from "../src/file/intake.ts";
import { defaultConfig } from "../src/modules.ts";
import type { PaymentInput } from "../src/pay/paylink.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine, type TestEngineOptions } from "../src/testing/index.ts";

export const ACCOUNT = "12345678";
export const DOB = "19850214";
export const PIN = "4826";
export const PHONE_ON_FILE = "+15555550100";

export const form: IntakeForm = {
  formId: "repair",
  version: "1",
  fields: [
    { key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true },
    { key: "urgent", label: { en: "Urgent", fr: "Urgent" }, type: "yes_no", required: false },
  ],
};

export const wording = { purpose: "texts", version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };

/** Every built-in module on, the PIN factor in keyed-hash mode, one form and one wording, no flows. */
export function testConfig(patch: (config: FlowConfig) => void = () => undefined): FlowConfig {
  const config = defaultConfig();
  config.modules.badge = {
    settings: {
      factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"],
      pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
    },
  };
  config.modules.dossier = { settings: { forms: [structuredClone(form)] } as unknown as JsonValue };
  config.modules.trace = { settings: { receipts: true, wordings: [structuredClone(wording)] } };
  patch(config);
  return config;
}

/** A test engine on `testConfig()` with one subject on file (account, date of birth and PIN). */
export function setup(options: TestEngineOptions = {}): TestEngine {
  const t = createTestEngine({ config: testConfig(), ...options });
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN }));
  return t;
}

export const rejects = (code: EngineErrorCode, message?: RegExp) => (e: unknown) =>
  e instanceof EngineError && e.code === code && (message === undefined || message.test(e.message));

/** Reads the amount back and has the caller confirm it, as every payment link needs (PAY-2). */
export async function confirmAmount(engine: Engine, callId: string, input?: PaymentInput): Promise<void> {
  const back = await engine.readBackPayment(callId, input);
  await engine.confirmPaymentAmount(callId, { digest: back.digest, confirmedBy: "keypad" });
}

/** A call verified to level 3 by keypad and photo ID, in the open phase. */
export async function verifiedCall(t: TestEngine, locale: "en" | "fr" = "en"): Promise<string> {
  const { callId } = await t.engine.startCall({ locale });
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  assert.deepEqual(await t.engine.submitKeypad(callId, { dob: DOB }), { matched: true, locked: false });
  await t.engine.startPhotoId(callId);
  const sessionId = t.identity.created.at(-1)!.sessionId;
  assert.deepEqual(await t.engine.applyIdentityOutcome({ sessionId, status: "verified" }), { applied: true, callId });
  assert.equal((await t.engine.finishVerification(callId)).level, 3);
  return callId;
}
