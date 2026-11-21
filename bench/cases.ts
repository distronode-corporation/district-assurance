// The cases `npm run bench` measures: engine costs on the memory adapters and the fakes of
// `district-assurance/testing`, never the cost of a store, a carrier or a provider. Every case checks
// its own result once before it is timed, so a case that stops doing its work fails the run
// instead of getting faster.
import { strict as assert } from "node:assert";

import {
  MemoryAuditLedger,
  defaultConfig,
  signReceipt,
  validateConfig,
  verifyReceipt,
  type AuditInput,
  type FlowConfig,
  type ReceiptBody,
} from "../src/index.ts";
import { hmacSha256Hex } from "../src/core/hash.ts";
import { checkPinRecord, hashPinRecord } from "../src/verify/pin-hash.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, generateTestSigner, testSubject, type TestEngine } from "../src/testing/index.ts";
import type { BenchCase } from "./harness.ts";

// Made-up values, not secrets: a 555 number and the test knowledge key.
const ACCOUNT = "12345678";
const DOB = "19850214";
const PIN = "4826";
const PHONE_ON_FILE = "+15555550100";

/** The demo's two flows: `owner-command` (a PIN, level 1) and `deposit` (keypad and carrier, level 2). */
export function benchConfig(): FlowConfig {
  const config = defaultConfig();
  config.revision = "bench-1";
  config.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"]] };
  config.policy.scopes["owner.command"] = 1;
  config.policy.scopeClasses = { "owner.command": "none" };
  config.modules.badge = {
    settings: {
      factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id"],
      pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
    },
  };
  config.modules.dossier = { settings: { forms: [form("maintenance", 2)] } };
  config.modules.trace = { settings: { receipts: true, wordings: [wording("repair_texts")] } };
  config.flows = {
    "owner-command": { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] },
    deposit: {
      steps: [
        { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
        { type: "dossier.collect", form: "maintenance" },
        { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" },
        { type: "trace.consent", purpose: "repair_texts" },
        { type: "trace.receipt" },
      ],
    },
  };
  return config;
}

function form(formId: string, fieldCount: number) {
  const types = ["text", "number", "date", "yes_no"] as const;
  return {
    formId,
    version: "1",
    fields: Array.from({ length: fieldCount }, (_, i) => ({
      key: `field_${i}`,
      label: { en: `Question ${i}`, fr: `Question ${i}` },
      type: types[i % types.length]!,
      required: i % 2 === 0,
    })),
  };
}

function wording(purpose: string) {
  return { purpose, version: "1", text: { en: "May we text you?", fr: "Pouvons-nous vous texter?" } };
}

/**
 * A large workspace config: 50 more forms of 20 fields, 50 more consent wordings and 500 more flows (half like
 * `owner-command`, half like `deposit`, each on its own form and wording), every one valid.
 */
export function largeConfig(): FlowConfig {
  const config = benchConfig();
  config.revision = "bench-large-1";
  // benchConfig's own two flows stay, so its form and wording do too.
  const forms = [form("maintenance", 2), ...Array.from({ length: 50 }, (_, i) => form(`form_${i}`, 20))];
  const wordings = [wording("repair_texts"), ...Array.from({ length: 50 }, (_, i) => wording(`purpose_${i}`))];
  config.modules.dossier = { settings: { forms } };
  config.modules.trace = { settings: { receipts: true, wordings } };
  for (let i = 0; i < 250; i++) {
    config.flows[`owner-${i}`] = { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] };
    config.flows[`deposit-${i}`] = {
      summary: `Deposit ${i}`,
      steps: [
        { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["intake.file", "payment.request"] },
        { type: "dossier.collect", form: `form_${i % 50}` },
        { type: "paylink.request", amountMinor: 1000 + i, currency: "cad", description: `Deposit ${i}`, amountSource: "price_list" },
        { type: "trace.consent", purpose: `purpose_${i % 50}` },
        { type: "trace.receipt" },
      ],
    };
  }
  return config;
}

/** A test engine on `benchConfig()`, one subject on file, and a carrier that answers `match`. */
function benchEngine(): { t: TestEngine; subjectKey: string } {
  const t = createTestEngine({ config: benchConfig() });
  const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge: { dob: DOB }, pin: PIN });
  t.records.putSubject("ws_test", subject);
  t.carrier.set(PHONE_ON_FILE, { identityMatch: "match" });
  return { t, subjectKey: subject.subjectKey };
}

function receiptBody(seq: number): ReceiptBody {
  return {
    v: 1,
    receiptId: `rcpt_${seq}`,
    callId: `call_${seq}`,
    workspaceId: "ws_test",
    startedAt: "2026-01-01T00:00:00.000Z",
    endedAt: "2026-01-01T00:04:00.000Z",
    issuedAt: "2026-01-01T00:04:00.000Z",
    verification: { level: 2, methods: ["keypad_knowledge", "carrier_identity_match"] },
    records: [{ recordId: "rec_1", formId: "maintenance", digest: "a".repeat(64) }],
    payments: [{ paymentId: "pay_1", status: "paid", amountMinor: 15000, currency: "cad", mode: "platform", providerRef: "cs_fake_1" }],
    consents: [{ purpose: "repair_texts", wordingVersion: "1", wordingDigest: "b".repeat(64), answer: "yes" }],
    ledger: { seq, hash: "c".repeat(64) },
  };
}

export const cases: readonly BenchCase[] = [
  {
    name: "owner-command flow",
    unit: "start, PIN, finish, authorize, end",
    async setup() {
      const { t, subjectKey } = benchEngine();
      const run = async (): Promise<boolean> => {
        const { callId } = await t.engine.startCall({ locale: "en", flow: "owner-command" });
        await t.engine.beginVerification(callId, { subjectKey });
        await t.engine.submitPin(callId, PIN);
        await t.engine.finishVerification(callId);
        const allowed = await t.engine.authorize(callId, "owner.command");
        await t.engine.endCall(callId);
        return allowed;
      };
      assert.equal(await run(), true);
      return run;
    },
  },
  {
    name: "PIN record check",
    unit: "one Argon2id check of a keyed PIN against its record (ADR-29)",
    async setup() {
      const keyedPin = hmacSha256Hex(TEST_KNOWLEDGE_KEY, `pin:${"a".repeat(64)}:${PIN}`);
      const record = await hashPinRecord(keyedPin);
      const run = async (): Promise<boolean> => (await checkPinRecord(record, keyedPin)).match;
      assert.equal(await run(), true);
      return run;
    },
  },
  {
    name: "level 2 verification",
    unit: "start, keypad, carrier, finish",
    async setup() {
      const { t } = benchEngine();
      const run = async (): Promise<number> => {
        // The deposit flow needs payment.request, so its starts are counted per subject (VER-15, at
        // most 5 an hour): each run starts an hour after the last, so the limit never refuses one.
        t.clock.advance(3_600_000);
        const { callId } = await t.engine.startCall({ locale: "en", flow: "deposit" });
        await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
        await t.engine.submitKeypad(callId, { dob: DOB });
        await t.engine.checkCarrier(callId);
        return (await t.engine.finishVerification(callId)).level;
      };
      assert.equal(await run(), 2);
      return run;
    },
  },
  {
    name: "ledger append",
    unit: "one entry, hashed and chained",
    async setup() {
      const ledger = new MemoryAuditLedger();
      let n = 0;
      const run = async () => {
        n++;
        const input: AuditInput = {
          eventId: `evt_${n}`,
          callId: "call_1",
          actor: "code",
          event: "verification.factor",
          at: "2026-01-01T00:00:00.000Z",
          detail: { factor: "keypad_knowledge", matched: true, attempt: 1 },
        };
        return ledger.append(input);
      };
      assert.equal((await run()).seq, 1);
      return run;
    },
  },
  {
    name: "receipt sign",
    unit: "ES256 over canonical JSON",
    async setup() {
      const signer = generateTestSigner();
      let n = 0;
      const run = () => signReceipt(signer, receiptBody(++n));
      assert.equal(verifyReceipt(await run(), [signer.publicJwk()]), true);
      return run;
    },
  },
  {
    name: "receipt verify",
    unit: "import the key, check the signature",
    async setup() {
      const signer = generateTestSigner();
      const keys = [signer.publicJwk()];
      const receipt = await signReceipt(signer, receiptBody(1));
      const run = () => verifyReceipt(receipt, keys);
      assert.equal(run(), true);
      return run;
    },
  },
  {
    name: "validateConfig, large",
    unit: "500 flows, 50 forms, 50 wordings",
    async setup() {
      const config = largeConfig();
      const registry = createTestEngine({ config: benchConfig() }).engine.registry;
      const run = () => validateConfig(config, registry);
      assert.deepEqual(run(), []);
      return run;
    },
  },
];
