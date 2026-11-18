// `district-assurance/testing`: fakes and a ready-wired engine for tests and demos.
import { createEngine, type Engine, type EngineOptions } from "../engine.ts";
import { MemoryAuditLedger } from "../prove/ledger.ts";
import {
  FakeCarrierSignals,
  FakeIdentityProvider,
  FakeMessageSender,
  FakePaymentLinks,
  FixedClock,
  MemoryRecordStore,
  SequentialIds,
  generateTestSigner,
} from "./fakes.ts";

export * from "./fakes.ts";

export const TEST_KNOWLEDGE_KEY = "test-knowledge-key-not-a-secret";

export interface TestEngine {
  engine: Engine;
  clock: FixedClock;
  ids: SequentialIds;
  identity: FakeIdentityProvider;
  carrier: FakeCarrierSignals;
  messages: FakeMessageSender;
  payments: FakePaymentLinks;
  records: MemoryRecordStore;
  ledger: MemoryAuditLedger;
}

/** An engine on fakes only: a fixed clock, sequential ids, in-memory stores, a throwaway key. */
export function createTestEngine(options: Partial<Omit<EngineOptions, "adapters">> = {}): TestEngine {
  const parts = {
    clock: new FixedClock(),
    ids: new SequentialIds(),
    identity: new FakeIdentityProvider(),
    carrier: new FakeCarrierSignals(),
    messages: new FakeMessageSender(),
    payments: new FakePaymentLinks(),
    records: new MemoryRecordStore(),
    ledger: new MemoryAuditLedger(),
  };
  const engine = createEngine({
    workspaceId: "ws_test",
    knowledgeKey: TEST_KNOWLEDGE_KEY,
    clock: parts.clock,
    ids: parts.ids,
    ...options,
    adapters: {
      identity: parts.identity,
      carrier: parts.carrier,
      messages: parts.messages,
      payments: parts.payments,
      records: parts.records,
      ledger: parts.ledger,
      signer: generateTestSigner(),
    },
  });
  return { engine, ...parts };
}
