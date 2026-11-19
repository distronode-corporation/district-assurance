// `district-assurance/testing`: fakes, contract suites and a ready-wired engine for tests and demos.
import type { AttemptCounters, SessionStore } from "../core/adapters.ts";
import type { EngineAdapters } from "../core/runtime.ts";
import { MemorySessionStore } from "../core/session-store.ts";
import { createEngine, type Engine, type EngineOptions } from "../engine.ts";
import { MemoryAuditLedger } from "../prove/ledger.ts";
import {
  FakeCallbackDialer,
  FakeCarrierSignals,
  FakeIdentityProvider,
  FakeMessageSender,
  FakePaymentLinks,
  FakePinVerifier,
  FixedClock,
  MemoryAttemptCounters,
  MemoryRecordStore,
  SequentialIds,
  generateTestSigner,
} from "./fakes.ts";

export * from "./contracts.ts";
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
  sessions: SessionStore;
  pinVerifier: FakePinVerifier;
  counters: AttemptCounters;
  dialer: FakeCallbackDialer;
}

export type TestEngineOptions = Partial<Omit<EngineOptions, "adapters">> & {
  /** Replace or remove (with `undefined`) any of the fakes. */
  adapters?: Partial<{ [K in keyof EngineAdapters]: EngineAdapters[K] | undefined }>;
};

/**
 * An engine on fakes only: a fixed clock, sequential ids, in-memory stores, a throwaway signing key,
 * every adapter wired, and `defaultConfig()` unless a config is given.
 */
export function createTestEngine(options: TestEngineOptions = {}): TestEngine {
  const parts = {
    clock: new FixedClock(),
    ids: new SequentialIds(),
    identity: new FakeIdentityProvider(),
    carrier: new FakeCarrierSignals(),
    messages: new FakeMessageSender(),
    payments: new FakePaymentLinks(),
    records: new MemoryRecordStore(),
    ledger: new MemoryAuditLedger(),
    sessions: new MemorySessionStore() as SessionStore,
    pinVerifier: new FakePinVerifier(),
    counters: new MemoryAttemptCounters() as AttemptCounters,
    dialer: new FakeCallbackDialer(),
  };
  const { adapters: overrides = {}, ...rest } = options;
  const adapters = {
    identity: parts.identity,
    carrier: parts.carrier,
    messages: parts.messages,
    payments: parts.payments,
    records: parts.records,
    ledger: parts.ledger,
    sessions: parts.sessions,
    pinVerifier: parts.pinVerifier,
    counters: parts.counters,
    dialer: parts.dialer,
    signer: generateTestSigner(),
    ...overrides,
  } as EngineAdapters;
  if (overrides.sessions !== undefined) parts.sessions = overrides.sessions;
  if (overrides.counters !== undefined) parts.counters = overrides.counters;
  const engine = createEngine({ workspaceId: "ws_test", knowledgeKey: TEST_KNOWLEDGE_KEY, clock: parts.clock, ids: parts.ids, ...rest, adapters });
  return { engine, ...parts };
}
