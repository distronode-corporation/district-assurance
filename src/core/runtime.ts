// What the built-in modules see of the engine while they run a step: the call record, a way to
// change it (one compare-and-set write per change), the adapters and the clock. This is internal
// to the package; outside modules use `Engine.updateModule` and `Engine.moduleState` instead.
import type {
  AuditLedger,
  AuditInput,
  CarrierSignals,
  ConsentStore,
  IdentityProvider,
  MessageSender,
  PaymentLinks,
  PinVerifier,
  ReceiptSigner,
  RecordStore,
  SessionStore,
} from "./adapters.ts";
import type { JsonValue } from "./canonical.ts";
import type { Clock, IdGenerator } from "./clock.ts";
import type { Actor, EngineEventName } from "./events.ts";
import type { FlowStep } from "./module.ts";
import type { VerificationPolicy } from "./policy.ts";
import type { SessionEvent, SessionState } from "./session.ts";

export type Locale = "en" | "fr";

/**
 * Everything the engine can be given. Only `ledger` is always required (the ledger is always on);
 * `sessions` defaults to a `MemorySessionStore`. Each module says which of the others it needs, and
 * `validateConfig` refuses a config whose modules need an adapter the engine lacks.
 */
export interface EngineAdapters {
  ledger: AuditLedger;
  sessions?: SessionStore;
  records?: RecordStore;
  identity?: IdentityProvider;
  carrier?: CarrierSignals;
  messages?: MessageSender;
  payments?: PaymentLinks;
  signer?: ReceiptSigner;
  pinVerifier?: PinVerifier;
  /** Where consents are kept so they can be revoked after the call. Without it, `revokeConsent` is refused. */
  consents?: ConsentStore;
}

export type AdapterName = keyof EngineAdapters;

export type FlowStatus = "running" | "completed" | "failed" | "abandoned";

/** Where a call is in its flow. The steps are copied in when the flow starts, so a config change never moves a call. */
export interface FlowCursor {
  name: string;
  revision: string;
  steps: FlowStep[];
  index: number;
  mark: JsonValue;
  status: FlowStatus;
}

/** One call, as the SessionStore holds it. JSON only. */
export interface CallRecord {
  v: 1;
  state: SessionState;
  locale: Locale;
  /** The config revision the call started under. */
  revision: string;
  flow: FlowCursor | null;
  /** Each module's own part, by module name. */
  modules: Record<string, JsonValue>;
  /** Ledger entries saved with a change and not yet known to be appended. */
  outbox: Array<{ eventId: string; name: EngineEventName; actor: Actor; at: string; detail: { [key: string]: JsonValue } }>;
}

/** A call being changed inside one compare-and-set attempt. Everything here is synchronous and pure. */
export interface CallDraft {
  readonly record: CallRecord;
  /** The module's own part of the record, to read and change in place. */
  slice<T>(module: string): T;
  apply(event: SessionEvent): void;
  assertCan(event: SessionEvent): void;
  /** Queues a ledger entry, written once the change is saved. */
  emit(name: EngineEventName, actor: Actor, detail: { [key: string]: JsonValue }): void;
  /** The flow step the call is on, or null when no flow is running. */
  step(): FlowStep | null;
}

export interface EngineRuntime {
  readonly workspaceId: string;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly policy: VerificationPolicy;
  now(): string;
  /** HMAC-SHA256 under the workspace's knowledge key, hex. The key itself never leaves the engine. */
  hmac(data: string): string;
  /** The module's validated settings. Throws `module_disabled` when it is off. */
  settings<T>(module: string): T;
  adapter<K extends AdapterName>(name: K): NonNullable<EngineAdapters[K]>;
  /** One step: read the call, change it with `fn`, write it with compare-and-set, retrying from a fresh read on conflict. */
  update<R>(callId: string, fn: (draft: CallDraft) => R): Promise<R>;
  read(callId: string): Promise<CallRecord>;
  /**
   * Appends one ledger entry that belongs to no write of a call record (a consent revoked after
   * the call), then tells the listener. Idempotent by `eventId`, like every append.
   */
  append(entry: AuditInput & { eventId: string; callId: string }): Promise<void>;
  /** Appends a call's pending ledger entries, in order. */
  flushLedger(callId: string): Promise<void>;
  /** Whether the call's grant covers a scope now. */
  authorized(record: CallRecord, scope: string): boolean;
  bindRef(ref: string, callId: string): Promise<void>;
  /** An idempotency key for a provider call, unique across workspaces and stable across retries. */
  idempotencyKey(callId: string, ...parts: string[]): string;
  resolveRef(ref: string): Promise<string | null>;
}
