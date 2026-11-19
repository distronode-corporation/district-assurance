// What the built-in modules see of the engine while they run a step: the call record, a way to
// change it (one compare-and-set write per change), the adapters and the clock. This is internal
// to the package; outside modules use `Engine.updateModule` and `Engine.moduleState` instead.
import type {
  AccessController,
  AmountSource,
  AttemptCounterKey,
  AttemptCounters,
  AuditLedger,
  CallbackDialer,
  CarrierSignals,
  DuressNotifier,
  IdentityProvider,
  MessageSender,
  Notifier,
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

/**
 * The languages a call can run in. Every catalog of text the engine builds (the texts it sends,
 * the amounts it formats, the spoken digits it redacts) is a `Record<Locale, ...>` with one entry
 * for each, and a test checks it: adding a locale here makes every catalog grow with it.
 */
export const SUPPORTED_LOCALES = Object.freeze(["en", "fr"] as const);

export type Locale = (typeof SUPPORTED_LOCALES)[number];

/** Whether a host's value is a supported locale. */
export function isSupportedLocale(value: unknown): value is Locale {
  return (SUPPORTED_LOCALES as readonly unknown[]).includes(value);
}

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
  /** Needed by a `paylink.request` step that names an `amountRef` (PAY-2). */
  amounts?: AmountSource;
  /** Gate's door controllers, by name. Targets in Gate's settings name one of these. */
  access?: Readonly<Record<string, AccessController>>;
  /** Signs Gate's access grants. Its own key (its own `kid`), not the receipt key. */
  accessSigner?: ReceiptSigner;
  /** Signs web sign-in step-up tokens. Its own key (its own `kid`), not the receipt or access key. */
  stepUpSigner?: ReceiptSigner;
  /** Failures across calls, shared by every engine of the workspace. Badge needs it when a factor the caller enters is on; a PIN reset clears the subject's PIN counters. */
  counters?: AttemptCounters;
  /** Places callbacks to the number on file. Badge needs it when the `callback` factor is on. */
  dialer?: CallbackDialer;
  /** Told of each lock, so the business knows someone is locked out (INT-7). Optional, best effort. */
  notifier?: Notifier;
  /** Told of a duress PIN entry (VER-12). Needed while Badge's `pin.duress` is set. */
  duressNotifier?: DuressNotifier;
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
  /**
   * The flow-start counters (`scope:key`) this flow was counted on, so a restart is not counted
   * twice; null for a flow whose starts are not limited (no money, contact or access scope).
   */
  counted: string[] | null;
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
  outbox: Array<{
    eventId: string;
    name: EngineEventName;
    actor: Actor;
    at: string;
    detail: { [key: string]: JsonValue };
    /** On a `verification.locked` entry, the counter that locked, for the lock notice (INT-7). Never in the ledger. */
    counter?: AttemptCounterKey;
  }>;
  /**
   * The writes so far that queued ledger entries, numbering their event ids. Absent on a record
   * saved before it was kept, which continues from its version.
   */
  ledgerWrites?: number;
  /**
   * Present, and true, while the call owes an alert to a host adapter (a duress alert, VER-12), so a
   * session store can index the calls a sweep must visit (`SessionStore.listCallsOwingAlerts`).
   */
  owesAlerts?: true;
}

/** A call being changed inside one compare-and-set attempt. Everything here is synchronous and pure. */
export interface CallDraft {
  readonly record: CallRecord;
  /** The module's own part of the record, to read and change in place. */
  slice<T>(module: string): T;
  apply(event: SessionEvent): void;
  assertCan(event: SessionEvent): void;
  /**
   * Queues a ledger entry, written once the change is saved. With `tag` (a PIN outcome, VER-12) the
   * entry gets a `tag` field, an HMAC of its event id and that outcome; the outcome is never saved.
   */
  emit(name: EngineEventName, actor: Actor, detail: { [key: string]: JsonValue }, tag?: string): void;
  /** The flow step the call is on, or null when no flow is running. */
  step(): FlowStep | null;
}

export interface EngineRuntime {
  readonly workspaceId: string;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly policy: VerificationPolicy;
  /** The revision of the config in force now (a call keeps the one it started under in `CallRecord.revision`). */
  readonly revision: string;
  now(): string;
  /** HMAC-SHA256 under the workspace's knowledge key, hex. The engine never holds a key kept in a key store. */
  hmac(data: string): Promise<string>;
  /** The module's validated settings. Throws `module_disabled` when it is off. */
  settings<T>(module: string): T;
  adapter<K extends AdapterName>(name: K): NonNullable<EngineAdapters[K]>;
  /** One step: read the call, change it with `fn`, write it with compare-and-set, retrying from a fresh read on conflict. */
  update<R>(callId: string, fn: (draft: CallDraft) => R): Promise<R>;
  read(callId: string): Promise<CallRecord>;
  /** Whether the call's grant covers a scope now. */
  authorized(record: CallRecord, scope: string): boolean;
  bindRef(ref: string, callId: string): Promise<void>;
  /** An idempotency key for a provider call, unique across workspaces and stable across retries. */
  idempotencyKey(callId: string, ...parts: string[]): string;
  resolveRef(ref: string): Promise<string | null>;
}
