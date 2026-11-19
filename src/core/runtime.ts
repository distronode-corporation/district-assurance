// What the built-in modules see of the engine while they run a step: the call record, a way to
// change it (one compare-and-set write per change), the adapters and the clock. This is internal
// to the package; outside modules use `Engine.updateModule` and `Engine.moduleState` instead.
import type {
  AccessController,
  AmountSource,
  AttemptCounterKey,
  AttemptCounters,
  AuditLedger,
  AuditInput,
  CallbackDialer,
  CarrierSignals,
  CodeStore,
  ConsentStore,
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
import type { Attestation, StepUpAmount, VerificationPolicy } from "./policy.ts";
import type { EngineError } from "./errors.ts";
import type { SessionEvent, SessionState } from "./session.ts";

/**
 * The languages a call can run in. Every catalog of text the engine builds (the texts it sends,
 * the amounts it formats, the spoken digits it redacts) is a `Record<Locale, ...>` with one entry
 * for each, and a test checks it: adding a locale here makes every catalog grow with it.
 */
export const SUPPORTED_LOCALES = Object.freeze(["en", "fr", "es"] as const);

export type Locale = (typeof SUPPORTED_LOCALES)[number];

/** The same list, by the name #122 (I18N) gave it. */
export const LOCALES = SUPPORTED_LOCALES;

/** Whether a host's value is a supported locale. */
export function isSupportedLocale(value: unknown): value is Locale {
  return (SUPPORTED_LOCALES as readonly unknown[]).includes(value);
}

/**
 * Words a workspace writes (a form's labels, a consent wording): English and French always,
 * Spanish when the workspace offers it. A call in Spanish can use only those that have it.
 */
export interface LocalisedText {
  en: string;
  fr: string;
  es?: string;
}

/**
 * Encrypts a sensitive intake value before the record is stored, with the host's key (for example
 * a KMS data key). The engine never decrypts: the host reads its records with its own key. The
 * context names the value's place, so a host can bind it as additional authenticated data and a
 * ciphertext moved to another record or field fails to decrypt. An answer may differ on every call
 * (a fresh nonce); the record's digest does not depend on it.
 */
export interface FieldCipher {
  encrypt(plain: string, context: { workspaceId: string; recordId: string; field: string }): Promise<string>;
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
  /** Send limits for texted codes, shared by every engine of the workspace. */
  codes?: CodeStore;
  /** Failures across calls, shared by every engine of the workspace. Badge needs it when a factor the caller enters is on; a PIN reset clears the subject's PIN counters. */
  counters?: AttemptCounters;
  /** Places callbacks to the number on file. Badge needs it when the `callback` factor is on. */
  dialer?: CallbackDialer;
  /** Told of each lock, so the business knows someone is locked out (INT-7). Optional, best effort. */
  notifier?: Notifier;
  /** Told of a duress PIN entry (VER-12). Needed while Badge's `pin.duress` is set. */
  duressNotifier?: DuressNotifier;
  /** Needed by Dossier once a form has a sensitive field. */
  fieldCipher?: FieldCipher;
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
  /**
   * The caller ID attestation the call started with, set once by `startCall`. Never a factor.
   * Absent on a call stored before VER-10, which reads as `none`.
   */
  attestation?: Attestation;
  /** A callback call the engine dialled (VER-9): never capped by its attestation (decision 10). */
  attestationExempt?: true;
  flow: FlowCursor | null;
  /** Each module's own part, by module name. */
  modules: Record<string, JsonValue>;
  /** Signals the host's code raised on the call, for step-up rules (VER-13). Raised, never cleared. Absent on a call saved before them. */
  signals?: string[];
  /** Step-up rules already written to the ledger for this call, by name. Absent on a call saved before them. */
  stepUps?: string[];
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
  /**
   * Appends one ledger entry that belongs to no write of a call record (a consent revoked after
   * the call), then tells the listener. Idempotent by `eventId`, like every append.
   */
  append(entry: AuditInput & { eventId: string; callId: string }): Promise<void>;
  /** Appends a call's pending ledger entries, in order. */
  flushLedger(callId: string): Promise<void>;
  /** Whether the call's grant covers a scope now. */
  /**
   * Whether the call's grant covers a scope now, at the minimum the policy's step-up rules raise it
   * to for `amount` (VER-13; left out, the current step's amount; null, no amount asked yet, so
   * amount rules are skipped). Inside a change, a rule applied for the first time is ledgered.
   */
  authorized(record: CallRecord, scope: string, amount?: StepUpAmount | null): boolean;
  /**
   * Holds a step's own work to a scope at the minimum the step-up rules raise it to for `amount`.
   * Null when the grant covers it. When step-up rules are why it does not, the running flow fails
   * naming them and the refusal is returned, to be thrown once the change is saved, so the ledger
   * keeps both. A refusal the grant earns without any rule is returned too when a rule applies
   * (naming it, so a first `policy.step_up` is kept; the flow is not failed); one no rule touches
   * throws `scope_denied` at once.
   */
  requireScope(draft: CallDraft, scope: string, amount: StepUpAmount | undefined | null): EngineError | null;
  bindRef(ref: string, callId: string): Promise<void>;
  /** An idempotency key for a provider call, unique across workspaces and stable across retries. */
  idempotencyKey(callId: string, ...parts: string[]): string;
  resolveRef(ref: string): Promise<string | null>;
}
