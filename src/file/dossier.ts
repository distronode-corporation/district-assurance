// Dossier (file): intake the caller confirms. The forms live in the module's settings, so a flow
// step names a form by id and a host's config is checked before any call uses it.
import { randomUUID } from "node:crypto";

import type { IntakeRecord } from "../core/adapters.ts";
import { canonicalJson, type JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import { hexDigestsEqual } from "../core/hash.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { CallRecord, EngineRuntime, FieldCipher, Locale } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isDenseArray, isObject, unknownKeys } from "../core/shape.ts";
import { formSpeaks, intakeDigest, isShown, missingRequired, normaliseFieldValue, shownValues, validateForm, type FieldValue, type IntakeForm, type NormaliseResult } from "./intake.ts";
import { buildReadBack, type ReadBack } from "./readback.ts";

export const DOSSIER = "dossier";

/** The locales whose callers may confirm a read-back by voice: not Spanish, whose spoken answers are refused (#84, Sean). */
const VOICE_CONFIRM_LOCALES: ReadonlySet<Locale> = new Set(["en", "fr"]);

export interface DossierSettings {
  forms: IntakeForm[];
}

export interface DossierCollectStep extends FlowStep {
  type: "dossier.collect";
  form: string;
}

export interface DossierSlice {
  /** The forms in force when the call started: a config change never strands a collect step. */
  forms: IntakeForm[];
  /** The open draft, with the form as it was when the intake started, and the record being filed (if any). Sensitive values are in the clear here until the record is filed or abandoned. */
  intake: {
    form: IntakeForm;
    values: Record<string, FieldValue>;
    filing: IntakeRecord | null;
    /**
     * The writes that claimed the filing to write it to the RecordStore, each by its own token, with
     * when it claimed: a process whose cipher failed meanwhile releases nothing while any claim is
     * live (WRITE_CLAIM_MS), and a failed write gives up only its own. Absent when nobody is writing.
     */
    writers?: Record<string, string>;
    /**
     * Set when a failing cipher started releasing the filing: no write claims it from then on, and
     * no write files it. The record is deleted by id (a tombstone) before the release completes.
     */
    releasing?: FilingFailure;
    /** The subject's erasure count read before `filing` was reserved (RecordStore.subjectErasures). Absent on calls saved before PRV-7. */
    erasuresSeen?: number;
    /** Set when abandonIntake claimed the filing to release it: no write claims or files it from then on. */
    abandoning?: true;
  } | null;
  records: Array<{ recordId: string; formId: string; digest: string }>;
  /** The record the last confirmation filed, until another intake starts: a retried confirmation gets it back. */
  confirmed: IntakeRecord | null;
}

const FORM_ID = /^[a-z][a-z0-9_-]{0,63}$/;

function formErrors(form: unknown, index: number): string[] {
  const at = `forms[${index}]`;
  if (!isObject(form) || typeof form.formId !== "string" || typeof form.version !== "string" || !isDenseArray(form.fields)) {
    return [`${at} must be { formId, version, fields }`];
  }
  const fieldsOk = form.fields.every(
    (f: unknown) => isObject(f) && typeof f.key === "string" && isObject(f.label) && typeof f.label.en === "string" && typeof f.label.fr === "string",
  );
  if (!fieldsOk) return [`${at} (${form.formId}): every field needs a key and an English and French label`];
  const typed = form as unknown as IntakeForm;
  const errors = validateForm(typed).map((e) => `${at} (${typed.formId}): ${e}`);
  if (!FORM_ID.test(typed.formId)) errors.push(`${at}: formId must be lower-case letters, digits, hyphens or underscores`);
  for (const field of typed.fields) {
    if (!["text", "number", "date", "yes_no"].includes(field.type)) errors.push(`${at} (${typed.formId}): field ${field.key} has an unknown type`);
  }
  return errors;
}

/** Whether a form has a field that is stored encrypted. */
function hasSensitive(form: IntakeForm): boolean {
  return form.fields.some((f) => f.sensitive === true);
}

export const dossierModule: AssuranceModule = {
  manifest: {
    name: DOSSIER,
    version: "1",
    summary: "Collect a form the caller confirms, as a fingerprinted record.",
    provides: { factors: [], steps: ["dossier.collect"], outcomes: ["record"] },
    scopes: { grants: [], needs: { "dossier.collect": "intake.file" }, classes: { "intake.file": "none" } },
    adapters: ["records"],
  },

  validateSettings(settings: unknown): string[] {
    if (!isObject(settings) || !isDenseArray(settings.forms)) return ["must be an object with a list of forms"];
    const errors = unknownKeys(settings, ["forms"]).map((k) => `${k} is not a dossier setting`);
    settings.forms.forEach((f: unknown, i: number) => errors.push(...formErrors(f, i)));
    const ids = settings.forms.map((f: unknown) => (isObject(f) ? f.formId : undefined));
    if (new Set(ids).size !== ids.length) errors.push("two forms have the same formId");
    return errors;
  },

  /** A form with a sensitive field needs the host's `fieldCipher`; without it the config is refused. */
  requiredAdapters(settings: unknown): string[] {
    return (settings as DossierSettings).forms.some(hasSensitive) ? ["records", "fieldCipher"] : ["records"];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "form"]).map((k) => `${k} is not a field of this step`);
    if (typeof step.form !== "string") return [...errors, "form must name a form"];
    const settings = ctx.settings as DossierSettings | null;
    if (settings !== null && !settings.forms.some((f) => f.formId === step.form)) errors.push(`no form ${step.form} in the dossier settings`);
    return errors;
  },

  initCall(settings: unknown): JsonValue {
    return { forms: structuredClone((settings as DossierSettings).forms), intake: null, records: [], confirmed: null } as unknown as JsonValue;
  },

  enterStep(_step: FlowStep, s: JsonValue): JsonValue {
    return (s as unknown as DossierSlice).records.length;
  },

  cannotRunStep(step: FlowStep, s: JsonValue, locale: Locale): string | null {
    const form = (s as unknown as DossierSlice).forms.find((f) => f.formId === step.form);
    if (form === undefined) return `the call has no form ${String(step.form)}`;
    return formSpeaks(form, locale) ? null : `form ${form.formId} has no ${locale} label for every field`;
  },

  blocksEnd(s: JsonValue): string | null {
    return (s as unknown as DossierSlice).intake?.filing != null ? "a record is being filed; confirm it first" : null;
  },

  stepStatus(step: FlowStep, view: StepView): StepStatus {
    const filed = (view.slice as unknown as DossierSlice).records.slice(view.mark as number);
    return filed.some((r) => r.formId === step.form) ? "complete" : "pending";
  },

  receiptPart(s: JsonValue, _state: SessionState): { [key: string]: JsonValue } {
    return { records: (s as unknown as DossierSlice).records };
  },
};

// ---- runtime -------------------------------------------------------------------------------

/**
 * The slice with no open draft, which endCall writes (engine-side, not a module hook) so a draft's
 * sensitive values never outlive the call in the clear. Records, digests and the filed record are
 * kept as they are. Not exported from the package.
 */
export function withoutOpenDraft(s: JsonValue): JsonValue {
  return { ...(s as unknown as DossierSlice), intake: null } as unknown as JsonValue;
}

export async function startIntake(rt: EngineRuntime, callId: string, formId: string): Promise<void> {
  rt.settings(DOSSIER);
  const refused = await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    const chosen = s.forms.find((f) => f.formId === formId);
    if (chosen === undefined) throw new EngineError("invalid_input", `no form ${formId} in this call's dossier settings`);
    const step = stepOfType<DossierCollectStep>(draft.record, "dossier.collect");
    if (step !== null && step.form !== formId) throw new EngineError("precondition_failed", `the flow step collects ${step.form}`);
    // Refused before the caller answers anything that could not be read back to them.
    if (!formSpeaks(chosen, draft.record.locale)) throw new EngineError("precondition_failed", `form ${formId} has no ${draft.record.locale} label for every field`);
    // Returned, not thrown, when a step-up rule is why: the change keeps the rule on the ledger (VER-13).
    const denied = rt.requireScope(draft, "intake.file", undefined);
    if (denied !== null) return denied;
    draft.apply({ type: "intake_started" });
    s.intake = { form: structuredClone(chosen), values: {}, filing: null };
    s.confirmed = null;
    draft.emit("intake.started", "code", { formId, version: chosen.version });
    return null;
  });
  if (refused !== null) throw refused;
}

function openIntake(s: DossierSlice): NonNullable<DossierSlice["intake"]> {
  if (s.intake === null) throw new EngineError("invalid_transition", "no intake is open on this call");
  if (s.intake.filing !== null) throw new EngineError("precondition_failed", "the intake is being filed");
  return s.intake;
}

/** Normalises and stores one value in the draft. A refused value is not stored. */
export async function setIntakeField(rt: EngineRuntime, callId: string, key: string, raw: string): Promise<NormaliseResult> {
  rt.settings(DOSSIER);
  return rt.update(callId, (draft) => {
    const intake = openIntake(draft.slice<DossierSlice>(DOSSIER));
    const field = intake.form.fields.find((f) => f.key === key);
    if (field === undefined) throw new EngineError("invalid_input", `the form has no field ${key}`);
    // Not a string is a host error. A lone surrogate (speech-to-text and model text can carry one) is
    // the caller's answer, refused as `not_text` by the normaliser (#76), so the host asks again.
    if (typeof raw !== "string") throw new EngineError("invalid_input", "the value must be text");
    if (!isShown(intake.form, intake.values, field)) throw new EngineError("precondition_failed", `field ${key} is not asked: its showIf does not hold`);
    const result = normaliseFieldValue(field, raw);
    if (result.ok) intake.values[key] = result.value;
    return result;
  });
}

/** The read-back of the open draft, in the call's locale, for the host to speak before the caller confirms. */
export async function intakeReadBack(rt: EngineRuntime, callId: string): Promise<ReadBack> {
  rt.settings(DOSSIER);
  const record = await rt.read(callId);
  const s = record.modules[DOSSIER] as unknown as DossierSlice | undefined;
  if (s === undefined) throw new EngineError("module_disabled", `${DOSSIER} was off when this call started`);
  if (s.intake === null) throw new EngineError("invalid_transition", "no intake is open on this call");
  return buildReadBack(s.intake.form, s.intake.values, record.locale);
}

/**
 * The values a record's digest covers: what the caller confirmed, with each sensitive value as an
 * HMAC under the knowledge key, bound to the record and the field. The digest is the same whatever
 * the cipher answers, and a receipt never lets anyone test guesses at a short sensitive value.
 */
async function digestValues(rt: EngineRuntime, recordId: string, form: IntakeForm, values: Readonly<Record<string, FieldValue>>): Promise<Record<string, FieldValue>> {
  const covered = { ...values };
  for (const field of form.fields) {
    if (field.sensitive === true && Object.hasOwn(values, field.key)) {
      covered[field.key] = await rt.hmac(canonicalJson(["intake", recordId, field.key, values[field.key]]));
    }
  }
  return covered;
}

/**
 * How long a claim to write a sealed filing holds off a failing cipher's release. A claim older
 * than this is a writer that died before it finished: a failing cipher may then release the filing,
 * so it never holds a call open for good.
 */
export const WRITE_CLAIM_MS = 120_000;

/** Why the host's cipher could not seal a record: it threw, or answered with no usable ciphertext. */
export type FilingFailure = "cipher_error" | "no_ciphertext";

/** The cipher failed: the reserved filing is released (`record.filing_failed`) and the draft dropped. */
class CipherFailed extends Error {
  readonly reason: FilingFailure;
  constructor(reason: FilingFailure) {
    super(reason);
    this.reason = reason;
  }
}

/** The record as it is stored: each sensitive value encrypted by the host's cipher, as text. */
async function sealed(rt: EngineRuntime, record: IntakeRecord, form: IntakeForm): Promise<IntakeRecord> {
  const keys = form.fields.filter((f) => f.sensitive === true && Object.hasOwn(record.values, f.key)).map((f) => f.key);
  if (keys.length === 0) return record;
  // A call keeps its forms and can move to another engine on the same SessionStore: an engine
  // without a cipher refuses, and the reservation waits for one that has it.
  const cipher: FieldCipher | undefined = rt.adapter("fieldCipher");
  if (cipher === undefined) throw new EngineError("precondition_failed", "a sensitive field needs the fieldCipher adapter, which the engine does not have");
  const values = { ...record.values };
  for (const field of keys) {
    const plain = String(values[field]);
    let sealedValue: unknown;
    try {
      sealedValue = await cipher.encrypt(plain, { workspaceId: record.workspaceId, recordId: record.recordId, field });
    } catch {
      // The cipher's own error is never passed on: it may quote the value.
      throw new CipherFailed("cipher_error");
    }
    // Fail closed on a cipher that answers with nothing, or with the value itself: the record is not stored.
    if (typeof sealedValue !== "string" || sealedValue === "" || sealedValue === plain) throw new CipherFailed("no_ciphertext");
    values[field] = sealedValue;
  }
  return { ...record, values };
}

/**
 * Files the draft once the caller confirmed the read-back: reserved, encrypted, stored, then
 * recorded. The host passes the digest of the read-back the caller heard (`intakeReadBack`), and a
 * draft that would no longer read back the same is refused. A filing that failed anywhere after
 * the reservation (the cipher, the store, a lost write) resumes with the same record on the next
 * call; the draft stays closed to changes until it is filed. Only the encrypted record leaves the
 * engine. `subjectOf` names the subject the call matched (or null), which the record is filed
 * under: the engine passes it, so Dossier never reads Badge's part of the call itself.
 */
export async function confirmIntake(
  rt: EngineRuntime,
  callId: string,
  input: { confirmedBy: "voice" | "keypad"; readBack: string },
  subjectOf: (record: CallRecord) => string | null,
): Promise<IntakeRecord> {
  rt.settings(DOSSIER);
  // Read once: the read-back digest compared and the channel filed are the values the host passed
  // at the call, not what a getter or a change to the object answers while the update waits.
  const { confirmedBy, readBack }: { confirmedBy?: unknown; readBack?: unknown } = input ?? {};
  // The host's channel goes into the record and the ledger as it is: refused before anything is written.
  if (confirmedBy !== "voice" && confirmedBy !== "keypad") throw new EngineError("invalid_input", "confirmedBy must be voice or keypad");
  // The record id and the sensitive values' keyed digests, taken before the reserving write: the
  // knowledge HMAC is asynchronous (#72). A draft changed since is refused below.
  const call = await rt.read(callId);
  const before = call.modules[DOSSIER] as unknown as DossierSlice | undefined;
  const records = rt.adapter("records");
  // Read before reserving: an erasure counted after this read keeps the record out of the store.
  const readKey = subjectOf(call);
  const seen = readKey === null ? 0 : await records.subjectErasures(rt.workspaceId, readKey);
  const open = before?.intake ?? null;
  let prepared: { recordId: string; form: string; shown: string; covered: Record<string, FieldValue> } | null = null;
  if (open !== null && open.filing === null) {
    const recordId = rt.ids.next("rec");
    const shown = shownValues(open.form, open.values);
    // The form too: the keyed digests follow its sensitive fields, so a draft started again on
    // another form with the same values is not filed under digests taken for this one.
    prepared = { recordId, form: canonicalJson(open.form), shown: canonicalJson(shown), covered: await digestValues(rt, recordId, open.form, shown) };
  }
  const reserved = await rt.update(callId, (draft): { record: IntakeRecord; form: IntakeForm | null; erasuresSeen: number } | { refused: EngineError } => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    const intake = s.intake;
    // Filed already (a retry after the last write's ledger entry failed): this write appends that
    // entry, and the same record comes back.
    if (intake === null && s.confirmed !== null) return { record: s.confirmed, form: null, erasuresSeen: seen };
    if (intake === null) throw new EngineError("invalid_transition", "no intake is open on this call");
    // A Spanish caller confirms on the keypad: Spanish spoken answers are refused until a reviewed
    // vocabulary exists, and the Spanish read-back asks for the 1.
    if (!VOICE_CONFIRM_LOCALES.has(draft.record.locale) && confirmedBy === "voice") {
      throw new EngineError("precondition_failed", "a Spanish call confirms its read-back on the keypad (confirmedBy keypad)");
    }
    const heard = buildReadBack(intake.form, intake.values, draft.record.locale).digest;
    if (typeof readBack !== "string" || !hexDigestsEqual(readBack, heard)) {
      throw new EngineError("precondition_failed", "the draft changed since the caller heard its read-back; read it back again");
    }
    // Checked again before a reserved filing resumes too: a step-up rule raised since the
    // reservation holds it. A refused resume keeps the reservation; abandonIntake releases it.
    const refused = rt.requireScope(draft, "intake.file", undefined);
    if (refused !== null) return { refused };
    if (intake.filing !== null) {
      // A filing reserved before PRV-7 has no erasure count, so the store could not keep it out once
      // its subject is erased: it is never filed (fail closed). abandonIntake releases it.
      if (intake.erasuresSeen === undefined) {
        throw new EngineError("precondition_failed", "this filing was reserved before subject erasures were counted, so it is not filed; abandon the intake and collect it again");
      }
      return { record: intake.filing, form: intake.form, erasuresSeen: intake.erasuresSeen };
    }
    const missing = missingRequired(intake.form, intake.values);
    if (missing.length > 0) throw new EngineError("invalid_input", `required fields missing: ${missing.join(", ")}`);
    // Only shown fields are filed: a value given before its showIf stopped holding stays out.
    const values = shownValues(intake.form, intake.values);
    if (prepared === null || canonicalJson(intake.form) !== prepared.form || canonicalJson(values) !== prepared.shown) throw new EngineError("conflict", "the draft changed while it was being filed; confirm again");
    const recordId = prepared.recordId;
    const built: IntakeRecord = {
      recordId,
      workspaceId: rt.workspaceId,
      callId,
      subjectKey: subjectOf(draft.record),
      formId: intake.form.formId,
      formVersion: intake.form.version,
      values,
      digest: intakeDigest(intake.form, prepared.covered),
      confirmedBy,
      confirmedAt: rt.now(),
    };
    // The count read above is for the subject matched then; a subject changed since is read again.
    if (built.subjectKey !== readKey) throw new EngineError("conflict", "the call's subject changed while the record was confirmed; confirm it again");
    intake.filing = built;
    intake.erasuresSeen = seen;
    return { record: built, form: intake.form, erasuresSeen: seen };
  });
  if ("refused" in reserved) throw reserved.refused;
  if (reserved.form === null) return reserved.record;
  // Encrypted on every attempt: a cipher may answer differently each time, and the digest does not
  // depend on it. A rejected write may still have been stored, so the reservation is kept and any
  // retry writes this record again (RecordStore.putIntakeRecord is idempotent by recordId). Two
  // processes confirming at once write the same record, each sensitive value possibly under a
  // different ciphertext of the same value; the first to commit files it, the other finds it filed.
  let record: IntakeRecord;
  try {
    record = await sealed(rt, reserved.record, reserved.form);
  } catch (error) {
    if (!(error instanceof CipherFailed)) throw error;
    // Another process may have sealed and filed the same record meanwhile: then that record stands.
    const released = await releaseFailedFiling(rt, callId, reserved.record, reserved.form, error.reason);
    if (released.kind === "filed") return released.record;
    if (released.kind === "writing") {
      throw new EngineError("conflict", "another process is writing this record; confirm again for its outcome");
    }
    throw new EngineError("precondition_failed", `the fieldCipher could not seal the record (${error.reason}); nothing was filed and the draft is gone`);
  }
  // Claim the filing before writing it, by the same compare-and-set as every write: a process whose
  // cipher fails meanwhile then releases nothing, so no failure is logged for a record that ends up
  // stored. A filing already released (that process failed first) is never written.
  const writer = randomUUID();
  const claim = await rt.update(callId, (draft): "claimed" | "released" | "filed" | "abandoning" | { releasing: FilingFailure } | { refused: EngineError } => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    // Filed meanwhile by another process: the record the store kept (its ciphertexts) is the answer, and nothing is written again.
    if (s.records.some((r) => r.recordId === record.recordId)) return "filed";
    if (s.intake?.filing?.recordId !== record.recordId) return "released";
    // A release that stopped part way (its delete failed): this confirmation carries it on.
    if (s.intake.releasing !== undefined) return { releasing: s.intake.releasing };
    // An abandonment that stopped part way (its delete failed): nothing is written; abandonIntake finishes it.
    if (s.intake.abandoning === true) return "abandoning";
    // A step-up rule raised while the record was sealed holds it, as at the reservation: nothing is
    // written, and the reservation stays for abandonIntake to release.
    const refused = rt.requireScope(draft, "intake.file", undefined);
    if (refused !== null) return { refused };
    s.intake.writers = { ...s.intake.writers, [writer]: rt.now() };
    return "claimed";
  });
  if (typeof claim === "object" && "refused" in claim) throw claim.refused;
  if (typeof claim === "object") await releaseFailedFiling(rt, callId, record, reserved.form, claim.releasing);
  if (claim === "abandoning") throw new EngineError("precondition_failed", "the intake is being abandoned; abandon it again to finish");
  if (claim !== "claimed" && claim !== "filed") throw new EngineError("precondition_failed", "the fieldCipher could not seal the record in another process; nothing was filed and the draft is gone");
  if (claim === "claimed") {
    try {
      // A write that lands after the record was erased stores nothing (RecordStore.deleteIntakeRecords),
      // nor one whose subject was erased since the count was read (RecordStore.markSubjectErased).
      await records.putIntakeRecord(record, reserved.erasuresSeen);
    } catch (error) {
      // The reservation is kept for a retry (the write may have landed); the claim is given up, so a
      // failing cipher is not held off by a writer that is no longer writing. Best effort.
      // Only this write's own claim: another write may hold it now. A release after this deletes the
      // record by id first, so a write that did land is never left behind a released filing.
      await rt
        .update(callId, (draft) => {
          const intake = draft.slice<DossierSlice>(DOSSIER).intake;
          if (intake?.writers !== undefined) delete intake.writers[writer];
        })
        .catch(() => undefined);
      throw error;
    }
  }
  // The record the store kept is the one filed and returned: an idempotent store keeps the first
  // write of a record id, so a retry's fresh ciphertexts are not what it holds.
  const kept = await records.getIntakeRecord(record.workspaceId, record.recordId);
  const filed = await rt.update(callId, (draft): "filed" | "abandoned" | "erased" | { refused: EngineError } => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    if (s.records.some((r) => r.recordId === record.recordId)) return "filed";
    // Abandoned while it was written (abandonIntake deleted the record by id, so the late write
    // stored nothing), or released by a failing cipher in another process (this write's claim went
    // stale, and the record was deleted by id): nothing is filed.
    if (s.intake?.filing?.recordId !== record.recordId || s.intake.releasing !== undefined || s.intake.abandoning === true) return "abandoned";
    // A step-up rule raised while the record was written holds it too: the call files nothing and
    // emits nothing. The reservation stays, and abandonIntake deletes what the write stored by id,
    // as for a write whose answer was lost. This write is over, so its claim goes.
    const refused = rt.requireScope(draft, "intake.file", undefined);
    if (refused !== null) {
      delete s.intake.writers![writer];
      return { refused };
    }
    // The store kept nothing (the subject was erased): the call files nothing either, and drops
    // the draft that holds the values.
    if (kept === null) {
      draft.apply({ type: "intake_abandoned" });
      s.intake = null;
      draft.emit("intake.abandoned", "code", {});
      return "erased";
    }
    draft.apply({ type: "intake_confirmed", recordId: record.recordId });
    s.intake = null;
    s.confirmed = kept;
    s.records.push({ recordId: record.recordId, formId: record.formId, digest: record.digest });
    draft.emit("intake.confirmed", "caller", { recordId: record.recordId, formId: record.formId, digest: record.digest, confirmedBy: record.confirmedBy });
    return "filed";
  });
  if (typeof filed === "object") throw filed.refused;
  if (filed === "abandoned") throw new EngineError("precondition_failed", "the filing was abandoned while it was written, or released by a failing fieldCipher; nothing was filed");
  // The subject was erased (after another process filed it, too): no locally sealed copy stands in for it.
  if (kept === null) throw new EngineError("precondition_failed", "the subject was erased while this record was filed; nothing was filed");
  return kept;
}

/**
 * A filing the cipher could not seal is released, so a failing cipher never holds a call open:
 * the draft and its reservation are dropped (no plaintext is kept), and `record.filing_failed`
 * names the record, the form, the sensitive fields and the reason, never a value. Nothing was
 * stored: the cipher runs before the record store, so no record can exist for it. The host can
 * collect the record again. A filing another process completed meanwhile is left as it is.
 */
async function releaseFailedFiling(
  rt: EngineRuntime,
  callId: string,
  record: IntakeRecord,
  form: IntakeForm,
  reason: FilingFailure,
): Promise<{ kind: "filed"; record: IntakeRecord } | { kind: "writing" } | { kind: "released" }> {
  // First mark the filing as releasing, so no write claims or files it from here on.
  const begun = await rt.update(callId, (draft): { kind: "filed"; record: IntakeRecord } | { kind: "writing" } | { kind: "released" } | { kind: "releasing" } => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    // Filed by another process: its record is the answer. Abandoned meanwhile: nothing to release.
    if (s.confirmed?.recordId === record.recordId) return { kind: "filed", record: s.confirmed };
    if (s.intake?.filing?.recordId !== record.recordId) return { kind: "released" };
    // Another process sealed it and is writing it: release nothing and log nothing, it may be stored.
    const now = rt.clock.now().getTime();
    const live = Object.values(s.intake.writers ?? {}).some((since) => now - Date.parse(since) < WRITE_CLAIM_MS);
    if (s.intake.releasing === undefined && live) return { kind: "writing" };
    s.intake.releasing ??= reason;
    return { kind: "releasing" };
  });
  if (begun.kind !== "releasing") return begun;
  // A write may have landed (a store that failed after storing, a writer whose claim went stale):
  // the record is deleted by id, and a write still in flight then stores nothing. A failed delete
  // leaves the filing releasing, and the next confirmation carries the release on from here.
  await rt.adapter("records").deleteIntakeRecords(rt.workspaceId, [record.recordId]);
  return rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    // No write files a releasing filing; another release of it may have finished first.
    if (s.intake?.filing?.recordId !== record.recordId) return { kind: "released" as const };
    // The reason the release began with, which may be another confirmation's.
    const why = s.intake.releasing!;
    draft.apply({ type: "intake_abandoned" });
    s.intake = null;
    const fields = form.fields.filter((f) => f.sensitive === true).map((f) => f.key);
    draft.emit("record.filing_failed", "code", { recordId: record.recordId, formId: record.formId, fields, reason: why });
    return { kind: "released" as const };
  });
}

/**
 * Drops the draft. A reserved filing (one whose resume was refused, or whose write failed) is
 * released too: its record, which the store may already hold, is deleted by id first, so a write
 * still in flight stores nothing, and the call can end.
 */
export async function abandonIntake(rt: EngineRuntime, callId: string): Promise<void> {
  rt.settings(DOSSIER);
  const seen = ((await rt.read(callId)).modules[DOSSIER] as unknown as DossierSlice | undefined)?.intake?.filing ?? null;
  // Claimed before the delete, by compare-and-set: a confirmation that committed the filing first
  // keeps its stored record, and one that has not yet committed never files it from here on.
  const reserved =
    seen === null
      ? null
      : await rt.update(callId, (draft) => {
          const intake = draft.slice<DossierSlice>(DOSSIER).intake;
          if (intake?.filing?.recordId !== seen.recordId) return null;
          intake.abandoning = true;
          return intake.filing;
        });
  if (reserved !== null) await rt.adapter("records").deleteIntakeRecords(rt.workspaceId, [reserved.recordId]);
  await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    const filing = s.intake?.filing ?? null;
    // The reservation this call claimed is gone: another abandonment (or a release) finished it
    // while this delete was in flight, and the call may hold a new draft since, which stays.
    if (reserved !== null && filing?.recordId !== reserved.recordId) return;
    // A filing reserved since the read is not released here: its record was not deleted.
    if (reserved === null && filing !== null) throw new EngineError("precondition_failed", "the intake is being filed");
    draft.apply({ type: "intake_abandoned" });
    s.intake = null;
    s.confirmed = null;
    draft.emit("intake.abandoned", "code", {});
  });
}

/**
 * Drops a call's own copy of records being erased: the last confirmed record, which the call keeps
 * so a retried confirmation gets it back. The digests in `records` stay, as on the receipt.
 * Refused while one of them is being filed, since finishing the filing would store it again. A
 * second confirmation of the same record whose write is still in flight once the filing finished
 * finds no filing here: the RecordStore stores nothing for a deleted record id, so that write
 * cannot bring the values back. Runs
 * whether or not Dossier is on now: the call filed the record when it was.
 */
export async function forgetRecords(rt: EngineRuntime, callId: string, recordIds: readonly string[]): Promise<void> {
  await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    if (s.intake?.filing != null && recordIds.includes(s.intake.filing.recordId)) {
      throw new EngineError("precondition_failed", "a record of this subject is being filed on a call; confirm it first");
    }
    if (s.confirmed !== null && recordIds.includes(s.confirmed.recordId)) s.confirmed = null;
  });
}
