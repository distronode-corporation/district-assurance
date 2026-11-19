// Dossier (file): intake the caller confirms. The forms live in the module's settings, so a flow
// step names a form by id and a host's config is checked before any call uses it.
import type { IntakeRecord } from "../core/adapters.ts";
import { canonicalJson, type JsonValue } from "../core/canonical.ts";
import { EngineError } from "../core/errors.ts";
import { stepOfType } from "../core/flow.ts";
import type { AssuranceModule, FlowStep, StepContext, StepStatus, StepView } from "../core/module.ts";
import type { EngineRuntime, FieldCipher } from "../core/runtime.ts";
import type { SessionState } from "../core/session.ts";
import { isDenseArray, isObject, unknownKeys } from "../core/shape.ts";
import { intakeDigest, missingRequired, normaliseFieldValue, validateForm, type FieldValue, type IntakeForm, type NormaliseResult } from "./intake.ts";

export const DOSSIER = "dossier";

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
  intake: { form: IntakeForm; values: Record<string, FieldValue>; filing: IntakeRecord | null } | null;
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

  cannotRunStep(step: FlowStep, s: JsonValue): string | null {
    return (s as unknown as DossierSlice).forms.some((f) => f.formId === step.form) ? null : `the call has no form ${String(step.form)}`;
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

export async function startIntake(rt: EngineRuntime, callId: string, formId: string): Promise<void> {
  rt.settings(DOSSIER);
  await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    const chosen = s.forms.find((f) => f.formId === formId);
    if (chosen === undefined) throw new EngineError("invalid_input", `no form ${formId} in this call's dossier settings`);
    const step = stepOfType<DossierCollectStep>(draft.record, "dossier.collect");
    if (step !== null && step.form !== formId) throw new EngineError("precondition_failed", `the flow step collects ${step.form}`);
    if (!rt.authorized(draft.record, "intake.file")) throw new EngineError("scope_denied", "the grant does not cover intake.file");
    draft.apply({ type: "intake_started" });
    s.intake = { form: structuredClone(chosen), values: {}, filing: null };
    s.confirmed = null;
    draft.emit("intake.started", "code", { formId, version: chosen.version });
  });
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
    const result = normaliseFieldValue(field, raw);
    if (result.ok) intake.values[key] = result.value;
    return result;
  });
}

/**
 * The values a record's digest covers: what the caller confirmed, with each sensitive value as an
 * HMAC under the knowledge key, bound to the record and the field. The digest is the same whatever
 * the cipher answers, and a receipt never lets anyone test guesses at a short sensitive value.
 */
function digestValues(rt: EngineRuntime, recordId: string, form: IntakeForm, values: Readonly<Record<string, FieldValue>>): Record<string, FieldValue> {
  const covered = { ...values };
  for (const field of form.fields) {
    if (field.sensitive === true && Object.hasOwn(values, field.key)) {
      covered[field.key] = rt.hmac(canonicalJson(["intake", recordId, field.key, values[field.key]]));
    }
  }
  return covered;
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
  for (const field of keys) values[field] = await cipher.encrypt(String(values[field]), { workspaceId: record.workspaceId, recordId: record.recordId, field });
  return { ...record, values };
}

/**
 * Files the draft once the caller confirmed the read-back: reserved, encrypted, stored, then
 * recorded. A filing that failed anywhere after the reservation (the cipher, the store, a lost
 * write) resumes with the same record on the next call; the draft stays closed to changes until
 * it is filed. Only the encrypted record leaves the engine.
 */
export async function confirmIntake(rt: EngineRuntime, callId: string, input: { confirmedBy: "voice" | "keypad" }): Promise<IntakeRecord> {
  rt.settings(DOSSIER);
  const reserved = await rt.update(callId, (draft): { record: IntakeRecord; form: IntakeForm | null } => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    const intake = s.intake;
    // Filed already (a retry after the last write's ledger entry failed): this write appends that
    // entry, and the same record comes back.
    if (intake === null && s.confirmed !== null) return { record: s.confirmed, form: null };
    if (intake === null) throw new EngineError("invalid_transition", "no intake is open on this call");
    if (intake.filing !== null) return { record: intake.filing, form: intake.form };
    if (!rt.authorized(draft.record, "intake.file")) throw new EngineError("scope_denied", "the grant does not cover intake.file");
    const missing = missingRequired(intake.form, intake.values);
    if (missing.length > 0) throw new EngineError("invalid_input", `required fields missing: ${missing.join(", ")}`);
    const recordId = rt.ids.next("rec");
    const built: IntakeRecord = {
      recordId,
      workspaceId: rt.workspaceId,
      callId,
      formId: intake.form.formId,
      formVersion: intake.form.version,
      values: structuredClone(intake.values),
      digest: intakeDigest(intake.form, digestValues(rt, recordId, intake.form, intake.values)),
      confirmedBy: input.confirmedBy,
      confirmedAt: rt.now(),
    };
    intake.filing = built;
    return { record: built, form: intake.form };
  });
  if (reserved.form === null) return reserved.record;
  // Encrypted on every attempt: a cipher may answer differently each time, and the digest does not
  // depend on it. A rejected write may still have been stored, so the reservation is kept and any
  // retry writes this same record again (RecordStore.putIntakeRecord is idempotent by recordId).
  // Two processes confirming at once write the same record; the first to commit files it, the
  // other finds it filed.
  const record = await sealed(rt, reserved.record, reserved.form);
  await rt.adapter("records").putIntakeRecord(record);
  await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    if (s.records.some((r) => r.recordId === record.recordId)) return;
    draft.apply({ type: "intake_confirmed", recordId: record.recordId });
    s.intake = null;
    s.confirmed = record;
    s.records.push({ recordId: record.recordId, formId: record.formId, digest: record.digest });
    draft.emit("intake.confirmed", "caller", { recordId: record.recordId, formId: record.formId, digest: record.digest, confirmedBy: record.confirmedBy });
  });
  return record;
}

export async function abandonIntake(rt: EngineRuntime, callId: string): Promise<void> {
  rt.settings(DOSSIER);
  await rt.update(callId, (draft) => {
    const s = draft.slice<DossierSlice>(DOSSIER);
    if (s.intake !== null) openIntake(s);
    draft.apply({ type: "intake_abandoned" });
    s.intake = null;
    s.confirmed = null;
    draft.emit("intake.abandoned", "code", {});
  });
}
