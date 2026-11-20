// An example outside module: Callback books a time for someone to call the caller back.
//
// It is what a host writes to add its own step to a flow, and it passes `moduleContract` from
// `district-assurance/testing` (test/contracts.test.ts). A host's own module imports from
// "district-assurance"; this one imports the sources so it runs in this repository.
//
// The workspace's config lists the windows a callback can be booked in. The flow step
// `callback.book` asks for one (or any) of them; the host's code, on the caller's answer, books it
// with `engine.updateModule(callId, "callback", (slice, call) => bookCallback(slice, window))`.
// Booking needs the `callback.book` scope, so the caller is verified first. The callback goes to
// the number on file, which the host looks up itself: nothing the caller says chooses where.
import {
  EngineError,
  isBilingual,
  isDenseArray,
  isObject,
  unknownKeys,
  type AssuranceModule,
  type FlowStep,
  type JsonValue,
  type StepContext,
  type StepStatus,
  type StepView,
} from "../../src/index.ts";

export interface CallbackWindow {
  /** snake_case, unique in the settings. */
  id: string;
  label: { en: string; fr: string };
}

export interface CallbackSettings {
  windows: CallbackWindow[];
}

/** The module's part of a call: the window ids it started with, and each answer in order. */
export interface CallbackSlice {
  windows: string[];
  answers: Array<{ window: string | null; status: "booked" | "declined" }>;
}

const WINDOW_ID = /^[a-z][a-z0-9_]{0,31}$/;

export const callbackModule: AssuranceModule = {
  manifest: {
    name: "callback",
    version: "1.0.0",
    summary: "Books a time for someone to call the caller back on the number on file.",
    provides: { factors: [], steps: ["callback.book"], outcomes: ["callback"] },
    // Booking a window moves no money, changes no contact details and opens nothing: class none.
    scopes: { grants: [], needs: { "callback.book": "callback.book" }, classes: { "callback.book": "none" } },
    adapters: [],
  },

  // Settings come from storage: every type is checked, and a problem is a sentence.
  validateSettings(settings: unknown): string[] {
    if (!isObject(settings) || !isDenseArray(settings.windows)) return ["must be an object with a list of windows"];
    const errors = unknownKeys(settings, ["windows"]).map((k) => `${k} is not a callback setting`);
    if (settings.windows.length === 0) errors.push("windows must list at least one window");
    settings.windows.forEach((w: unknown, i: number) => {
      if (!isObject(w)) {
        errors.push(`windows[${i}] must be an object`);
        return;
      }
      errors.push(...unknownKeys(w, ["id", "label"]).map((k) => `windows[${i}].${k} is not a window field`));
      if (typeof w.id !== "string" || !WINDOW_ID.test(w.id)) errors.push(`windows[${i}].id must be snake_case`);
      if (!isBilingual(w.label)) errors.push(`windows[${i}].label needs English and French`);
    });
    const ids = settings.windows.map((w: unknown) => (isObject(w) ? w.id : undefined));
    if (new Set(ids).size !== ids.length) errors.push("two windows have the same id");
    return errors;
  },

  requiredAdapters(): string[] {
    return [];
  },

  validateStep(step: FlowStep, ctx: StepContext): string[] {
    const errors = unknownKeys(step, ["type", "window"]).map((k) => `${k} is not a field of this step`);
    if (step.window === undefined) return errors;
    if (typeof step.window !== "string") return [...errors, "window must name a window"];
    const settings = ctx.settings as CallbackSettings | null;
    if (settings !== null && !settings.windows.some((w) => w.id === step.window)) errors.push(`no window ${step.window} in the callback settings`);
    return errors;
  },

  // A call keeps the windows it started with, so a config change mid-call never moves it.
  initCall(settings: unknown): JsonValue {
    const slice: CallbackSlice = { windows: (settings as CallbackSettings).windows.map((w) => w.id), answers: [] };
    return slice as unknown as JsonValue;
  },

  // The mark is how many answers the call had when the step started: only later ones count.
  enterStep(_step: FlowStep, slice: JsonValue): JsonValue {
    return (slice as unknown as CallbackSlice).answers.length;
  },

  // Pure: reads the view, changes nothing, keeps nothing between calls.
  stepStatus(step: FlowStep, view: StepView): StepStatus {
    const answers = (view.slice as unknown as CallbackSlice).answers.slice(view.mark as number);
    const last = answers.at(-1);
    if (last === undefined) return "pending";
    if (last.status === "declined") return "failed";
    return step.window === undefined || step.window === last.window ? "complete" : "pending";
  },

  cannotRunStep(step: FlowStep, slice: JsonValue): string | null {
    const windows = (slice as unknown as CallbackSlice).windows;
    return typeof step.window === "string" && !windows.includes(step.window) ? `this call has no callback window ${step.window}` : null;
  },
};

/** The slice with a booking in `window`. For the `fn` of `engine.updateModule`; throws on an unknown window. */
export function bookCallback(slice: JsonValue, window: string): JsonValue {
  const s = slice as unknown as CallbackSlice;
  if (!s.windows.includes(window)) throw new EngineError("invalid_input", "no such callback window");
  const next: CallbackSlice = { ...s, answers: [...s.answers, { window, status: "booked" }] };
  return next as unknown as JsonValue;
}

/** The slice with the caller's "no thanks": the step fails. */
export function declineCallback(slice: JsonValue): JsonValue {
  const s = slice as unknown as CallbackSlice;
  const next: CallbackSlice = { ...s, answers: [...s.answers, { window: null, status: "declined" }] };
  return next as unknown as JsonValue;
}

/** Sample settings, for the contract suite and the tests. */
export const callbackSettings: CallbackSettings = {
  windows: [
    { id: "today", label: { en: "later today", fr: "plus tard aujourd'hui" } },
    { id: "tomorrow_morning", label: { en: "tomorrow morning", fr: "demain matin" } },
  ],
};
