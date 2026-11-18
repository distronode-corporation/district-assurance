// Helpers the modules share for running inside a flow.
import { EngineError } from "./errors.ts";
import type { FlowStep } from "./module.ts";
import type { CallRecord } from "./runtime.ts";

/** The step a call's running flow is on, or null when no flow is running. */
export function currentStep(record: CallRecord): FlowStep | null {
  const flow = record.flow;
  return flow !== null && flow.status === "running" ? flow.steps[flow.index]! : null;
}

/**
 * The current flow step when it is of `type`, null when no flow is running. While a flow runs,
 * only its current step's work is allowed: anything else is refused, so a flow cannot be skipped.
 */
export function stepOfType<T extends FlowStep>(record: CallRecord, type: string): T | null {
  const step = currentStep(record);
  if (step === null) return null;
  if (step.type !== type) throw new EngineError("precondition_failed", `the flow is on step ${step.type}, not ${type}`);
  return step as T;
}
