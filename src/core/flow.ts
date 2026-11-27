// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

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
 * The current flow step when it is of `type`, null when the call runs no flow. While a flow runs,
 * only its current step's work is allowed: anything else is refused, so a flow cannot be skipped.
 * Once a call's flow has ended (completed, failed or abandoned), no step work runs on that call at
 * all: the flow's limits on factors, scopes and amounts would otherwise stop applying.
 */
export function stepOfType<T extends FlowStep>(record: CallRecord, type: string): T | null {
  assertFlowNotEnded(record);
  const step = currentStep(record);
  if (step === null) return null;
  if (step.type !== type) throw new EngineError("precondition_failed", `the flow is on step ${step.type}, not ${type}`);
  return step as T;
}

/** Refuses work on a call whose flow has ended. */
export function assertFlowNotEnded(record: CallRecord): void {
  const flow = record.flow;
  if (flow !== null && flow.status !== "running") {
    throw new EngineError("precondition_failed", `the call's flow ${flow.name} has ${flow.status}; no more steps run on this call`);
  }
}
