// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Badge's public surface. The runtime functions in badge.ts are reached through the Engine.
export {
  BADGE,
  BadgeModule,
  DEFAULT_KEYPAD_IDLE_SECONDS,
  PIN_PASS_MAX_SECONDS,
  badgeModule,
  type BadgeSlice,
  type BadgeVerifyStep,
  type BeginVerificationInput,
  type CallbackState,
  type KeypadResult,
  type KeypadTiming,
  type OutcomeResult,
  type PinPassRecord,
  type VerificationResult,
} from "./badge.ts";
export type { PinReuseRefusal } from "./pin-pass.ts";
export {
  TEXT_CODE_DIGITS,
  TEXT_CODE_LIMITS,
  TEXT_CODE_MAX_TRIES,
  TEXT_CODE_TTL_SECONDS,
  textCodeDestinationAllowed,
  textCodeText,
  type TextCodeRefusal,
  type TextCodeState,
} from "./text-code.ts";
export { CALLBACK, CALLBACKS_PLACED, MAX_CALLBACKS_PER_DAY, type CallbackOutcome } from "./callback.ts";
export { DEFAULT_LOCKOUT, counterKeys, lockState, lockoutOf, numberKeyFor, type Lock, type Lockout, type LockoutSettings } from "./counters.ts";
export { duressClearedSubject, duressFlagKey, hiddenCounterKey } from "./duress-flag.ts";
export { PinChangeUnfinishedError, isWeakPin, type PinChangeRef, type PinReplacement } from "./pin.ts";
export { OwnerPinConflictError, createOwnerPin, ownerSubjectKey, type OwnerLine, type OwnerPin, type OwnerPinOptions, type OwnerPinSetResult, type OwnerPinStatus, type SubjectWriter } from "./owner-pin.ts";
export * from "./factors.ts";
export * from "./knowledge.ts";
export * from "./spoken.ts";
