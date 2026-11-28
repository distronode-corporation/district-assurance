// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Pay pieces that are planned and not built. Each throws NotImplementedError naming its issue.
// Saved-card charges (PAY-4) are built: `chargeSavedCard` in paylink.ts, off unless turned on.
import { NotImplementedError } from "../core/errors.ts";

/**
 * Keypad card entry captured by a PCI-certified carrier payment service, on a call path where the
 * tones never reach this engine. Gated on an assessor's scoping; see SECURITY-MODEL.md, PCI scope.
 */
export function startKeypadCardCapture(_input: { callId: string; paymentId: string }): never {
  throw new NotImplementedError("startKeypadCardCapture", "PAY-6");
}
