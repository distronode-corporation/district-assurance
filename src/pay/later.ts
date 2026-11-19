// Pay pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** Charges a card the business already holds at its payment provider (P1b), for a level 2 caller. */
export function chargeSavedCard(_input: { callId: string; paymentId: string }): never {
  throw new NotImplementedError("chargeSavedCard", "PAY-4");
}

/**
 * Keypad card entry captured by a PCI-certified carrier payment service, on a call path where the
 * tones never reach this engine. Gated on an assessor's scoping; see SECURITY-MODEL.md, PCI scope.
 */
export function startKeypadCardCapture(_input: { callId: string; paymentId: string }): never {
  throw new NotImplementedError("startKeypadCardCapture", "PAY-6");
}
