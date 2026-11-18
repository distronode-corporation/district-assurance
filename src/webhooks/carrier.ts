// Carrier webhook signature checks: planned, not built. Each throws NotImplementedError, and the
// reference server answers 501 on these routes, so an unsigned request is never trusted.
import { NotImplementedError } from "../core/errors.ts";

export interface CarrierWebhookInput {
  url: string;
  headers: Readonly<Record<string, string | undefined>>;
  body: string;
  now: Date;
}

export function verifyTwilioSignature(_input: CarrierWebhookInput): never {
  throw new NotImplementedError("verifyTwilioSignature", "SRV-1");
}

export function verifyTelnyxSignature(_input: CarrierWebhookInput): never {
  throw new NotImplementedError("verifyTelnyxSignature", "SRV-1");
}
