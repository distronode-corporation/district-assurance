// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. Not built yet: each method throws NotImplementedError naming its roadmap issue. They will
// call Stripe's REST API with fetch (no SDK dependency) and a restricted key from the environment.
import { NotImplementedError, type IdentityProvider, type PaymentLinks } from "../../../src/index.ts";

/** Stripe Identity: a VerificationSession of type document with a selfie check. */
export class StripeIdentityProvider implements IdentityProvider {
  readonly #apiKey: string;

  constructor(apiKey: string) {
    this.#apiKey = apiKey;
  }

  async createDocumentCheck(_input: { callId: string; idempotencyKey: string }): Promise<{ sessionId: string; url: string }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeIdentityProvider.createDocumentCheck", "VER-5");
  }
}

/** Stripe Checkout: a Session in payment mode, cards only, on the business's own account. */
export class StripeCheckoutLinks implements PaymentLinks {
  readonly #apiKey: string;

  constructor(apiKey: string) {
    this.#apiKey = apiKey;
  }

  async createLink(_input: {
    callId: string;
    paymentId: string;
    amountMinor: number;
    currency: string;
    description: string;
    idempotencyKey: string;
  }): Promise<{ linkId: string; url: string }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeCheckoutLinks.createLink", "PAY-1");
  }
}
