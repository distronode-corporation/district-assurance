// Stripe adapters for the reference server, so people can try it with their OWN Stripe test-mode
// keys. Not built yet: each method throws NotImplementedError naming its roadmap issue. They will
// call Stripe's REST API with fetch (no SDK dependency) and a restricted key from the environment.
import { NotImplementedError, type IdentityProvider, type PaymentLinkRequest, type PaymentLinks, type PaymentMode } from "../../../src/index.ts";

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

/**
 * Stripe Checkout: a Session in payment mode with the engine's instant payment methods, as a
 * direct charge on the business's connected account (`connect`, the `Stripe-Account` header) or on
 * the platform's own account (`platform`). Stripe's shortest `expires_at` is 30 minutes, so the
 * adapter sends the later of that and the engine's deadline, and `expireLink` calls
 * `/v1/checkout/sessions/{id}/expire` when the engine's own deadline comes.
 */
export class StripeCheckoutLinks implements PaymentLinks {
  readonly #apiKey: string;

  constructor(apiKey: string) {
    this.#apiKey = apiKey;
  }

  async createLink(_input: PaymentLinkRequest): Promise<{ linkId: string; url: string }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeCheckoutLinks.createLink", "PAY-1");
  }

  async expireLink(_input: { linkId: string; mode: PaymentMode; connectedAccountId?: string; idempotencyKey: string }): Promise<{ state: "expired" | "not_open" }> {
    void this.#apiKey;
    throw new NotImplementedError("StripeCheckoutLinks.expireLink", "PAY-1");
  }
}
