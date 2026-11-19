// The signed-webhook relay: the first real AccessController. It POSTs the signed access grant to a
// small relay on the site's own network (a program on a Raspberry Pi or the business's server),
// which checks it with the public key (`verifyAccessGrant`), refuses a grant id it has seen
// (`SeenGrants`), and then pulses the door's relay (a Shelly, an ESPHome board, a strike). The
// grant's ES256 signature is the webhook's signature: the relay holds only the public key, so a
// relay that is taken over still cannot mint grants. No vendor account is involved.
//
// One request per grant, never retried, no redirects followed. A 2xx answer is "delivered"
// (confirmed only if the relay says so), a 4xx is "refused" (the relay certainly did not act), and
// anything else (5xx, a timeout, a dropped connection, a redirect) throws, which Gate records as
// "unknown".
import { canonicalJson } from "../core/canonical.ts";
import type { AccessController, UnlockResult } from "./access.ts";

export interface WebhookRelayOptions {
  /** The relay's unlock URL. HTTPS, or HTTP only to the loopback address (tests, the demo). */
  url: string;
  /** How long to wait for the relay's answer, 100 to 30,000 ms. Default 5,000. */
  timeoutMs?: number;
  /** Default: the global `fetch`. */
  fetch?: typeof fetch;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** The relay contract, version 1: SPEC.md, section 17. */
export function webhookRelay(options: WebhookRelayOptions): AccessController {
  const url = new URL(options.url);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new TypeError("webhookRelay needs an https URL (http only to the loopback address)");
  }
  if (url.username !== "" || url.password !== "") throw new TypeError("webhookRelay URLs carry no credentials");
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw new TypeError("timeoutMs must be an integer from 100 to 30000");
  const send = options.fetch ?? fetch;
  return {
    async unlock(input): Promise<UnlockResult> {
      const response = await send(url, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": input.idempotencyKey },
        body: canonicalJson(input.grant),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.status >= 200 && response.status < 300) {
        const answer = await response.json().catch(() => null);
        const reported = typeof answer === "object" && answer !== null ? (answer as Record<string, unknown>) : {};
        const ref = typeof reported.ref === "string" && reported.ref.length <= 200 ? reported.ref : input.grant.body.grantId;
        return { outcome: "delivered", providerRef: ref, confirmed: reported.state === "confirmed" };
      }
      // A replay answer means an earlier request with this grant was accepted, and may have opened
      // the door: that is not a refusal, so it is thrown and recorded as unknown.
      if (response.status === 409) throw new Error("the relay answered 409: the grant was already used");
      if (response.status >= 400 && response.status < 500) {
        const answer = await response.json().catch(() => null);
        const error = typeof answer === "object" && answer !== null ? (answer as Record<string, unknown>).error : undefined;
        return { outcome: "refused", reason: typeof error === "string" ? error : `http_${response.status}` };
      }
      throw new Error(`the relay answered ${response.status}`);
    },
  };
}
