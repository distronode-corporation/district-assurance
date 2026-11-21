// Which webhook deliveries the Stripe recorder (record.ts) keeps. Only one the reference server
// applied (a 2xx answer) is recorded; a 400, 500 or 503 answer fails the run instead, since a
// fixture of an event that was never applied would prove nothing.

/** One webhook delivery as it reached this machine, and what the reference server answered. */
export interface Delivery {
  listener: "account" | "connect";
  route: "identity" | "payments" | "connect";
  type: string;
  objectId: string;
  body: string;
  signatureVerified: boolean;
  answer: { status: number; body: unknown };
}

const ok = (status: number): boolean => status >= 200 && status < 300;

/** What the receiver answers `stripe listen`: the reference server's own status when it failed, so the failure shows there too. */
export function receiverStatus(answerStatus: number): number {
  return ok(answerStatus) ? 200 : answerStatus;
}

/**
 * The applied delivery of `type` for `objectId`, or undefined while none has arrived. Throws on a
 * delivery of it the reference server did not apply, whatever arrived after: the run fails loudly
 * instead of recording it, or of waiting on as if it had never come.
 */
export function settledDelivery(deliveries: readonly Delivery[], objectId: string, type: string): Delivery | undefined {
  const matching = deliveries.filter((d) => d.objectId === objectId && d.type === type);
  const failed = matching.find((d) => !ok(d.answer.status));
  if (failed !== undefined) throw new Error(`the reference server answered ${failed.answer.status} to ${type} for the recorded object: not recorded`);
  return matching[0];
}
