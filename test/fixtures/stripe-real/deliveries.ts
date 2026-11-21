// Which webhook deliveries the Stripe recorder (record.ts) keeps. Only one the reference server
// applied (a 2xx answer saying `applied: true`) is recorded; a 400, 500 or 503 answer, or a 2xx one
// that did not apply the event (the wrong route answers `applied: false`), fails the run instead,
// since a fixture of an event that was never applied would prove nothing.

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

/** A delivery in the order it arrived, its answer null while the reference server has not answered. */
export type PendingDelivery = Omit<Delivery, "answer"> & { answer: Delivery["answer"] | null };

const ok = (status: number): boolean => status >= 200 && status < 300;
const applied = (d: Delivery | PendingDelivery): boolean => d.answer !== null && typeof d.answer.body === "object" && d.answer.body !== null && (d.answer.body as { applied?: unknown }).applied === true;

/** What the receiver answers `stripe listen`: the reference server's own status when it failed, so the failure shows there too. */
export function receiverStatus(answerStatus: number): number {
  return ok(answerStatus) ? 200 : answerStatus;
}

/** Settles a delivery whose forwarding to the reference server failed, as a 502, so the run fails at once instead of waiting on it. */
export function forwardingFailed(entry: PendingDelivery): void {
  entry.answer = { status: 502, body: { forwarded: false } };
}

/**
 * The applied delivery of `type` for `objectId`, from deliveries in arrival order, or undefined
 * while none has arrived or the first to arrive has no answer yet (answers can finish out of
 * order). Throws on a failed answer to any delivery of it, and on a first delivery the reference
 * server did not apply,
 * whatever arrived after (a later one is Stripe's duplicate): the run fails loudly instead of
 * recording it, or of waiting on as if it had never come.
 */
export function settledDelivery(deliveries: readonly PendingDelivery[], objectId: string, type: string): Delivery | undefined {
  const matching = deliveries.filter((d) => d.objectId === objectId && d.type === type);
  const failed = matching.find((d) => d.answer !== null && !ok(d.answer.status));
  if (failed !== undefined) throw new Error(`the reference server answered ${failed.answer!.status} to ${type} for the recorded object: not recorded`);
  const first = matching[0];
  if (first === undefined || first.answer === null) return undefined;
  if (!applied(first)) throw new Error(`the reference server did not apply ${type} for the recorded object: not recorded`);
  return first as Delivery;
}
