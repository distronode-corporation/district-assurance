// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The Connect webhook's verifier. Direct charges on a connected account arrive as Connect events
// (the endpoint is a "Connected accounts" endpoint), each naming the account in `account`. One
// endpoint URL may serve both modes, each with its own signing secret: the mode is the SECRET's,
// and the event must agree.
import { verifyStripeSignature } from "../webhooks/stripe.ts";
import type { StripeMode } from "./keys.ts";

const CONNECTED_ACCOUNT = /^acct_[A-Za-z0-9]{1,255}$/;
const EVENT_ID = /^evt_[A-Za-z0-9_]{1,255}$/;

/** A verified Connect event, as much of it as the verifier checks. The rest is the host's to read. */
export interface ConnectEvent {
  id: string;
  type: string;
  livemode: boolean;
  /** The connected account the event is about; null on a platform event. */
  account: string | null;
  data: { object: Record<string, unknown> };
}

export type ConnectEventVerdict =
  /** No mode has a signing secret. */
  | { kind: "unconfigured" }
  /** No secret verifies the signature (or the timestamp is outside the tolerance), or BOTH modes' secrets do. */
  | { kind: "invalid" }
  /** Signed, but not a Stripe event this verifier can read. */
  | { kind: "malformed"; mode: StripeMode }
  /** Verified by `mode`'s secret, but the event's `livemode` is the other mode's. */
  | { kind: "wrong_mode"; mode: StripeMode; event: ConnectEvent }
  | { kind: "verified"; mode: StripeMode; event: ConnectEvent };

export interface ConnectEventInput {
  /** The raw body, exactly as received. */
  payload: string | Uint8Array;
  header: string | null | undefined;
  /** Each mode's signing secret(s); more than one while a secret is rolled. */
  secrets: { test?: string | readonly string[]; live?: string | readonly string[] };
  now: Date;
  /** Default 300 seconds (`verifyStripeSignature`). */
  toleranceSeconds?: number;
}

function list(secret: string | readonly string[] | undefined): string[] {
  if (secret === undefined) return [];
  return (typeof secret === "string" ? [secret] : [...secret]).filter((s) => typeof s === "string" && s.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function eventOf(payload: string | Uint8Array): ConnectEvent | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof payload === "string" ? payload : new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    return null;
  }
  if (!isRecord(parsed) || parsed.object !== "event") return null;
  const { id, type, livemode, account, data } = parsed;
  if (typeof id !== "string" || !EVENT_ID.test(id) || typeof type !== "string" || type === "" || typeof livemode !== "boolean") return null;
  if (!isRecord(data) || !isRecord(data.object)) return null;
  if (account !== undefined && account !== null && (typeof account !== "string" || !CONNECTED_ACCOUNT.test(account))) return null;
  return { id, type, livemode, account: typeof account === "string" ? account : null, data: { object: data.object } };
}

/**
 * Verifies a Connect webhook against each mode's secrets, with Stripe's own signature scheme
 * (`verifyStripeSignature`, including its timestamp tolerance, so an old event replayed is
 * invalid). Exactly one mode's secret must verify: a signature both modes' secrets verify (the same
 * secret set in both) is refused as invalid, since the mode could not be told. The event's
 * `livemode` must then be the verifying secret's mode, else `wrong_mode`.
 */
export function verifyConnectEvent(input: ConnectEventInput): ConnectEventVerdict {
  const modes: Array<{ mode: StripeMode; secrets: string[] }> = [
    { mode: "test", secrets: list(input.secrets.test) },
    { mode: "live", secrets: list(input.secrets.live) },
  ];
  const configured = modes.filter((m) => m.secrets.length > 0);
  if (configured.length === 0) return { kind: "unconfigured" };
  const verified = configured.filter(
    (m) =>
      verifyStripeSignature({
        payload: input.payload,
        header: input.header,
        secrets: m.secrets,
        now: input.now,
        ...(input.toleranceSeconds === undefined ? {} : { toleranceSeconds: input.toleranceSeconds }),
      }).ok,
  );
  const [match] = verified;
  if (match === undefined || verified.length > 1) return { kind: "invalid" };
  const event = eventOf(input.payload);
  if (event === null) return { kind: "malformed", mode: match.mode };
  return event.livemode === (match.mode === "live") ? { kind: "verified", mode: match.mode, event } : { kind: "wrong_mode", mode: match.mode, event };
}

/**
 * Whether a Connect event is about the account the host stored for the payment or workspace:
 * `match` only for the same well-formed `acct_` id. A host applies an event only on `match`, and
 * logs the others by ids only.
 */
export function connectEventAccount(event: Pick<ConnectEvent, "account">, storedAccountId: string | null | undefined): "match" | "mismatch" | "missing" {
  if (event.account === null) return "missing";
  if (typeof storedAccountId !== "string" || !CONNECTED_ACCOUNT.test(storedAccountId)) return "mismatch";
  return event.account === storedAccountId ? "match" : "mismatch";
}
