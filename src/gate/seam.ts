// The Seam adapter: an AccessController for locks Seam reaches (August, Yale, Nuki, Salto KS, Kisi,
// Brivo, Avigilon Alta) through one API. The target's `ref` is the Seam `device_id`.
//
// Three steps, each one request:
// 1. Check the device: `POST /devices/get`. Unless Seam says it can unlock remotely and does not
//    report it offline, the unlock is refused. Nothing has been sent to the lock yet, so any failure
//    here (an error, no answer) is also "refused": the door certainly did not act.
// 2. Unlock: `POST /locks/unlock_door`, once, and only while the grant has at least the request
//    timeout left (the pre-check can be slow): that bounds when it is sent and how long the client
//    waits, not the network, nor when Seam's attempt completes. With less left, it is "refused" (`grant_expiring`) and nothing is sent. Sent once: Seam
//    documents no idempotency key for it, so it is never retried. A 4xx is "refused"; anything
//    else without a readable action attempt (5xx, a timeout, a dropped connection, a redirect)
//    throws, which Gate records as "unknown".
// 3. Confirm: `POST /action_attempts/get` until the attempt leaves "pending" or the confirmation
//    window (elapsed time) ends. Confirmed only when Seam says the device confirmed it. Reading an attempt is not an unlock, so it may be asked more than once. "success"
//    is delivered and confirmed; an attempt still pending, or one that cannot be read, is delivered
//    and unconfirmed (Seam took the request); "error" throws, so Gate records "unknown", because a
//    lock that timed out may still have moved.
//
// The API key goes only in the authorization header, never into a result, an error or the ledger.
import { systemClock, type Clock } from "../core/clock.ts";
import type { AccessController, UnlockResult } from "./access.ts";

export interface SeamAccessControllerOptions {
  /** A Seam API key (workspace scoped). Sent only as a bearer token. */
  apiKey: string;
  /**
   * Default `https://connect.getseam.com`, the only host allowed (`SEAM_HOSTS`), over HTTPS on the
   * default port. The loopback address, over HTTP or HTTPS, only with `allowLoopbackForTests`.
   */
  baseUrl?: string;
  /** Test only: lets `baseUrl` be the loopback address (a local fake of Seam). Never in production. */
  allowLoopbackForTests?: boolean;
  /** How long to wait for each of Seam's answers, 100 to 30,000 ms. Default 5,000. */
  timeoutMs?: number;
  /** How long to ask Seam whether the lock confirmed, 0 to 30,000 ms. Default 10,000. 0 never asks. */
  confirmWithinMs?: number;
  /** The pause between two questions about the attempt, 10 to 5,000 ms. Default 1,000. */
  pollIntervalMs?: number;
  /** Default: the global `fetch`. */
  fetch?: typeof fetch;
  /** Read for the grant's expiry. Default: the system clock. */
  clock?: Clock;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** The hosts the API key may be sent to. */
export const SEAM_HOSTS: readonly string[] = Object.freeze(["connect.getseam.com"]);
const SHORT_CODE = /^[a-z][a-z0-9_]{0,31}$/;

function intIn(value: number, min: number, max: number, name: string): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new TypeError(`${name} must be an integer from ${min} to ${max}`);
  return value;
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** Seam's error type as a short code for the ledger, or the HTTP status. Never its message. */
function refusal(status: number, answer: unknown): string {
  const type = record(record(answer).error).type;
  return typeof type === "string" && SHORT_CODE.test(type) ? type : `http_${status}`;
}

type AttemptStatus = "pending" | "success" | "error";

/**
 * A Seam action attempt as far as Gate needs it, or null when the answer does not carry one.
 * `byDevice` is Seam's `result.was_confirmed_by_device`: a `success` alone means Seam sent the
 * command, not that the lock confirmed it moved.
 */
function actionAttempt(answer: unknown): { id: string; status: AttemptStatus; byDevice: boolean } | null {
  const attempt = record(record(answer).action_attempt);
  const id = attempt.action_attempt_id;
  const status = attempt.status;
  if (typeof id !== "string" || id === "" || id.length > 200) return null;
  if (status !== "pending" && status !== "success" && status !== "error") return null;
  return { id, status, byDevice: record(attempt.result).was_confirmed_by_device === true };
}

/** The Seam adapter (GAT-5): SPEC.md, section 17. */
export function seamAccessController(options: SeamAccessControllerOptions): AccessController {
  if (typeof options.apiKey !== "string" || options.apiKey.trim() === "") throw new TypeError("seamAccessController needs an API key");
  const base = new URL(options.baseUrl ?? "https://connect.getseam.com");
  // The key goes wherever the base URL points, so only Seam's own host, or the loopback address
  // when a test says so, is accepted: a mistyped or injected host never receives it.
  const loopback = options.allowLoopbackForTests === true && LOOPBACK.has(base.hostname) && (base.protocol === "http:" || base.protocol === "https:");
  if (!loopback && !(base.protocol === "https:" && SEAM_HOSTS.includes(base.hostname) && base.port === "")) {
    throw new TypeError(`seamAccessController needs an https base URL on ${SEAM_HOSTS.join(", ")} (the loopback address only with allowLoopbackForTests)`);
  }
  if (base.username !== "" || base.password !== "" || base.search !== "" || base.hash !== "") {
    throw new TypeError("seamAccessController base URLs carry no credentials, query or fragment");
  }
  const timeoutMs = intIn(options.timeoutMs ?? 5000, 100, 30_000, "timeoutMs");
  const confirmWithinMs = intIn(options.confirmWithinMs ?? 10_000, 0, 30_000, "confirmWithinMs");
  const pollIntervalMs = intIn(options.pollIntervalMs ?? 1000, 10, 5000, "pollIntervalMs");
  const send = options.fetch ?? fetch;
  const clock = options.clock ?? systemClock;
  const authorization = `Bearer ${options.apiKey}`;
  const path = base.pathname.replace(/\/+$/, "");

  /**
   * One request. The path is set on a copy of the validated base, never resolved against it: a
   * base path that starts with `//` would otherwise be read as another host, and the key sent there.
   */
  function post(route: string, body: Record<string, string>, waitMs = timeoutMs): Promise<Response> {
    const url = new URL(base.href);
    url.pathname = `${path}${route}`;
    return send(url, {
      method: "POST",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(waitMs),
    });
  }

  /** Step 1. Null when the device can be unlocked remotely; otherwise why not. Never throws. */
  async function cannotUnlock(deviceId: string): Promise<string | null> {
    try {
      const response = await post("/devices/get", { device_id: deviceId });
      const answer = await response.json().catch(() => null);
      if (response.status >= 400 && response.status < 500) return refusal(response.status, answer);
      if (response.status < 200 || response.status >= 300) return "seam_unavailable";
      const device = record(record(answer).device);
      if (device.device_id !== deviceId) return "device_unreadable";
      if (device.can_remotely_unlock !== true) return "cannot_unlock_remotely";
      if (record(device.properties).online === false) return "device_offline";
      return null;
    } catch {
      return "seam_unavailable";
    }
  }

  /**
   * Step 4. The attempt once it left "pending", or a pending one when it did not in time or could
   * not be read. The whole wait is held to `confirmWithinMs` of elapsed time (a monotonic clock):
   * each pause and each request is cut to what is left.
   */
  async function settle(attemptId: string): Promise<{ status: AttemptStatus; byDevice: boolean }> {
    const pending = { status: "pending" as const, byDevice: false };
    const deadline = performance.now() + confirmWithinMs;
    const left = () => deadline - performance.now();
    for (;;) {
      const remaining = left();
      if (remaining <= 0) return pending;
      await new Promise((resolve) => setTimeout(resolve, Math.min(pollIntervalMs, remaining)));
      try {
        // At least 1 ms: a request whose window just ran out times out at once, and reads as pending.
        const response = await post("/action_attempts/get", { action_attempt_id: attemptId }, Math.max(1, Math.min(timeoutMs, Math.floor(left()))));
        if (response.status < 200 || response.status >= 300) return pending;
        const attempt = actionAttempt(await response.json());
        if (attempt === null || attempt.id !== attemptId) return pending;
        if (attempt.status !== "pending") return attempt;
      } catch {
        return pending;
      }
    }
  }

  return {
    async unlock(input): Promise<UnlockResult> {
      const deviceId = input.target;
      const refused = await cannotUnlock(deviceId);
      if (refused !== null) return { outcome: "refused", reason: refused };
      // The grant's expiry is strict: an unlock is never sent with less than its timeout left.
      if (Date.parse(input.grant.body.expiresAt) - clock.now().getTime() < timeoutMs) return { outcome: "refused", reason: "grant_expiring" };

      // Step 2: once, never retried.
      const response = await post("/locks/unlock_door", { device_id: deviceId });
      const answer = await response.json().catch(() => null);
      if (response.status >= 400 && response.status < 500) return { outcome: "refused", reason: refusal(response.status, answer) };
      if (response.status < 200 || response.status >= 300) throw new Error(`Seam answered the unlock with ${response.status}`);
      const attempt = actionAttempt(answer);
      if (attempt === null) throw new Error("Seam answered the unlock without a readable action attempt");

      const settled = attempt.status === "pending" ? await settle(attempt.id) : attempt;
      if (settled.status === "error") throw new Error("Seam reported that the unlock attempt failed");
      // Confirmed only when Seam reports that the device itself confirmed the unlock.
      return { outcome: "delivered", providerRef: attempt.id, confirmed: settled.status === "success" && settled.byDevice };
    },
  };
}
