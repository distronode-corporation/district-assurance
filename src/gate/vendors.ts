// Direct vendor adapters (GAT-6): an AccessController that unlocks a door through one access
// vendor's own documented API, for systems no aggregator reaches (Verkada) or a host with an
// account at one vendor only (Kisi).
//
// Unlike the relay, the vendor cannot check the signed grant: the vendor's API key opens the door
// on its own, so the key is a secret for the host's key store, scoped to as few doors as the
// vendor allows. The adapter checks that the grant names the door it is asked to open, and sends
// nothing otherwise.
//
// The grant's expiry is strict, and the engine lets a call end once a grant at its door expired:
// so nothing is sent for a grant with less than `timeoutMs` left, the client's own bound on the
// whole unlock (Verkada's token included). That is "refused" (`grant_expiring`). It bounds when
// the request is sent and how long the client waits, not the network: neither vendor's request
// carries a deadline, so a request delayed in transit could still arrive after the grant expired.
//
// The same rule as the relay: one unlock request per grant, never retried, no redirects followed.
// A 2xx answer is "delivered" (never confirmed: neither vendor reports in its answer that the door
// moved), a 4xx is "refused" (the vendor certainly did not act), and anything else (5xx, a timeout,
// a dropped connection, a redirect) throws, which Gate records as "unknown". The vendor's own
// error text is never passed on: a refusal's reason is `http_<status>`. The API key is never put
// in an error.
//
// Kisi: `POST {baseUrl}/locks/{lock id}/unlock` with `Authorization: KISI-LOGIN <api key>`.
// Verkada: `POST {baseUrl}/token` with `x-api-key: <api key>` for a short-lived token, then
// `POST {baseUrl}/access/v1/door/admin_unlock` with `x-verkada-auth: <token>` and
// `{"door_id": "<door id>"}`. A token that cannot be had means the unlock was never sent, so it is
// "refused" whatever went wrong. A token is fetched for each unlock and never kept.
import { systemClock, type Clock } from "../core/clock.ts";
import type { AccessController, UnlockResult } from "./access.ts";

export interface VendorAccessOptions {
  vendor: "kisi" | "verkada";
  /** The vendor's API key. A secret: kept in the host's key store, never logged. */
  apiKey: string;
  /**
   * The vendor's API. Default `https://api.kisi.io` for Kisi and `https://api.verkada.com` for
   * Verkada (`https://api.eu.verkada.com` or `https://api.au.verkada.com` for those regions): the
   * host must be one of the vendor's (`VENDOR_HOSTS`), over HTTPS on the default port. The loopback
   * address, over HTTP or HTTPS, only with `allowLoopbackForTests`.
   */
  baseUrl?: string;
  /** Test only: lets `baseUrl` be the loopback address (a local fake of the vendor). Never in production. */
  allowLoopbackForTests?: boolean;
  /** How long to wait for the vendor, for the whole unlock, 100 to 30,000 ms. Default 5,000. */
  timeoutMs?: number;
  /** Default: the global `fetch`. */
  fetch?: typeof fetch;
  /** Read for the grant's expiry. Default: the system clock. */
  clock?: Clock;
}

const DEFAULT_BASE_URL = { kisi: "https://api.kisi.io", verkada: "https://api.verkada.com" } as const;

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** The hosts each vendor's API key may be sent to. */
export const VENDOR_HOSTS: Readonly<Record<VendorAccessOptions["vendor"], readonly string[]>> = Object.freeze({
  kisi: Object.freeze(["api.kisi.io"]),
  verkada: Object.freeze(["api.verkada.com", "api.eu.verkada.com", "api.au.verkada.com"]),
});

/** A Kisi lock id is a number; a Verkada door id is a UUID. Both go into the request as they are. */
const TARGET = { kisi: /^[0-9]{1,20}$/, verkada: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/ } as const;

/** Kisi or Verkada, through the vendor's documented unlock call. SPEC.md, section 17. */
export function vendorAccessController(options: VendorAccessOptions): AccessController {
  const vendor = options.vendor;
  if (vendor !== "kisi" && vendor !== "verkada") throw new TypeError("vendor must be kisi or verkada");
  if (typeof options.apiKey !== "string" || !/^[\x21-\x7e]{1,500}$/.test(options.apiKey)) {
    throw new TypeError("apiKey must be 1 to 500 printable characters with no spaces");
  }
  const base = new URL(options.baseUrl ?? DEFAULT_BASE_URL[vendor]);
  // The key goes wherever the base URL points, so only the vendor's own hosts, or the loopback
  // address when a test says so, are accepted: a mistyped or injected host never receives it.
  const loopback = options.allowLoopbackForTests === true && LOOPBACK.has(base.hostname) && (base.protocol === "http:" || base.protocol === "https:");
  const hosts = VENDOR_HOSTS[vendor];
  if (!loopback && !(base.protocol === "https:" && hosts.includes(base.hostname) && base.port === "")) {
    throw new TypeError(`vendorAccessController needs an https baseUrl on ${hosts.join(", ")} (the loopback address only with allowLoopbackForTests)`);
  }
  if (base.username !== "" || base.password !== "" || base.search !== "" || base.hash !== "") {
    throw new TypeError("vendorAccessController baseUrls carry no credentials, query or fragment");
  }
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw new TypeError("timeoutMs must be an integer from 100 to 30000");
  const send = options.fetch ?? fetch;
  const clock = options.clock ?? systemClock;
  // The path is set on a copy of the validated base, never resolved against it: a base path that
  // starts with `//` would otherwise be read as another host, and the key sent there.
  const at = (path: string) => {
    const url = new URL(base.href);
    url.pathname = `${base.pathname.replace(/\/+$/, "")}${path}`;
    return url;
  };
  const apiKey = options.apiKey;

  /** The single unlock request, whose answer is mapped the relay's way. */
  async function post(url: URL, headers: Record<string, string>, body: string, signal: AbortSignal, grantId: string): Promise<UnlockResult> {
    const response = await send(url, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json", ...headers },
      body,
      redirect: "error",
      signal,
    });
    // The body is not read for its content: neither vendor's answer changes the outcome.
    await response.body?.cancel();
    if (response.status >= 200 && response.status < 300) return { outcome: "delivered", providerRef: grantId, confirmed: false };
    if (response.status >= 400 && response.status < 500) return { outcome: "refused", reason: `http_${response.status}` };
    throw new Error(`${vendor} answered ${response.status}`);
  }

  /** A Verkada API token, or null when there is none to be had (the unlock is then never sent). */
  async function verkadaToken(signal: AbortSignal): Promise<string | null> {
    try {
      const response = await send(at("/token"), { method: "POST", headers: { accept: "application/json", "x-api-key": apiKey }, redirect: "error", signal });
      const answer: unknown = await response.json().catch(() => null);
      if (response.status !== 200 || typeof answer !== "object" || answer === null) return null;
      const token = (answer as Record<string, unknown>).token;
      return typeof token === "string" && /^[\x21-\x7e]{1,4000}$/.test(token) ? token : null;
    } catch {
      return null;
    }
  }

  return {
    async unlock(input): Promise<UnlockResult> {
      const grant = input.grant.body;
      if (input.target !== grant.target) return { outcome: "refused", reason: "target_mismatch" };
      if (!TARGET[vendor].test(input.target)) return { outcome: "refused", reason: "bad_target" };
      if (Date.parse(grant.expiresAt) - clock.now().getTime() < timeoutMs) return { outcome: "refused", reason: "grant_expiring" };
      const signal = AbortSignal.timeout(timeoutMs);
      if (vendor === "kisi") {
        return post(at(`/locks/${input.target}/unlock`), { authorization: `KISI-LOGIN ${apiKey}` }, "{}", signal, grant.grantId);
      }
      const token = await verkadaToken(signal);
      if (token === null) return { outcome: "refused", reason: "token_unavailable" };
      return post(at("/access/v1/door/admin_unlock"), { "x-verkada-auth": token }, JSON.stringify({ door_id: input.target }), signal, grant.grantId);
    },
  };
}
