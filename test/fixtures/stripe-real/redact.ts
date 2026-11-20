// Redaction for the recorded Stripe test-mode runs. The repository is public, so nothing that names
// the recording account or its objects is kept: every Stripe id becomes a placeholder of the same
// prefix and shape (`acct_redacted0001`, `cs_test_redacted0001`), the same id always the same
// placeholder across every file of one recording (so a session, its event and its account still
// line up), hosted page URLs lose their path and fragment, business display names are replaced,
// and client secrets, keys and webhook signing secrets are removed. Text is redacted in place, so
// an event body keeps Stripe's own bytes apart from the replaced values.

/** A Stripe object id: a lower-case prefix (`cs_test` included), then a mixed-case token with a digit and a capital. */
export const STRIPE_ID = /\b([a-z]{1,10}(?:_test|_live)?)_((?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Z])[A-Za-z0-9]{10,})\b/g;
/** Any API key or webhook signing secret. */
export const KEY_OR_SECRET = /\b(?:(?:sk|rk|pk)_(?:test|live)|whsec)_[A-Za-z0-9]+/g;
/** A client secret (`<object id>_secret_<token>`). */
const CLIENT_SECRET = /\b[a-z]{1,10}(?:_test|_live)?_[A-Za-z0-9]+_secret_[A-Za-z0-9]+/g;
/** A Stripe-hosted page: its path and fragment carry the session and a publishable key. */
const HOSTED_PAGE = /https:\/\/(checkout|verify|connect|pay|invoice)\.stripe\.com\/[^"\s\\]*/g;
/** A business's display name (the platform's own branding on a platform-mode session), raw or inside an escaped JSON string. */
const DISPLAY_NAME = /(\\*"display_name\\*":\s*\\*")[^"\\]*/g;
/** A placeholder this redactor writes. */
export const PLACEHOLDER = /^[a-z]{1,10}(?:_test|_live)?_redacted\d{4}$/;

export class Redactor {
  readonly #ids = new Map<string, string>();
  readonly #counts = new Map<string, number>();

  /** The placeholder for one real id, the same every time. */
  id(real: string): string {
    let placeholder = this.#ids.get(real);
    if (placeholder === undefined) {
      const prefix = real.slice(0, real.lastIndexOf("_"));
      const n = (this.#counts.get(prefix) ?? 0) + 1;
      this.#counts.set(prefix, n);
      placeholder = `${prefix}_redacted${String(n).padStart(4, "0")}`;
      this.#ids.set(real, placeholder);
    }
    return placeholder;
  }

  text(value: string): string {
    return value
      .replace(KEY_OR_SECRET, "[removed]")
      .replace(CLIENT_SECRET, "[removed]")
      .replace(HOSTED_PAGE, (_url, host: string) => `https://${host}.stripe.com/redacted`)
      .replace(DISPLAY_NAME, "$1[redacted]")
      .replace(STRIPE_ID, (real) => this.id(real));
  }

  /** A JSON value with every string redacted (keys included). */
  json<T>(value: T): T {
    return JSON.parse(this.text(JSON.stringify(value))) as T;
  }
}

/** What a redacted file must never hold: a key or secret, or a Stripe id that is not a placeholder. */
export function leaks(text: string): string[] {
  const found = [...text.matchAll(KEY_OR_SECRET)].map((m) => m[0]);
  for (const m of text.matchAll(STRIPE_ID)) if (!PLACEHOLDER.test(m[0])) found.push(m[0]);
  for (const m of text.matchAll(HOSTED_PAGE)) if (!/^https:\/\/[a-z]+\.stripe\.com\/redacted$/.test(m[0])) found.push(m[0]);
  return found;
}
