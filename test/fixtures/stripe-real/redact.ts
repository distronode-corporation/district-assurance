// Redaction for the recorded Stripe test-mode runs. The repository is public, so nothing that names
// the recording account or its objects is kept: every Stripe id becomes a placeholder of the same
// prefix and shape (`acct_redacted0001`, `cs_test_redacted0001`), the same id always the same
// placeholder across every file of one recording (so a session, its event and its account still
// line up), hosted page URLs lose their path and fragment, business display names are replaced,
// a customer's personal details (every value under `customer_details`, `billing_details`,
// `shipping_details` or `shipping`, and `customer_email` or `receipt_email`) are replaced, and
// client secrets, keys and webhook signing secrets are removed. Text is redacted in place, so
// an event body keeps Stripe's own bytes apart from the replaced values.

/** A Stripe object id: a lower-case prefix (`cs_test` included), then a mixed-case token with a digit and a capital. */
export const STRIPE_ID = /\b([a-z]{1,10}(?:_test|_live)?)_((?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Z])[A-Za-z0-9]{10,})\b/g;
/** Any API key or webhook signing secret. */
export const KEY_OR_SECRET = /\b(?:(?:sk|rk|pk)_(?:test|live)|whsec)_[A-Za-z0-9]+/g;
/** A client secret (`<object id>_secret_<token>`), the whole token: it can hold underscores (`_secret_test_...`) and base64 of the account id. */
const CLIENT_SECRET = /\b[a-z]{1,10}(?:_test|_live)?_[A-Za-z0-9]+_secret_[A-Za-z0-9_-]+/g;
/** A Stripe-hosted page: its path and fragment carry the session and a publishable key. */
const HOSTED_PAGE = /https:\/\/(checkout|verify|connect|pay|invoice)\.stripe\.com\/[^"\s\\]*/g;
/** A business's display name in JSON text: the whole string literal, escaped characters included. */
const DISPLAY_NAME = /("display_name"\s*:\s*")(?:[^"\\]|\\.)*"/g;
/** Objects whose every string is a customer's personal detail, at any depth (`address` included). */
const PERSONAL_OBJECTS = new Set(["customer_details", "billing_details", "shipping_details", "shipping"]);
/** A customer's email address outside those objects. */
const PERSONAL_KEYS = new Set(["customer_email", "receipt_email"]);
/** A field inside such an object that is not personal. */
const NOT_PERSONAL = new Set(["tax_exempt"]);
const REDACTED = "[redacted]";

/** Whether the string under `key` is personal, given whether it sits inside a personal object. */
const personal = (key: string | null, inPersonal: boolean): boolean => (key !== null && PERSONAL_KEYS.has(key)) || (inPersonal && (key === null || !NOT_PERSONAL.has(key)));

/** Every personal string in `value` replaced, by key and at any depth; `changed` says whether one was. */
function redactPersonal(value: unknown, key: string | null, inPersonal: boolean): { value: unknown; changed: boolean } {
  if (typeof value === "string") return personal(key, inPersonal) && value !== REDACTED ? { value: REDACTED, changed: true } : { value, changed: false };
  let changed = false;
  const each = (k: string | null, x: unknown, within: boolean) => {
    const out = redactPersonal(x, k, within);
    changed ||= out.changed;
    return out.value;
  };
  if (Array.isArray(value)) return { value: value.map((x) => each(key, x, inPersonal)), changed };
  if (typeof value === "object" && value !== null) {
    const out = Object.fromEntries(Object.entries(value).map(([k, x]) => [k, each(k, x, inPersonal || PERSONAL_OBJECTS.has(k))]));
    return { value: out, changed };
  }
  return { value, changed: false };
}

/** JSON text as a value, or undefined for text that is not a JSON object or array. */
function parsed(text: string): unknown {
  if (!/^\s*[{[]/.test(text)) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** Personal strings left in `value`, by key and at any depth, JSON text held in a string included. */
function personalLeaks(value: unknown, key: string | null, inPersonal: boolean, found: string[]): void {
  if (typeof value === "string") {
    if (personal(key, inPersonal) && value !== REDACTED) found.push(`${key ?? "item"}: ${value}`);
    else {
      const inner = parsed(value);
      if (inner !== undefined) personalLeaks(inner, null, false, found);
    }
  } else if (Array.isArray(value)) for (const x of value) personalLeaks(x, key, inPersonal, found);
  else if (typeof value === "object" && value !== null) for (const [k, x] of Object.entries(value)) personalLeaks(x, k, inPersonal || PERSONAL_OBJECTS.has(k), found);
}

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
    const redacted = value
      .replace(KEY_OR_SECRET, "[removed]")
      .replace(CLIENT_SECRET, "[removed]")
      .replace(HOSTED_PAGE, (_url, host: string) => `https://${host}.stripe.com/redacted`)
      .replace(DISPLAY_NAME, '$1[redacted]"')
      .replace(STRIPE_ID, (real) => this.id(real));
    return this.#personalText(redacted);
  }

  /**
   * JSON text with a customer's personal details replaced. Text with none is returned as it was,
   * byte for byte; text with some is written again at its own indentation (Stripe's bodies are
   * two-space JSON), since a value can hold anything, braces included, and only a parse finds it.
   */
  #personalText(text: string): string {
    const value = parsed(text);
    if (value === undefined) return text;
    const out = redactPersonal(value, null, false);
    if (!out.changed) return text;
    const indent = /^[{[]\r?\n( +)/.exec(text)?.[1]?.length ?? 0;
    return `${JSON.stringify(out.value, null, indent)}${text.endsWith("\n") ? "\n" : ""}`;
  }

  /**
   * A JSON value with every string redacted, keys included, one string at a time: a string that
   * holds JSON text (an event body) is redacted as that text, so its own escaping is never in the way.
   */
  json<T>(value: T): T {
    const walk = (v: unknown, key: string | null, inPersonal: boolean): unknown => {
      if (typeof v === "string") return personal(key, inPersonal) ? REDACTED : this.text(v);
      if (Array.isArray(v)) return v.map((x) => walk(x, key, inPersonal));
      if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [this.text(k), walk(x, k, inPersonal || PERSONAL_OBJECTS.has(k))]));
      return v;
    };
    return walk(value, null, false) as T;
  }
}

/** What a redacted file must never hold: a key or secret, a Stripe id that is not a placeholder, or a customer's personal detail. */
export function leaks(text: string): string[] {
  const found = [...text.matchAll(KEY_OR_SECRET)].map((m) => m[0]);
  for (const m of text.matchAll(STRIPE_ID)) if (!PLACEHOLDER.test(m[0])) found.push(m[0]);
  for (const m of text.matchAll(HOSTED_PAGE)) if (!/^https:\/\/[a-z]+\.stripe\.com\/redacted$/.test(m[0])) found.push(m[0]);
  // What a partial redaction leaves: a secret's tail after the marker, base64 of an account id.
  for (const m of text.matchAll(/\[removed\][A-Za-z0-9_-]+|_secret_[A-Za-z0-9]|YWNjdF|FjY3Rf|hY2N0X/g)) found.push(m[0]);
  // A customer's personal details, found by parsing (a file, and each body it holds as JSON text).
  const value = parsed(text);
  if (value !== undefined) personalLeaks(value, null, false, found);
  return found;
}
