// Canonical JSON: one byte sequence per value, so a hash or a signature over it is stable.
//
// The output follows RFC 8785 (JSON Canonicalization Scheme) for the values this engine
// produces: object keys sorted by UTF-16 code units, no whitespace, strings and numbers
// serialised as ECMAScript's JSON.stringify does. Anything JSON cannot carry faithfully is
// refused instead of being dropped or coerced: undefined, functions, symbols, bigints,
// non-finite numbers, objects that are not plain (a Date, a Map, a class instance), and
// strings or keys holding a lone surrogate (RFC 8785, section 3.2.2.2: not valid Unicode).

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  return serialise(value, "$");
}

function serialise(value: unknown, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return serialiseString(value, path);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`canonicalJson: non-finite number at ${path}`);
      return JSON.stringify(value);
    case "object":
      return Array.isArray(value) ? serialiseArray(value, path) : serialiseObject(value, path);
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value} at ${path}`);
  }
}

function serialiseArray(items: unknown[], path: string): string {
  const parts: string[] = [];
  for (let i = 0; i < items.length; i++) {
    // A sparse array's hole would read as undefined, and is refused like one.
    parts.push(serialise(items[i], `${path}[${i}]`));
  }
  return `[${parts.join(",")}]`;
}

function serialiseObject(value: object, path: string): string {
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`canonicalJson: not a plain object at ${path}`);
  }
  const record = value as Record<string, unknown>;
  // Default sort compares UTF-16 code units, which is what RFC 8785 asks for.
  const keys = Object.keys(record).sort();
  const parts = keys.map((key) => `${serialiseString(key, `${path}.${key}`)}:${serialise(record[key], `${path}.${key}`)}`);
  return `{${parts.join(",")}}`;
}

function serialiseString(value: string, path: string): string {
  // JSON.stringify would write a lone surrogate as an escape; RFC 8785 refuses it.
  if (!value.isWellFormed()) throw new TypeError(`canonicalJson: lone surrogate at ${path}`);
  return JSON.stringify(value);
}
