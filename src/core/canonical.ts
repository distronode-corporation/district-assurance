// Canonical JSON: one byte sequence per value, so a hash or a signature over it is stable.
//
// The output follows RFC 8785 (JSON Canonicalization Scheme) for the values this engine
// produces: object keys sorted by UTF-16 code units, no whitespace, strings and numbers
// serialised as ECMAScript's JSON.stringify does. Anything JSON cannot carry faithfully is
// refused instead of being dropped or coerced: undefined, functions, symbols, bigints,
// non-finite numbers, strings with a lone UTF-16 surrogate, and objects that are not plain (a
// Date, a Map, a class instance).

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
      return jsonString(value, path);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`canonicalJson: non-finite number at ${path}`);
      return JSON.stringify(value);
    case "object":
      return Array.isArray(value) ? serialiseArray(value, path) : serialiseObject(value, path);
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value} at ${path}`);
  }
}

/** A string as JSON, refusing a lone UTF-16 surrogate, which RFC 8785 says must fail. */
function jsonString(value: string, path: string): string {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
    }
    if (unit >= 0xd800 && unit <= 0xdfff) throw new TypeError(`canonicalJson: lone surrogate in a string at ${path}`);
  }
  return JSON.stringify(value);
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
  const parts = keys.map((key) => `${jsonString(key, path)}:${serialise(record[key], `${path}.${key}`)}`);
  return `{${parts.join(",")}}`;
}
