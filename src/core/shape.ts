// Small type checks for values that come from storage or a request (a FlowConfig, module
// settings). Validators use them so that a malformed document gives sentences, never a crash.

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A dense array of strings. A hole in a sparse array is not a string. */
export function isStringArray(value: unknown): value is string[] {
  return isDenseArray(value) && value.every((item) => typeof item === "string");
}

/**
 * An array with no holes (`every` and `forEach` skip holes, so check before using them): an own
 * element at every index. Counting keys is not enough, since a named key can stand in for a hole.
 */
export function isDenseArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value)) return false;
  for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) return false;
  return true;
}

export function isIntegerIn(value: unknown, min: number, max: number): value is number {
  return Number.isInteger(value) && (value as number) >= min && (value as number) <= max;
}

export function isBilingual(value: unknown): value is { en: string; fr: string } {
  return isObject(value) && typeof value.en === "string" && value.en.trim() !== "" && typeof value.fr === "string" && value.fr.trim() !== "";
}

/** Keys of an object that are not in the allowed list, so a typo in a config never passes silently. */
export function unknownKeys(value: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(value).filter((key) => !allowed.includes(key));
}
