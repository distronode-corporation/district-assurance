// Small type checks for values that come from storage or a request (a FlowConfig, module
// settings). Validators use them so that a malformed document gives sentences, never a crash.

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
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
