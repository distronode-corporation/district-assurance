// Assurance levels and the policy that decides what a verified caller may do.
//
// The model never takes part in this: factors are results recorded by code, the level is computed
// from them here, and a scope is allowed only when the level reaches the scope's minimum. Caller
// ID is not a factor kind at all, so no policy can count it.

export type AssuranceLevel = 0 | 1 | 2 | 3;

export const FACTOR_KINDS = [
  /** Digits keyed on the phone keypad and compared with the record on file (account number, date of birth). */
  "keypad_knowledge",
  /** A spoken answer, normalised and compared exactly, for values a keypad cannot enter. */
  "spoken_knowledge",
  /** A one-time code texted to the number on file, sent only after the keypad checks match. */
  "text_code",
  /** The carrier confirms that the number on file belongs to the person on record. */
  "carrier_identity_match",
  /** A keypad PIN the caller chose after an earlier strong verification. */
  "returning_pin",
  /** A government photo ID plus a selfie, checked by an identity provider through a texted link. */
  "photo_id",
] as const;

export type FactorKind = (typeof FACTOR_KINDS)[number];

export interface FactorResult {
  kind: FactorKind;
  passed: boolean;
  /** ISO 8601. */
  at: string;
}

/** What a carrier said about the number on file. Never about the calling number. */
export interface CarrierSignalReport {
  /** False when the carrier could not answer (no coverage, no approval, an error). */
  checked: boolean;
  /** Hours since the last SIM change, or null when none is known. */
  lastSimSwapHoursAgo: number | null;
  /** Hours since the number was last ported, or null when none is known. */
  lastPortHoursAgo: number | null;
  identityMatch: "match" | "no_match" | "unavailable";
}

export interface LevelRule {
  level: 1 | 2 | 3;
  /** The level is reached when every factor in at least one of these sets has passed. */
  anyOf: FactorKind[][];
}

export interface VerificationPolicy {
  version: string;
  levels: LevelRule[];
  /** Scope key to the minimum level. A scope that is not listed is refused. */
  scopes: Record<string, AssuranceLevel>;
  /** The keypad fields judged together as one keypad_knowledge factor, for example ["dob"]. */
  keypadFields: string[];
  /** Keypad attempts allowed per call before the line stops judging. */
  maxKeypadAttemptsPerCall: number;
  /** A SIM change or port this recent makes a texted code worthless. */
  simSwapWindowHours: number;
  /** When the carrier could not answer, whether a texted code still counts. Default policy: no. */
  trustTextCodeWithoutCarrierCheck: boolean;
}

/**
 * Minimum levels a policy cannot go below, by scope prefix. Money and contact changes always need
 * two factors (level 2), whatever the business sets.
 */
export const SCOPE_FLOORS: ReadonlyArray<readonly [prefix: string, floor: AssuranceLevel]> = [
  ["payment.", 2],
  ["payout.", 2],
  ["contact.", 2],
];

/** A conservative starting policy. Contact and payout changes need the photo ID tier. */
export function defaultVerificationPolicy(): VerificationPolicy {
  return {
    version: "default-1",
    levels: [
      { level: 1, anyOf: [["keypad_knowledge"]] },
      {
        level: 2,
        anyOf: [
          ["keypad_knowledge", "text_code"],
          ["keypad_knowledge", "carrier_identity_match"],
          ["returning_pin", "text_code"],
        ],
      },
      { level: 3, anyOf: [["keypad_knowledge", "photo_id"]] },
    ],
    scopes: {
      "status.read": 1,
      "intake.file": 1,
      "payment.request": 2,
      "contact.update": 3,
      "payout.update": 3,
    },
    keypadFields: ["dob"],
    maxKeypadAttemptsPerCall: 2,
    simSwapWindowHours: 72,
    trustTextCodeWithoutCarrierCheck: false,
  };
}

/** Every problem with a policy, as sentences. An empty list means the policy can be used. */
export function validatePolicy(policy: VerificationPolicy): string[] {
  const errors: string[] = [];
  const seen = new Set<number>();
  for (const rule of policy.levels) {
    if (![1, 2, 3].includes(rule.level)) errors.push(`level ${rule.level} is not 1, 2 or 3`);
    if (seen.has(rule.level)) errors.push(`level ${rule.level} is defined twice`);
    seen.add(rule.level);
    if (rule.anyOf.length === 0) errors.push(`level ${rule.level} has no factor sets`);
    for (const set of rule.anyOf) errors.push(...checkFactorSet(rule.level, set));
  }
  for (const [scope, level] of Object.entries(policy.scopes)) {
    if (![0, 1, 2, 3].includes(level)) errors.push(`scope ${scope} has level ${level}, not 0 to 3`);
    const floor = scopeFloor(scope);
    if (level < floor) errors.push(`scope ${scope} is below its floor of level ${floor}`);
  }
  if (policy.keypadFields.length === 0) errors.push("keypadFields is empty");
  if (new Set(policy.keypadFields).size !== policy.keypadFields.length) errors.push("keypadFields has duplicates");
  if (!Number.isInteger(policy.maxKeypadAttemptsPerCall) || policy.maxKeypadAttemptsPerCall < 1) {
    errors.push("maxKeypadAttemptsPerCall must be a positive integer");
  }
  if (!(policy.simSwapWindowHours > 0)) errors.push("simSwapWindowHours must be positive");
  return errors;
}

function checkFactorSet(level: number, set: FactorKind[]): string[] {
  const errors: string[] = [];
  const label = `level ${level} set [${set.join(", ")}]`;
  if (set.length === 0) return [`level ${level} has an empty factor set`];
  for (const kind of set) {
    if (!(FACTOR_KINDS as readonly string[]).includes(kind)) errors.push(`${label}: unknown factor ${kind}`);
  }
  if (new Set(set).size !== set.length) errors.push(`${label}: a factor is repeated`);
  if (level >= 2 && new Set(set).size < 2) errors.push(`${label}: level 2 and above need two different factors`);
  if (set.length === 1 && set[0] === "text_code") errors.push(`${label}: a texted code is never a factor on its own`);
  if (level === 3 && !set.includes("photo_id")) errors.push(`${label}: level 3 needs photo_id`);
  return errors;
}

/** The floor for a scope key: the highest floor whose prefix matches, or 0. */
export function scopeFloor(scope: string): AssuranceLevel {
  let floor: AssuranceLevel = 0;
  for (const [prefix, value] of SCOPE_FLOORS) if (scope.startsWith(prefix) && value > floor) floor = value;
  return floor;
}

/** Whether a texted code can be trusted, given what the carrier said about the number on file. */
export function textCodeTrusted(policy: VerificationPolicy, report: CarrierSignalReport | null): boolean {
  if (report === null || !report.checked) return policy.trustTextCodeWithoutCarrierCheck;
  const recent = (hours: number | null) => hours !== null && hours <= policy.simSwapWindowHours;
  return !recent(report.lastSimSwapHoursAgo) && !recent(report.lastPortHoursAgo);
}

export interface AssuranceResult {
  level: AssuranceLevel;
  /** The passed factor kinds that counted, sorted. */
  counted: FactorKind[];
  /** Passed factors that did not count, and why. */
  discounted: Array<{ kind: FactorKind; reason: "carrier_signal" }>;
}

/** The level a set of recorded factors reaches under a policy. */
export function evaluateAssurance(
  policy: VerificationPolicy,
  factors: readonly FactorResult[],
  carrier: CarrierSignalReport | null,
): AssuranceResult {
  const passed = new Set(factors.filter((f) => f.passed).map((f) => f.kind));
  const discounted: AssuranceResult["discounted"] = [];
  if (passed.has("text_code") && !textCodeTrusted(policy, carrier)) {
    passed.delete("text_code");
    discounted.push({ kind: "text_code", reason: "carrier_signal" });
  }
  let level: AssuranceLevel = 0;
  for (const rule of policy.levels) {
    if (rule.level > level && rule.anyOf.some((set) => set.every((kind) => passed.has(kind)))) level = rule.level;
  }
  return { level, counted: [...passed].sort(), discounted };
}

/** The scopes a level unlocks, sorted. Scopes at level 0 need no verification and are included. */
export function scopesForLevel(policy: VerificationPolicy, level: AssuranceLevel): string[] {
  return Object.entries(policy.scopes)
    .filter(([, min]) => min <= level)
    .map(([scope]) => scope)
    .sort();
}
