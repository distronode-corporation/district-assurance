// Assurance levels and the policy that decides what a verified caller may do.
//
// The model never takes part in this: factors are results recorded by code, the level is computed
// from them here, and a scope is allowed only when the level reaches the scope's minimum. Caller
// ID is not a factor kind at all, so no policy can count it, and no factor plug-in may take a name
// that means it (FORBIDDEN_FACTOR_KINDS).

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
  /** A keypad PIN, compared against a keyed hash on file or by the host's own PIN verifier. */
  "pin",
  /** A government photo ID plus a selfie, checked by an identity provider through a texted link. */
  "photo_id",
  /**
   * The business calls back the number on file and the person who answers keys a confirmation. It
   * proves possession of that line, like a texted code, and is recorded on the callback call only.
   */
  "callback",
] as const;

export type BuiltInFactorKind = (typeof FACTOR_KINDS)[number];

/** A built-in kind, or the kind of a factor plug-in a host added to Badge. */
export type FactorKind = BuiltInFactorKind | (string & {});

/** Names no factor may take: the calling number is never evidence of who is calling. */
export const FORBIDDEN_FACTOR_KINDS: readonly string[] = ["caller_id", "calling_number", "ani", "cli"];

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
  /**
   * The class of each scope whose name does not imply one (SCOPE_PREFIX_CLASSES), for example
   * `{ "owner.command": "none" }`. A scope with no class is refused, so a new money scope cannot
   * slip under the floor by its name. A class here can make a scope stricter, never looser.
   */
  scopeClasses?: Record<string, ScopeClass>;
}

/**
 * What a scope does, which sets its floor. Money movement, contact changes and access are never
 * below level 2, whatever the business sets. `none` is for scopes that move nothing (reading a
 * status, filing a request, an owner's own command); its floor is 0.
 */
export const SCOPE_CLASSES = ["money", "contact", "access", "none"] as const;
export type ScopeClass = (typeof SCOPE_CLASSES)[number];

export const CLASS_FLOORS: Readonly<Record<ScopeClass, AssuranceLevel>> = { money: 2, contact: 2, access: 2, none: 0 };

/** Scope name prefixes and the class their name implies. A name can only make a class stricter. */
export const SCOPE_PREFIX_CLASSES: ReadonlyArray<readonly [prefix: string, cls: ScopeClass]> = [
  ["payment.", "money"],
  ["payout.", "money"],
  ["refund.", "money"],
  ["transfer.", "money"],
  ["charge.", "money"],
  ["contact.", "contact"],
  ["entry.", "access"],
  ["access.", "access"],
  ["status.", "none"],
  ["intake.", "none"],
];

/** Factors that are not something the caller knows. Level 2 and above need one of them. */
export const NON_KNOWLEDGE_FACTORS: readonly string[] = ["text_code", "carrier_identity_match", "photo_id", "callback"];

/**
 * Factors that prove possession of the number on file, and share its weaknesses (a SIM swap, a
 * port-out, call forwarding, someone else answering). Never a set on their own, and discounted by
 * the carrier rule (`textCodeTrusted`).
 */
export const NUMBER_POSSESSION_FACTORS: readonly string[] = ["text_code", "callback"];

/** The policy's limit on keypad attempts per call, like the PIN's. */
export const MAX_KEYPAD_ATTEMPTS = 5;

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
          ["pin", "text_code"],
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

/**
 * Every problem with a policy, as sentences, in one pass: a malformed part is reported and the
 * rest is still checked. An empty list means the policy can be used. `knownFactors` is every
 * factor kind the installed modules provide; `declaredClasses` the scope classes their manifests
 * declare.
 */
export function validatePolicy(
  policy: unknown,
  knownFactors: readonly string[] = FACTOR_KINDS,
  declaredClasses: Readonly<Record<string, ScopeClass>> = {},
): string[] {
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) return ["must be an object"];
  const p = policy as Record<string, unknown>;
  const errors: string[] = [];
  if (typeof p.version !== "string" || p.version === "") errors.push("version must be a non-empty string");
  if (!Array.isArray(p.levels)) errors.push("levels must be a list of { level, anyOf: [[factor, ...], ...] }");
  const seen = new Set<unknown>();
  for (const [index, rule] of (Array.isArray(p.levels) ? p.levels : []).entries()) {
    const r = (typeof rule === "object" && rule !== null ? rule : {}) as Record<string, unknown>;
    const sets = Array.isArray(r.anyOf) && r.anyOf.every((set) => Array.isArray(set) && set.every((k) => typeof k === "string")) ? (r.anyOf as string[][]) : null;
    if (typeof r.level !== "number" || sets === null) {
      errors.push(`levels[${index}] must be { level, anyOf: [[factor, ...], ...] }`);
      continue;
    }
    if (![1, 2, 3].includes(r.level)) errors.push(`level ${r.level} is not 1, 2 or 3`);
    if (seen.has(r.level)) errors.push(`level ${r.level} is defined twice`);
    seen.add(r.level);
    if (sets.length === 0) errors.push(`level ${r.level} has no factor sets`);
    for (const set of sets) errors.push(...checkFactorSet(r.level, set, knownFactors));
  }
  const classes = p.scopeClasses;
  const classesOk = classes === undefined || (typeof classes === "object" && classes !== null && !Array.isArray(classes));
  if (!classesOk) errors.push("scopeClasses must map scope names to money, contact, access or none");
  const policyClasses = (classesOk ? (classes ?? {}) : {}) as Record<string, unknown>;
  for (const [scope, cls] of Object.entries(policyClasses)) {
    if (!(SCOPE_CLASSES as readonly unknown[]).includes(cls)) errors.push(`scopeClasses.${scope} must be money, contact, access or none`);
  }
  if (typeof p.scopes !== "object" || p.scopes === null || Array.isArray(p.scopes)) {
    errors.push("scopes must map scope names to levels");
  } else {
    for (const [scope, level] of Object.entries(p.scopes)) {
      if (!([0, 1, 2, 3] as unknown[]).includes(level)) {
        // Never coerce the value: an object with no usable toString would throw.
        errors.push(`scope ${scope} has level ${typeof level === "number" ? level : `of type ${level === null ? "null" : typeof level}`}, not 0 to 3`);
      }
      const cls = scopeClass(scope, policyClasses, declaredClasses);
      if (cls === null) {
        errors.push(`scope ${scope} has no class: name it in scopeClasses (money, contact, access or none)`);
        continue;
      }
      const floor = CLASS_FLOORS[cls];
      if (typeof level === "number" && level < floor) errors.push(`scope ${scope} is ${cls}, and below its floor of level ${floor}`);
    }
  }
  if (!Array.isArray(p.keypadFields) || !p.keypadFields.every((f) => typeof f === "string")) {
    errors.push("keypadFields must be a list of field names");
  } else {
    if (p.keypadFields.length === 0) errors.push("keypadFields is empty");
    if (new Set(p.keypadFields).size !== p.keypadFields.length) errors.push("keypadFields has duplicates");
  }
  const attempts = p.maxKeypadAttemptsPerCall;
  if (!Number.isInteger(attempts) || (attempts as number) < 1 || (attempts as number) > MAX_KEYPAD_ATTEMPTS) {
    errors.push(`maxKeypadAttemptsPerCall must be an integer from 1 to ${MAX_KEYPAD_ATTEMPTS}`);
  }
  if (typeof p.simSwapWindowHours !== "number" || !(p.simSwapWindowHours > 0)) errors.push("simSwapWindowHours must be a positive number");
  if (typeof p.trustTextCodeWithoutCarrierCheck !== "boolean") errors.push("trustTextCodeWithoutCarrierCheck must be true or false");
  return errors;
}

function checkFactorSet(level: number, set: string[], knownFactors: readonly string[]): string[] {
  const errors: string[] = [];
  const label = `level ${level} set [${set.join(", ")}]`;
  if (set.length === 0) return [`level ${level} has an empty factor set`];
  for (const kind of set) {
    if (!knownFactors.includes(kind)) errors.push(`${label}: unknown factor ${kind}`);
  }
  if (new Set(set).size !== set.length) errors.push(`${label}: a factor is repeated`);
  if (level >= 2 && new Set(set).size < 2) errors.push(`${label}: level 2 and above need two different factors`);
  if (level >= 2 && !set.some((kind) => NON_KNOWLEDGE_FACTORS.includes(kind))) {
    errors.push(`${label}: level 2 and above need a factor that is not something the caller knows (${NON_KNOWLEDGE_FACTORS.join(", ")})`);
  }
  if (set.every((kind) => NUMBER_POSSESSION_FACTORS.includes(kind))) {
    errors.push(`${label}: possession of the number on file (${NUMBER_POSSESSION_FACTORS.join(", ")}) is never a factor on its own`);
  }
  if (level === 3 && !set.includes("photo_id")) errors.push(`${label}: level 3 needs photo_id`);
  return errors;
}

const STRICTNESS: Readonly<Record<ScopeClass, number>> = { none: 0, access: 1, contact: 2, money: 3 };

/**
 * A scope's class: the strictest of what its name implies, what a module's manifest declares and
 * what the policy says. Null when none of them says anything.
 */
export function scopeClass(
  scope: string,
  policyClasses: Readonly<Record<string, unknown>> = {},
  declaredClasses: Readonly<Record<string, ScopeClass>> = {},
): ScopeClass | null {
  const found: ScopeClass[] = [];
  for (const [prefix, cls] of SCOPE_PREFIX_CLASSES) if (scope.startsWith(prefix)) found.push(cls);
  if (Object.hasOwn(declaredClasses, scope)) found.push(declaredClasses[scope]!);
  const own = Object.hasOwn(policyClasses, scope) ? policyClasses[scope] : undefined;
  if ((SCOPE_CLASSES as readonly unknown[]).includes(own)) found.push(own as ScopeClass);
  if (found.length === 0) return null;
  return found.reduce((a, b) => (STRICTNESS[b] > STRICTNESS[a] ? b : a));
}

/** The floor for a scope key by its name alone: the class its prefix implies, or 0. */
export function scopeFloor(scope: string): AssuranceLevel {
  const cls = scopeClass(scope);
  return cls === null ? 0 : CLASS_FLOORS[cls];
}

/**
 * Whether possession of the number on file (a texted code, a callback) can be trusted, given what
 * the carrier said about that number: not after a SIM change or a port inside the window, and not
 * without an answer unless the policy says so.
 */
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
  const trusted = textCodeTrusted(policy, carrier);
  for (const kind of NUMBER_POSSESSION_FACTORS) {
    if (passed.has(kind) && !trusted) {
      passed.delete(kind);
      discounted.push({ kind, reason: "carrier_signal" });
    }
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
