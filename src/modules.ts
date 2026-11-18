// The built-in modules and a starting config that turns them on.
import type { FlowConfig } from "./core/config.ts";
import type { AssuranceModule } from "./core/module.ts";
import { defaultVerificationPolicy } from "./core/policy.ts";
import { dossierModule } from "./file/dossier.ts";
import { paylinkModule } from "./pay/paylink.ts";
import { traceModule } from "./prove/trace.ts";
import { badgeModule, type BadgeModule } from "./verify/badge.ts";

/** The names of the built-in modules. Gate (entry) joins them in PR 2 of the modular core (GAT-1). */
export const BUILT_IN_MODULES = ["badge", "dossier", "paylink", "trace"] as const;

/** Badge (with the given factor plug-ins, if any), Dossier, Paylink and Trace. */
export function builtInModules(badge: BadgeModule = badgeModule()): AssuranceModule[] {
  return [badge, dossierModule, paylinkModule, traceModule];
}

/**
 * Every built-in module on, the default policy, keypad knowledge, carrier signals and photo ID as
 * factors, receipts on, and no forms, wordings or flows. A host starts from its own config instead.
 */
export function defaultConfig(): FlowConfig {
  return {
    version: 1,
    revision: "default",
    policy: defaultVerificationPolicy(),
    modules: {
      badge: { settings: { factors: ["keypad_knowledge", "carrier_identity_match", "photo_id"] } },
      dossier: { settings: { forms: [] } },
      paylink: { settings: {} },
      trace: { settings: { receipts: true, wordings: [] } },
    },
    flows: {},
  };
}
