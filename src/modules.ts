// The built-in modules and a starting config that turns them on.
import type { FlowConfig } from "./core/config.ts";
import type { AssuranceModule } from "./core/module.ts";
import { defaultVerificationPolicy } from "./core/policy.ts";
import { dossierModule } from "./file/dossier.ts";
import { gateModule } from "./gate/gate.ts";
import { paylinkModule } from "./pay/paylink.ts";
import { traceModule } from "./prove/trace.ts";
import { badgeModule, type BadgeModule } from "./verify/badge.ts";

/**
 * The names of the built-in modules, which the engine wires and runs itself: no outside code can
 * reach their part of a call. Gate is one (ADR-25): its controllers and signer are engine adapters.
 */
export const BUILT_IN_MODULES = ["badge", "dossier", "paylink", "trace", "gate"] as const;

/** Badge (with the given factor plug-ins, if any), Dossier, Paylink, Trace and Gate. */
export function builtInModules(badge: BadgeModule = badgeModule()): AssuranceModule[] {
  return [badge, dossierModule, paylinkModule, traceModule, gateModule];
}

/**
 * Badge, Dossier, Paylink and Trace on (Gate off: it needs doors, and the access adapters), the
 * default policy, keypad knowledge, carrier signals and photo ID as factors, receipts on, and no
 * forms, wordings or flows. A host starts from its own config instead.
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
