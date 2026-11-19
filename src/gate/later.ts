// Gate pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";
import type { AccessController } from "./access.ts";

/** Seam, one API for August, Yale, Nuki, Salto KS, Kisi, Brivo and Avigilon Alta (GAT-5, after its pricing and data handling are checked). */
export function seamAccessController(_options: { apiKey: string }): AccessController {
  return {
    unlock: () => {
      throw new NotImplementedError("seamAccessController.unlock", "GAT-5");
    },
  };
}

/** Direct vendor adapters, one per brand, for systems no aggregator reaches (GAT-6). */
export function vendorAccessController(_options: { vendor: "kisi" | "verkada"; apiKey: string }): never {
  throw new NotImplementedError("vendorAccessController", "GAT-6");
}
