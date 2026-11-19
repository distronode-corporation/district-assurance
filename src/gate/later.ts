// Gate pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** Direct vendor adapters, one per brand, for systems no aggregator reaches (GAT-6). */
export function vendorAccessController(_options: { vendor: "kisi" | "verkada"; apiKey: string }): never {
  throw new NotImplementedError("vendorAccessController", "GAT-6");
}
