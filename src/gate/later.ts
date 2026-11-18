// Gate (entry): planned, the fifth built-in module. After verification it produces a signed,
// time-limited access grant (ES256 over canonical JSON, like receipts), delivers it through an
// `AccessController` adapter (a door controller webhook, a one-time access code, a web sign-in
// step-up), refuses without a valid verification grant, and writes every grant to the ledger.
import { NotImplementedError } from "../core/errors.ts";

/** The Gate module, to install with `engine.use(...)` and turn on in the config. */
export function gateModule(): never {
  throw new NotImplementedError("gateModule", "GAT-1");
}
