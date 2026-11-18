// Prove pieces that are planned and not built. Each throws NotImplementedError naming its issue.
import { NotImplementedError } from "../core/errors.ts";

/** Exports ledger entries from a cursor as signed newline-delimited JSON. */
export function exportLedger(_input: { fromSeq: number }): never {
  throw new NotImplementedError("exportLedger", "PRV-4");
}
