// The audit pack's --out check (SRV-8), apart from scripts/audit-pack.mjs so it can be tested
// without building a pack.
import { existsSync, readdirSync } from "node:fs";

/** Written first into every pack, so an earlier pack (finished or not) is told from a folder of someone's own. */
export const MARKER = ".audit-pack";

/** The entries a pack holds. */
export const PACK_ENTRIES: readonly string[] = [MARKER, "tests", "coverage", "contracts", "sbom", "docs", "INDEX.md", "SHA256SUMS"];

/**
 * Null when `dir` may be emptied and filled with a pack, else why not. The folder is emptied, so it
 * must be new, empty, or an earlier pack: one holding the marker and nothing but a pack's entries.
 * A folder of someone's own that happens to hold only `docs/` or `tests/` has no marker and is kept.
 */
export function outProblem(dir: string): string | null {
  if (!existsSync(dir)) return null;
  const names = readdirSync(dir);
  if (names.length === 0) return null;
  if (!names.includes(MARKER)) return "is not empty and is not an earlier pack; choose a new folder";
  if (!names.every((name) => PACK_ENTRIES.includes(name))) return "holds files that are not part of the earlier pack; choose a new folder";
  return null;
}
