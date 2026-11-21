// How the Stripe recorder (record.ts) writes a hosted page URL to a file: a new file, created
// exclusively with mode 0600 beside the destination, then renamed over it. A mode given to
// writeFileSync applies only to a file it creates, so writing over an existing file readable by
// others would leave the fresh URL readable by them too.
import { randomUUID } from "node:crypto";
import { renameSync, rmSync, writeFileSync } from "node:fs";

/** Writes `text` to `path` as a file only its owner can read, whatever was there before. */
export function writePrivateFile(path: string, text: string): void {
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, text, { mode: 0o600, flag: "wx" });
  try {
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}
