// Tests run on Windows too: a file URL's pathname is not a path there ("/C:/..."), so a path
// built from import.meta.url goes through fileURLToPath.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "node_modules" ? [] : files(path);
    return /\.(ts|mjs|js)$/.test(entry.name) ? [path] : [];
  });
}

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SCANNED = ["test", "scripts", "examples"].flatMap((dir) => files(join(ROOT, dir)));

describe("portable paths", () => {
  it("never use a file URL's pathname as a path", () => {
    assert.ok(SCANNED.length > 0);
    const offenders = SCANNED.filter((path) => /import\.meta\.url\)\.pathname/.test(readFileSync(path, "utf8")));
    assert.deepEqual(offenders, []);
  });
});
