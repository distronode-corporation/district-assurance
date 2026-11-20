// Every workflow that installs dependencies does so with install scripts off, so a compromised
// dependency's preinstall or postinstall never runs on a runner (with a token in reach).
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";

const dir = new URL("../.github/workflows/", import.meta.url);
const workflows = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));

const INSTALL = /\bnpm\s+(ci|cit|i|install|install-test|install-ci-test|add)\b/;

/** Each non-comment line of a workflow that runs an npm install without `--ignore-scripts`. */
function bareInstalls(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/(^|\s)#.*$/, ""))
    .filter((line) => INSTALL.test(line) && !/--ignore-scripts\b/.test(line))
    .map((line) => line.trim());
}

describe("dependency installs in the workflows", () => {
  it("finds the workflows", () => {
    assert.ok(workflows.includes("ci.yml"), workflows.join(", "));
  });

  for (const file of workflows) {
    it(`${file} installs only with --ignore-scripts`, () => {
      assert.deepEqual(bareInstalls(readFileSync(new URL(file, dir), "utf8")), []);
    });
  }

  it("the check catches a bare install in any spelling, and skips comments", () => {
    for (const line of ["      - run: npm ci", "        run: npm install", "          npm i left-pad", "npm   ci --omit=dev", "npm cit"]) {
      assert.deepEqual(bareInstalls(line), [line.trim()], line);
    }
    for (const line of ["      - run: npm ci --ignore-scripts", "      # No `npm ci`, on purpose", "      - run: npm run lint # not npm ci", "npm audit"]) {
      assert.deepEqual(bareInstalls(line), [], line);
    }
  });

  it("reads CRLF line endings, as a Windows checkout may hold a workflow: comments still skipped", () => {
    assert.deepEqual(bareInstalls("      # No `npm ci`, on purpose\r\n      - run: npm ci --ignore-scripts # not npm ci\r\n"), []);
    assert.deepEqual(bareInstalls("      - run: npm ci\r\n      # npm install\r\n"), ["- run: npm ci"]);
  });
});
