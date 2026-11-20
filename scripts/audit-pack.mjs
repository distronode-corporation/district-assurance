// Builds the audit pack (SRV-8): one folder an outside auditor can start from. It holds the test
// and coverage reports, the contract suite results, the SBOM, the threat model with its STRIDE
// tables and the other documents, an INDEX.md that says where to begin, and SHA256SUMS over
// every file in it.
//
//   node scripts/audit-pack.mjs [--out <dir>] [--sbom <file>]
//
// --out   Where to write the pack. Default: .tmp/audit-pack (git ignores .tmp/). It is emptied
//         first, so it must be new, empty or an earlier pack (one holding the .audit-pack marker
//         this script writes first, and nothing else of its own); anything else is refused.
// --sbom  The release SBOM to include (SRV-6), copied into sbom/supplied/ so it never shares a
//         name with the manifests. Without it, the pack holds a CycloneDX SBOM that `npm sbom`
//         derives from package-lock.json, and INDEX.md says it is a stand-in.
//
// The pack fails closed: a failing test, coverage under 100% in any src/ file, a failing contract
// suite, a missing document or no SBOM stops it with a non-zero exit. A pack that exists is one
// whose gate passed. It reads no secret, and writes only --out and a new temporary folder (mkdtemp
// under the OS temp folder) for the v8 coverage data, which never overlaps --out.
//
// Importing this file builds nothing: the pack is built only when it is the program node runs,
// so its path checks can be tested on their own.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { MARKER, outProblem } from "./audit-pack-out.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The documents an auditor reads, copied as they are. SECURITY-MODEL.md holds the STRIDE tables. */
const DOCS = [
  "README.md",
  "ARCHITECTURE.md",
  "SPEC.md",
  "SECURITY-MODEL.md",
  "SECURITY.md",
  "DECISIONS.md",
  "ROADMAP.md",
  "ISSUES.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "LICENSE",
  "NOTICE",
];

/** The manifests the SBOM is derived from, copied next to it. */
export const MANIFESTS = ["package.json", "package-lock.json"];

/** The folder of sbom/ a supplied SBOM goes in, so a file named like a manifest never overwrites it, nor is overwritten. */
export const SUPPLIED_SBOM_DIR = "supplied";

/** Where in the pack a supplied SBOM is copied, with forward slashes: `sbom/supplied/<its name>`. */
export function suppliedSbomPath(given) {
  return `sbom/${SUPPLIED_SBOM_DIR}/${basename(given)}`;
}

/** A path with every part that exists resolved through symlinks; the parts that do not exist yet are kept as given. */
function realish(path) {
  const absolute = resolve(path);
  const rest = [];
  let at = absolute;
  for (;;) {
    try {
      return join(realpathSync(at), ...rest);
    } catch {
      const parent = dirname(at);
      // The root always resolves, so the loop ends there at the latest.
      rest.unshift(basename(at));
      at = parent;
    }
  }
}

/** Whether `inner` is `outer` or inside it. */
function within(inner, outer) {
  return inner === outer || inner.startsWith(outer.endsWith(sep) ? outer : outer + sep);
}

/**
 * Null when --out (`out`) and the v8 temp folder (`temp`) are apart, else why not. The temp folder
 * is removed after the tests and --out is emptied, so neither may hold the other: compared through
 * symlinks, in both directions.
 */
export function v8TempProblem(out, temp) {
  const o = realish(out);
  const t = realish(temp);
  if (within(o, t) || within(t, o)) return `overlaps the coverage temp folder ${temp}; choose a folder apart from it`;
  return null;
}

/** A test file that runs a contract suite: it calls one of the `...Contract(` functions of src/testing. */
const CONTRACT_CALL = /\b[a-z]\w*Contract\(/;

function fail(message) {
  console.error(`audit-pack: ${message}`);
  process.exit(1);
}

/** Runs a command in the repository root; stderr goes to the console, stdout is returned. */
function run(command, args, what) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "inherit"],
    // npm is a .cmd script on Windows, which only a shell can start.
    shell: command === "npm" && process.platform === "win32",
  });
  if (result.error) fail(`${what}: ${result.error.message}`);
  return { status: result.status, stdout: result.stdout };
}

function git(args) {
  const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

/** The node --test reporter flags for a spec report on stderr, and spec and JUnit files in `dir`. */
function reporters(dir) {
  return [
    "--test-reporter=spec",
    "--test-reporter-destination=stderr",
    "--test-reporter=spec",
    `--test-reporter-destination=${join(dir, "spec.txt")}`,
    "--test-reporter=junit",
    `--test-reporter-destination=${join(dir, "junit.xml")}`,
  ];
}

/** The counts node's spec reporter prints at the end ("ℹ tests 9", "ℹ pass 9" and so on). */
function counts(specFile) {
  const text = readFileSync(specFile, "utf8").replace(/\r\n/g, "\n");
  const out = {};
  for (const name of ["tests", "suites", "pass", "fail", "cancelled", "skipped", "todo"]) {
    const m = new RegExp(`^\\S+ ${name} (\\d+)$`, "m").exec(text);
    out[name] = m ? Number(m[1]) : null;
  }
  return out;
}

/** The STRIDE rows of SECURITY-MODEL.md: table, id and status, and the proof of open rows. */
function strideRows(markdown) {
  const start = markdown.indexOf("\n## STRIDE tables\n");
  if (start < 0) fail("SECURITY-MODEL.md has no STRIDE tables section");
  const end = markdown.indexOf("\n## ", start + 1);
  const rows = [];
  let table = "";
  for (const line of markdown.slice(start, end < 0 ? undefined : end).split("\n")) {
    if (line.startsWith("### ")) table = line.slice(4).trim();
    if (!line.startsWith("| ") || line.startsWith("| Id |")) continue;
    const cells = line.slice(1, -1).split("|").map((c) => c.trim());
    rows.push({ table, id: cells[0], threat: cells[2], status: cells[4], proof: cells[5] });
  }
  return rows;
}

/** Every file under `dir`, as sorted paths relative to it with forward slashes. */
function files(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) out.push(relative(dir, join(entry.parentPath, entry.name)).split(sep).join("/"));
  }
  return out.sort();
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Builds the pack: the steps below, in order, stopping at the first that fails. */
function build() {
  const { values } = parseArgs({
    options: { out: { type: "string", default: join(".tmp", "audit-pack") }, sbom: { type: "string" } },
    strict: true,
  });
  const OUT = resolve(ROOT, values.out);
  const FOLDERS = ["tests", "coverage", "contracts", "sbom", "docs"];
  // The folder is emptied, so it must be new, empty or an earlier pack (finished or not, told by its
  // marker), never the repository, a folder of it, or a folder of someone's own, by mistake.
  const outRefused = outProblem(OUT);
  if (outRefused !== null) fail(`--out ${values.out} ${outRefused}`);
  // The v8 coverage data goes in a new folder of its own, made before --out is touched, so a --out
  // that holds it, or that it holds, is refused before anything is emptied.
  const v8Temp = mkdtempSync(join(tmpdir(), "audit-pack-v8-"));
  const tempRefused = v8TempProblem(OUT, v8Temp);
  if (tempRefused !== null) {
    rmSync(v8Temp, { recursive: true, force: true });
    fail(`--out ${values.out} ${tempRefused}`);
  }

  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  // The marker first, so a pack that stops part way can be emptied by the next run.
  writeFileSync(join(OUT, MARKER), "district-assurance audit pack: this folder is emptied by the next scripts/audit-pack.mjs run\n");
  for (const dir of FOLDERS) mkdirSync(join(OUT, dir), { recursive: true });

  // 1. Every test, under c8: the test reports, and the coverage reports held to .c8rc.json's 100%.
  const c8 = join(dirname(createRequire(import.meta.url).resolve("c8/package.json")), "bin", "c8.js");
  const tested = run(
    process.execPath,
    [
      c8,
      "--reporter=text",
      "--reporter=json-summary",
      "--reporter=lcov",
      `--reports-dir=${join(OUT, "coverage")}`,
      `--temp-directory=${v8Temp}`,
      process.execPath,
      "--test",
      "--throw-deprecation",
      ...reporters(join(OUT, "tests")),
      "test/**/*.test.ts",
    ],
    "tests and coverage",
  );
  rmSync(v8Temp, { recursive: true, force: true });
  writeFileSync(join(OUT, "coverage", "coverage.txt"), tested.stdout);
  process.stdout.write(tested.stdout);
  if (tested.status !== 0) fail("the tests or the coverage gate failed; no pack");

  // 2. The contract suites on their own, so their results read apart from the rest.
  const contractFiles = readdirSync(join(ROOT, "test"))
    .filter((name) => name.endsWith(".test.ts") && CONTRACT_CALL.test(readFileSync(join(ROOT, "test", name), "utf8")))
    .sort()
    .map((name) => `test/${name}`);
  if (contractFiles.length === 0) fail("no test file runs a contract suite");
  const contracts = run(process.execPath, ["--test", "--throw-deprecation", ...reporters(join(OUT, "contracts")), ...contractFiles], "contract suites");
  if (contracts.status !== 0) fail("a contract suite failed; no pack");

  // 3. The SBOM: the release's own when given (SRV-6), otherwise one derived from the lockfile.
  let sbomNote;
  if (values.sbom !== undefined) {
    const given = resolve(values.sbom);
    if (!existsSync(given)) fail(`--sbom ${values.sbom} does not exist`);
    const packed = suppliedSbomPath(given);
    mkdirSync(join(OUT, "sbom", SUPPLIED_SBOM_DIR), { recursive: true });
    copyFileSync(given, join(OUT, ...packed.split("/")));
    sbomNote = `\`${packed}\` is the release SBOM given to this script.`;
  } else {
    const sbom = run("npm", ["sbom", "--sbom-format", "cyclonedx", "--package-lock-only"], "npm sbom");
    if (sbom.status !== 0 || sbom.stdout.trim() === "") fail("npm sbom failed; no pack");
    writeFileSync(join(OUT, "sbom", "sbom.cdx.json"), sbom.stdout);
    sbomNote =
      "`sbom/sbom.cdx.json` is a **stand-in**: CycloneDX from `npm sbom --package-lock-only`, the whole tree, development tools included. " +
      "Pass the release SBOM (SRV-6) with `--sbom <file>` to include it instead.";
  }
  for (const name of MANIFESTS) copyFileSync(join(ROOT, name), join(OUT, "sbom", name));

  // 4. The documents.
  for (const name of DOCS) {
    if (!existsSync(join(ROOT, name))) fail(`${name} is missing`);
    copyFileSync(join(ROOT, name), join(OUT, "docs", name));
  }

  // 5. INDEX.md: where to start, what was built from what, and the counts.
  const all = counts(join(OUT, "tests", "spec.txt"));
  const contractCounts = counts(join(OUT, "contracts", "spec.txt"));
  // Line endings normalised: a Windows checkout can hold the file with CRLF.
  const rows = strideRows(readFileSync(join(ROOT, "SECURITY-MODEL.md"), "utf8").replace(/\r\n/g, "\n"));
  const open = rows.filter((r) => r.status === "open");
  const covered = rows.filter((r) => r.status === "covered");
  if (rows.length === 0 || covered.length + open.length !== rows.length) fail("a STRIDE row is neither covered nor open");
  const commit = git(["rev-parse", "HEAD"]) ?? "unknown (not a git checkout)";
  const dirty = git(["status", "--porcelain"]);
  const committed = git(["log", "-1", "--format=%cI"]) ?? "unknown";
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

  const index = `# Audit pack: ${pkg.name} ${pkg.version}

Built by \`scripts/audit-pack.mjs\` from commit \`${commit}\` (committed ${committed})${dirty ? ", **with uncommitted changes**" : ""},
on Node ${process.version} (${process.platform}). The pack is built only when every test passes and
every \`src/\` file is at 100% coverage, so its reports are of a passing tree.

## Where to start

1. \`docs/SECURITY-MODEL.md\`: the threat model. Its STRIDE tables give one table per module and
    adapter; each row names its control and the test that proves it, or the ROADMAP.md issue that
    will build it while it is open. \`test/security-model.test.ts\` checks that every test named
    exists and every open issue is in ROADMAP.md.
2. \`docs/SPEC.md\` and \`docs/ARCHITECTURE.md\`: what the code does and how it is put together.
3. \`docs/DECISIONS.md\`: why, with alternatives.
4. The reports below, then the source at the commit above.

## Contents

| Folder | Holds |
|---|---|
| \`tests/\` | every test: \`spec.txt\` (readable) and \`junit.xml\` |
| \`coverage/\` | \`coverage.txt\` (per file), \`coverage-summary.json\`, \`lcov.info\` and an HTML report in \`lcov-report/\` |
| \`contracts/\` | the test files that run a contract suite, on their own (${contractFiles.map((f) => `\`${f}\``).join(", ")}): \`spec.txt\` and \`junit.xml\` |
| \`sbom/\` | the SBOM (a supplied one in \`sbom/${SUPPLIED_SBOM_DIR}/\`), \`package.json\` and \`package-lock.json\` |
| \`docs/\` | ${DOCS.map((d) => `\`${d}\``).join(", ")} |
| \`${MARKER}\` | marks the folder as a pack, which the next run may empty |
| \`SHA256SUMS\` | the SHA-256 of every other file in the pack (\`sha256sum -c SHA256SUMS\`) |

${sbomNote}

## Counts

| Run | Tests | Pass | Fail | Skipped | Todo |
|---|---|---|---|---|---|
| All tests | ${all.tests} | ${all.pass} | ${all.fail} | ${all.skipped} | ${all.todo} |
| Contract suites | ${contractCounts.tests} | ${contractCounts.pass} | ${contractCounts.fail} | ${contractCounts.skipped} | ${contractCounts.todo} |

STRIDE rows: ${rows.length}, of which ${covered.length} covered by tests and ${open.length} open.

## Open threats

Open rows are not covered, whatever the code does today; each names the issue that closes it.

| Table | Row | Threat | Issue |
|---|---|---|---|
${open.map((r) => `| ${r.table} | ${r.id} | ${r.threat} | ${r.proof} |`).join("\n")}
`;
  writeFileSync(join(OUT, "INDEX.md"), index);

  // 6. SHA256SUMS over everything else, in the format `sha256sum -c` reads.
  const sums = files(OUT)
    .filter((f) => f !== "SHA256SUMS")
    .map((f) => `${sha256(join(OUT, f))}  ${f}`)
    .join("\n");
  writeFileSync(join(OUT, "SHA256SUMS"), `${sums}\n`);

  console.log(`audit-pack: ${relative(ROOT, OUT) || "."} (${rows.length} STRIDE rows, ${open.length} open; ${all.tests} tests)`);
}

/** Whether this file is the program node was started with (not a test importing it), through symlinks. */
function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) build();
