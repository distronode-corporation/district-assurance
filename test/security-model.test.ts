// SRV-8: the STRIDE tables in SECURITY-MODEL.md name real tests and open issues, never an issue as proof.
import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { BUILT_IN_MODULES } from "../src/modules.ts";

interface Row {
  table: string;
  id: string;
  stride: string;
  threat: string;
  control: string;
  status: string;
  proof: string;
}

const STATUSES = ["covered", "open"];
/** One `file`: "test name" reference; the name is the literal first argument of an `it` or a `describe`. */
const TEST_REF = /`([a-z0-9-]+\.test\.ts)`: "([^"]+)"/g;
/** A covered row's proof: test references and nothing else, joined by "; ". */
const COVERED_PROOF = /^`[a-z0-9-]+\.test\.ts`: "[^"]+"(?:; `[a-z0-9-]+\.test\.ts`: "[^"]+")*$/;
/** An open row's proof: issue ids and nothing else, joined by ", ". */
const OPEN_PROOF = /^[A-Z]{3}-\d+(?:, [A-Z]{3}-\d+)*$/;

/** The "## STRIDE tables" section, up to the next level-2 heading. */
function strideSection(markdown: string): string {
  const start = markdown.indexOf("\n## STRIDE tables\n");
  assert.ok(start >= 0, "SECURITY-MODEL.md has no STRIDE tables section");
  const end = markdown.indexOf("\n## ", start + 1);
  return markdown.slice(start, end < 0 ? undefined : end);
}

/** Every table row under each `### ` heading of the section; header and separator rows are skipped. */
function readTables(section: string): { headings: string[]; rows: Row[] } {
  const headings: string[] = [];
  const rows: Row[] = [];
  let table = "";
  for (const line of section.split("\n")) {
    if (line.startsWith("### ")) {
      table = line.slice(4).trim();
      headings.push(table);
      continue;
    }
    if (!line.startsWith("|") || line.startsWith("| Id |") || line.startsWith("|---")) continue;
    const cells = line.slice(1, line.endsWith("|") ? -1 : undefined).split("|").map((c) => c.trim());
    const [id = "", stride = "", threat = "", control = "", status = "", proof = "", ...rest] = cells;
    assert.equal(rest.length, 0, `${table}: row ${id} has more than six cells`);
    rows.push({ table, id, stride, threat, control, status, proof });
  }
  return { headings, rows };
}

/** Every problem with the rows, given a way to read a test file and the roadmap's text. */
function problems(rows: Row[], testSource: (file: string) => string | null, roadmap: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const where = `${row.table} ${row.id}`;
    if (!/^[a-z]+-\d+$/.test(row.id)) found.push(`${where}: the id is not lower-case words and a number`);
    if (seen.has(row.id)) found.push(`${where}: the id is used twice`);
    seen.add(row.id);
    if (!/^[STRIDE]+$/.test(row.stride) || new Set(row.stride).size !== row.stride.length) found.push(`${where}: STRIDE is not a set of S, T, R, I, D, E`);
    if (row.threat === "" || row.control === "") found.push(`${where}: names no threat or no control`);
    if (!STATUSES.includes(row.status)) {
      found.push(`${where}: status "${row.status}" is neither covered nor open`);
    } else if (row.status === "covered") {
      if (!COVERED_PROOF.test(row.proof)) found.push(`${where}: a covered row's proof is only tests`);
      for (const [, file, name] of row.proof.matchAll(TEST_REF)) {
        const source = testSource(file!);
        if (source === null) found.push(`${where}: test/${file} does not exist`);
        else if (!source.includes(`it(${JSON.stringify(name)}`) && !source.includes(`describe(${JSON.stringify(name)}`)) {
          found.push(`${where}: test/${file} has no test "${name}"`);
        }
      }
    } else {
      if (!OPEN_PROOF.test(row.proof)) found.push(`${where}: an open row's proof is only issue ids`);
      for (const [issue] of row.proof.matchAll(/[A-Z]{3}-\d+/g)) {
        if (!roadmap.includes(`#### **${issue}**`)) found.push(`${where}: ${issue} is not an open issue in ROADMAP.md`);
      }
    }
  }
  return found;
}

/** The interface names of `EngineAdapters` in src/core/runtime.ts, so a new adapter cannot skip its table. */
function adapterInterfaces(runtime: string): string[] {
  const block = /export interface EngineAdapters \{([^}]*)\}/.exec(runtime);
  assert.ok(block, "EngineAdapters not found");
  return [...block[1]!.matchAll(/^\s*\w+\??: (\w+);/gm)].map((m) => m[1]!);
}

/** Line endings as the reader expects them: a Windows checkout can hold a file with CRLF. */
const lf = (text: string): string => text.replace(/\r\n/g, "\n");
const raw = (path: string): string => readFileSync(new URL(path, import.meta.url), "utf8");
const read = (path: string): string => lf(raw(path));
const testSource = (file: string): string | null => {
  const url = new URL(file, import.meta.url);
  return existsSync(url) ? lf(readFileSync(url, "utf8")) : null;
};

describe("the STRIDE table reader", () => {
  const roadmap = "#### **VER-1** Lockouts\n\nDone: **INT-3**\n";
  const tests = (file: string) => (file === "a.test.ts" ? 'it("guards", () => {});\ndescribe("suite", () => {});' : null);
  const row = (proof: string, status = "covered", extra: Partial<Row> = {}): Row => ({
    table: "Core",
    id: "core-1",
    stride: "S",
    threat: "t",
    control: "c",
    status,
    proof,
    ...extra,
  });

  it("reads rows under their headings and skips headers, separators and prose", () => {
    const md = [
      "# Model",
      "",
      "## STRIDE tables",
      "",
      "Prose | with a pipe.",
      "### Core",
      "| Id | STRIDE | Threat | Control | Status | Proof |",
      "|---|---|---|---|---|---|",
      '| core-1 | S | t | c | covered | `a.test.ts`: "guards" |',
      "### Badge",
      "| badge-1 | E | t | c | open | VER-1 |",
      "",
      "## Left to the host",
      "| not-1 | S | t | c | covered | x |",
    ].join("\n");
    const { headings, rows } = readTables(strideSection(md));
    assert.deepEqual(headings, ["Core", "Badge"]);
    assert.deepEqual(
      rows.map((r) => [r.table, r.id, r.status, r.proof]),
      [
        ["Core", "core-1", "covered", '`a.test.ts`: "guards"'],
        ["Badge", "badge-1", "open", "VER-1"],
      ],
    );
    assert.throws(() => strideSection("# Model\n"), /no STRIDE tables/);
    assert.throws(() => readTables("### Core\n| a | b | c | d | e | f | g |"), /more than six cells/);
  });

  it("accepts tests that exist and open issues in ROADMAP.md", () => {
    assert.deepEqual(problems([row('`a.test.ts`: "guards"; `a.test.ts`: "suite"'), row("VER-1", "open", { id: "core-2" })], tests, roadmap), []);
  });

  it("refuses a covered row that cites an issue, or names a test that does not exist", () => {
    assert.deepEqual(
      problems(
        [
          row("VER-1"),
          row('`a.test.ts`: "guards", VER-1', "covered", { id: "core-2" }),
          row('`a.test.ts`: "missing"', "covered", { id: "core-3" }),
          row('`b.test.ts`: "guards"', "covered", { id: "core-4" }),
        ],
        tests,
        roadmap,
      ),
      [
        "Core core-1: a covered row's proof is only tests",
        "Core core-2: a covered row's proof is only tests",
        'Core core-3: test/a.test.ts has no test "missing"',
        "Core core-4: test/b.test.ts does not exist",
      ],
    );
  });

  it("refuses an open row without an open issue, a done issue, or with a test as its proof", () => {
    assert.deepEqual(
      problems(
        [
          row("", "open"),
          row("INT-3", "open", { id: "core-2" }),
          row('VER-1; `a.test.ts`: "guards"', "open", { id: "core-3" }),
          row("XYZ-9", "open", { id: "core-4" }),
        ],
        tests,
        roadmap,
      ),
      [
        "Core core-1: an open row's proof is only issue ids",
        "Core core-2: INT-3 is not an open issue in ROADMAP.md",
        "Core core-3: an open row's proof is only issue ids",
        "Core core-4: XYZ-9 is not an open issue in ROADMAP.md",
      ],
    );
  });

  it("refuses other statuses, bad ids, repeated ids, bad STRIDE letters and empty cells", () => {
    assert.deepEqual(
      problems(
        [
          row("VER-1", "partly"),
          row("VER-1", "open", { id: "Core 2", stride: "SS" }),
          row("VER-1", "open", { id: "Core 2", stride: "X", threat: "" }),
        ],
        tests,
        roadmap,
      ),
      [
        'Core core-1: status "partly" is neither covered nor open',
        "Core Core 2: the id is not lower-case words and a number",
        "Core Core 2: STRIDE is not a set of S, T, R, I, D, E",
        "Core Core 2: the id is not lower-case words and a number",
        "Core Core 2: the id is used twice",
        "Core Core 2: STRIDE is not a set of S, T, R, I, D, E",
        "Core Core 2: names no threat or no control",
      ],
    );
  });

  it("reads SECURITY-MODEL.md the same from a CRLF copy, as a Windows checkout may hold it", () => {
    const crlf = raw("../SECURITY-MODEL.md").replace(/\r?\n/g, "\r\n");
    assert.deepEqual(readTables(strideSection(lf(crlf))), readTables(strideSection(read("../SECURITY-MODEL.md"))));
  });

  it("reads the adapter interfaces of EngineAdapters", () => {
    assert.deepEqual(adapterInterfaces("export interface EngineAdapters {\n  ledger: AuditLedger;\n  sessions?: SessionStore;\n}"), ["AuditLedger", "SessionStore"]);
    assert.throws(() => adapterInterfaces("interface Other {}"), /EngineAdapters not found/);
  });
});

describe("SECURITY-MODEL.md STRIDE tables", () => {
  const { headings, rows } = readTables(strideSection(read("../SECURITY-MODEL.md")));
  const roadmap = read("../ROADMAP.md");

  it("every test a row names exists, and every open row names an open issue in ROADMAP.md", () => {
    assert.ok(rows.length > 0);
    assert.deepEqual(problems(rows, testSource, roadmap), []);
  });

  it("has a table for the core, every built-in module, Gate, and every adapter", () => {
    const modules = BUILT_IN_MODULES.map((name) => name[0]!.toUpperCase() + name.slice(1));
    const adapters = adapterInterfaces(read("../src/core/runtime.ts"));
    assert.ok(adapters.length >= 9, "EngineAdapters was read");
    for (const name of ["Core", ...modules, "Gate", "Webhooks", "Reference server", ...adapters]) {
      assert.ok(headings.includes(name), `no STRIDE table for ${name}`);
      assert.ok(rows.some((r) => r.table === name), `the STRIDE table for ${name} is empty`);
    }
  });

  it("lists open threats as open: VER-1, the hard gate, is open and never covered", () => {
    const open = rows.filter((r) => r.status === "open");
    assert.ok(open.length > 0);
    assert.ok(open.some((r) => r.proof.includes("VER-1")));
    assert.ok(rows.every((r) => r.status === "open" || !/[A-Z]{3}-\d+/.test(r.proof)));
  });
});
