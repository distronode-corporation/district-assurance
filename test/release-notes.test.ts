// The release notes release.yml writes from CHANGELOG.md (scripts/release-notes.mjs): the guard
// that refuses a release with no dated section, the section copied as it is with its hard wraps
// joined, the link to it, and the link alone for a long one. The real 0.1.0, 0.2.0 and 0.3.0
// sections are read live from CHANGELOG.md.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// A plain .mjs script has no type declarations: its exports are typed here, from a URL import.
const script = new URL("../scripts/release-notes.mjs", import.meta.url);
const { NOTES_LIMIT, changelogSection, headingAnchor, releaseNotes, unwrap } = (await import(script.href)) as {
  NOTES_LIMIT: number;
  changelogSection(changelog: string, version: string): { header: string; body: string };
  headingAnchor(heading: string): string;
  releaseNotes(changelog: string, version: string, repository: string, limit?: number): string;
  unwrap(markdown: string): string;
};

const REPO = "example-owner/example-repo";
const CHANGELOG = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");

const SAMPLE = `# Changelog

## [Unreleased]

- Not released yet.

## [1.2.0] - 2026-12-01

Version 1.2 makes checks faster
and receipts clearer.

### Added

- **A new step.** It does one thing, with a long line
  wrapped onto a second line
  and a third.
- **Another item.**

\`\`\`ts
const a = 1;
const b = 2;
\`\`\`

| a | b |
|---|---|
| 1 | 2 |

## [1.1.0] - 2026-11-01

- Older.
`;

/** Runs the script as release.yml does. */
function cli(...args: string[]) {
  return spawnSync(process.execPath, [fileURLToPath(script), ...args], { encoding: "utf8" });
}

describe("release notes: the section", () => {
  it("N1 a normal section is the dated header and the body up to the next version", () => {
    const { header, body } = changelogSection(SAMPLE, "1.2.0");
    assert.equal(header, "## [1.2.0] - 2026-12-01");
    assert.ok(body.startsWith("Version 1.2 makes checks faster\n"));
    assert.ok(body.endsWith("| 1 | 2 |"));
    assert.ok(!body.includes("Older."), "the next version's section is not included");
    assert.ok(!body.includes("Not released yet."));
  });

  it("N2 a missing version, an undated header, or a version that only looks alike fails loudly", () => {
    assert.throws(() => changelogSection(SAMPLE, "9.9.9"), /no dated '## \[9\.9\.9\] - YYYY-MM-DD' section/);
    assert.throws(() => changelogSection("## [1.2.0]\n\n- x\n", "1.2.0"), /no dated/);
    assert.throws(() => changelogSection("## [1.2.0] - soon\n\n- x\n", "1.2.0"), /no dated/);
    // A dot in the version matches only a dot, as the guard's grep did.
    assert.throws(() => changelogSection("## [1x2x0] - 2026-12-01\n", "1.2.0"), /no dated/);
    assert.throws(() => changelogSection(SAMPLE, "Unreleased"), /no dated/);
  });

  it("N3b a heading inside a fenced code block neither ends the section nor starts one", () => {
    const fenced = "## [2.0.0] - 2026-12-01\n\nBefore.\n\n```md\n## Example\n## [1.0.0] - 2026-11-01\n```\n\nAfter.\n\n## [1.0.0] - 2026-11-01\n\n- Older.\n";
    assert.equal(changelogSection(fenced, "2.0.0").body, "Before.\n\n```md\n## Example\n## [1.0.0] - 2026-11-01\n```\n\nAfter.");
    assert.equal(changelogSection(fenced, "1.0.0").body, "- Older.", "the real 1.0.0 header, not the one in the fence");
    assert.throws(() => changelogSection("```\n## [3.0.0] - 2026-12-01\n```\n", "3.0.0"), /no dated/);
    assert.equal(changelogSection("## [3.0.0] - 2026-12-01\n\n~~~\n## x\n", "3.0.0").body, "~~~\n## x", "an unclosed fence runs to the end");
  });

  it("N3 CRLF line endings read the same as LF", () => {
    const { header, body } = changelogSection(SAMPLE.replace(/\n/g, "\r\n"), "1.2.0");
    assert.equal(header, "## [1.2.0] - 2026-12-01");
    assert.equal(body, changelogSection(SAMPLE, "1.2.0").body);
  });

  it("N4 the notes are the section as it is, unwrapped, then a link to it on main", () => {
    assert.equal(
      releaseNotes(SAMPLE, "1.2.0", REPO),
      [
        "Version 1.2 makes checks faster and receipts clearer.",
        "",
        "### Added",
        "",
        "- **A new step.** It does one thing, with a long line wrapped onto a second line and a third.",
        "- **Another item.**",
        "",
        "```ts",
        "const a = 1;",
        "const b = 2;",
        "```",
        "",
        "| a | b |",
        "|---|---|",
        "| 1 | 2 |",
        "",
        "The full changelog is in the [1.2.0 section of CHANGELOG.md](https://github.com/example-owner/example-repo/blob/main/CHANGELOG.md#120---2026-12-01).",
        "",
      ].join("\n"),
    );
  });

  it("N5 the guard command passes a dated section and fails a missing one with an ::error:: line", () => {
    const ok = cli("check", "0.3.0");
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.equal(ok.stdout, "");
    const missing = cli("check", "9.9.9");
    assert.equal(missing.status, 1);
    assert.equal(missing.stdout, "::error::CHANGELOG.md has no dated '## [9.9.9] - YYYY-MM-DD' section.\n");
    const notes = cli("notes", "9.9.9", REPO);
    assert.equal(notes.status, 1);
    assert.match(notes.stdout, /^::error::/);
  });

  it("N6 a usage error exits 2", () => {
    for (const args of [[], ["check"], ["check", ""], ["check", "1.0.0", "extra"], ["notes", "1.0.0"], ["notes", "1.0.0", "not a repo"], ["publish", "1.0.0"]]) {
      const run = cli(...args);
      assert.equal(run.status, 2, args.join(" "));
      assert.match(run.stderr, /^usage:/);
    }
  });
});

describe("release notes: unwrapping", () => {
  it("U1 a wrapped paragraph and a wrapped list item are each joined onto one line", () => {
    assert.equal(unwrap("A paragraph that was\nwrapped by hand.\n\nAnother."), "A paragraph that was wrapped by hand.\n\nAnother.");
    assert.equal(unwrap("- one\n  two\n- three"), "- one two\n- three");
  });

  it("U2 list items, headings, code fences and tables stay as they are", () => {
    assert.equal(unwrap("~~~\nkeep\nthis\n~~~\njoin\nme"), "~~~\nkeep\nthis\n~~~\njoin me");
    assert.equal(unwrap("````\n```\nstill code\n````"), "````\n```\nstill code\n````", "a shorter fence does not close a longer one");
    assert.equal(unwrap("- a\n  b\n  - c\n    d\n1. e\n2) f"), "- a b\n  - c d\n1. e\n2) f");
    assert.equal(unwrap("| a |\n|---|\n| 1 |"), "| a |\n|---|\n| 1 |");
    // GitHub tables need no outer pipes: every row is kept, up to the blank line that ends it.
    assert.equal(unwrap("Name | Value\n--- | ---\none | two\nthree | four\n\nwrapped\nprose"), "Name | Value\n--- | ---\none | two\nthree | four\n\nwrapped prose");
    assert.equal(unwrap("a | b\n:--|--:\nc | d"), "a | b\n:--|--:\nc | d");
    // Another block ends a table without a blank line, and is itself handled: a fence stays code.
    assert.equal(unwrap("a | b\n--- | ---\nc | d\n```\nfirst\n\nsecond\nthird\n```"), "a | b\n--- | ---\nc | d\n```\nfirst\n\nsecond\nthird\n```");
    assert.equal(unwrap("a | b\n--- | ---\nc | d\n- item\n  wrapped"), "a | b\n--- | ---\nc | d\n- item wrapped");
    assert.equal(unwrap("| a |\n|---|\n| b |\n# Next\ntext\nmore"), "| a |\n|---|\n| b |\n# Next\ntext more");
    assert.equal(unwrap("text\nwith a | pipe\nand more"), "text with a | pipe and more", "a pipe in prose, with no delimiter row, is prose");
    assert.equal(unwrap("# Heading\nnext"), "# Heading\nnext");
  });

  it("U3 quotes, rules, HTML and hard breaks keep their lines", () => {
    assert.equal(unwrap("> quoted\n> more"), "> quoted\n> more");
    assert.equal(unwrap("text\n---\nafter"), "text\n---\nafter");
    assert.equal(unwrap("Title\n===\nafter"), "Title\n===\nafter");
    assert.equal(unwrap("* * *\nafter"), "* * *\nafter");
    assert.equal(unwrap("hard  \nbreak\nback\\\nslash"), "hard  \nbreak back\\\nslash");
    assert.equal(unwrap("<br>\nnext"), "<br>\nnext");
  });
});

describe("release notes: the long-section link", () => {
  it("L1 a section over the limit becomes one line linking to its anchor on main", () => {
    assert.equal(
      releaseNotes(SAMPLE, "1.2.0", REPO, 50),
      "The changes in 1.2.0 are too long to show here; see the [1.2.0 section of CHANGELOG.md](https://github.com/example-owner/example-repo/blob/main/CHANGELOG.md#120---2026-12-01).\n",
    );
    // The limit counts bytes, not characters, after unwrapping.
    const wide = `## [3.0.0] - 2026-12-01\n\n${"é".repeat(30)}\n`;
    assert.ok(!releaseNotes(wide, "3.0.0", REPO, 59).includes("é"));
    assert.ok(releaseNotes(wide, "3.0.0", REPO, 60).includes("é"));
    assert.equal(NOTES_LIMIT, 20 * 1024);
  });

  it("L2 an empty section links to it rather than showing nothing", () => {
    assert.equal(
      releaseNotes("## [3.0.0] - 2026-12-01\n\n## [2.0.0] - 2026-11-01\n", "3.0.0", REPO),
      "See the [3.0.0 section of CHANGELOG.md](https://github.com/example-owner/example-repo/blob/main/CHANGELOG.md#300---2026-12-01).\n",
    );
  });

  it("L3 the anchor is GitHub's for the header", () => {
    assert.equal(headingAnchor("## [0.1.0] - 2026-11-20"), "010---2026-11-20");
    assert.equal(headingAnchor("## [1.0.0-rc.1] - 2027-01-02"), "100-rc1---2027-01-02");
  });
});

describe("release notes: the real CHANGELOG.md", () => {
  const REAL = "distronode-corporation/district-assurance";

  it("R1 0.1.0 is over 20 KB, so its notes are the link alone", () => {
    assert.ok(Buffer.byteLength(changelogSection(CHANGELOG, "0.1.0").body, "utf8") > 50 * 1024);
    assert.equal(
      releaseNotes(CHANGELOG, "0.1.0", REAL),
      "The changes in 0.1.0 are too long to show here; see the [0.1.0 section of CHANGELOG.md](https://github.com/distronode-corporation/district-assurance/blob/main/CHANGELOG.md#010---2026-11-20).\n",
    );
  });

  for (const [version, date] of [
    ["0.2.0", "2026-11-22"],
    ["0.3.0", "2026-11-22"],
  ] as const) {
    it(`R2 ${version} is shown whole, unwrapped, and linked`, () => {
      const notes = releaseNotes(CHANGELOG, version, REAL);
      assert.ok(notes.startsWith("### Added\n\n- "));
      assert.ok(notes.includes("\n### Changed\n\n- "));
      assert.ok(notes.endsWith(`The full changelog is in the [${version} section of CHANGELOG.md](https://github.com/${REAL}/blob/main/CHANGELOG.md#${version.replace(/\./g, "")}---${date}).\n`));
      // No line starts with a wrap's indentation: every continuation line was joined.
      assert.deepEqual(notes.split("\n").filter((line) => /^ {2}\S/.test(line)), []);
      // Nothing was lost: the words are the section's words.
      const words = (text: string) => text.split(/\s+/).filter(Boolean);
      assert.deepEqual(words(notes).slice(0, -10), words(changelogSection(CHANGELOG, version).body));
    });
  }
});
