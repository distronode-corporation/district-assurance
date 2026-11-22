#!/usr/bin/env node
// A version's CHANGELOG.md section, for its GitHub release. release.yml runs it twice: the decide
// job's guard (`check`) refuses a release with no dated section, and the github-release job
// (`notes`) puts the section at the top of the release notes. One parser serves both, so the guard
// and the notes can never disagree about what the section is.
//
//   node scripts/release-notes.mjs check <version>
//   node scripts/release-notes.mjs notes <version> <owner/repo>
//
// `notes` prints the section as it is, with its hard-wrapped lines joined (a GitHub release renders
// each newline as a line break), then a line linking to it in CHANGELOG.md on main; a section over
// NOTES_LIMIT bytes is replaced by that link alone. Either command exits 1 with a `::error::` line
// when CHANGELOG.md has no `## [<version>] - YYYY-MM-DD` section, and 2 on a usage error.
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Above this many bytes (UTF-8) the notes link to the section instead of holding it. */
export const NOTES_LIMIT = 20 * 1024;

/** The dated header a released version's section must start with: `## [X.Y.Z] - YYYY-MM-DD`. */
export function headerPattern(version) {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^## \\[${escaped}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$`);
}

/**
 * The version's section: its header line and the body up to the next level-two heading (or the end),
 * with surrounding blank lines trimmed. Throws when there is no dated section for the version.
 */
export function changelogSection(changelog, version) {
  const lines = changelog.replace(/\r\n?/g, "\n").split("\n");
  const pattern = headerPattern(version);
  // A heading inside a fenced code block is text, not a heading: only lines outside fences count.
  const outside = outsideFences(lines);
  const start = lines.findIndex((line, index) => outside[index] && pattern.test(line));
  if (start === -1) throw new Error(`CHANGELOG.md has no dated '## [${version}] - YYYY-MM-DD' section.`);
  let end = lines.findIndex((line, index) => index > start && outside[index] && line.startsWith("## "));
  if (end === -1) end = lines.length;
  const header = lines[start];
  const body = lines.slice(start + 1, end);
  while (body.length > 0 && body[0].trim() === "") body.shift();
  while (body.length > 0 && body[body.length - 1].trim() === "") body.pop();
  return { header, body: body.join("\n") };
}

const FENCE = /^\s*(`{3,}|~{3,})/;

/** Whether a line closes the fence `open` (the same character, at least as long, nothing after it). */
function closesFence(line, open) {
  const close = FENCE.exec(line);
  return close !== null && close[1][0] === open[0] && close[1].length >= open.length && line.trim() === close[1];
}

/** For each line, whether it is outside every fenced code block (a fence line itself is not). */
function outsideFences(lines) {
  let fence = null;
  return lines.map((line) => {
    if (fence !== null) {
      if (closesFence(line, fence)) fence = null;
      return false;
    }
    const open = FENCE.exec(line);
    if (open !== null) {
      fence = open[1];
      return false;
    }
    return true;
  });
}

// A table's delimiter row: cells of dashes with optional colons, at least one pipe, outer pipes
// optional (`--- | ---`, `|:--|--:|`).
const TABLE_DELIMITER = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$|^\s*\|\s*:?-+:?\s*\|\s*$/;
// Lines that start a block of their own and are never joined onto the line before: headings, list
// items, table rows, block quotes, thematic breaks (or setext underlines) and HTML.
const BLOCK_START = /^\s*(#{1,6}(\s|$)|[-*+]\s|\d{1,9}[.)]\s|\||>|<|=+\s*$|([-*_])(\s*\3){2,}\s*$)/;
// Lines nothing may be joined onto: headings, table rows, thematic breaks, setext underlines and
// HTML.
const CLOSED = /^\s*(#{1,6}(\s|$)|\||<|=+\s*$|([-*_])(\s*\3){2,}\s*$)/;

/**
 * Joins hard-wrapped lines: each paragraph, and each list item with its indented continuation
 * lines, becomes one line. Blank lines, headings, list items, tables (with or without outer
 * pipes), block quotes and fenced code blocks stay as they are, and a line ending in a Markdown
 * hard break (two spaces or a backslash) keeps its break.
 */
export function unwrap(markdown) {
  const out = [];
  const lines = markdown.split("\n");
  let fence = null;
  let table = false;
  let joinable = false;
  for (const [index, line] of lines.entries()) {
    if (fence !== null) {
      out.push(line);
      if (closesFence(line, fence)) fence = null;
      continue;
    }
    // A table, with or without outer pipes, is its header row, its delimiter row and every row up
    // to a blank line: each kept as it is.
    if (!table && line.includes("|") && TABLE_DELIMITER.test(lines[index + 1] ?? "")) table = true;
    if (table) {
      if (line.trim() === "") {
        table = false;
      } else {
        out.push(line);
        joinable = false;
        continue;
      }
    }
    const open = FENCE.exec(line);
    if (open !== null) {
      out.push(line);
      fence = open[1];
      joinable = false;
      continue;
    }
    if (line.trim() === "") {
      out.push(line);
      joinable = false;
      continue;
    }
    if (joinable && !BLOCK_START.test(line)) {
      out[out.length - 1] = `${out[out.length - 1]} ${line.trim()}`;
    } else {
      out.push(line);
    }
    const last = out[out.length - 1];
    joinable = !CLOSED.test(last) && !/( {2}|\\)$/.test(last) && !/^\s*>/.test(last);
  }
  return out.join("\n");
}

/** GitHub's anchor for a heading: lower case, punctuation other than `-` and `_` dropped, spaces to `-`. */
export function headingAnchor(heading) {
  return heading
    .replace(/^#+\s*/, "")
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

/**
 * The top of the release notes: the version's section, unwrapped, then a link to it in CHANGELOG.md
 * on main; or the link alone when the section is over `limit` bytes.
 */
export function releaseNotes(changelog, version, repository, limit = NOTES_LIMIT) {
  const { header, body } = changelogSection(changelog, version);
  const text = unwrap(body);
  const link = `[${version} section of CHANGELOG.md](https://github.com/${repository}/blob/main/CHANGELOG.md#${headingAnchor(header)})`;
  if (text === "") return `See the ${link}.\n`;
  if (Buffer.byteLength(text, "utf8") > limit) return `The changes in ${version} are too long to show here; see the ${link}.\n`;
  return `${text}\n\nThe full changelog is in the ${link}.\n`;
}

function main(argv) {
  const [command, version, repository] = argv;
  const usage = "usage: release-notes.mjs check <version> | notes <version> <owner/repo>";
  const valid =
    (command === "check" && argv.length === 2) || (command === "notes" && argv.length === 3 && /^[\w.-]+\/[\w.-]+$/.test(repository));
  if (!valid || !version) {
    console.error(usage);
    return 2;
  }
  const changelog = readFileSync(join(ROOT, "CHANGELOG.md"), "utf8");
  try {
    if (command === "check") changelogSection(changelog, version);
    else process.stdout.write(releaseNotes(changelog, version, repository));
  } catch (error) {
    console.log(`::error::${error.message}`);
    return 1;
  }
  return 0;
}

/** Whether this file is the program node was started with (not a test importing it), through symlinks. */
function isEntryPoint() {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) process.exitCode = main(process.argv.slice(2));
