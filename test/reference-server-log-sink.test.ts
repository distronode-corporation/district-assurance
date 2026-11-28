// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The default log sink of npm run serve: one JSON line per entry on standard output, bounded while
// standard output is backpressured, and stopped (never a crash) when standard output fails.
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import type { AddressInfo } from "node:net";
import { PassThrough } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, it, type TestContext } from "node:test";

import { createReferenceServer, jsonLinesLog, logJsonLines, type RequestLog } from "../examples/reference-server/src/app.ts";
import { guardLogStream, isProgram } from "../examples/reference-server/src/main.ts";
import { createTestEngine } from "../src/testing/index.ts";

/** A stream that records each write, and answers backpressure while `full` until `drain()`. */
class FakeStream extends EventEmitter {
  readonly lines: string[] = [];
  full = false;
  write(chunk: string): boolean {
    this.lines.push(chunk);
    return !this.full;
  }
  drain(): void {
    this.full = false;
    this.emit("drain");
  }
}

const entry = (status: number): RequestLog => ({ time: "2026-01-01T00:00:00.000Z", address: "127.0.0.1", method: "GET", route: "/healthz", status, ms: 0 });

describe("logJsonLines under backpressure", () => {
  it("drops entries while standard output is backpressured, then writes one line with the count on drain", (ctx) => {
    const lines: string[] = [];
    const write = ctx.mock.method(process.stdout, "write", (chunk: string) => {
      lines.push(chunk);
      return false;
    });
    try {
      logJsonLines(entry(200));
      logJsonLines(entry(201));
      logJsonLines(entry(429));
      assert.deepEqual(lines, [`${JSON.stringify(entry(200))}\n`], "only the entry that met the full buffer is written");
      write.mock.mockImplementation((chunk: string) => {
        lines.push(chunk);
        return true;
      });
      process.stdout.emit("drain");
      logJsonLines(entry(202));
    } finally {
      write.mock.restore();
    }
    assert.deepEqual(lines.slice(1), [`${JSON.stringify({ warning: "log_entries_dropped", dropped: 2 })}\n`, `${JSON.stringify(entry(202))}\n`]);
  });
});

describe("jsonLinesLog", () => {
  it("writes each entry while the stream takes it, and nothing blocks the caller", () => {
    const stream = new FakeStream();
    const log = jsonLinesLog(stream);
    log(entry(200));
    log(entry(404));
    assert.deepEqual(stream.lines, [entry(200), entry(404)].map((e) => `${JSON.stringify(e)}\n`));
  });

  it("counts every entry dropped across backpressure, and re-arms when the warning itself meets a full buffer", () => {
    const stream = new FakeStream();
    const log = jsonLinesLog(stream);
    stream.full = true;
    log(entry(200));
    for (let i = 0; i < 1000; i++) log(entry(429));
    assert.equal(stream.lines.length, 1, "1000 entries never queue");
    assert.equal(stream.listenerCount("drain"), 1, "one drain listener, however many are dropped");
    // The warning is written, and it meets a full buffer again.
    stream.emit("drain");
    assert.equal(stream.lines.at(-1), `${JSON.stringify({ warning: "log_entries_dropped", dropped: 1000 })}\n`);
    log(entry(201));
    stream.drain();
    assert.equal(stream.lines.at(-1), `${JSON.stringify({ warning: "log_entries_dropped", dropped: 1 })}\n`);
    log(entry(202));
    assert.equal(stream.lines.at(-1), `${JSON.stringify(entry(202))}\n`);
    stream.full = true;
    log(entry(203));
    stream.drain();
    assert.equal(stream.lines.at(-1), `${JSON.stringify(entry(203))}\n`, "a drain with nothing dropped writes no warning");
  });

  it("drops the server's rate-limit refusals the same way", async (ctx) => {
    const stream = new FakeStream();
    const t = createTestEngine();
    const server = createReferenceServer({
      engine: t.engine,
      stripeSecrets: { identity: [], payments: [] },
      clock: t.clock,
      rateLimit: { requests: 1, windowMs: 60_000 },
      log: jsonLinesLog(stream),
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    ctx.after(
      () =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    );
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/healthz`;
    stream.full = true;
    const statuses = [];
    for (let i = 0; i < 5; i++) statuses.push((await fetch(url)).status);
    assert.deepEqual(statuses, [200, 429, 429, 429, 429]);
    assert.deepEqual(stream.lines.map((l) => (JSON.parse(l) as RequestLog).status), [200]);
    stream.drain();
    assert.equal(stream.lines.at(-1), `${JSON.stringify({ warning: "log_entries_dropped", dropped: 4 })}\n`);
  });

  it("writes nothing more once stopped", () => {
    const stream = new FakeStream();
    const log = jsonLinesLog(stream);
    log.stop();
    log(entry(200));
    assert.deepEqual(stream.lines, []);
  });
});

describe("guardLogStream", () => {
  it("takes the stream's error events, so none is unhandled, and stops the log", () => {
    const stream = new FakeStream();
    const log = jsonLinesLog(stream);
    guardLogStream(stream, log);
    assert.equal(stream.listenerCount("error"), 1);
    const epipe = Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
    stream.emit("error", epipe);
    stream.emit("error", epipe);
    log(entry(200));
    assert.deepEqual(stream.lines, []);
  });

  it("keeps npm run serve running when standard output's reader goes away", { timeout: 30_000 }, async (ctx) => {
    const { child, port, stderr } = await startServe(ctx);
    // The reader closes its end: the next log line is an EPIPE.
    child.stdout.destroy();
    const url = `http://127.0.0.1:${port}/healthz`;
    for (let i = 0; i < 3; i++) assert.equal((await fetch(url)).status, 200);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(child.exitCode, null, stderr());
    assert.equal((await fetch(url)).status, 200);
  });
});

const MAIN = fileURLToPath(new URL("../examples/reference-server/src/main.ts", import.meta.url));

/**
 * Starts `npm run serve`'s program (node on main.ts) with PORT=0 and reads the port it bound from
 * its first line, so no other test can take the port between choosing it and listening on it.
 * `nodeArgs` go before the entry. Rejects with its standard error if it exits first.
 */
async function startServe(ctx: TestContext, nodeArgs: string[] = []) {
  const child = spawn(process.execPath, [...nodeArgs, MAIN], { env: { ...process.env, PORT: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  ctx.after(() => {
    child.kill();
  });
  let stderr = "";
  child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
  const banner = await new Promise<string>((resolve, reject) => {
    firstLine(child.stdout).then(resolve, reject);
    child.once("exit", () => reject(new Error(`exited early: ${stderr}`)));
  });
  const port = Number(/^reference server on http:\/\/127\.0\.0\.1:(\d+) /.exec(banner)?.[1]);
  return { child, port, banner, stderr: () => stderr };
}

// Node.js 24.2 sets import.meta.main to false for a .ts entry. Node 24.19 does not, so this load
// hook gives main.ts what 24.2 gives it: every `import.meta.main` in its source reads false.
const NODE_24_2_MAIN = `data:text/javascript,${encodeURIComponent(`
import { registerHooks } from "node:module";
registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.endsWith("/examples/reference-server/src/main.ts")) return result;
    return { ...result, source: String(result.source).replaceAll("import.meta.main", "false") };
  },
});
`)}`;

/** The stream's first line, without its newline: chunks are buffered until one arrives. */
function firstLine(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve) => {
    let text = "";
    const onData = (c: Buffer): void => {
      text += c.toString("utf8");
      const end = text.indexOf("\n");
      if (end === -1) return;
      stream.off("data", onData);
      resolve(text.slice(0, end));
    };
    stream.on("data", onData);
  });
}

describe("npm run serve's banner", () => {
  it("is read through its newline, even when standard output splits it across chunks", async () => {
    const stream = new PassThrough();
    const line = firstLine(stream);
    stream.write("reference server on http://127.0.0.1:");
    await new Promise((resolve) => setImmediate(resolve));
    stream.write("4321 (fake adapters)\nnext");
    assert.equal(await line, "reference server on http://127.0.0.1:4321 (fake adapters)");
  });
  it("names the port the server bound, so PORT=0 gives a port that answers", { timeout: 30_000 }, async (ctx) => {
    const { child, port, banner, stderr } = await startServe(ctx);
    assert.ok(Number.isInteger(port) && port > 0, banner);
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    assert.equal(child.exitCode, null, stderr());
  });
});

describe("npm run serve's entry check", () => {
  it("starts the server where import.meta.main is false for a .ts entry, as on Node.js 24.2", { timeout: 30_000 }, async (ctx) => {
    const { child, port, stderr } = await startServe(ctx, ["--import", NODE_24_2_MAIN]);
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    assert.equal(child.exitCode, null, stderr());
  });

  it("is the program only for main.ts itself, so importing main.ts does not start the server", () => {
    const url = pathToFileURL(MAIN).href;
    assert.equal(isProgram(MAIN, url), true);
    assert.equal(isProgram(fileURLToPath(import.meta.url), url), false, "this test file imports main.ts");
    assert.equal(isProgram(undefined, url), false, "no entry, as under node -e");
    assert.equal(isProgram(`${MAIN}.missing`, url), false, "an entry that does not resolve");
  });
});
