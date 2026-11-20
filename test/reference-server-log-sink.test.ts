// The default log sink of npm run serve: one JSON line per entry on standard output, bounded while
// standard output is backpressured, and stopped (never a crash) when standard output fails.
import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import { createReferenceServer, jsonLinesLog, logJsonLines, type RequestLog } from "../examples/reference-server/src/app.ts";
import { guardLogStream } from "../examples/reference-server/src/main.ts";
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
    const free = createServer();
    await new Promise<void>((resolve) => free.listen(0, "127.0.0.1", resolve));
    const port = (free.address() as AddressInfo).port;
    await new Promise<void>((resolve) => free.close(() => resolve()));
    const main = fileURLToPath(new URL("../examples/reference-server/src/main.ts", import.meta.url));
    const child = spawn(process.execPath, [main], { env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
    ctx.after(() => {
      child.kill();
    });
    let stderr = "";
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    await new Promise<void>((resolve, reject) => {
      child.stdout.once("data", () => resolve());
      child.once("exit", () => reject(new Error(`exited early: ${stderr}`)));
    });
    // The reader closes its end: the next log line is an EPIPE.
    child.stdout.destroy();
    const url = `http://127.0.0.1:${port}/healthz`;
    for (let i = 0; i < 3; i++) assert.equal((await fetch(url)).status, 200);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(child.exitCode, null, stderr);
    assert.equal((await fetch(url)).status, 200);
  });
});
