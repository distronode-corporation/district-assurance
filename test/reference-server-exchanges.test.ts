// The reference server's exchanges at their edges: an upload that outlasts its deadline after
// claiming its link, a client that resets while its answer is pending, and a malformed request
// pipelined behind one still being answered.
import { strict as assert } from "node:assert";
import { connect, type AddressInfo } from "node:net";
import { describe, it, type TestContext } from "node:test";

import { ReceiptLinks, createReferenceServer, type ReferenceServerOptions, type RequestLog } from "../examples/reference-server/src/app.ts";
import { MemoryDocumentStore, createUploadLink, type Engine } from "../src/index.ts";
import { createTestEngine, type TestEngine } from "../src/testing/index.ts";

/** A server, closed when the test ends, passed or failed. */
async function serve(ctx: TestContext, options: Partial<ReferenceServerOptions>, t: TestEngine = createTestEngine()): Promise<{ base: string; port: number }> {
  const server = createReferenceServer({ engine: t.engine, stripeSecrets: { identity: [], payments: [] }, clock: t.clock, ...options });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  ctx.after(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const port = (server.address() as AddressInfo).port;
  return { base: `http://127.0.0.1:${port}`, port };
}

/** Writes `text` on a raw socket and answers everything read until the server closes it. */
function rawSocket(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1", () => socket.write(text));
    let answer = "";
    socket.on("data", (chunk: Buffer) => (answer += chunk.toString("utf8")));
    socket.on("close", () => resolve(answer));
    socket.on("error", reject);
  });
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const statuses = (answer: string) => [...answer.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((m) => Number(m[1]));

describe("an upload that outlasts its deadline", () => {
  const JPEG = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);

  async function setup(ctx: TestContext) {
    const t = createTestEngine();
    const documents = new MemoryDocumentStore();
    await t.records.putIntakeRecord({ recordId: "rec_1", workspaceId: t.engine.workspaceId, callId: "call_1", subjectKey: null, formId: "f", formVersion: "1", values: {}, digest: "0".repeat(64), confirmedBy: "voice", confirmedAt: "2026-01-01T00:00:00.000Z" });
    let scans = 0;
    let finish: () => void = () => undefined;
    const scanner = {
      scan: () => {
        scans += 1;
        return new Promise<{ clean: boolean }>((resolve) => (finish = () => resolve({ clean: true })));
      },
    };
    const logs: RequestLog[] = [];
    const s = await serve(ctx, { uploads: { documents, scanner, ids: t.ids }, timeoutMs: 100, log: (e) => logs.push(e) }, t);
    const { token } = await createUploadLink({ callId: "call_1", recordId: "rec_1" }, { workspaceId: t.engine.workspaceId, documents, clock: t.clock, records: t.records });
    const send = async () => {
      const body = new FormData();
      body.append("file", new Blob([JPEG], { type: "image/jpeg" }), "photo.jpg");
      const res = await fetch(`${s.base}/u/${token}`, { method: "POST", body });
      return { status: res.status, retryAfter: res.headers.get("retry-after"), html: await res.text() };
    };
    return { t, documents, send, finish: () => finish(), scans: () => scans, logs };
  }

  it("answers a retry with the same link the outcome it kept: 201 and the same document", async (ctx) => {
    const u = await setup(ctx);
    const first = await u.send();
    assert.equal(first.status, 503, "the deadline answers first");
    u.finish();
    await sleep(50);
    const retry = await u.send();
    assert.equal(retry.status, 201);
    const stored = u.documents.documents();
    assert.equal(stored.length, 1, "one document, stored once");
    const ref = stored[0]!.document.documentId;
    assert.match(retry.html, /Your document was received/);
    assert.ok(retry.html.includes(ref), "the page names the document it kept");
    const again = await u.send();
    assert.deepEqual([again.status, again.html.includes(ref)], [201, true], "and again, the same document");
    assert.equal(u.scans(), 1, "scanned once");
  });

  it("answers 503 with retry-after, and no second scan, while the first upload still runs", async (ctx) => {
    const u = await setup(ctx);
    assert.equal((await u.send()).status, 503);
    const during = await u.send();
    assert.deepEqual([during.status, during.retryAfter], [503, "1"]);
    assert.match(during.html, /still being checked/);
    assert.doesNotMatch(during.html, /<form/);
    assert.equal(u.scans(), 1, "never scanned twice");
    u.finish();
    await sleep(50);
    assert.equal((await u.send()).status, 201);
    assert.equal(u.documents.documents().length, 1);
  });

  it("answers a retry after the link's lifetime with the refusal any used link gets", async (ctx) => {
    const u = await setup(ctx);
    assert.equal((await u.send()).status, 503);
    u.finish();
    await sleep(50);
    u.t.clock.advance(30 * 60 * 1000);
    const late = await u.send();
    assert.equal(late.status, 410);
    assert.match(late.html, /expired or was already used/);
  });
});

describe("a client that resets while its answer is pending", () => {
  it("is not answered or logged when the deadline passes", async (ctx) => {
    const logs: RequestLog[] = [];
    const links = new ReceiptLinks();
    const token = links.issue("call_slow");
    const engine = { receipt: () => new Promise(() => undefined) } as unknown as Engine;
    const s = await serve(ctx, { engine, receiptLinks: links, timeoutMs: 100, log: (e) => logs.push(e) });
    const socket = connect(s.port, "127.0.0.1");
    socket.on("error", () => undefined);
    await new Promise<void>((resolve) => socket.once("connect", resolve));
    socket.write(`GET /r/${token}.json HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n`);
    await sleep(30);
    socket.resetAndDestroy();
    await sleep(250);
    assert.deepEqual(logs, []);
  });
});

describe("a malformed request pipelined behind one still being answered", () => {
  const slowNull = () => new Promise((resolve) => setTimeout(() => resolve(null), 80));

  it("is refused only after the earlier answer, so the 400 is never read as it", async (ctx) => {
    const logs: RequestLog[] = [];
    const links = new ReceiptLinks();
    const token = links.issue("call_slow");
    const s = await serve(ctx, { engine: { receipt: slowNull } as unknown as Engine, receiptLinks: links, log: (e) => logs.push(e) });
    const answer = await rawSocket(s.port, `GET /r/${token}.json HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\nNOT HTTP AT ALL\r\n\r\n`);
    assert.deepEqual(statuses(answer), [404, 400], answer);
    assert.deepEqual(
      logs.map((e) => [e.route, e.status]),
      [
        ["/r/:token.json", 404],
        ["unmatched", 400],
      ],
    );
  });

  it("waits for every earlier answer, in order", async (ctx) => {
    const links = new ReceiptLinks();
    const token = links.issue("call_slow");
    const s = await serve(ctx, { engine: { receipt: slowNull } as unknown as Engine, receiptLinks: links });
    const get = (path: string) => `GET ${path} HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n`;
    const answer = await rawSocket(s.port, `${get(`/r/${token}.json`)}${get("/healthz")}NOT HTTP AT ALL\r\n\r\nMORE GARBAGE\r\n\r\n`);
    assert.deepEqual(statuses(answer), [404, 200, 400], answer);
  });

  it("still waits when the earlier answer is the deadline's 503", async (ctx) => {
    const links = new ReceiptLinks();
    const token = links.issue("call_slow");
    const engine = { receipt: () => new Promise(() => undefined) } as unknown as Engine;
    const s = await serve(ctx, { engine, receiptLinks: links, timeoutMs: 100 });
    const answer = await rawSocket(s.port, `GET /r/${token}.json HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\nNOT HTTP AT ALL\r\n\r\n`);
    assert.deepEqual(statuses(answer), [503, 400], answer);
  });
});
