// Records the Stripe test-mode runs for VER-5 (Stripe Identity) and PAY-1 (Checkout, both modes)
// into test/fixtures/stripe-real/, redacted (redact.ts). test/stripe-real.test.ts replays them
// offline and never touches a network; this script is run by hand, once, and is not part of `npm test`.
//
//   STRIPE_TEST_SECRET_KEY=sk_test_... STRIPE_TEST_CONNECTED_ACCOUNT=acct_... node test/fixtures/stripe-real/record.ts
//
// TEST MODE ONLY: anything but a secret test key (`sk_test_`) is refused before anything runs, and
// the key is dropped from this process's environment once read. It needs the Stripe CLI on PATH
// (`stripe listen` forwards the account's real, signed webhook deliveries to this machine).
//
// What it does, each through the reference server's own code:
// 1. Identity: `npm run serve`'s trial call (`createServe`) with `StripeIdentityProvider`, which
//    creates a VerificationSession. Open its page (test mode offers "Verification success") and the
//    `identity.verification_session.verified` event Stripe sends is forwarded to the server's
//    `/webhooks/stripe/identity` route, which applies it to the call.
// 2. Checkout, platform mode: a call verified to level 2 requests a deposit with
//    `StripeCheckoutLinks`; pay the page with 4242 4242 4242 4242; `checkout.session.completed`
//    goes to `/webhooks/stripe/payments` and settles the payment.
// 3. Checkout, connect mode: the same as a direct charge on the connected account, offering cards
//    and both wallets; its event comes from the Connect listener (it names the account) and goes to
//    `/webhooks/stripe/connect`.
// 4. Cards and Link on the connected account, then cancelled: the engine closes the link with the
//    adapter's `expireLink`, on the connected account.
// 5. What Checkout refuses: `apple_pay` or `google_pay` as a payment method type, and `link` alone.
//
// Every page URL is written to a file of its own in RECORD_URL_DIR (mode 0600) when that is set,
// else printed. The adapters' requests go through a recording proxy on the loopback, which sends
// them on to api.stripe.com. StripeIdentityProvider takes a restricted key only; a restricted key
// can be made only in the Dashboard, so the proxy sends the secret test key in its place. The
// request is the adapter's own otherwise, and the restricted key's refusal of anything else is
// covered by test/stripe-identity.test.ts.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { randomIds, systemClock, verifyStripeSignature } from "../../../src/index.ts";
import { createReferenceServer } from "../../../examples/reference-server/src/app.ts";
import { createServe } from "../../../examples/reference-server/src/main.ts";
import { createDemoWorld } from "../../../examples/reference-server/src/script.ts";
import { STRIPE_API_VERSION, StripeCheckoutLinks, assertTestModeSecretKey } from "../../../examples/reference-server/src/stripe-adapters.ts";
import { recordedConfig, requestRecordedLink, type RecordedFlow } from "./flows.ts";
import { type Delivery, type PendingDelivery, forwardingFailed, receiverStatus, settledDelivery } from "./deliveries.ts";
import { writePrivateFile } from "./private-file.ts";
import { Redactor, leaks } from "./redact.ts";

const key = process.env.STRIPE_TEST_SECRET_KEY;
delete process.env.STRIPE_TEST_SECRET_KEY;
assertTestModeSecretKey(key);
const account = process.env.STRIPE_TEST_CONNECTED_ACCOUNT ?? "";
if (!/^acct_[A-Za-z0-9]{1,255}$/.test(account)) throw new Error("set STRIPE_TEST_CONNECTED_ACCOUNT to a test-mode connected account (acct_...)");
const urlDir = process.env.RECORD_URL_DIR;
const WAIT_MS = 15 * 60_000;
const out = new URL("./", import.meta.url);

/** One exchange with Stripe's API as the recording proxy saw it. The key is never kept. */
interface Exchange {
  method: string;
  path: string;
  headers: { "stripe-version": string | null; "stripe-account": string | null; "idempotency-key": boolean };
  form: Array<[string, string]>;
  status: number;
  body: string;
}

const exchanges: Exchange[] = [];
const deliveries: PendingDelivery[] = [];
const ours = new Set<string>();

function body(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

/**
 * The only Stripe paths the adapters call: a VerificationSession, a Checkout Session, a session's
 * read and its expiry. Anything else is refused, so the proxy can send the key nowhere else.
 */
const STRIPE_PATH = /^\/v1\/(?:identity\/verification_sessions|checkout\/sessions(?:\/cs_test_[A-Za-z0-9]{1,200}(?:\/expire)?)?)$/;

// The recording proxy: the adapters' apiBase. Each request goes on to Stripe with the test key. A
// failure answers 502, so the step that asked fails inside the run and the cleanup below still runs.
const proxy = createServer((req, res) => {
  void (async () => {
    const path = req.url ?? "";
    if (!STRIPE_PATH.test(path)) return void res.writeHead(404).end("{}");
    const target = new URL(path, "https://api.stripe.com");
    const raw = (await body(req)).toString("utf8");
    const header = (name: string) => (typeof req.headers[name] === "string" ? (req.headers[name] as string) : null);
    const headers: Record<string, string> = { authorization: `Bearer ${key}` };
    for (const name of ["stripe-version", "stripe-account", "idempotency-key", "content-type"]) if (header(name) !== null) headers[name] = header(name)!;
    const init: RequestInit = { method: req.method!, headers, redirect: "error" };
    if (raw !== "") init.body = raw;
    const answer = await fetch(target, init);
    const text = await answer.text();
    exchanges.push({
      method: req.method!,
      path,
      headers: { "stripe-version": header("stripe-version"), "stripe-account": header("stripe-account"), "idempotency-key": header("idempotency-key") !== null },
      form: [...new URLSearchParams(raw)],
      status: answer.status,
      body: text,
    });
    for (const id of [...text.matchAll(/"id": ?"((?:cs_test|vs)_[A-Za-z0-9]+)"/g)].map((m) => m[1]!)) ours.add(id);
    res.writeHead(answer.status, { "content-type": "application/json" }).end(text);
  })().catch((error: unknown) => {
    console.error(`proxy: ${error instanceof Error ? error.name : "error"}`);
    if (!res.headersSent) res.writeHead(502);
    res.end("{}");
  });
});
const apiBase = await listen(proxy);

// Stripe CLI: the endpoint secret first, then the listener forwarding both kinds of event here.
const cliEnv = { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", STRIPE_API_KEY: key };
const secret = await new Promise<string>((resolve, reject) => {
  const child = spawn("stripe", ["listen", "--print-secret"], { env: cliEnv });
  let text = "";
  child.stdout.on("data", (c: Buffer) => (text += c.toString()));
  child.on("error", reject);
  child.on("close", () => (/^whsec_[A-Za-z0-9]+$/.test(text.trim()) ? resolve(text.trim()) : reject(new Error("stripe listen --print-secret gave no secret"))));
});

const page = (name: string, url: string): void => {
  if (urlDir === undefined) {
    console.log(`open ${name}: ${url}`);
    return;
  }
  mkdirSync(urlDir, { recursive: true });
  writePrivateFile(`${urlDir}/${name}.url`, url);
  console.log(`open ${name}: the URL is in ${urlDir}/${name}.url`);
};

const runTag = Date.now().toString(36);
let idCount = 0;

// 1. The identity server, as `npm run serve` builds it. Its stand-in phone prints the text with the link.
const printed: string[] = [];
const serve = createServe({
  env: { STRIPE_IDENTITY_KEY: "rk_test_recordingProxySendsTheTestKey", STRIPE_IDENTITY_WEBHOOK_SECRET: secret },
  stripe: { apiBase },
  // Ids of this run's own, plain words and digits: the test engine's start at call_1 every time.
  ids: { next: (prefix) => `${prefix}_run${runTag}_${++idCount}` },
  print: (line) => {
    const link = /https:\/\/verify\.stripe\.com\/\S+/.exec(line);
    if (link === null) printed.push(line);
    else page("identity", link[0]);
  },
  log: () => undefined,
});
const identityBase = await listen(serve.server);

// 2 and 3. The payments world and its reference server. Checkout returns the payer to the identity
// server's page, which is all a success URL needs here.
const world = createDemoWorld({
  payments: new StripeCheckoutLinks(key, { apiBase, successUrl: `${identityBase}/` }),
  clock: systemClock,
  ids: randomIds,
  config: recordedConfig(account),
});
const paymentsServer = createReferenceServer({ engine: world.engine, clock: systemClock, stripeSecrets: { identity: [], payments: [secret], connect: [secret] }, log: () => undefined });
const paymentsBase = await listen(paymentsServer);

// The receiver `stripe listen` forwards to: checks the signature, then hands the same bytes on. It
// answers with the reference server's status when that failed (deliveries.ts), and the run's wait
// for that event then fails at once, never recording it; a failure of the receiver itself answers
// 500, and a delivery it was forwarding is settled as failed, so that wait fails at once too.
const receiver = createServer((req, res) => {
  let entry: PendingDelivery | undefined;
  void (async () => {
    const listener = req.url === "/connect" ? "connect" : "account";
    const raw = await body(req);
    const signature = typeof req.headers["stripe-signature"] === "string" ? req.headers["stripe-signature"] : "";
    const event = JSON.parse(raw.toString("utf8")) as { type: string; data: { object: { id: string } } };
    const objectId = event.data.object.id;
    if (!ours.has(objectId)) return void res.writeHead(200).end("{}");
    const route = event.type.startsWith("identity.") ? "identity" : listener === "connect" ? "connect" : "payments";
    const target = `${route === "identity" ? identityBase : paymentsBase}/webhooks/stripe/${route}`;
    // Its place is taken as it arrives, and its answer filled in when the server gives it.
    entry = {
      listener,
      route,
      type: event.type,
      objectId,
      body: raw.toString("utf8"),
      signatureVerified: verifyStripeSignature({ payload: raw, header: signature, secrets: [secret], now: new Date() }).ok,
      answer: null,
    };
    deliveries.push(entry);
    const answer = await fetch(target, { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: raw });
    const answerBody = (await answer.json()) as unknown;
    entry.answer = { status: answer.status, body: answerBody };
    res.writeHead(receiverStatus(answer.status)).end("{}");
  })().catch((error: unknown) => {
    console.error(`receiver: ${error instanceof Error ? error.name : "error"}`);
    // A delivery that took its place but never got an answer fails the run now, not after the wait.
    if (entry !== undefined && entry.answer === null) forwardingFailed(entry);
    if (!res.headersSent) res.writeHead(500);
    res.end("{}");
  });
});
const receiverBase = await listen(receiver);
const events = ["identity.verification_session.verified", "identity.verification_session.requires_input", "checkout.session.completed"].join(",");
const cli: ChildProcess = spawn("stripe", ["listen", "--events", events, "--forward-to", `${receiverBase}/account`, "--forward-connect-to", `${receiverBase}/connect`], { env: cliEnv });

/** Set when `stripe listen` exits at any time: no event can arrive after that, so a wait ends at once. */
let listenerExit: string | null = null;
cli.on("exit", (code) => (listenerExit = `stripe listen exited (${code})`));

/** Stops everything this script started. */
async function cleanUp(): Promise<void> {
  cli.kill();
  await world.close();
  for (const server of [proxy, serve.server, paymentsServer, receiver]) server.close();
}

// The listener is ready when it says so; one that exits first, fails to start or takes over a
// minute ends the run, with everything stopped.
try {
  await new Promise<void>((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error("stripe listen was not ready within a minute")), 60_000);
    cli.stderr!.on("data", (c: Buffer) => {
      if (c.toString().includes("Ready!")) {
        clearTimeout(deadline);
        resolve();
      }
    });
    cli.on("error", (error) => (clearTimeout(deadline), reject(error)));
    cli.on("exit", (code) => (clearTimeout(deadline), reject(new Error(`stripe listen exited (${code}) before it was ready`))));
  });
} catch (error) {
  await cleanUp();
  throw error;
}

async function delivered(objectId: string, type: string): Promise<Delivery> {
  const until = Date.now() + WAIT_MS;
  for (;;) {
    const found = settledDelivery(deliveries, objectId, type);
    if (found !== undefined) return found;
    if (listenerExit !== null) throw new Error(`${listenerExit}: no ${type} can arrive`);
    if (Date.now() > until) throw new Error(`no ${type} for the recorded object in ${WAIT_MS / 60_000} minutes`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

try {
  // 1. Identity.
  const trial = await serve.startTrialCall!();
  const identityEvent = await delivered(trial.sessionId, "identity.verification_session.verified");
  const identityExchanges = exchanges.splice(0);

  // 2 and 3. Checkout in each mode.
  const checkout: Record<string, { exchanges: Exchange[]; delivery: Delivery; flowStatus: string }> = {};
  for (const flow of ["record-platform", "record-connect"] as RecordedFlow[]) {
    const { call, link } = await requestRecordedLink(world, flow);
    page(flow, link.url);
    const delivery = await delivered(link.linkId, "checkout.session.completed");
    const position = await world.engine.flowPosition(call.callId);
    checkout[flow] = { exchanges: exchanges.splice(0), delivery, flowStatus: `${position!.status} at step ${position!.index}` };
  }

  // 4. Cards and Link on the connected account, a link the caller then cancels: the engine closes
  // it at Stripe through the adapter's expireLink, on the connected account.
  const { call: cancelled, link: toCancel } = await requestRecordedLink(world, "record-connect-link");
  const cancel = await world.engine.cancelPaymentLink(cancelled.callId, toCancel.paymentId);
  const connectLink = { exchanges: exchanges.splice(0), cancelStatus: cancel.status };

  // 5. What Checkout refuses: each wallet as a payment method type, and Link without card, on the
  // connected account. Asked directly, since the adapter never sends either.
  const refused: Array<{ types: string[]; status: number; error: { type: unknown; code: unknown; param: unknown } }> = [];
  for (const types of [["apple_pay"], ["google_pay"], ["link"]]) {
    const form = new URLSearchParams([
      ["mode", "payment"],
      ["line_items[0][quantity]", "1"],
      ["line_items[0][price_data][currency]", "cad"],
      ["line_items[0][price_data][unit_amount]", "100"],
      ["line_items[0][price_data][product_data][name]", "Payment method types Checkout refuses"],
      ...types.map((type, i): [string, string] => [`payment_method_types[${i}]`, type]),
      ["success_url", "https://example.com/"],
    ]);
    const answer = await fetch(`${apiBase}/v1/checkout/sessions`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "stripe-version": STRIPE_API_VERSION, "stripe-account": account },
      body: form.toString(),
    });
    const error = ((await answer.json()) as { error?: Record<string, unknown> }).error ?? {};
    refused.push({ types, status: answer.status, error: { type: error.type, code: error.code, param: error.param } });
  }
  exchanges.splice(0);

  // One redactor for every file, so a session, its event and its account keep one placeholder each.
  const r = new Redactor();
  const files: Record<string, unknown> = {
    "identity.json": { exchanges: identityExchanges, delivery: identityEvent, engineEvents: printed.map((line) => line.replace(/^\S+ /, "")) },
    "checkout-platform.json": checkout["record-platform"],
    "checkout-connect.json": checkout["record-connect"],
    "checkout-connect-link.json": connectLink,
    "methods.json": { account, refused },
    "recording.json": {
      recordedOn: new Date().toISOString().slice(0, 10),
      stripeVersionPinned: STRIPE_API_VERSION,
      eventApiVersion: (JSON.parse(identityEvent.body) as { api_version: string }).api_version,
      cli: "stripe listen (the account's real, signed deliveries, forwarded to the loopback)",
      account,
    },
  };
  const texts = Object.entries(files).map(([name, value]) => [name, `${JSON.stringify(r.json(value), null, 2)}\n`] as const);
  for (const [name, text] of texts) {
    const found = leaks(text);
    if (found.length > 0) throw new Error(`${name} would leak ${found.length} value(s); nothing written`);
  }
  for (const [name, text] of texts) writeFileSync(new URL(name, out), text);
  console.log(`recorded: ${texts.map(([name]) => name).join(", ")}`);
} finally {
  await cleanUp();
}
