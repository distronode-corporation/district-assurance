// The demo's scripted calls, one step at a time. `npm run demo` runs every step of the four flows
// in a row and prints a line per step; the browser UI (`npm run ui`) runs the same steps one click at a
// time. A step takes no input: what the caller keys is fixed here, so the UI can only replay the
// script, never drive the engine with values of its own.
//
// Everything is made up: the accounts, the PIN, the date of birth and the phone numbers (555
// numbers). The Stripe webhooks are signed here with a demo secret and posted to the reference
// server over the loopback. Gate's door is an example relay on the loopback that checks each grant
// with the engine's access key before it "opens" (it only records the door's name).
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  canonicalJson,
  createEngine,
  signStripePayload,
  subjectKeyFor,
  webhookRelay,
  type AccessController,
  type Clock,
  type Engine,
  type FlowConfig,
  type IdGenerator,
  type PaymentLinks,
  type SignedAccessGrant,
  type SignedReceipt,
} from "../../../src/index.ts";
import { FixedClock, TEST_KNOWLEDGE_KEY, createTestEngine, generateTestSigner, testSubject, type TestEngine } from "../../../src/testing/index.ts";
import { createDoorRelay } from "./door-relay.ts";
import { demoConfig } from "./flows.ts";

/** The demo's webhook signing secret. Not a secret: it is published here on purpose. */
export const DEMO_SECRET = "whsec_demo_not_a_secret";
/** The demo's Connect endpoint secret (connect-mode payments), published on purpose too. */
export const DEMO_CONNECT_SECRET = "whsec_demo_connect_not_a_secret";
/** The made-up business account connect-mode deposits are taken on. */
export const DEMO_ACCOUNT = "acct_demo_business";
const OWNER_ACCOUNT = "10000001";
const OWNER_PIN = "4826";

/** A payment link as the payments adapter answered it. */
export interface CreatedLink {
  paymentId: string;
  linkId: string;
  url: string;
}

/** What `npm run demo:e2e` changes in the world; the fake demo and the UI pass nothing. */
export interface DemoWorldOptions {
  /** The payments adapter. Default: the test engine's fake. */
  payments?: PaymentLinks;
  /** Default: the test engine's fixed clock. The live demo passes the wall clock (Stripe and the relay read it). */
  clock?: Clock;
  /**
   * Default: the test engine's sequential ids. The live demo passes random ids: the engine's
   * idempotency keys are built from them, and Stripe keeps a key for 24 hours, so ids that restart
   * at `call_1` with every run would collide with an earlier run's requests.
   */
  ids?: IdGenerator;
  /** Default: `demoCallbackConfig()`. */
  config?: FlowConfig;
  /** Hears each door the example relay opens. */
  onDoorOpened?: (target: string) => void;
}

/** One engine with the demo's records, a second engine on the same stores, and a signed-webhook poster. */
export interface DemoWorld {
  t: TestEngine;
  /** Process A: the engine the reference server holds. */
  engine: Engine;
  /** Process B: another engine on the same session store and ledger. */
  other: Engine;
  /** The reference server's base URL, set once it listens. */
  base: string;
  /** Signs a Stripe event with the demo secret (the Connect one on the Connect route) and posts it. */
  stripe(path: string, type: string, object: Record<string, unknown>, account?: string): Promise<Record<string, unknown>>;
  /** Gate's one door controller, the relay adapter to the example door relay, on both engines. */
  lobby: AccessController;
  /** Every door the example relay opened, in order (for display). */
  doorsOpened: string[];
  /** The grant ids the example relay opened a door for: each run checks its own. */
  openedFor: Set<string>;
  /** Each grant Gate sent, by grant id, so a step can try to replay it. */
  sentGrants: Map<string, SignedAccessGrant>;
  /** The example door relay's unlock URL; starts the relay on the loopback the first time. */
  relayUrl(): Promise<string>;
  /** Stops the door relay, if it was started. */
  close(): Promise<void>;
  /** The clock both engines and the door relay read. */
  clock: Clock;
  /** The FlowConfig both engines run. */
  config: FlowConfig;
  /** Every link a real payments adapter created, oldest first (the fake keeps its own list). */
  links: CreatedLink[];
}

/**
 * Wraps a real payments adapter so each link it creates is also kept in `links`. Every other member
 * (`expireLink`, and the optional ones such as `cancel` and `refund`) is the adapter's own, called
 * on the adapter itself so its private fields still work, and a member the adapter lacks stays
 * missing: the engine reads a missing optional method as "this adapter cannot do that".
 */
export function recordLinks(real: PaymentLinks, links: CreatedLink[]): PaymentLinks {
  const createLink: PaymentLinks["createLink"] = async (input) => {
    const link = await real.createLink(input);
    links.push({ paymentId: input.paymentId, linkId: link.linkId, url: link.url });
    return link;
  };
  return new Proxy(real, {
    get(target, name) {
      if (name === "createLink") return createLink;
      const value: unknown = Reflect.get(target, name, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/**
 * VER-1's wait after a first failed try (its default and floor, which the demo's config keeps). It
 * holds across calls and engines, so the owner keys the right PIN only after it.
 */
export const FIRST_FAILURE_WAIT_MS = 5_000;

/**
 * Lets VER-1's wait after a failure pass: on the demo's fixed clock by moving the clock, on any
 * other clock (the live e2e demo's wall clock) by waiting it out for real.
 */
export async function waitOutFailureWait(clock: Clock): Promise<void> {
  if (clock instanceof FixedClock) clock.advance(FIRST_FAILURE_WAIT_MS + 1_000);
  else await new Promise<void>((resolve) => setTimeout(resolve, FIRST_FAILURE_WAIT_MS + 100));
}

/**
 * The demo's FlowConfig plus the callback factor (VER-9): on in Badge, a PIN and a callback reach
 * level 2, and the `owner-callback` flow asks for it on its first step. Owner commands stay at level 1.
 */
export function demoCallbackConfig(): FlowConfig {
  const config = demoConfig();
  (config.modules.badge!.settings as { factors: string[] }).factors.push("callback");
  config.policy.levels[1]!.anyOf.push(["pin", "callback"]);
  config.flows["owner-callback"] = {
    summary: "The owner's PIN, then a callback to the number on file, which runs the step again on its own call.",
    steps: [{ type: "badge.verify", level: 2, factors: ["pin", "callback", "carrier_identity_match"], scopes: ["owner.command"] }],
  };
  return config;
}

export function createDemoWorld(options: DemoWorldOptions = {}): DemoWorld {
  const doorsOpened: string[] = [];
  const links: CreatedLink[] = [];
  const config = options.config ?? demoCallbackConfig();
  const openedFor = new Set<string>();
  const sentGrants = new Map<string, SignedAccessGrant>();
  let relay: Server | null = null;
  let starting: Promise<string> | null = null;
  let closed = false;
  // The relay adapter needs the relay's port, known once it listens: built per unlock.
  // Gate's adapters: its own signing key, and one controller, the relay adapter, whose URL is known
  // once the example relay listens (so it is built per unlock).
  const accessSigner = generateTestSigner("demo-gate-key-1");
  const lobby: AccessController = {
    unlock: async (input) => {
      sentGrants.set(input.grant.body.grantId, input.grant);
      return webhookRelay({ url: await world.relayUrl() }).unlock(input);
    },
  };
  // A real adapter (the live demo) is wrapped to record what it answered, so a step finds its own
  // call's link; the fake records its links itself (`t.payments.created`).
  const real = options.payments;
  const recorded = real === undefined ? undefined : recordLinks(real, links);
  const t = createTestEngine({
    config,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.ids === undefined ? {} : { ids: options.ids }),
    adapters: { access: { lobby }, accessSigner, ...(recorded === undefined ? {} : { payments: recorded }) },
  });
  const payments = recorded ?? t.payments;
  const clock = options.clock ?? t.clock;
  t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OWNER_ACCOUNT, phoneOnFile: "+15555550101", knowledge: {}, pin: OWNER_PIN }));
  t.records.putSubject(
    "ws_test",
    testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214" } }),
  );
  t.carrier.set("+15555550100", { identityMatch: "match" });
  const other = createEngine({
    workspaceId: "ws_test",
    knowledgeKey: TEST_KNOWLEDGE_KEY,
    config,
    clock,
    ids: options.ids ?? t.ids,
    adapters: { ledger: t.ledger, sessions: t.sessions, records: t.records, identity: t.identity, carrier: t.carrier, messages: t.messages, payments, counters: t.counters, dialer: t.dialer, signer: generateTestSigner(), access: { lobby }, accessSigner },
  });
  let n = 0;
  const world: DemoWorld = {
    t,
    engine: t.engine,
    other,
    base: "",
    lobby,
    doorsOpened,
    openedFor,
    sentGrants,
    clock,
    config,
    links,
    relayUrl() {
      // A closed world starts nothing: a start after close() would listen with no one to stop it.
      if (closed) return Promise.reject(new Error("the demo world is closed"));
      // One startup shared by every caller, so two runs that begin together both wait for it.
      starting ??= (async () => {
        relay = createDoorRelay({
          workspaceId: "ws_test",
          audience: "lobby",
          keys: t.engine.accessKeys(),
          clock,
          open: async (target, grant) => {
            doorsOpened.push(target);
            openedFor.add(grant.grantId);
            options.onDoorOpened?.(target);
          },
        });
        const started = relay;
        await new Promise<void>((resolve) => started.listen(0, "127.0.0.1", resolve));
        // Never keeps a process alive on its own: the demo, the UI and the tests decide when to stop.
        started.unref();
        return `http://127.0.0.1:${(started.address() as AddressInfo).port}/unlock`;
      })();
      return starting;
    },
    async close() {
      // A relay still starting is waited for, then stopped: closing a server before it listens
      // leaves its listen pending forever, so relayUrl() and every unlock behind it would hang.
      if (closed) return;
      closed = true;
      const pending = starting;
      if (pending === null) return;
      await pending;
      const running = relay!;
      await new Promise<void>((resolve) => running.close(() => resolve()));
    },
    async stripe(path, type, object, account) {
      const payload = JSON.stringify({ id: `evt_demo_${++n}`, type, livemode: false, data: { object }, ...(account === undefined ? {} : { account }) });
      const secret = path.endsWith("/connect") ? DEMO_CONNECT_SECRET : DEMO_SECRET;
      const header = signStripePayload(payload, secret, Math.floor(clock.now().getTime() / 1000));
      const res = await fetch(`${world.base}${path}`, { method: "POST", headers: { "stripe-signature": header }, body: payload });
      return (await res.json()) as Record<string, unknown>;
    },
  };
  return world;
}

/** One scripted call in progress. */
export interface ScriptRun {
  callId: string;
  /** This call's payment link, once requested: runs share the fakes, so never "the latest link". */
  linkId: string;
  receipt: SignedReceipt | null;
  /** The call the engine placed back to the number on file, in the callback script. */
  callbackCallId?: string;
  /** This call's access grant, once Gate sent one (entry). */
  grantId?: string;
  /** The engine's deadline for this call's link, once texted (the live demo's payment wait). */
  paymentExpiresAt?: string | null;
}

/** What a step did, in one line, and whether the demo's check on it held. */
export interface StepOutcome {
  detail: string;
  ok: boolean;
  /** A link the page shows with the step (the live demo's Checkout page). https only. */
  link?: { href: string; text: string };
}

export interface ScriptStep {
  label: string;
  run(world: DemoWorld, call: ScriptRun): Promise<StepOutcome>;
}

/** The scripts a set of runs can replay, by flow name. */
export type Scripts = Readonly<Record<string, readonly ScriptStep[]>>;

export type DemoFlow = "owner-command" | "deposit" | "deposit-connect" | "entry";

export const pass = (detail: string): StepOutcome => ({ detail, ok: true });

/** The owner's PIN only, on two engines that share one session store. One wrong PIN, then the right one. */
const ownerCommand: ScriptStep[] = [
  {
    label: "owner-command: call started",
    async run(w, call) {
      call.callId = (await w.engine.startCall({ flow: "owner-command" })).callId;
      return pass(`${call.callId} on process A`);
    },
  },
  {
    label: "owner-command: PIN on process B",
    async run(w, call) {
      await w.other.beginVerification(call.callId, { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, OWNER_ACCOUNT), callingNumber: "+15555550101" });
      await w.other.openSensitive(call.callId, "keypad");
      const wrong = await w.other.submitPin(call.callId, "1111");
      return { detail: wrong.matched ? "MATCHED a wrong PIN" : "no match (one attempt used)", ok: !wrong.matched };
    },
  },
  {
    label: "owner-command: PIN on process A",
    async run(w, call) {
      await waitOutFailureWait(w.clock);
      const right = await w.engine.submitPin(call.callId, OWNER_PIN);
      return { detail: right.matched ? "matched" : "no match", ok: right.matched };
    },
  },
  {
    label: "owner-command: verified",
    async run(w, call) {
      const level = await w.other.finishVerification(call.callId);
      const position = await w.engine.flowPosition(call.callId);
      return { detail: `level ${level.level}, flow ${position!.status}`, ok: level.level === 1 };
    },
  },
  {
    label: "owner-command: scopes",
    async run(w, call) {
      const allowed = await w.engine.authorize(call.callId, "owner.command");
      const moneyRefused = !(await w.engine.authorize(call.callId, "payment.request"));
      return {
        detail: `owner.command ${allowed ? "allowed" : "REFUSED"}, payment.request ${moneyRefused ? "refused (floor 2)" : "ALLOWED"}`,
        ok: allowed && moneyRefused,
      };
    },
  },
  {
    label: "owner-command: call ended",
    async run(w, call) {
      call.receipt = await w.engine.endCall(call.callId);
      return { detail: call.receipt === null ? "no receipt in this flow, the ledger has it all" : "receipt issued", ok: call.receipt === null };
    },
  },
];

/** Keypad and carrier to level 2, a repair form, a deposit by link settled by a signed webhook, a consent, a receipt. */
const deposit: ScriptStep[] = [
  {
    label: "deposit: call started",
    async run(w, call) {
      call.callId = (await w.engine.startCall({ locale: "en", flow: "deposit" })).callId;
      return pass(call.callId);
    },
  },
  {
    label: "verify: keypad checks",
    async run(w, call) {
      await w.engine.beginVerification(call.callId, { accountNumber: "12345678" });
      await w.engine.openSensitive(call.callId, "keypad");
      const keypad = await w.engine.submitKeypad(call.callId, { dob: "19850214" });
      await w.engine.closeSensitive(call.callId);
      return { detail: keypad.matched ? "matched (one answer for all fields)" : "no match", ok: keypad.matched };
    },
  },
  {
    label: "verify: carrier signals",
    async run(w, call) {
      const carrier = await w.engine.checkCarrier(call.callId);
      return pass(`identity match recorded, texted code trusted: ${carrier.textCodeTrusted}`);
    },
  },
  {
    label: "verify: finished",
    async run(w, call) {
      const verified = await w.engine.finishVerification(call.callId);
      const noOwnerScope = !(await w.engine.authorize(call.callId, "owner.command"));
      return { detail: `level ${verified.level}, scopes ${verified.scopes.join(", ")}`, ok: verified.level === 2 && noOwnerScope };
    },
  },
  {
    label: "file: record confirmed",
    async run(w, call) {
      await w.engine.startIntake(call.callId, "maintenance");
      await w.engine.setIntakeField(call.callId, "issue", "Water leak under the kitchen sink");
      await w.engine.setIntakeField(call.callId, "urgent", "yes");
      // The host speaks the read-back's text, and the caller's yes confirms the digest of what they heard.
      const readBack = await w.engine.intakeReadBack(call.callId);
      const record = await w.engine.confirmIntake(call.callId, { confirmedBy: "voice", readBack: readBack.digest });
      return pass(`${record.recordId}, digest ${record.digest.slice(0, 16)}...`);
    },
  },
  {
    label: "guard: transcript redacted",
    async run(w, call) {
      const heard = await w.engine.redact(call.callId, "my card is four two four two four two four two four two four two four two four two");
      return { detail: `"${heard.text}", interrupt: ${heard.interrupt}`, ok: heard.interrupt };
    },
  },
  {
    label: "pay: amount read back",
    async run(w, call) {
      // Every link waits for the caller to hear its amount and say yes (PAY-2); code builds the line.
      const back = await w.engine.readBackPayment(call.callId);
      await w.engine.confirmPaymentAmount(call.callId, { digest: back.digest, confirmedBy: "keypad" });
      return pass(`"${back.text}" caller: yes`);
    },
  },
  {
    label: "pay: link texted, amount from flow",
    async run(w, call) {
      const payment = await w.engine.requestPayment(call.callId);
      call.linkId = w.t.payments.created.find((link) => link.paymentId === payment.paymentId)!.linkId;
      const text = w.t.messages.sent.find((message) => message.body.endsWith(`/${call.linkId}`))!;
      return pass(`${payment.paymentId}: "${text.body}"`);
    },
  },
  {
    label: "webhook: payment completed",
    async run(w, call) {
      const hook = await w.stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: call.linkId, payment_status: "paid" });
      return { detail: `signed, applied: ${String(hook.applied)}`, ok: hook.applied === true };
    },
  },
  {
    label: "webhook: same outcome again",
    async run(w, call) {
      const replay = await w.stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: call.linkId, payment_status: "paid" });
      return { detail: `applied: ${String(replay.applied)} (settled once)`, ok: replay.applied === false };
    },
  },
  {
    label: "prove: consent recorded",
    async run(w, call) {
      await w.engine.recordConsent(call.callId, { purpose: "repair_texts", answer: "yes" });
      return pass("wording fingerprinted, answer yes");
    },
  },
  {
    label: "deposit: call ended",
    async run(w, call) {
      const done = await w.engine.flowPosition(call.callId);
      call.receipt = await w.engine.endCall(call.callId);
      return { detail: `flow ${done!.status} (${done!.index} steps), receipt ${call.receipt === null ? "MISSING" : "signed"}`, ok: call.receipt !== null };
    },
  },
];

/** Keypad and carrier to level 2, the scopes the flow's verify step names. */
export async function verifyToLevel2(w: DemoWorld, call: ScriptRun, scope: string): Promise<StepOutcome> {
  await w.engine.beginVerification(call.callId, { accountNumber: "12345678" });
  await w.engine.submitKeypad(call.callId, { dob: "19850214" });
  await w.engine.checkCarrier(call.callId);
  const verified = await w.engine.finishVerification(call.callId);
  return { detail: `level ${verified.level}, scopes ${verified.scopes.join(", ")}`, ok: verified.level === 2 && verified.scopes.includes(scope) };
}

/** A deposit on the business's own account (connect mode), settled by the Connect webhook only. */
const depositConnect: ScriptStep[] = [
  {
    label: "deposit-connect: call started",
    async run(w, call) {
      call.callId = (await w.engine.startCall({ locale: "fr", flow: "deposit-connect" })).callId;
      return pass(call.callId);
    },
  },
  { label: "verify: level 2", run: (w, call) => verifyToLevel2(w, call, "payment.request") },
  {
    label: "pay: connect mode",
    async run(w, call) {
      // The amount is read back and confirmed first, as for every link (PAY-2).
      const back = await w.engine.readBackPayment(call.callId);
      await w.engine.confirmPaymentAmount(call.callId, { digest: back.digest, confirmedBy: "voice" });
      const payment = await w.engine.requestPayment(call.callId);
      const asked = w.t.payments.created.find((link) => link.paymentId === payment.paymentId)!;
      call.linkId = asked.linkId;
      return {
        detail: `account ${asked.connectedAccountId}, methods ${asked.paymentMethods.join(", ")}, the engine expires it at ${payment.expiresAt}`,
        ok: asked.mode === "connect" && asked.connectedAccountId === DEMO_ACCOUNT,
      };
    },
  },
  {
    label: "webhook: on the platform endpoint",
    async run(w, call) {
      const hook = await w.stripe("/webhooks/stripe/payments", "checkout.session.completed", { id: call.linkId, payment_status: "paid" });
      return { detail: `applied: ${String(hook.applied)} (no connected account: ignored)`, ok: hook.applied === false };
    },
  },
  {
    label: "webhook: on the Connect endpoint",
    async run(w, call) {
      const hook = await w.stripe("/webhooks/stripe/connect", "checkout.session.completed", { id: call.linkId, payment_status: "paid" }, DEMO_ACCOUNT);
      return { detail: `signed with its own secret, applied: ${String(hook.applied)}`, ok: hook.applied === true };
    },
  },
  {
    label: "deposit-connect: call ended",
    async run(w, call) {
      call.receipt = await w.engine.endCall(call.callId);
      const mode = call.receipt?.body.payments[0]?.mode;
      return { detail: `receipt ${call.receipt === null ? "MISSING" : "signed"}, payment mode ${String(mode)}`, ok: mode === "connect" };
    },
  },
];

/** Posts a body to the door relay, within 5 seconds; an answer that is not JSON reads as an error. */
async function postToRelay(w: DemoWorld, body: string): Promise<{ status: number; error: string }> {
  try {
    const res = await fetch(await w.relayUrl(), { method: "POST", body, signal: AbortSignal.timeout(5000) });
    const answer = (await res.json().catch(() => null)) as { error?: unknown } | null;
    return { status: res.status, error: typeof answer?.error === "string" ? answer.error : "no_answer" };
  } catch {
    return { status: 0, error: "unreachable" };
  }
}

/** Verification to level 2 for entry.open, then a signed 30-second grant, checked by the door relay. */
const entry: ScriptStep[] = [
  {
    label: "entry: call started",
    async run(w, call) {
      call.callId = (await w.engine.startCall({ flow: "entry" })).callId;
      return pass(call.callId);
    },
  },
  { label: "verify: level 2", run: (w, call) => verifyToLevel2(w, call, "entry.open") },
  {
    label: "gate: access grant delivered",
    async run(w, call) {
      const access = await w.engine.grantAccess(call.callId);
      call.grantId = access.grantId;
      // This run's own grant opened the door: other runs' openings never count here.
      const opened = w.openedFor.has(access.grantId);
      return {
        detail: `${access.grantId}, ${access.status}, door moved: ${access.confirmed}, ${opened ? "the door opened for it" : "NO door opened for it"}`,
        ok: access.status === "delivered" && opened,
      };
    },
  },
  {
    label: "gate: same grant sent again",
    async run(w, call) {
      const res = await postToRelay(w, canonicalJson(w.sentGrants.get(call.grantId!)!));
      return { detail: `${res.status} ${res.error}`, ok: res.status === 409 };
    },
  },
  {
    label: "gate: a changed grant",
    async run(w, call) {
      const forged = structuredClone(w.sentGrants.get(call.grantId!)!);
      forged.body.target = "door-2";
      const res = await postToRelay(w, canonicalJson(forged));
      return { detail: `${res.status} ${res.error}, the door stays shut`, ok: res.status === 401 };
    },
  },
  {
    label: "entry: call ended",
    async run(w, call) {
      const done = await w.engine.flowPosition(call.callId);
      call.receipt = await w.engine.endCall(call.callId);
      return { detail: `flow ${done!.status}; the ledger holds the grant's digest, never the grant`, ok: done!.status === "completed" };
    },
  },
];

export const SCRIPTS: Readonly<Record<DemoFlow, readonly ScriptStep[]>> = { "owner-command": ownerCommand, deposit, "deposit-connect": depositConnect, entry };

/**
 * A callback (VER-9), run by `npm run demo` after the four flows. Someone calls from a number that is
 * not the owner's and keys the owner's PIN; the first call is ended and earns nothing. The engine
 * calls the number on file back, the owner keys the confirmation and the PIN again, and only the
 * callback call reaches level 2.
 */
export const CALLBACK_SCRIPT: readonly ScriptStep[] = [
  {
    label: "callback: PIN from another number",
    async run(w, call) {
      call.callId = (await w.engine.startCall({ flow: "owner-callback" })).callId;
      await w.engine.beginVerification(call.callId, { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, OWNER_ACCOUNT), callingNumber: "+15555550199" });
      const pin = await w.engine.submitPin(call.callId, OWNER_PIN);
      return { detail: pin.matched ? "matched, but caller ID can be spoofed" : "no match", ok: pin.matched };
    },
  },
  {
    label: "callback: asked, first call ended",
    async run(w, call) {
      await w.engine.requestCallback(call.callId);
      const first = await w.engine.state(call.callId);
      const position = await w.engine.flowPosition(call.callId);
      return { detail: `first call ${first.phase}, level ${first.level}, flow ${position!.status}`, ok: first.phase === "ended" && first.level === 0 };
    },
  },
  {
    label: "callback: number on file answered",
    async run(w, call) {
      const dial = w.t.dialer.dialed.at(-1)!;
      call.callbackCallId = dial.callId;
      const outcome = await w.other.applyCallbackOutcome({ ref: dial.ref, answered: true, confirmed: true });
      return { detail: `${dial.callId} rang the number on file, confirmation keyed, applied: ${String(outcome.applied)}`, ok: outcome.applied };
    },
  },
  {
    label: "callback: PIN again, carrier checked",
    async run(w, call) {
      const callbackCallId = call.callbackCallId!;
      const pin = await w.engine.submitPin(callbackCallId, OWNER_PIN);
      const carrier = await w.engine.checkCarrier(callbackCallId);
      const verified = await w.engine.finishVerification(callbackCallId);
      const first = await w.engine.state(call.callId);
      return {
        detail: `callback call level ${verified.level} (callback trusted: ${carrier.textCodeTrusted}), first call level ${first.level}`,
        ok: pin.matched && verified.level === 2 && first.level === 0,
      };
    },
  },
  {
    label: "callback: call ended",
    async run(w, call) {
      call.receipt = await w.engine.endCall(call.callbackCallId!);
      return { detail: "no receipt in this flow, the ledger has both calls", ok: call.receipt === null };
    },
  },
];

export function isDemoFlow(name: unknown): name is DemoFlow {
  return name === "owner-command" || name === "deposit" || name === "deposit-connect" || name === "entry";
}
