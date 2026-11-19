// The demo's scripted calls, one step at a time. `npm run demo` runs every step of every flow in a
// row and prints a line per step; the browser UI (`npm run ui`) runs the same steps one click at a
// time. A step takes no input: what the caller keys is fixed here, so the UI can only replay the
// script, never drive the engine with values of its own.
//
// Everything is made up: the accounts, the PIN, the date of birth and the phone numbers (555
// numbers). The Stripe webhooks are signed here with a demo secret and posted to the reference
// server over the loopback. Gate's grants go to an example door relay on the loopback.
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  createEngine,
  gateModule,
  signStripePayload,
  subjectKeyFor,
  webhookRelay,
  type AccessController,
  type Clock,
  type Engine,
  type FlowConfig,
  type IdGenerator,
  type GateModule,
  type PaymentLinks,
  type SignedAccessGrant,
  type SignedReceipt,
} from "../../../src/index.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, generateTestSigner, testSubject, type TestEngine } from "../../../src/testing/index.ts";
import { createDoorRelay } from "./door-relay.ts";
import { demoConfig } from "./flows.ts";

/** The demo's webhook signing secret. Not a secret: it is published here on purpose. */
export const DEMO_SECRET = "whsec_demo_not_a_secret";
/** The demo's Connect endpoint secret, published on purpose too. */
export const DEMO_CONNECT_SECRET = "whsec_demo_connect_not_a_secret";
/** The made-up connected account of `deposit-connect`. */
export const DEMO_ACCOUNT = "acct_demo_business";
export const DEMO_WORKSPACE = "ws_test";
const OWNER_ACCOUNT = "10000001";
const OWNER_PIN = "4826";

/** A payment link as the payments adapter answered it, by payment id. */
export interface CreatedLink {
  paymentId: string;
  linkId: string;
  url: string;
  connectedAccountId?: string;
  paymentMethods: readonly string[];
}

export interface DemoWorldOptions {
  /** The payments adapter. Default: the fake from `createTestEngine`. */
  payments?: PaymentLinks;
  /** Default: the test engine's fixed clock. The live demo passes the system clock. */
  clock?: Clock;
  /** Default: `demoConfig()`. */
  config?: FlowConfig;
  /**
   * Default: the test engine's sequential ids. The live demo passes random ids: the engine's
   * idempotency keys are built from them, and Stripe keeps a key for 24 hours, so ids that restart
   * at `call_1` with every run would collide with the last run's requests.
   */
  ids?: IdGenerator;
}

/** One engine with the demo's records, a second engine on the same stores, Gate, and a signed-webhook poster. */
export interface DemoWorld {
  t: TestEngine;
  /** Process A: the engine the reference server holds. */
  engine: Engine;
  /** Process B: another engine on the same session store and ledger. */
  other: Engine;
  gate: GateModule;
  clock: Clock;
  /** The FlowConfig both engines run. */
  config: FlowConfig;
  /** The reference server's base URL, set once it listens. */
  base: string;
  /** The example door relay's unlock URL, set once it listens (`startDoorRelay`). */
  relayUrl: string;
  /** Every link the payments adapter created, oldest first. */
  links: CreatedLink[];
  /** Every grant Gate handed the relay adapter, oldest first. */
  sentGrants: SignedAccessGrant[];
  /** Every door the relay opened, oldest first. */
  doorOpened: string[];
  /** The door each grant opened, by grant id. */
  openedBy: Map<string, string>;
  /** Signs a Stripe event with the demo secret (the Connect one on `/connect`) and posts it to the server. */
  stripe(path: string, type: string, object: Record<string, unknown>, account?: string): Promise<Record<string, unknown>>;
}

export function createDemoWorld(options: DemoWorldOptions = {}): DemoWorld {
  const links: CreatedLink[] = [];
  const sentGrants: SignedAccessGrant[] = [];
  let world: DemoWorld | undefined;
  // Gate's one controller, the signed-webhook relay, pointed at the example door relay once it listens.
  const lobby: AccessController = {
    unlock: (input) => {
      sentGrants.push(input.grant);
      return webhookRelay({ url: world!.relayUrl }).unlock(input);
    },
  };
  const gate = gateModule({ signer: generateTestSigner("demo-gate-key-1"), controllers: { lobby } });
  const config = options.config ?? demoConfig();
  const t = createTestEngine({ config, modules: [gate], ...(options.clock === undefined ? {} : { clock: options.clock }) });
  const clock = options.clock ?? t.clock;
  const ids = options.ids ?? t.ids;
  const inner = options.payments ?? t.payments;
  // Records what the adapter answered, so a step finds its own call's link whatever the adapter.
  const payments: PaymentLinks = {
    capabilities: inner.capabilities,
    async createLink(input) {
      const link = await inner.createLink(input);
      links.push({
        paymentId: input.paymentId,
        linkId: link.linkId,
        url: link.url,
        paymentMethods: input.paymentMethods,
        ...(input.connectedAccountId === undefined ? {} : { connectedAccountId: input.connectedAccountId }),
      });
      return link;
    },
    expireLink: (input) => inner.expireLink(input),
  };
  const adapters = { ledger: t.ledger, sessions: t.sessions, records: t.records, identity: t.identity, carrier: t.carrier, messages: t.messages, payments, signer: generateTestSigner() };
  const engine = createEngine({ workspaceId: DEMO_WORKSPACE, knowledgeKey: TEST_KNOWLEDGE_KEY, config, modules: [gate], clock, ids, adapters });
  t.records.putSubject(DEMO_WORKSPACE, testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: OWNER_ACCOUNT, phoneOnFile: "+15555550101", knowledge: {}, pin: OWNER_PIN }));
  t.records.putSubject(
    DEMO_WORKSPACE,
    testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: "12345678", phoneOnFile: "+15555550100", knowledge: { dob: "19850214" } }),
  );
  t.carrier.set("+15555550100", { identityMatch: "match" });
  // A second engine on the same session store and ledger: another process of the same host.
  const other = createEngine({
    workspaceId: DEMO_WORKSPACE,
    knowledgeKey: TEST_KNOWLEDGE_KEY,
    config,
    modules: [gate],
    clock,
    ids,
    adapters: { ...adapters, signer: generateTestSigner() },
  });
  let n = 0;
  world = {
    t,
    engine,
    other,
    gate,
    clock,
    config,
    base: "",
    relayUrl: "",
    links,
    sentGrants,
    doorOpened: [],
    openedBy: new Map(),
    async stripe(path, type, object, account) {
      const payload = JSON.stringify({ id: `evt_demo_${++n}`, type, livemode: false, data: { object }, ...(account === undefined ? {} : { account }) });
      const secret = path.endsWith("/connect") ? DEMO_CONNECT_SECRET : DEMO_SECRET;
      const header = signStripePayload(payload, secret, Math.floor(clock.now().getTime() / 1000));
      const res = await fetch(`${world!.base}${path}`, { method: "POST", headers: { "stripe-signature": header }, body: payload });
      return (await res.json()) as Record<string, unknown>;
    },
  };
  return world;
}

/**
 * Starts the example door relay on 127.0.0.1 with Gate's public key and the demo's workspace, and
 * points Gate's relay adapter at it. `onOpen` hears each door it opens.
 */
export async function startDoorRelay(world: DemoWorld, port = 0, onOpen: (target: string) => void = () => undefined): Promise<Server> {
  const relay = createDoorRelay({
    audience: "lobby",
    workspaceId: DEMO_WORKSPACE,
    keys: world.gate.keys(),
    clock: world.clock,
    open: async (target, grant) => {
      world.doorOpened.push(target);
      world.openedBy.set(grant.grantId, target);
      onOpen(target);
    },
  });
  await new Promise<void>((resolve, reject) => {
    relay.once("error", reject);
    relay.listen(port, "127.0.0.1", resolve);
  });
  world.relayUrl = `http://127.0.0.1:${(relay.address() as AddressInfo).port}/unlock`;
  return relay;
}

/** One scripted call in progress. */
export interface ScriptRun {
  callId: string;
  /** This call's payment link, once requested: runs share the adapters, so never "the latest link". */
  linkId: string;
  receipt: SignedReceipt | null;
  /** The engine's deadline for this call's link, once texted. */
  paymentExpiresAt?: string | null;
  /** This call's access grant, once Gate sent one: runs share the relay, so never "the latest grant". */
  grantId?: string;
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
      await w.other.beginVerification(call.callId, { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, OWNER_ACCOUNT) });
      await w.other.openSensitive(call.callId, "keypad");
      const wrong = await w.other.submitPin(call.callId, "1111");
      return { detail: wrong.matched ? "MATCHED a wrong PIN" : "no match (one attempt used)", ok: !wrong.matched };
    },
  },
  {
    label: "owner-command: PIN on process A",
    async run(w, call) {
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

/** The steps that take a deposit caller to level 2: keypad knowledge, then a carrier identity match. */
export function verifyToLevel2(flow: string, locale: "en" | "fr" = "en"): ScriptStep[] {
  return [
    {
      label: `${flow}: call started`,
      async run(w, call) {
        call.callId = (await w.engine.startCall({ locale, flow })).callId;
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
  ];
}

/** Requests the call's payment and finds its own link among the adapter's. */
export async function requestLink(w: DemoWorld, call: ScriptRun): Promise<{ paymentId: string; expiresAt: string | null; link: CreatedLink }> {
  const payment = await w.engine.requestPayment(call.callId);
  const link = w.links.find((l) => l.paymentId === payment.paymentId)!;
  call.linkId = link.linkId;
  call.paymentExpiresAt = payment.expiresAt;
  return { paymentId: payment.paymentId, expiresAt: payment.expiresAt, link };
}

/** Gate's grant for the call, sent to the door relay. */
export const openDoor: ScriptStep = {
  label: "gate: access grant delivered",
  async run(w, call) {
    const access = await w.gate.grantAccess(w.engine, call.callId);
    call.grantId = access.grantId;
    const opened = w.openedBy.get(access.grantId);
    return {
      detail: `${access.grantId}, ${access.status}, door moved: ${access.confirmed}${opened === undefined ? "" : `, opened ${opened}`}`,
      ok: access.status === "delivered" && access.confirmed,
    };
  },
};

/** Ends the call and keeps its signed receipt. */
export function endWithReceipt(flow: string): ScriptStep {
  return {
    label: `${flow}: call ended`,
    async run(w, call) {
      const done = await w.engine.flowPosition(call.callId);
      call.receipt = await w.engine.endCall(call.callId);
      return { detail: `flow ${done!.status} (${done!.index} steps), receipt ${call.receipt === null ? "MISSING" : "signed"}`, ok: call.receipt !== null };
    },
  };
}

/** Level 2, a repair form, a deposit by link settled by a signed webhook, a consent, a receipt. */
const deposit: ScriptStep[] = [
  ...verifyToLevel2("deposit"),
  {
    label: "file: record confirmed",
    async run(w, call) {
      await w.engine.startIntake(call.callId, "maintenance");
      await w.engine.setIntakeField(call.callId, "issue", "Water leak under the kitchen sink");
      await w.engine.setIntakeField(call.callId, "urgent", "yes");
      const record = await w.engine.confirmIntake(call.callId, { confirmedBy: "voice" });
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
    label: "pay: link texted, amount from flow",
    async run(w, call) {
      const { paymentId } = await requestLink(w, call);
      const text = w.t.messages.sent.find((message) => message.body.endsWith(`/${call.linkId}`))!;
      return pass(`${paymentId}: "${text.body}"`);
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
  endWithReceipt("deposit"),
];

/** A deposit on the business's own account: the platform endpoint's webhook is ignored, the Connect one settles it. */
const depositConnect: ScriptStep[] = [
  ...verifyToLevel2("deposit-connect", "fr"),
  {
    label: "pay: connect mode",
    async run(w, call) {
      const { expiresAt, link } = await requestLink(w, call);
      return { detail: `account ${link.connectedAccountId}, methods ${link.paymentMethods.join(", ")}, expires ${expiresAt}`, ok: link.connectedAccountId === DEMO_ACCOUNT };
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
  endWithReceipt("deposit-connect"),
];

/** The grant Gate sent for this call. */
function sentGrant(w: DemoWorld, call: ScriptRun): SignedAccessGrant {
  return w.sentGrants.find((grant) => grant.body.grantId === call.grantId)!;
}

/** Level 2 for `entry.open`, a signed grant the door relay checks; the same grant again and a changed copy are refused. */
const entry: ScriptStep[] = [
  ...verifyToLevel2("entry"),
  openDoor,
  {
    label: "gate: same grant sent again",
    async run(w, call) {
      const again = await fetch(w.relayUrl, { method: "POST", body: JSON.stringify(sentGrant(w, call)) });
      return { detail: `${again.status} ${((await again.json()) as { error: string }).error}`, ok: again.status === 409 };
    },
  },
  {
    label: "gate: a changed grant",
    async run(w, call) {
      const opened = w.doorOpened.length;
      const forged = structuredClone(sentGrant(w, call));
      forged.body.target = "door-2";
      const changed = await fetch(w.relayUrl, { method: "POST", body: JSON.stringify(forged) });
      return {
        detail: `${changed.status} ${((await changed.json()) as { error: string }).error}, the door stays shut`,
        ok: changed.status === 401 && w.doorOpened.length === opened,
      };
    },
  },
  {
    label: "entry: call ended",
    async run(w, call) {
      const done = await w.engine.flowPosition(call.callId);
      call.receipt = await w.engine.endCall(call.callId);
      return { detail: `flow ${done!.status}`, ok: done!.status === "completed" };
    },
  },
];

export const SCRIPTS: Readonly<Record<DemoFlow, readonly ScriptStep[]>> = { "owner-command": ownerCommand, deposit, "deposit-connect": depositConnect, entry };

export function isDemoFlow(name: unknown): name is DemoFlow {
  return typeof name === "string" && Object.hasOwn(SCRIPTS, name);
}
