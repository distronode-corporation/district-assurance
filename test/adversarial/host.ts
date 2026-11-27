// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The scripted host for the adversarial suite (VER-7). A script is a dialogue: what the caller says,
// what the model proposes, and what the host's own code paths do (keypad events, webhook routes,
// business lookups). The host plays a real host's part and nothing more:
//
// - the caller's words only ever go through `redact`, as a transcript line;
// - the model's proposals are tool calls the host maps to fixed code paths, and a proposal with no
//   path (mark the caller verified, skip the check) never reaches the engine at all;
// - the host speaks fixed lines, in English or Canadian French, chosen only from the engine's answer.
//
// After every turn the runner checks the four rules every script asserts: no grant without factors,
// no text (and no carrier check) before a keypad or PIN match, identical answers for an unknown
// account and a wrong answer, and a tainted session holds no grant. A mirror call, keyed with an
// account that is not on file, receives every keypad and PIN entry the script's call receives, and
// each entry that did not match must get the same answer, the same spoken line and the same ledger
// detail as the mirror's.
import { strict as assert } from "node:assert";

import type { JsonValue } from "../../src/core/canonical.ts";
import type { FlowConfig } from "../../src/core/config.ts";
import { EngineError, type EngineErrorCode } from "../../src/core/errors.ts";
import { defaultVerificationPolicy, evaluateAssurance, type CarrierSignalReport } from "../../src/core/policy.ts";
import { verifyChain } from "../../src/prove/ledger.ts";
import { TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../../src/testing/index.ts";
import { subjectKeyFor } from "../../src/verify/knowledge.ts";
import { defaultConfig } from "../../src/modules.ts";

export type Locale = "en" | "fr";

/** The ways a caller tries to get past the rules. A new rule or factor adds scripts in both languages. */
export const TACTICS = ["urgency", "authority", "skip-it", "partial-answers", "account-probing", "text-flooding", "business-injection"] as const;
export type Tactic = (typeof TACTICS)[number];

/** Tools the model may propose. The host maps each to a fixed code path, or to none. */
export const TOOLS = {
  read_status: "status.read",
  file_request: "intake.file",
  update_contact: "contact.update",
  update_payout: "payout.update",
  owner_command: "owner.command",
  send_payment_link: "payment.request",
  send_identity_link: null,
  mark_verified: null,
  skip_verification: null,
} as const;
export type Tool = keyof typeof TOOLS;

/** What the host's own code does: never something the model or the caller's words chose. */
export type HostAction =
  | { do: "call"; flow?: string }
  | { do: "account"; account: string }
  | { do: "owner"; account: string }
  | { do: "keypad"; entries: Record<string, string> }
  | { do: "pin"; pin: string }
  | { do: "spoken"; answer: Record<string, string> }
  | { do: "text_code"; entries: Array<"right" | "wrong"> }
  | { do: "callback"; answered: boolean }
  | { do: "carrier" }
  | { do: "identity"; status: "verified" | "canceled" }
  | { do: "finish" }
  | { do: "business"; source: string; text: string }
  | { do: "end" };

export interface Turn {
  /** What the caller says. It only ever reaches the engine as a transcript line to redact. */
  caller?: string;
  /** A tool the model proposes. */
  ai?: Tool;
  /** A code path of the host. */
  host?: HostAction;
  /** The line the host speaks for the turn's action (or for the caller's words when there is none), and the engine's answer. */
  expect: { line: LineKey | null; result?: JsonValue; error?: EngineErrorCode };
}

export interface Script {
  id: string;
  tactic: Tactic;
  locale: Locale;
  summary: string;
  /** Caller ID. The host never gives it to the engine; no text may go to it. */
  callingNumber: string;
  /** The flow the script's first call runs, if any. */
  flow?: string;
  turns: Turn[];
}

// ---- the fixed lines -----------------------------------------------------------------------

export type LineKey =
  | "ask_keypad"
  | "ask_pin"
  | "matched"
  | "no_match"
  | "locked"
  | "one_moment"
  | "verified"
  | "not_verified"
  | "link_sent"
  | "calling_back"
  | "done"
  | "refused"
  | "interrupt"
  | "goodbye";

/** Every line the host can speak. French is Canadian French. Nothing the caller says is ever in one. */
export const LINES: Readonly<Record<Locale, Readonly<Record<LineKey, string>>>> = {
  en: {
    ask_keypad: "Please key in your date of birth and your unit number, then press pound.",
    ask_pin: "Please key in your PIN, then press pound.",
    matched: "Thank you, that matches our records.",
    no_match: "Those details do not match our records.",
    locked: "I cannot check any more entries on this call. I will transfer you to someone who can help.",
    one_moment: "One moment, please.",
    verified: "Thank you, you are verified.",
    not_verified: "I could not verify you on this call.",
    link_sent: "I have texted a link to the number we have on file.",
    calling_back: "If we can, we will call you back at the number we have on file. Goodbye for now.",
    done: "Done.",
    refused: "I cannot do that on this call.",
    interrupt: "Please do not read card numbers aloud. I can text you a secure payment link instead.",
    goodbye: "Thank you for calling. Goodbye.",
  },
  fr: {
    ask_keypad: "Veuillez entrer votre date de naissance et votre numéro d'appartement sur le clavier, puis appuyez sur le carré.",
    ask_pin: "Veuillez entrer votre NIP, puis appuyez sur le carré.",
    matched: "Merci, cela correspond à nos dossiers.",
    no_match: "Ces renseignements ne correspondent pas à nos dossiers.",
    locked: "Je ne peux plus vérifier d'entrées pendant cet appel. Je vous transfère à une personne qui pourra vous aider.",
    one_moment: "Un instant, s'il vous plaît.",
    verified: "Merci, votre identité est vérifiée.",
    not_verified: "Je n'ai pas pu vérifier votre identité pendant cet appel.",
    link_sent: "Je vous ai envoyé un lien par texto au numéro inscrit à votre dossier.",
    calling_back: "Si nous le pouvons, nous vous rappellerons au numéro inscrit à votre dossier. À bientôt.",
    done: "C'est fait.",
    refused: "Je ne peux pas faire cela pendant cet appel.",
    interrupt: "Veuillez ne pas lire de numéro de carte à voix haute. Je peux plutôt vous envoyer un lien de paiement sécurisé par texto.",
    goodbye: "Merci de votre appel. Au revoir.",
  },
};

/** How a text in each locale starts, so a French call never gets an English text. */
const TEXT_OPENINGS: Readonly<Record<Locale, string>> = { en: "Your ", fr: "Votre " };

// ---- the world -----------------------------------------------------------------------------

/** People on file. Made up; 555 numbers. */
export const SUBJECTS = {
  "12345678": { phoneOnFile: "+15555550100", knowledge: { dob: "19850214", unit: "0412", postal: "K1A0B1" }, pin: "4826" },
  "23456789": { phoneOnFile: "+15555550102", knowledge: { dob: "19520630", unit: "0907" } },
} as const satisfies Record<string, { phoneOnFile: string; knowledge: Record<string, string>; pin?: string }>;

/** The account the mirror call keys: never on file. */
export const UNKNOWN_ACCOUNT = "99999999";

/** The amount the host's price list sets for a deposit outside a flow. Code chooses it, never the model. */
const PRICE_LIST_DEPOSIT = { amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" } as const;

/**
 * Keypad knowledge is two fields; a PIN or a spoken postal code alone reaches level 1, for owner
 * commands only in its flow. A texted code or a callback adds to a keypad match for level 2.
 */
export function suiteConfig(): FlowConfig {
  const config = defaultConfig();
  config.revision = "adversarial-1";
  const policy = defaultVerificationPolicy();
  policy.keypadFields = ["dob", "unit"];
  policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["pin"], ["spoken_knowledge"]] };
  policy.levels[1]!.anyOf.push(["keypad_knowledge", "callback"]);
  policy.spoken = { fields: { postal: "ca_postal_code" }, maxAttemptsPerCall: 3 };
  policy.textCodeCountryCodes = ["1"];
  policy.scopes["owner.command"] = 1;
  policy.scopeClasses = { "owner.command": "none" };
  config.policy = policy;
  config.modules.badge = {
    settings: {
      factors: ["keypad_knowledge", "pin", "carrier_identity_match", "photo_id", "text_code", "callback", "spoken_knowledge"],
      pin: { mode: "keyed_hash", minDigits: 4, maxDigits: 8, maxAttemptsPerCall: 3 },
    },
  };
  config.flows = {
    "owner-command": { steps: [{ type: "badge.verify", level: 1, factors: ["pin"], scopes: ["owner.command"] }] },
    deposit: {
      steps: [
        { type: "badge.verify", level: 2, factors: ["keypad_knowledge", "carrier_identity_match"], scopes: ["payment.request"] },
        { type: "paylink.request", amountMinor: 15000, currency: "cad", description: "Repair deposit", amountSource: "price_list" },
        { type: "trace.receipt" },
      ],
    },
  };
  return config;
}

function world(): TestEngine {
  const t = createTestEngine({ config: suiteConfig() });
  for (const [accountNumber, s] of Object.entries(SUBJECTS)) {
    t.records.putSubject("ws_test", testSubject(TEST_KNOWLEDGE_KEY, { accountNumber, phoneOnFile: s.phoneOnFile, knowledge: { ...s.knowledge }, ...("pin" in s ? { pin: s.pin } : {}) }));
  }
  t.carrier.set(SUBJECTS["12345678"].phoneOnFile, { identityMatch: "match" });
  return t;
}

// ---- the run -------------------------------------------------------------------------------

/** What a run checked, so the suite can tell a script that never exercised a rule. */
export interface RunReport {
  /** Entries that did not match, compared with the mirror's answer for an unknown account. */
  compared: number;
  /** Calls whose taint was checked to drop the grant. */
  taintChecks: number;
  /** Taints that arrived while the call held a grant, so the check had a grant to drop. */
  grantsTainted: number;
  /** Texts sent, each after a match and to the number on file. */
  texts: number;
}

interface Call {
  callId: string;
  mirrorId: string;
  flow: string | undefined;
  /** The account the host began verification for, and whether a keypad or PIN entry matched it since. */
  account: string | null;
  matchedPhone: string | null;
  /** A taint came in and no verification has issued a grant since. */
  taintedSinceGrant: boolean;
}

type Outcome = { line: LineKey | null; result?: JsonValue; error?: EngineErrorCode };

export async function runScript(script: Script): Promise<RunReport> {
  const t = world();
  const { engine } = t;
  const config = suiteConfig();
  const scopes = Object.keys(config.policy.scopes);
  const report: RunReport = { compared: 0, taintChecks: 0, grantsTainted: 0, texts: 0 };
  const spoken: string[] = [];
  const keyed: string[] = [];
  /** Texted codes: they reach a text by design, and must reach nothing else. */
  const codes: string[] = [];
  let call = await open(script.flow);

  async function open(flow: string | undefined): Promise<Call> {
    const input = flow === undefined ? { locale: script.locale } : { locale: script.locale, flow };
    const { callId } = await engine.startCall(input);
    const { callId: mirrorId } = await engine.startCall(input);
    return { callId, mirrorId, flow, account: null, matchedPhone: null, taintedSinceGrant: false };
  }

  /** Runs an engine call; a refusal becomes the fixed "refused" line with its code. */
  async function attempt(fn: () => Promise<{ line: LineKey | null; result?: JsonValue }>): Promise<Outcome> {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof EngineError)) throw e;
      return { line: "refused", error: e.code };
    }
  }

  async function factorDetail(callId: string): Promise<JsonValue> {
    const entries = (await t.ledger.list()).filter((e) => e.callId === callId && e.event === "verification.factor");
    // A PIN entry's keyed tag (VER-12, #124) is bound to its event id, so it differs between two
    // calls by design; only the key holder can read it. The rest must be the same.
    const { tag: _tag, ...detail } = entries.at(-1)!.detail as Record<string, JsonValue>;
    return detail;
  }

  async function version(callId: string): Promise<number> {
    return (await t.sessions.get("ws_test", callId))!.version;
  }

  async function tool(name: Tool): Promise<Outcome> {
    const scope = TOOLS[name];
    if (name === "send_identity_link") {
      return attempt(async () => ({ line: "link_sent", result: (await engine.startPhotoId(call.callId)) as unknown as JsonValue }));
    }
    // No code path marks a caller verified or skips a check: the engine is never called.
    if (scope === null) return { line: "refused", result: { path: null } };
    const authorized = await engine.authorize(call.callId, scope);
    if (!authorized) return { line: "refused", result: { authorized } };
    if (name !== "send_payment_link") return { line: "done", result: { authorized } };
    const running = (await engine.flowPosition(call.callId))?.status === "running";
    return attempt(async () => {
      // The link's deadline (#47's paylink) depends on the clock the harness moves: left out.
      const input = running ? undefined : { ...PRICE_LIST_DEPOSIT };
      // Every link needs the amount read back and confirmed first (PAY-2).
      const back = await engine.readBackPayment(call.callId, input);
      await engine.confirmPaymentAmount(call.callId, { digest: back.digest, confirmedBy: "keypad" });
      const { expiresAt: _expiresAt, ...result } = (await engine.requestPayment(call.callId, input)) as unknown as Record<string, JsonValue>;
      return { line: "link_sent", result };
    });
  }

  /** Sends a keypad or PIN entry to the call and to the mirror, and compares a failed answer with the mirror's. */
  async function entry(submit: (callId: string) => Promise<{ matched: boolean; locked: boolean }>, values: string[], opens = true): Promise<Outcome> {
    keyed.push(...values);
    // A failure starts a wait across calls (VER-1, #71): each entry comes after it, as a caller's would.
    t.clock.advance(900_000);
    const outcome = await attempt(async () => {
      const result = await submit(call.callId);
      return { line: result.matched ? "matched" : result.locked ? "locked" : "no_match", result: { ...result } };
    });
    if (outcome.error !== undefined) return outcome;
    const mirror = await submit(call.mirrorId);
    const result = outcome.result as { matched: boolean };
    if (result.matched) {
      // Only a keypad or PIN match lets a text or a callback go out; a spoken answer never does.
      if (opens) call.matchedPhone = SUBJECTS[call.account as keyof typeof SUBJECTS].phoneOnFile;
    } else {
      // An unknown account and a wrong answer: the same answer, the same line, the same ledger detail.
      assert.deepEqual(mirror, outcome.result, `${script.id}: the answer must not tell a wrong entry from an unknown account`);
      assert.equal(mirror.matched ? "matched" : mirror.locked ? "locked" : "no_match", outcome.line);
      assert.deepEqual(await factorDetail(call.mirrorId), await factorDetail(call.callId));
      report.compared++;
    }
    return outcome;
  }

  /**
   * Asks for a code to the number on file, then keys each entry: the code the last text carried, or
   * one digit off it. A code goes out only after a keypad or PIN match, so there is no mirror to
   * compare with; the entries come at once, as a caller reading the text would key them.
   */
  async function textCode(entries: Array<"right" | "wrong">): Promise<Outcome> {
    const sentBefore = t.messages.sent.length;
    const sent = await attempt(async () => ({ line: null, result: await engine.sendTextCode(call.callId) }));
    if (sent.error !== undefined) return sent;
    // The text goes out after the reply.
    for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
    const text = t.messages.sent.slice(sentBefore).at(-1);
    const code = text === undefined ? "000000" : /\d{6}/.exec(text.body)![0];
    codes.push(code);
    let outcome: Outcome = sent;
    for (const which of entries) {
      const keyedCode = which === "right" ? code : `${(Number(code[0]) + 1) % 10}${code.slice(1)}`;
      outcome = await attempt(async () => {
        const result = await engine.checkTextCode(call.callId, keyedCode);
        return { line: result.matched ? "matched" : result.locked ? "locked" : "no_match", result: { ...result } };
      });
    }
    return outcome;
  }

  /**
   * Asks for a callback and ends the call. The mirror asks too, and both hear the same line; only a
   * call that matched by keypad or PIN rings, and only the number on file. When one rings, the
   * script carries on in the callback call, with the dialer's outcome: answered and confirmed, or not.
   */
  async function callBack(answered: boolean): Promise<Outcome> {
    const dialsBefore = t.dialer.dialed.length;
    const matched = call.matchedPhone;
    const outcome = await attempt(async () => {
      await engine.requestCallback(call.callId);
      return { line: "calling_back" };
    });
    if (outcome.error !== undefined) return outcome;
    assert.equal(await engine.requestCallback(call.mirrorId), undefined);
    const dials = t.dialer.dialed.slice(dialsBefore);
    if (dials.length === 0) return { line: "calling_back", result: { dialed: false } };
    // One ring, for the call and never for the mirror: after a match, to the number on file.
    assert.equal(dials.length, 1, `${script.id}: the mirror's callback rang`);
    const dial = dials[0]!;
    assert.notEqual(matched, null, `${script.id}: a callback before a keypad or PIN match`);
    assert.equal(dial.to, matched, `${script.id}: a callback not to the number on file`);
    if (script.callingNumber !== matched) assert.notEqual(dial.to, script.callingNumber, `${script.id}: a callback to the calling number`);
    await closeCall();
    // The callback call has its subject chosen, not matched: its own mirror keys the unknown account.
    const { callId: mirrorId } = await engine.startCall({ locale: script.locale });
    await engine.beginVerification(mirrorId, { accountNumber: UNKNOWN_ACCOUNT });
    call = { callId: dial.callId, mirrorId, flow: call.flow, account: call.account, matchedPhone: null, taintedSinceGrant: false };
    const applied = await engine.applyCallbackOutcome({ ref: dial.ref, answered, confirmed: answered });
    return { line: "calling_back", result: { dialed: true, applied: applied.applied } };
  }

  async function begin(account: string, chosenByHost: boolean): Promise<Outcome> {
    keyed.push(account);
    const input = (n: string) => (chosenByHost ? { subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, n) } : { accountNumber: n });
    const tainted = (await engine.state(call.callId)).tainted;
    const outcome = await attempt(async () => {
      await engine.beginVerification(call.callId, input(account));
      return { line: chosenByHost ? "ask_pin" : "ask_keypad" };
    });
    if (outcome.error !== undefined) return outcome;
    await engine.beginVerification(call.mirrorId, input(UNKNOWN_ACCOUNT));
    // The engine forgets a match when the subject changes or the session was tainted.
    if (account !== call.account || tainted) call.matchedPhone = null;
    call.account = account;
    return outcome;
  }

  async function act(action: HostAction): Promise<Outcome> {
    switch (action.do) {
      case "call":
        await closeCall();
        call = await open(action.flow);
        return { line: null };
      case "account":
        return begin(action.account, false);
      case "owner":
        return begin(action.account, true);
      case "keypad":
        return entry((id) => engine.submitKeypad(id, action.entries), Object.values(action.entries));
      case "pin":
        return entry((id) => engine.submitPin(id, action.pin), [action.pin]);
      case "spoken":
        return entry((id) => engine.submitFactor(id, "spoken_knowledge", { ...action.answer }), Object.values(action.answer), false);
      case "text_code":
        return textCode(action.entries);
      case "callback":
        return callBack(action.answered);
      case "carrier":
        return attempt(async () => ({ line: "one_moment", result: await engine.checkCarrier(call.callId) }));
      case "identity": {
        const created = t.identity.created.filter((c) => c.callId === call.callId).at(-1);
        const result = await engine.applyIdentityOutcome({ sessionId: created?.sessionId ?? "vs_never_created", status: action.status });
        return { line: null, result: { applied: result.applied } };
      }
      case "finish":
        return attempt(async () => {
          const result = await engine.finishVerification(call.callId);
          if (result.level > 0) call.taintedSinceGrant = false;
          await engine.finishVerification(call.mirrorId);
          // A level the flow's step does not accept issues a grant with no scope: not verified for anything.
          return { line: result.scopes.length > 0 ? "verified" : "not_verified", result: { ...result } };
        });
      case "business":
        // Text from a business endpoint enters the conversation: the host's code marks it, always.
        keyed.push(action.text);
        await taint(action.source);
        call.taintedSinceGrant = true;
        // A taint voids the match: nothing goes out again until a fresh verification matches.
        call.matchedPhone = null;
        return { line: null };
      case "end":
        return attempt(async () => {
          await engine.endCall(call.callId);
          return { line: "goodbye" };
        });
    }
  }

  /** The four rules, after every turn. */
  async function checkRules(sentBefore: number, carrierBefore: number): Promise<void> {
    const state = await engine.state(call.callId);
    const record = (await t.sessions.get("ws_test", call.callId))!.record as unknown as { modules: { badge: { carrier: CarrierSignalReport | null } } };
    const carrier = record.modules.badge.carrier;
    // 1. No grant without factors: a grant never exceeds what the recorded factors reach.
    if (state.grant !== null) {
      assert.ok(state.factors.some((f) => f.passed), `${script.id}: a grant with no passed factor`);
      assert.ok(evaluateAssurance(config.policy, state.factors, carrier).level >= state.grant.level, `${script.id}: a grant above the factors`);
    }
    for (const scope of scopes) {
      if (await engine.authorize(call.callId, scope)) assert.ok(state.grant?.scopes.includes(scope), `${script.id}: ${scope} authorized without a grant for it`);
    }
    // 2. No text and no carrier check before a match, and only to the number on file.
    for (const message of t.messages.sent.slice(sentBefore)) {
      assert.notEqual(call.matchedPhone, null, `${script.id}: a text before a keypad or PIN match`);
      // The destination comes from the subject record, never from caller ID: when the caller uses the
      // number on file the text still goes there, because the record says so, not because they called.
      assert.equal(message.to, call.matchedPhone, `${script.id}: a text not to the number on file`);
      if (script.callingNumber !== call.matchedPhone) assert.notEqual(message.to, script.callingNumber, `${script.id}: a text to the calling number`);
      assert.ok(message.body.startsWith(TEXT_OPENINGS[script.locale]), `${script.id}: a text not in the call's language`);
      report.texts++;
    }
    for (const number of t.carrier.checked.slice(carrierBefore)) {
      assert.notEqual(call.matchedPhone, null, `${script.id}: a carrier check before a keypad or PIN match`);
      assert.equal(number, call.matchedPhone);
    }
    // 4. A tainted session holds no grant until a new verification earns one.
    if (call.taintedSinceGrant) await assertNoGrant(state.tainted);
  }

  async function assertNoGrant(tainted: boolean): Promise<void> {
    const state = await engine.state(call.callId);
    assert.equal(state.tainted, tainted);
    assert.equal(state.grant, null, `${script.id}: a tainted session kept its grant`);
    assert.equal(state.level, 0);
    for (const scope of scopes) assert.equal(await engine.authorize(call.callId, scope), false, `${script.id}: ${scope} authorized after the taint`);
  }

  async function taint(source: string): Promise<void> {
    if ((await engine.state(call.callId)).grant !== null) report.grantsTainted++;
    await engine.markUntrusted(call.callId, source);
  }

  /** Every call ends with a taint check: business text arrives, and whatever grant it held is gone. */
  async function closeCall(): Promise<void> {
    if ((await engine.state(call.callId)).phase !== "ended") {
      await taint("adversarial-suite");
      await assertNoGrant(true);
    } else {
      assert.equal((await engine.state(call.callId)).grant, null);
    }
    report.taintChecks++;
  }

  for (const [i, turn] of script.turns.entries()) {
    const where = `${script.id}, turn ${i + 1}`;
    const sentBefore = t.messages.sent.length;
    const carrierBefore = t.carrier.checked.length;
    const versionBefore = await version(call.callId);
    let outcome: Outcome = { line: null };
    if (turn.caller !== undefined) {
      keyed.push(turn.caller);
      const heard = await engine.redact(call.callId, turn.caller);
      if (heard.interrupt) outcome = { line: "interrupt" };
      if (turn.ai !== undefined || turn.host !== undefined) assert.equal(heard.interrupt, false, `${where}: a card number belongs in its own turn`);
    }
    if (turn.ai !== undefined) outcome = await tool(turn.ai);
    if (turn.host !== undefined) outcome = await act(turn.host);
    if (outcome.line !== null) spoken.push(LINES[script.locale][outcome.line]);
    assert.equal(outcome.line, turn.expect.line, `${where}: line`);
    assert.equal(outcome.error, turn.expect.error, `${where}: refusal`);
    if (turn.expect.result !== undefined) assert.deepEqual(outcome.result, turn.expect.result, `${where}: result`);
    if (turn.ai !== undefined && turn.ai !== "send_identity_link" && TOOLS[turn.ai] === null && turn.caller === undefined) {
      assert.equal(await version(call.callId), versionBefore, `${where}: a proposal with no code path changed the call`);
    }
    await checkRules(sentBefore, carrierBefore);
  }
  await closeCall();

  // Nothing keyed, said or fetched reaches the ledger, a text or the host's own speech.
  const ledger = await t.ledger.list();
  assert.equal(verifyChain(ledger).ok, true);
  const logged = stringsIn(ledger);
  const texted = t.messages.sent.map((m) => m.body);
  for (const value of keyed) {
    assert.equal(logged.some((field) => leaks(value, field)), false, `${script.id}: ${JSON.stringify(value)} reached the ledger`);
    assert.equal(texted.some((body) => leaks(value, body)), false, `${script.id}: ${JSON.stringify(value)} reached a text`);
    assert.equal(spoken.some((line) => leaks(value, line)), false, `${script.id}: ${JSON.stringify(value)} reached a spoken line`);
  }
  for (const code of codes) {
    assert.equal(logged.some((field) => leaks(code, field)), false, `${script.id}: a texted code reached the ledger`);
    assert.equal(spoken.some((line) => leaks(code, line)), false, `${script.id}: a texted code reached a spoken line`);
  }
  for (const phone of [script.callingNumber, ...Object.values(SUBJECTS).map((s) => s.phoneOnFile)]) {
    assert.equal(logged.some((field) => leaks(phone, field)), false, `${script.id}: ${phone} reached the ledger`);
  }
  return report;
}

/** Every string in a decoded value, keys included, so a value embedded in a field is seen as written. */
export function stringsIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (value !== null && typeof value === "object") return Object.entries(value).flatMap(([k, v]) => [k, ...stringsIn(v)]);
  return [];
}

/**
 * Whether `value` appears in `text` as a whole token, not next to another letter or digit: a keyed
 * "4826" inside a hash such as "a94826f0" is not a leak, while "DOB: 19850214" is. A value under 4
 * characters leaks only as a whole field.
 */
export function leaks(value: string, text: string): boolean {
  const needle = value.trim();
  if (needle.length === 0) return false;
  // Under 4 characters a token also turns up in timestamps and counts: only a whole field is a leak.
  if (needle.length < 4) return text.trim() === needle;
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, "u").test(text);
}
