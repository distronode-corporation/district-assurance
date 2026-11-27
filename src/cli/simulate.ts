#!/usr/bin/env node

// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The flow simulator (MOD-4): `district-assurance simulate <config.json> --flow <name> --script <name or file>`
// runs one flow of a workspace's FlowConfig against a scripted caller, on the in-memory adapters,
// and prints each step, each decision, every event and the final receipt. A business sees what a
// flow does before a real caller meets it.
//
// It never needs a network or a key: the engine is `createTestEngine`'s, with the fixed clock,
// sequential ids, the fakes and a throwaway signing key. The caller is made up (a 555 number, an
// account, answers and a PIN chosen here), and nothing it keys is printed: events carry no values,
// and decisions say "right" or "wrong", never the digits. Only the built-in modules run: a config
// that turns on an outside module is refused, because its code is not here to run.
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { canonicalJson } from "../core/canonical.ts";
import { validateConfig, type FlowConfig } from "../core/config.ts";
import type { EngineEvent } from "../core/events.ts";
import type { FlowStep } from "../core/module.ts";
import type { SpokenFormat } from "../core/policy.ts";
import { isObject, unknownKeys } from "../core/shape.ts";
import type { IntakeField, IntakeForm } from "../file/intake.ts";
import type { StepUpSettings } from "../gate/step-up.ts";
import { BUILT_IN_MODULES } from "../modules.ts";
import type { PaymentOutcome } from "../pay/payment.ts";
import { verifyReceipt } from "../prove/receipt.ts";
import { FakeAccessController, TEST_KNOWLEDGE_KEY, createTestEngine, testSubject, type TestEngine } from "../testing/index.ts";
import type { BadgeSettings } from "../verify/factors.ts";
import { lockState, lockoutOf } from "../verify/counters.ts";
import { subjectKeyFor } from "../verify/knowledge.ts";

/** How the scripted caller behaves at each kind of step. A script file is a JSON object with any of these fields. */
export interface CallerScript {
  summary: string;
  /** Wrong keypad answers keyed before the right ones (0 to 5); the caller stops once locked out. */
  wrongKeypad: number;
  /** Wrong PINs keyed before the right one (0 to 5); the caller stops once locked out. */
  wrongPins: number;
  /** What the carrier reports about the number on file. */
  carrier: "match" | "no_match" | "unavailable";
  /** What the identity provider reports for the photo ID check. */
  photoId: "verified" | "requires_input" | "canceled";
  /** The caller's answer to every consent question. */
  consent: "yes" | "no";
  /** What the payment provider reports: paid at once, paid later (completed unpaid, then succeeded), failed or expired. */
  payment: "paid" | "paid_later" | "failed" | "expired";
  /** The texted code the caller keys: the one texted, or a wrong one. */
  textCode: "right" | "wrong";
  /** How speech-to-text hears the caller's spoken answers: right, or as another value. */
  spoken: "right" | "wrong";
  /** Whoever answers the callback on the number on file keys the confirmation, or does not. */
  callback: "confirmed" | "not_confirmed";
  /** What the door's controller does with an access grant: opens the door, or refuses it. */
  door: "opens" | "refuses";
}

const PASS: CallerScript = {
  summary: "the caller keys every answer right, the carrier matches, the photo ID is verified, the caller consents and pays",
  wrongKeypad: 0,
  wrongPins: 0,
  carrier: "match",
  photoId: "verified",
  consent: "yes",
  payment: "paid",
  textCode: "right",
  spoken: "right",
  callback: "confirmed",
  door: "opens",
};

/** The built-in scripts, by name. */
export const BUILT_IN_SCRIPTS: Readonly<Record<string, CallerScript>> = {
  pass: PASS,
  "wrong-pin": { ...PASS, summary: "one wrong PIN (and one wrong keypad answer), then the right ones", wrongKeypad: 1, wrongPins: 1 },
  lockout: { ...PASS, summary: "wrong PINs and keypad answers until the line stops judging them", wrongKeypad: 5, wrongPins: 5 },
  "consent-no": { ...PASS, summary: "as pass, but the caller answers no to consent", consent: "no" },
  "payment-paid": { ...PASS, summary: "as pass, but the payment completes unpaid (a bank debit) and the provider reports it paid later", payment: "paid_later" },
  "payment-expired": { ...PASS, summary: "as pass, but the payment link expires unpaid", payment: "expired" },
  "text-code-wrong": { ...PASS, summary: "as pass, but the caller keys a wrong texted code", textCode: "wrong" },
  "spoken-wrong": { ...PASS, summary: "as pass, but speech-to-text hears the spoken answers as another value", spoken: "wrong" },
  "callback-not-confirmed": { ...PASS, summary: "as pass, but whoever answers the callback does not key the confirmation", callback: "not_confirmed" },
  "door-refused": { ...PASS, summary: "as pass, but the door's controller refuses the unlock", door: "refuses" },
};

const CHOICES: Readonly<Record<string, readonly string[]>> = {
  carrier: ["match", "no_match", "unavailable"],
  photoId: ["verified", "requires_input", "canceled"],
  consent: ["yes", "no"],
  payment: ["paid", "paid_later", "failed", "expired"],
  textCode: ["right", "wrong"],
  spoken: ["right", "wrong"],
  callback: ["confirmed", "not_confirmed"],
  door: ["opens", "refuses"],
};

/** A script from a file: every problem, or the script with `pass` filling the fields it leaves out. */
export function parseCallerScript(value: unknown): { script: CallerScript; problems: [] } | { script: null; problems: string[] } {
  if (!isObject(value)) return { script: null, problems: ["a script must be a JSON object"] };
  const problems = unknownKeys(value, Object.keys(PASS)).map((key) => `${key}: not a script field`);
  if (value.summary !== undefined && typeof value.summary !== "string") problems.push("summary: must be a string");
  for (const key of ["wrongKeypad", "wrongPins"]) {
    const n = value[key];
    if (n !== undefined && !(Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 5)) problems.push(`${key}: must be an integer from 0 to 5`);
  }
  for (const [key, allowed] of Object.entries(CHOICES)) {
    if (value[key] !== undefined && !allowed.includes(value[key] as string)) problems.push(`${key}: must be one of ${allowed.join(", ")}`);
  }
  if (problems.length > 0) return { script: null, problems };
  return { script: { ...PASS, summary: "a script from a file", ...(value as Partial<CallerScript>) }, problems: [] };
}

/**
 * The config the simulator runs, or every reason it refuses it: each outside module the config
 * turns on (the simulator runs the built-in modules only), then every problem `validateConfig`
 * finds with outside modules left out. An outside module the config switches off is left out.
 */
export function simulationConfig(config: unknown, t: TestEngine): { config: FlowConfig; problems: [] } | { config: null; problems: string[] } {
  const problems: string[] = [];
  let builtIn = config;
  if (isObject(config) && isObject(config.modules)) {
    const modules: Record<string, unknown> = {};
    for (const [name, entry] of Object.entries(config.modules)) {
      if ((BUILT_IN_MODULES as readonly string[]).includes(name)) modules[name] = entry;
      else if (!isObject(entry) || entry.enabled !== false) {
        problems.push(`modules.${name}: ${name} is an outside module; the simulator runs the built-in modules only (${BUILT_IN_MODULES.join(", ")})`);
      }
    }
    builtIn = { ...config, modules };
  }
  problems.push(...validateConfig(builtIn, t.engine.registry));
  return problems.length === 0 ? { config: builtIn as FlowConfig, problems: [] } : { config: null, problems };
}

// The made-up caller. Not real values: a 555 number, and answers that are printed nowhere.
const ACCOUNT = "12345678";
const PHONE_ON_FILE = "+15555550100";
const ANSWER = "19850214";
const WRONG_ANSWER = "00000000";
const PIN_DIGITS = "482601357913";
/** The digits the caller keys for a web sign-in (step-up's nonce): printed nowhere either. */
const NONCE = "730146";
/** Every built-in factor, in the order the scripted caller answers them. */
const FACTOR_ORDER = ["keypad_knowledge", "pin", "spoken_knowledge", "carrier_identity_match", "text_code", "photo_id", "callback"];
/** For each spoken format: the value on file, what the caller says, and what a wrong hearing makes of it. */
const SPOKEN: Readonly<Record<SpokenFormat, { value: string; right: string; wrong: string }>> = {
  ca_postal_code: { value: "K1A0B1", right: "kay one ay zero bee one", wrong: "kay one ay zero bee two" },
  us_zip_code: { value: "90210", right: "nine zero two one zero", wrong: "nine zero two one one" },
  reference: { value: "AB12CD", right: "alpha bravo one two charlie delta", wrong: "alpha bravo one two charlie echo" },
};
const SAMPLE_VALUES: Readonly<Record<string, string>> = { text: "A simulated answer", number: "1", date: "2026-01-01", yes_no: "yes" };
/** A sample answer the field accepts: a text answer is cut to the field's `maxLength` (at least one character). */
function sampleValue(field: IntakeField): string {
  const sample = SAMPLE_VALUES[field.type]!;
  return field.type === "text" ? sample.slice(0, Math.max(1, field.maxLength ?? sample.length)) : sample;
}
const OUTCOMES: Readonly<Record<CallerScript["payment"], ReadonlyArray<(linkId: string) => PaymentOutcome>>> = {
  paid: [(linkId) => ({ kind: "completed", linkId, paymentStatus: "paid" })],
  paid_later: [(linkId) => ({ kind: "completed", linkId, paymentStatus: "unpaid" }), (linkId) => ({ kind: "async_succeeded", linkId })],
  failed: [(linkId) => ({ kind: "async_failed", linkId })],
  expired: [(linkId) => ({ kind: "expired", linkId })],
};

interface Run {
  t: TestEngine;
  config: FlowConfig;
  script: CallerScript;
  /** The call the caller is on: after a callback, the callback call. */
  callId: string;
  pin: string;
  line(text: string): void;
}

/** Prints what the caller does, then the engine's events (the listener prints them), then the decision, or the refusal. */
async function act(run: Run, doing: string, fn: () => Promise<string>): Promise<void> {
  run.line(`  caller: ${doing}`);
  try {
    run.line(`  decision: ${await fn()}`);
  } catch (e) {
    run.line(`  refused: ${(e as Error).message}`);
  }
}

/** Keys wrong entries, then the right one, and stops once the line no longer judges them. */
async function keyEntries(run: Run, what: string, wrong: number, submit: (right: boolean) => Promise<{ matched: boolean; locked: boolean }>): Promise<void> {
  let locked = false;
  const key = (right: boolean) =>
    act(run, `keys ${what} (${right ? "right" : "wrong"})`, async () => {
      const result = await submit(right);
      locked = result.locked;
      return result.matched ? `${what} matched` : result.locked ? `no match, locked: no more ${what} attempts on this call` : "no match";
    });
  // A wrong entry starts a wait across calls (VER-1): the simulated caller keys again after it.
  // The wait is the engine's own (counters.ts, lockState) for the failures still inside the window
  // when the caller keys again, so a longer backoff is waited out too, and a wait that moves an old
  // failure out of the window is recomputed for the ones left. Nothing is cleared, and a hard lock
  // still stops the caller. Only badge.verify keys entries, and its config has the badge module on.
  const lockout = lockoutOf((run.config.modules.badge!.settings as unknown as BadgeSettings).lockout);
  const failures: string[] = [];
  const waitOut = () => {
    for (;;) {
      const now = run.t.clock.now();
      // The window counters.ts reads: a failure exactly one window old has left it.
      const since = now.getTime() - lockout.windowHours * 3_600_000 + 1;
      const state = lockState(lockout, failures.filter((at) => Date.parse(at) >= since), now);
      if (state === null || state.hard) return;
      run.t.clock.advance(Date.parse(state.until) - now.getTime());
    }
  };
  for (let i = 0; i < wrong && !locked; i++) {
    failures.push(run.t.clock.now().toISOString());
    await key(false);
    waitOut();
  }
  if (!locked) await key(true);
}

/**
 * The factors the caller enters, with the transcript paused: the keypad answers, the PIN and the
 * spoken answers, as the script says. On a callback call they are entered again the same way.
 */
async function enterFactors(run: Run, factors: readonly string[]): Promise<void> {
  const { engine } = run.t;
  await act(run, "starts keying", async () => {
    await engine.openSensitive(run.callId, "keypad");
    return "transcript paused for the keypad";
  });
  if (factors.includes("keypad_knowledge")) {
    await keyEntries(run, "keypad answers", run.script.wrongKeypad, (right) => {
      const value = right ? ANSWER : WRONG_ANSWER;
      return engine.submitKeypad(run.callId, Object.fromEntries(run.config.policy.keypadFields.map((field) => [field, value])));
    });
  }
  if (factors.includes("pin")) {
    await keyEntries(run, "PIN", run.script.wrongPins, (right) => engine.submitPin(run.callId, right ? run.pin : "0".repeat(run.pin.length)));
  }
  if (factors.includes("spoken_knowledge")) {
    const fields = Object.entries(run.config.policy.spoken!.fields);
    const heard = run.script.spoken;
    await act(run, `says ${fields.map(([field]) => field).join(", ")} (heard ${heard})`, async () => {
      const result = await engine.submitFactor(run.callId, "spoken_knowledge", Object.fromEntries(fields.map(([field, format]) => [field, SPOKEN[format][heard]])));
      return result.matched ? "spoken answers matched" : result.locked ? "no match, locked: no more spoken attempts on this call" : "no match";
    });
  }
  await act(run, "finishes keying", async () => {
    await engine.closeSensitive(run.callId);
    return "transcript resumed";
  });
}

/** Asks for a code by text and keys it, right or wrong. The code is read from the fake sender, never printed. */
async function textCode(run: Run): Promise<void> {
  const { engine, messages } = run.t;
  const before = messages.sent.length;
  await act(run, "asks for a code by text", async () => {
    await engine.sendTextCode(run.callId);
    // The text goes out after the engine answers: let it.
    for (let i = 0; i < 10; i++) await new Promise((resolve) => setImmediate(resolve));
    return messages.sent.length > before ? "code texted to the number on file" : "no text came";
  });
  const right = run.script.textCode === "right";
  await act(run, `keys the texted code (${run.script.textCode})`, async () => {
    // Read inside the act: a text without a code is printed as a refusal, never a crash.
    const texted = messages.sent.length > before ? /\d{6}/.exec(messages.sent.at(-1)!.body)![0] : "000000";
    const code = right ? texted : `${(Number(texted[0]) + 1) % 10}${texted.slice(1)}`;
    const result = await engine.checkTextCode(run.callId, code);
    // One try per code here, so never the fifth that spends it.
    return result.matched ? "texted code matched" : "no match";
  });
}

const STEP_ACTIONS: Readonly<Record<string, (run: Run, step: FlowStep) => Promise<void>>> = {
  async "badge.verify"(run, step) {
    const { engine } = run.t;
    const factors = FACTOR_ORDER.filter((kind) => (step.factors as string[]).includes(kind));
    await act(run, "keys the account number", async () => {
      await engine.beginVerification(run.callId, { accountNumber: ACCOUNT });
      return "verification started";
    });
    await enterFactors(run, factors);
    if (factors.includes("callback")) {
      // The callback ends this call, which earns nothing from it, and the engine calls the number
      // on file: the caller goes on there, keying the entered factors again.
      let placed: { callId: string; ref: string } | null = null;
      await act(run, "asks to be called back on the number on file", async () => {
        const before = run.t.dialer.dialed.length;
        await engine.requestCallback(run.callId);
        placed = run.t.dialer.dialed.length > before ? run.t.dialer.dialed.at(-1)! : null;
        const level = (await engine.state(run.callId)).level;
        return placed === null ? `this call ended at level ${level}; no callback was placed` : `this call ended at level ${level}; callback call ${placed.callId} placed`;
      });
      if (placed === null) return;
      const { callId, ref } = placed;
      const confirmed = run.script.callback === "confirmed";
      await act(run, confirmed ? "answers the callback and keys the confirmation" : "answers the callback and does not key the confirmation", async () => {
        const outcome = await engine.applyCallbackOutcome({ ref, answered: true, confirmed });
        return `callback outcome applied: ${outcome.applied}`;
      });
      run.callId = callId;
      run.line(`call: the callback call ${callId}`);
      await enterFactors(run, factors);
    }
    if (factors.includes("carrier_identity_match")) {
      await act(run, `stays on the line while the carrier is asked (it reports ${run.script.carrier})`, async () => {
        const { textCodeTrusted } = await engine.checkCarrier(run.callId);
        return `carrier checked, texted code trusted: ${textCodeTrusted}`;
      });
    }
    if (factors.includes("text_code")) await textCode(run);
    if (factors.includes("photo_id")) {
      await act(run, `opens the texted link (the provider reports ${run.script.photoId})`, async () => {
        await engine.startPhotoId(run.callId);
        const outcome = await engine.applyIdentityOutcome({ sessionId: run.t.identity.created.at(-1)!.sessionId, status: run.script.photoId });
        return `link texted to the number on file, outcome applied: ${outcome.applied}`;
      });
    }
    await act(run, "waits for the result", async () => {
      const result = await engine.finishVerification(run.callId);
      return `level ${result.level}, scopes: ${result.scopes.join(", ") || "none"}`;
    });
  },

  async "dossier.collect"(run, step) {
    const { engine } = run.t;
    const forms = (run.config.modules.dossier!.settings as unknown as { forms: IntakeForm[] }).forms;
    const form = forms.find((f) => f.formId === step.form)!;
    await act(run, `starts the ${form.formId} form`, async () => {
      await engine.startIntake(run.callId, form.formId);
      return `form ${form.formId} version ${form.version} open`;
    });
    for (const field of form.fields) {
      await act(run, `answers ${field.key} (${field.type})`, async () => {
        const result = await engine.setIntakeField(run.callId, field.key, sampleValue(field));
        return `normalised: ${canonicalJson(result)}`;
      });
    }
    await act(run, "confirms the read-back", async () => {
      // The caller confirms the read-back they heard (FIL-1): its digest goes with the confirmation.
      const { digest } = await engine.intakeReadBack(run.callId);
      const record = await engine.confirmIntake(run.callId, { confirmedBy: "keypad", readBack: digest });
      return `record ${record.recordId} filed, digest ${record.digest}`;
    });
  },

  async "paylink.request"(run) {
    const { engine, payments } = run.t;
    let linkId = "";
    await act(run, "hears the amount and says yes", async () => {
      // Every link waits for the caller to confirm the amount read back (PAY-2).
      const back = await engine.readBackPayment(run.callId);
      await engine.confirmPaymentAmount(run.callId, { digest: back.digest, confirmedBy: "keypad" });
      return back.text;
    });
    await act(run, "asks to pay", async () => {
      const payment = await engine.requestPayment(run.callId);
      const link = payments.created.find((l) => l.paymentId === payment.paymentId)!;
      linkId = link.linkId;
      return `${payment.paymentId} for ${link.amountMinor} ${link.currency} (minor units), link texted to the number on file, status ${payment.status}`;
    });
    for (const make of OUTCOMES[run.script.payment]) {
      const { linkId: _, ...reported } = make(linkId);
      await act(run, `uses the link; the provider reports ${canonicalJson(reported)}`, async () => {
        const result = await engine.applyPaymentOutcome(make(linkId));
        return result.applied ? `settled ${result.status}` : "nothing settled yet";
      });
    }
  },

  async "gate.grant"(run, step) {
    run.t.door.mode = run.script.door === "opens" ? "confirm" : "refuse";
    await act(run, `waits at ${String(step.target)} (the controller ${run.script.door})`, async () => {
      const access = await run.t.engine.grantAccess(run.callId);
      return `access grant ${access.grantId} ${access.status}, the door moved: ${access.confirmed}`;
    });
  },

  async "step-up.issue"(run, step) {
    const { engine } = run.t;
    const settings = run.config.modules["step-up"]!.settings as unknown as StepUpSettings;
    const audience = settings.sites.find((site) => site.id === step.site)!.audience;
    // The website (the token's audience) exchanges it at once, as a sign-in page waiting for it would.
    await act(run, `keys the sign-in code the website (${audience}) shows`, async () => {
      const issued = await engine.issueStepUpToken(run.callId, { nonce: NONCE });
      const exchange = await engine.exchangeStepUpToken(issued.token, { audience, subjectKey: subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT), nonce: NONCE });
      return `step-up token ${issued.tokenId} issued, expires ${issued.expiresAt}; the website exchanged it: ${exchange.ok}`;
    });
  },

  async "trace.consent"(run, step) {
    await act(run, `answers ${run.script.consent} to ${String(step.purpose)}`, async () => {
      const consent = await run.t.engine.recordConsent(run.callId, { purpose: step.purpose as string, answer: run.script.consent });
      return `${consent.consentId} recorded, wording version ${consent.wordingVersion}`;
    });
  },
};

/** Why the simulator cannot run a step, or null: a step type without a caller, or a badge.verify factor outside FACTOR_ORDER. */
function unsupportedStep(step: FlowStep): string | null {
  if (!Object.hasOwn(STEP_ACTIONS, step.type)) return `step ${step.type} is not simulated`;
  if (step.type !== "badge.verify") return null;
  const factor = (step.factors as string[]).find((kind) => !FACTOR_ORDER.includes(kind));
  return factor === undefined ? null : `step badge.verify factor ${factor} is not simulated`;
}

/** The outcome of a simulation: the lines it printed and the flow's final status. */
export interface Simulation {
  lines: string[];
  status: string;
  /** 0 when every step ran; 3 when the run stopped at a step the simulator has no caller for. */
  exitCode: 0 | 3;
}

/**
 * Runs one flow of a config from `simulationConfig` with a scripted caller, on the engine of `t`
 * (from `simulationEngine`). Every engine refusal is printed and the caller goes
 * on; the call ends after the last step, abandoning a flow that is still running.
 */
export async function simulate(t: TestEngine, lines: string[], config: FlowConfig, flow: string, scriptName: string, script: CallerScript): Promise<Simulation> {
  const line = (text: string) => lines.push(text);
  const badge = config.modules.badge?.settings as BadgeSettings | undefined;
  const pin = PIN_DIGITS.slice(0, badge?.pin?.minDigits ?? 4);
  const knowledge = Object.fromEntries([
    ...config.policy.keypadFields.map((f) => [f, ANSWER]),
    ...Object.entries(config.policy.spoken?.fields ?? {}).map(([f, format]) => [f, SPOKEN[format].value]),
  ]);
  const subject = testSubject(TEST_KNOWLEDGE_KEY, { accountNumber: ACCOUNT, phoneOnFile: PHONE_ON_FILE, knowledge, pin });
  t.records.putSubject(t.engine.workspaceId, subject);
  t.pinVerifier.set(t.engine.workspaceId, subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT), pin);
  t.carrier.set(PHONE_ON_FILE, { identityMatch: script.carrier });
  t.engine.configure(config);

  const steps = config.flows[flow]!.steps;
  line(`simulate: flow ${flow}, steps: ${steps.length}, config revision ${config.revision}`);
  line(`script: ${scriptName}: ${script.summary}`);
  line("call: started");
  const { callId } = await t.engine.startCall({ flow });
  const run: Run = { t, config, script, callId, pin, line };
  let position = (await t.engine.flowPosition(run.callId))!;
  // Each turn either moves the flow on or ends it, so the flow's length bounds the turns.
  let exitCode: 0 | 3 = 0;
  for (let turn = 0; turn < steps.length && position.status === "running"; turn++) {
    const step = position.step!;
    const { type, ...fields } = step;
    line(`step ${position.index + 1}/${steps.length}: ${type} ${canonicalJson(fields)}`);
    // A step type another module adds, or a factor the scripted caller cannot answer, has no
    // caller here: the run stops, it never guesses or skips part of the step.
    const unsupported = unsupportedStep(step);
    if (unsupported !== null) {
      line(terminalSafe(unsupported));
      exitCode = 3;
      break;
    }
    await STEP_ACTIONS[type]!(run, step);
    position = (await t.engine.flowPosition(run.callId))!;
  }
  line("call: ending");
  // A callback request ends the call it was made on; one that placed no callback leaves the caller there.
  const ended = (await t.engine.state(run.callId)).phase === "ended";
  const receipt = ended ? await t.engine.receipt(run.callId) : await t.engine.endCall(run.callId);
  // Ending the call abandons a flow that is still running; completed and failed flows keep their status.
  position = (await t.engine.flowPosition(run.callId))!;
  line(`flow: ${position.status}`);
  if (receipt === null) {
    line("receipt: none (the flow has no trace.receipt step)");
  } else {
    line(`receipt: signature valid against the engine's key set: ${verifyReceipt(receipt, t.engine.receiptKeys())}`);
    lines.push(...JSON.stringify(receipt, null, 2).split("\n"));
  }
  return { lines, status: position.status, exitCode };
}

/**
 * A fresh engine on the fakes, which prints every event to `lines` as it is appended to the ledger.
 * The fake door answers as every access controller named in `controllers` (`door` by default).
 */
export function simulationEngine(lines: string[], controllers: readonly string[] = ["door"]): TestEngine {
  const door = new FakeAccessController();
  const access = Object.fromEntries(controllers.map((name) => [name, door]));
  const t = createTestEngine({ onEvent: (event: EngineEvent) => lines.push(`    event ${event.name} (${event.actor}) ${canonicalJson(event.detail)}`), adapters: { access } });
  return { ...t, door };
}

/** The access controllers a config's Gate targets name, so the fake door can answer as each. */
export function gateControllers(config: unknown): string[] {
  const names = new Set(["door"]);
  const gate = isObject(config) && isObject(config.modules) ? config.modules.gate : undefined;
  const targets = isObject(gate) && isObject(gate.settings) ? gate.settings.targets : undefined;
  for (const target of Array.isArray(targets) ? targets : []) {
    if (isObject(target) && typeof target.controller === "string" && target.controller !== "") names.add(target.controller);
  }
  return [...names];
}

export const USAGE = "usage: district-assurance simulate <config.json> --flow <name> --script <" + Object.keys(BUILT_IN_SCRIPTS).join(" | ") + " | file.json>";

/** What `main` writes to. */
export interface Output {
  out(line: string): void;
  err(line: string): void;
}

async function readJson(path: string): Promise<{ value: unknown } | { error: string }> {
  try {
    return { value: JSON.parse(await readFile(path, "utf8")) as unknown };
  } catch (e) {
    return { error: `${path}: ${(e as Error).message}` };
  }
}

/**
 * The characters a terminal acts on or that reorder or hide text, as code point ranges: C0, DEL
 * and C1 controls (escape sequences, the 8-bit CSI U+009B), the Arabic letter mark, the zero-width
 * characters and bidi marks (U+200B to U+200F), U+2028, U+2029 and the bidi embeddings and
 * overrides (to U+202E), the invisible format characters and bidi isolates (U+2060 to U+206F), and
 * U+FEFF. The same table as the receipt verifier's (scripts/verify-receipt.mjs); keep the two identical.
 */
const TERMINAL_UNSAFE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00, 0x1f],
  [0x7f, 0x9f],
  [0x61c, 0x61c],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0xfeff, 0xfeff],
];

/**
 * A line as the terminal may show it. A config or a script file is text from someone else: a
 * character of TERMINAL_UNSAFE_RANGES (one the terminal acts on, or one that reorders or hides
 * text) is written as a `\u` escape, so a file can never move the
 * cursor, set the title or make one result read as another.
 */
export function terminalSafe(line: string): string {
  let safe = "";
  for (const c of line) {
    const n = c.codePointAt(0)!;
    safe += TERMINAL_UNSAFE_RANGES.some(([lo, hi]) => n >= lo && n <= hi) ? `\\u${n.toString(16).padStart(4, "0")}` : c;
  }
  return safe;
}

/**
 * The command line. Exit codes: 0 the flow ran (whatever its outcome), 1 a refused config, flow or
 * script, 2 bad usage, 3 the run stopped at a step the simulator has no caller for.
 */
export async function main(args: readonly string[], given: Output): Promise<number> {
  // Every line leaves through here, escaped.
  const output: Output = { out: (line) => given.out(terminalSafe(line)), err: (line) => given.err(terminalSafe(line)) };
  let parsed;
  try {
    parsed = parseArgs({ args: [...args], allowPositionals: true, strict: true, options: { flow: { type: "string" }, script: { type: "string" } } });
  } catch (e) {
    output.err((e as Error).message);
    output.err(USAGE);
    return 2;
  }
  const { positionals, values } = parsed;
  if (positionals.length !== 2 || positionals[0] !== "simulate" || values.flow === undefined || values.script === undefined) {
    output.err(USAGE);
    return 2;
  }
  const refuse = (problems: readonly string[]): number => {
    output.err(`simulate: refused, ${problems.length} problem(s):`);
    for (const problem of problems) output.err(`  - ${problem}`);
    return 1;
  };

  const config = await readJson(positionals[1]!);
  if ("error" in config) return refuse([config.error]);
  let script = Object.hasOwn(BUILT_IN_SCRIPTS, values.script) ? BUILT_IN_SCRIPTS[values.script]! : null;
  if (script === null) {
    const file = await readJson(values.script);
    if ("error" in file) return refuse([`${file.error} (not a built-in script: ${Object.keys(BUILT_IN_SCRIPTS).join(", ")})`]);
    const parsedScript = parseCallerScript(file.value);
    if (parsedScript.script === null) return refuse(parsedScript.problems.map((p) => `${values.script}: ${p}`));
    script = parsedScript.script;
  }

  const lines: string[] = [];
  const t = simulationEngine(lines, gateControllers(config.value));
  const checked = simulationConfig(config.value, t);
  if (checked.config === null) return refuse(checked.problems);
  if (!Object.hasOwn(checked.config.flows, values.flow)) {
    return refuse([`flows: no flow named ${values.flow}; the config's flows are ${JSON.stringify(Object.keys(checked.config.flows))}`]);
  }
  const { exitCode } = await simulate(t, lines, checked.config, values.flow, values.script, script);
  for (const text of lines) output.out(text);
  return exitCode;
}

/**
 * Whether the module at `moduleUrl` is the program node was started with (`entry`, its argv[1]).
 * Not `import.meta.main`: on Node.js 24.2 it is false for a `.ts` entry. Both paths are resolved
 * through symlinks, so the package's bin (a link in node_modules/.bin) counts as the program.
 */
export function isEntryPoint(entry: string | undefined, moduleUrl: string): boolean {
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1], import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2), { out: (line) => console.log(line), err: (line) => console.error(line) });
}
