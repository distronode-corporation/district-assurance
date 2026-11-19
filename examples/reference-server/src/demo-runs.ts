// The browser UI's side of the demo: runs of script.ts, one step per request, and what each run
// looks like after it (the call's session state, its flow position, its ledger entries). A run
// can only replay its script; nothing a browser sends reaches the engine except the flow's name.
import { randomUUID } from "node:crypto";

import { EngineError, verifyChain, type AuditEntry, type FlowPosition, type SessionState } from "../../../src/index.ts";
import { SCRIPTS, type DemoWorld, type ScriptRun, type Scripts } from "./script.ts";

export interface StepResult {
  index: number;
  label: string;
  detail: string;
  ok: boolean;
  link?: { href: string; text: string };
}

export interface FlowView {
  flow: string;
  summary: string;
  steps: string[];
}

export interface RunView extends FlowView {
  runId: string;
  /** The index of the next step; equal to the number of steps once done. */
  next: number;
  /** Every step ran, or one threw. */
  done: boolean;
  results: StepResult[];
  callId: string | null;
  state: SessionState | null;
  position: FlowPosition | null;
  /** This call's entries, in order. */
  ledger: AuditEntry[];
  /** The whole ledger's hash chain (every run's calls share one ledger). */
  chain: { ok: boolean; entries: number };
}

export type RunAnswer = { ok: true; view: RunView } | { ok: false; status: 404 | 409; error: "not_found" | "busy" | "done" };

interface Run {
  runId: string;
  flow: string;
  call: ScriptRun;
  results: StepResult[];
  busy: boolean;
  failed: boolean;
  /** Steps and views of one run take turns, so a view never mixes a step's before and after. */
  turn: Promise<unknown>;
}

export class DemoRuns {
  readonly #world: DemoWorld;
  readonly #max: number;
  readonly #scripts: Scripts;
  readonly #runs = new Map<string, Run>();

  /** Keeps the newest `maxRuns` runs (default 20); an older run's id answers 404. `scripts` defaults to the demo's four flows. */
  constructor(world: DemoWorld, maxRuns = 20, scripts: Scripts = SCRIPTS) {
    this.#world = world;
    this.#max = maxRuns;
    this.#scripts = scripts;
  }

  /** Whether `flow` is one of these runs' scripts. */
  hasFlow(flow: string): boolean {
    return Object.hasOwn(this.#scripts, flow) && Object.hasOwn(this.#world.config.flows, flow);
  }

  flows(): FlowView[] {
    return Object.keys(this.#scripts)
      .filter((flow) => this.hasFlow(flow))
      .map((flow) => this.#describe(flow));
  }

  async start(flow: string): Promise<RunView> {
    const run: Run = { runId: `run_${randomUUID()}`, flow, call: { callId: "", linkId: "", receipt: null }, results: [], busy: false, failed: false, turn: Promise.resolve() };
    this.#runs.set(run.runId, run);
    for (const old of this.#runs.keys()) {
      if (this.#runs.size <= this.#max) break;
      this.#runs.delete(old);
    }
    return this.#view(run);
  }

  async view(runId: string): Promise<RunAnswer> {
    const run = this.#runs.get(runId);
    return run === undefined ? { ok: false, status: 404, error: "not_found" } : { ok: true, view: await this.#inTurn(run, () => this.#view(run)) };
  }

  /** Runs the next step. One step at a time per run: a second request while one runs answers `busy`. */
  async step(runId: string): Promise<RunAnswer> {
    const run = this.#runs.get(runId);
    if (run === undefined) return { ok: false, status: 404, error: "not_found" };
    if (run.busy) return { ok: false, status: 409, error: "busy" };
    const steps = this.#scripts[run.flow]!;
    const index = run.results.length;
    if (run.failed || index >= steps.length) return { ok: false, status: 409, error: "done" };
    run.busy = true;
    try {
      return { ok: true, view: await this.#inTurn(run, () => this.#runStep(run, index)) };
    } finally {
      run.busy = false;
    }
  }

  async #runStep(run: Run, index: number): Promise<RunView> {
    const step = this.#scripts[run.flow]![index]!;
    try {
      const outcome = await step.run(this.#world, run.call);
      run.results.push({ index, label: step.label, ...outcome });
      // A failed check ends the run: the next step may depend on it (no door before a payment).
      if (!outcome.ok) run.failed = true;
    } catch (error) {
      run.failed = true;
      const detail = error instanceof EngineError ? `refused: ${error.code}` : "failed: internal error";
      run.results.push({ index, label: step.label, detail, ok: false });
    }
    return this.#view(run);
  }

  /** Runs `fn` after everything already queued on this run; a failure is the caller's, not the queue's. */
  #inTurn<T>(run: Run, fn: () => Promise<T>): Promise<T> {
    const next = run.turn.then(fn);
    run.turn = next.catch(() => undefined);
    return next;
  }

  async #view(run: Run): Promise<RunView> {
    const { engine, t } = this.#world;
    const callId = run.call.callId === "" ? null : run.call.callId;
    const all = await t.ledger.list();
    const chain = verifyChain(all);
    return {
      runId: run.runId,
      ...this.#describe(run.flow),
      next: run.results.length,
      done: run.failed || run.results.length === this.#scripts[run.flow]!.length,
      results: structuredClone(run.results),
      callId,
      state: callId === null ? null : await engine.state(callId),
      position: callId === null ? null : await engine.flowPosition(callId),
      ledger: callId === null ? [] : all.filter((entry) => entry.callId === callId),
      chain: { ok: chain.ok, entries: all.length },
    };
  }

  #describe(flow: string): FlowView {
    return { flow, summary: this.#world.config.flows[flow]!.summary ?? "", steps: this.#scripts[flow]!.map((step) => step.label) };
  }
}
