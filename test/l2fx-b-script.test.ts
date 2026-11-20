// The reference script over a flow's hourly limit: the engine fails the flow and leaves the call
// open, so the step ends that call and fails, never leaving it open behind a thrown error.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { SCRIPTS, createDemoWorld, type DemoFlow, type ScriptRun } from "../examples/reference-server/src/script.ts";
import { EngineError, RateLimitedError } from "../src/index.ts";

/** Starts `flow` and runs its verification step until the subject's hourly limit refuses one. */
async function untilRefused(flow: DemoFlow) {
  const w = createDemoWorld();
  try {
    for (let i = 0; i < 20; i++) {
      const call: ScriptRun = { callId: "", linkId: "", receipt: null };
      await SCRIPTS[flow][0]!.run(w, call);
      const outcome = await SCRIPTS[flow][1]!.run(w, call);
      if (!outcome.ok) return { outcome, state: await w.engine.state(call.callId), position: await w.engine.flowPosition(call.callId), callId: call.callId, attempt: i };
    }
    throw new Error("never refused");
  } finally {
    await w.close();
  }
}

describe("reference script: a rate-limited verification ends its call", () => {
  for (const flow of ["deposit", "entry", "deposit-connect"] as const) {
    it(`${flow}: the refused call is ended and the step fails`, async () => {
      const { outcome, state, position, callId, attempt } = await untilRefused(flow);
      assert.equal(attempt, 5, "the subject's default limit is 5 starts an hour");
      assert.deepEqual(outcome, { detail: `refused: rate_limited, call ${callId} ended`, ok: false });
      assert.equal(state.phase, "ended");
      assert.equal(position?.status, "failed");
    });
  }

  it("an error that is not a rate limit still reaches the runner", async () => {
    const w = createDemoWorld();
    try {
      const call: ScriptRun = { callId: "no-such-call", linkId: "", receipt: null };
      await assert.rejects(SCRIPTS.deposit[1]!.run(w, call), (error) => error instanceof EngineError && !(error instanceof RateLimitedError));
      await assert.rejects(SCRIPTS.entry[1]!.run(w, call), (error) => error instanceof EngineError && !(error instanceof RateLimitedError));
    } finally {
      await w.close();
    }
  });
});
