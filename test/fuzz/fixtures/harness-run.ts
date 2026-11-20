// Runs one fuzz() case named by argv[2] in its own process, so the harness reads this process's
// DA_FUZZ_* settings. Exits 0 when fuzz resolves, 2 when it reports the property failing, and 1
// when it rejects for any other reason (test/fuzz/harness.test.ts).
import fc from "fast-check";

import { fuzz } from "../harness.ts";

const mode = process.argv[2];

async function run(): Promise<void> {
  if (mode === "examples") {
    // 21 examples and 20 minimum runs: only the last example fails.
    const examples = Array.from({ length: 21 }, (_, i) => [i] as [number]);
    await fuzz(fc.property(fc.integer({ min: 0, max: 0 }), (n) => n !== 20), { examples, minRuns: 20 });
  } else if (mode === "replay") {
    // Only the example fails; its path is "0" on the stream that starts with the examples.
    await fuzz(fc.property(fc.integer({ min: 0, max: 0 }), (n) => n === 0), { examples: [[1]] });
  } else if (mode === "late") {
    // The first cases pass at once; a later one fails only after the time budget is spent.
    let calls = 0;
    await fuzz(
      fc.asyncProperty(fc.constant(0), async () => {
        calls++;
        if (calls <= 2) return;
        await new Promise((resolve) => setTimeout(resolve, 150));
        throw new Error("a late case failed");
      }),
      { minRuns: 2, maxRuns: 4 },
    );
  } else throw new Error(`unknown mode ${mode}`);
}

run().then(
  () => process.exit(0),
  (e: unknown) => {
    if (process.env.DA_FUZZ_DEBUG === "1") console.error(e);
    // 2: the property's own failure was reported; 1: the run failed some other way.
    const text = `${String(e)} ${String((e as { cause?: unknown }).cause)}`;
    process.exit(/a late case failed|Property failed/.test(text) ? 2 : 1);
  },
);
