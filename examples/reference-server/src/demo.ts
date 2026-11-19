// `npm run demo`: two scripted calls, end to end, on fake adapters and a server on 127.0.0.1.
// No network beyond the loopback, no keys, no real people (script.ts holds the script).
//
// 1. `owner-command`: the owner's PIN only, on two engines that share one session store (as two
//    processes of a host would). One wrong PIN, then the right one.
// 2. `deposit`: keypad knowledge and a carrier match to level 2, a repair form, a deposit by link
//    settled by a signed webhook, a consent, and a signed receipt checked with the public key.
import type { JsonWebKey } from "node:crypto";
import type { AddressInfo } from "node:net";

import { verifyChain, verifyReceipt, type SignedReceipt } from "../../../src/index.ts";
import { createReferenceServer } from "./app.ts";
import { DEMO_SECRET, SCRIPTS, createDemoWorld, type DemoFlow, type ScriptRun } from "./script.ts";

const log = (step: string, detail = "") => console.log(`  ${step.padEnd(36)} ${detail}`);

export interface DemoResult {
  /** Every step's own check held (script.ts). */
  checksOk: boolean;
  ownerReceipt: SignedReceipt | null;
  receipt: SignedReceipt;
  tamperedFails: boolean;
  chainOk: boolean;
}

export async function runDemo(print = true): Promise<DemoResult> {
  const say = print ? log : () => undefined;
  const world = createDemoWorld();
  const server = createReferenceServer({ engine: world.engine, stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET] }, clock: world.t.clock });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  world.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  let allOk = true;
  const play = async (flow: DemoFlow): Promise<ScriptRun> => {
    const call: ScriptRun = { callId: "", linkId: "", receipt: null };
    for (const step of SCRIPTS[flow]) {
      const outcome = await step.run(world, call);
      allOk &&= outcome.ok;
      say(step.label, outcome.detail);
    }
    return call;
  };

  try {
    say("District Assurance demo (fake adapters, no network)");
    const owner = await play("owner-command");
    const { callId } = await play("deposit");
    const receipt = (await (await fetch(`${world.base}/receipts/${callId}`)).json()) as SignedReceipt;
    const { keys } = (await (await fetch(`${world.base}/.well-known/receipt-keys.json`)).json()) as { keys: JsonWebKey[] };
    const valid = verifyReceipt(receipt, keys);
    const tampered = structuredClone(receipt);
    tampered.body.payments[0]!.amountMinor = 1;
    const tamperedFails = !verifyReceipt(tampered, keys);
    say("prove: receipt signature", valid ? "valid" : "INVALID");
    say("prove: receipt with one change", tamperedFails ? "rejected" : "ACCEPTED");
    const chain = verifyChain(await world.t.ledger.list());
    say("prove: audit ledger (both calls)", chain.ok ? `${chain.head.seq} entries, hash chain intact` : "BROKEN");
    if (!allOk || !valid || !tamperedFails || !chain.ok) throw new Error("the demo's checks failed");
    return { checksOk: allOk, ownerReceipt: owner.receipt, receipt, tamperedFails, chainOk: chain.ok };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

if (import.meta.main) {
  const { receipt } = await runDemo();
  console.log("\nDeposit receipt body:\n" + JSON.stringify(receipt.body, null, 2));
}
