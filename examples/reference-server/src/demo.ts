// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// `npm run demo`: four scripted calls, end to end, on fake adapters and servers on 127.0.0.1.
// No network beyond the loopback, no keys, no real people (script.ts holds the script).
//
// 1. `owner-command`: the owner's PIN only, on two engines that share one session store (as two
//    processes of a host would). One wrong PIN, then the right one.
// 2. `deposit`: keypad knowledge and a carrier match to level 2, a repair form, a deposit by link
//    settled by a signed webhook, a consent, and a signed receipt, fetched by its capability link
//    and checked with the public key.
//    The money goes to the platform's own account (`platform` mode).
// 3. `deposit-connect`: a deposit on the business's own account (`connect` mode). A webhook on
//    the platform endpoint, without the connected account, is ignored; the Connect one settles it.
// 4. `entry`: verification to level 2, then Gate signs a 30-second access grant and the
//    signed-webhook relay adapter posts it to an example door relay on the loopback, which checks
//    it with Gate's public key and opens the (pretend) door. The same grant again, and a changed
//    copy, are refused.
// 5. A callback: the owner's PIN from a number that is not the owner's, then a callback to the
//    number on file; only the callback call gains a level.
import type { JsonWebKey } from "node:crypto";
import type { AddressInfo } from "node:net";

import { verifyChain, verifyReceipt, type SignedReceipt } from "../../../src/index.ts";
import { createReferenceServer } from "./app.ts";
import { isProgram } from "./main.ts";
import { CALLBACK_SCRIPT, DEMO_CONNECT_SECRET, DEMO_SECRET, SCRIPTS, createDemoWorld, type ScriptRun, type ScriptStep } from "./script.ts";

const log = (step: string, detail = "") => console.log(`  ${step.padEnd(36)} ${detail}`);

export interface DemoResult {
  /** Every step's own check held (script.ts). */
  checksOk: boolean;
  ownerReceipt: SignedReceipt | null;
  receipt: SignedReceipt;
  tamperedFails: boolean;
  chainOk: boolean;
  /** The connect-mode deposit's receipt. */
  connectReceipt: SignedReceipt;
  /** Every door the example relay opened. */
  doorOpened: string[];
}

export async function runDemo(print = true): Promise<DemoResult> {
  const say = print ? log : () => undefined;
  const world = createDemoWorld();
  const server = createReferenceServer({
    engine: world.engine,
    stripeSecrets: { identity: [DEMO_SECRET], payments: [DEMO_SECRET], connect: [DEMO_CONNECT_SECRET] },
    clock: world.t.clock,
    receiptLinks: world.receiptLinks,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  world.base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  let allOk = true;
  const play = async (steps: readonly ScriptStep[]): Promise<ScriptRun> => {
    const call: ScriptRun = { callId: "", linkId: "", receipt: null, receiptToken: null };
    for (const step of steps) {
      const outcome = await step.run(world, call);
      allOk &&= outcome.ok;
      say(step.label, outcome.detail);
    }
    return call;
  };

  try {
    say("District Assurance demo (fake adapters, no network)");
    const owner = await play(SCRIPTS["owner-command"]);
    const { receiptToken } = await play(SCRIPTS.deposit);
    // The receipt by its capability link, as the caller would open it: the page, then the JSON.
    const page = await (await fetch(`${world.base}/r/${receiptToken}`)).text();
    const pageOk = page.includes("Signature valid");
    say("prove: receipt page at /r/<token>", pageOk ? "signature valid" : "NOT VALID");
    const receipt = (await (await fetch(`${world.base}/r/${receiptToken}.json`)).json()) as SignedReceipt;
    const { keys } = (await (await fetch(`${world.base}/.well-known/receipt-keys.json`)).json()) as { keys: JsonWebKey[] };
    const valid = verifyReceipt(receipt, keys);
    const tampered = structuredClone(receipt);
    tampered.body.payments[0]!.amountMinor = 1;
    const tamperedFails = !verifyReceipt(tampered, keys);
    say("prove: receipt signature", valid ? "valid" : "INVALID");
    say("prove: receipt with one change", tamperedFails ? "rejected" : "ACCEPTED");
    const connect = await play(SCRIPTS["deposit-connect"]);
    await play(SCRIPTS.entry);
    await play(CALLBACK_SCRIPT);
    const chain = verifyChain(await world.t.ledger.list());
    say("prove: audit ledger (all calls)", chain.ok ? `${chain.head.seq} entries, hash chain intact` : "BROKEN");
    if (!allOk || !pageOk || !valid || !tamperedFails || !chain.ok) throw new Error("the demo's checks failed");
    return { checksOk: allOk, ownerReceipt: owner.receipt, receipt, tamperedFails, chainOk: chain.ok, connectReceipt: connect.receipt!, doorOpened: [...world.doorsOpened] };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await world.close();
  }
}

// Not `import.meta.main`, which Node.js 24.2 sets false for a .ts entry (see `isProgram`).
if (isProgram(process.argv[1], import.meta.url)) {
  const { receipt } = await runDemo();
  console.log("\nDeposit receipt body:\n" + JSON.stringify(receipt.body, null, 2));
}
