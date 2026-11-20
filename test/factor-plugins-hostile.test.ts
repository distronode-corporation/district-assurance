// Hostile-pass regressions for #99 (MOD-3): Badge factor plug-ins registered after the engine is built.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { AssuranceModule, FactorPlugin } from "../src/core/module.ts";
import { badgeModule } from "../src/verify/badge.ts";
import { ACCOUNT, rejects, setup, testConfig, waitOut } from "./helpers.ts";

const token = (): FactorPlugin => ({
  kind: "hardware_token",
  summary: "a code from a token",
  maxAttemptsPerCall: 2,
  adapters: [],
  judge: async (input) => input.entry === "246810" && input.subject !== null,
});
const tokenConfig = () =>
  testConfig((c) => {
    c.policy.levels[0] = { level: 1, anyOf: [["keypad_knowledge"], ["hardware_token"]] };
    (c.modules.badge!.settings as { factors: string[] }).factors.push("hardware_token");
  });
const tokenModule = (plugins: FactorPlugin[]): AssuranceModule => ({
  manifest: { name: "token-check", version: "1", summary: "tokens", provides: { factors: ["hardware_token"], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
  factorPlugins: plugins,
  validateSettings: () => [],
  requiredAdapters: () => [],
  validateStep: () => [],
  initCall: () => null,
  enterStep: () => null,
  stepStatus: () => "pending",
});

async function attempts(t: ReturnType<typeof setup>, n: number): Promise<boolean[]> {
  const { callId } = await t.engine.startCall();
  await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
  const locked: boolean[] = [];
  for (let i = 0; i < n; i++) {
    locked.push((await t.engine.submitFactor(callId, "hardware_token", "000000")).locked);
    waitOut(t); // past each failure's wait, so only the attempt limit can lock
  }
  return locked;
}

describe("hostile #99: a plug-in changed after it was registered", () => {
  it("keeps the attempt limit that was checked, though the host raises it afterwards", async () => {
    const t = setup();
    const plugin = token();
    t.engine.useFactor(plugin);
    t.engine.configure(tokenConfig());
    (plugin as { maxAttemptsPerCall: number }).maxAttemptsPerCall = 1000;
    assert.deepEqual(await attempts(t, 3), [false, true, true], "two attempts, as registered");
  });

  it("registers the kind it checked, never caller ID through a getter", () => {
    const t = setup();
    let reads = 0;
    const sneaky = {
      ...token(),
      get kind() {
        reads += 1;
        return reads <= 3 ? "hardware_token" : "caller_id";
      },
    };
    t.engine.useFactor(sneaky as FactorPlugin);
    assert.equal(t.engine.registry.factorKinds().includes("caller_id"), false);
    assert.ok(t.engine.registry.factorKinds().includes("hardware_token"));
  });

  it("never runs a judge pushed onto an outside module's list after it was installed", async () => {
    const t = setup();
    const list = [token()];
    t.engine.use(tokenModule(list));
    t.engine.configure(tokenConfig());
    list[0] = { ...token(), maxAttemptsPerCall: Number.NaN, judge: async () => true };
    // A later swap of Badge (another module removed) must not pick up the changed list.
    t.engine.use({ ...tokenModule([]), manifest: { ...tokenModule([]).manifest, name: "other", provides: { factors: [], steps: [], outcomes: [] } }, factorPlugins: [] });
    t.engine.remove("other");
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    assert.deepEqual(await t.engine.submitFactor(callId, "hardware_token", "000000"), { matched: false, locked: false }, "judged by the checked judge");
  });
});

describe("hostile #99: what holds", () => {
  it("a Badge shared by two engines gains a factor only in the engine that added it", () => {
    const shared = badgeModule();
    const a = setup({ badge: shared });
    const b = setup({ badge: shared });
    a.engine.useFactor(token());
    assert.ok(a.engine.registry.factorKinds().includes("hardware_token"));
    assert.equal(b.engine.registry.factorKinds().includes("hardware_token"), false);
  });

  it("refuses a judge that is not a function, from the copy it checks", () => {
    const t = setup();
    assert.throws(() => t.engine.useFactor({ ...token(), judge: "always" as never }), rejects("invalid_input", /judge must be a function/));
    assert.throws(() => t.engine.use(tokenModule([{ ...token(), judge: 1 as never }])), rejects("invalid_input", /judge must be a function/));
  });

  it("refuses to remove a module whose factor the config uses", () => {
    const t = setup();
    t.engine.use(tokenModule([token()]));
    t.engine.configure(tokenConfig());
    assert.throws(() => t.engine.remove("token-check"), rejects("precondition_failed", /supplies the factor hardware_token/));
  });
});
