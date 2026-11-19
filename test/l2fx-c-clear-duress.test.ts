// L2 fix T9 (PR #130 review): clearDuress clears the hidden counters of every factor Badge judges,
// outside modules' judges included, on or off.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import type { FlowConfig } from "../src/core/config.ts";
import type { AssuranceModule, FactorPlugin } from "../src/core/module.ts";
import { hiddenCounterKey } from "../src/verify/duress-flag.ts";
import type { PinSettings } from "../src/verify/factors.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { FakeDuressNotifier, TEST_KNOWLEDGE_KEY, type TestEngine } from "../src/testing/index.ts";
import { ACCOUNT, setup, testConfig } from "./helpers.ts";

const OWNER = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const LONG_AGO = "1970-01-01T00:00:00.000Z";
const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();
const badgeSettings = (c: FlowConfig) => c.modules.badge!.settings as unknown as { pin: PinSettings; factors: string[] };
const duressConfig = (more?: (c: FlowConfig) => void) =>
  testConfig((c) => {
    c.policy.levels[0]!.anyOf.push(["pin"]);
    badgeSettings(c).pin.duress = { refuseScopes: [] };
    more?.(c);
  });

async function duressEngine(config: FlowConfig): Promise<TestEngine> {
  const t = setup({ config, adapters: { duressNotifier: new FakeDuressNotifier() } });
  assert.deepEqual(await t.engine.enrolDuressPin(OWNER, "7391"), { enrolled: true });
  return t;
}

describe("T9: clearDuress clears the hidden locks of outside factors", () => {
  const token: FactorPlugin = { kind: "hardware_token", summary: "a token code", maxAttemptsPerCall: 2, adapters: [], judge: async () => false };
  const tokenModule: AssuranceModule = {
    manifest: { name: "token-check", version: "1", summary: "tokens", provides: { factors: ["hardware_token"], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
    factorPlugins: [token],
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => null,
    enterStep: () => null,
    stepStatus: () => "pending",
  };

  for (const on of [true, false]) {
    it(`an outside factor ${on ? "turned on" : "installed but turned off"} loses its hidden lock`, async () => {
      const t = await duressEngine(duressConfig());
      t.engine.use(tokenModule);
      if (on) t.engine.configure(duressConfig((c) => badgeSettings(c).factors.push("hardware_token")));
      const hidden = hiddenCounterKey("ws_test", "hardware_token", OWNER);
      for (let i = 0; i < 10; i++) await t.counters.recordFailure(hidden, iso(T0 + i), LONG_AGO);
      await t.engine.clearDuress(OWNER, "member_1");
      assert.deepEqual(await t.counters.get(hidden, LONG_AGO), []);
    });
  }
});

describe("T9: unlock lifts an outside factor's lock", () => {
  const token: FactorPlugin = { kind: "hardware_token", summary: "a token code", maxAttemptsPerCall: 2, adapters: [], judge: async () => false };
  const tokenModule: AssuranceModule = {
    manifest: { name: "token-check", version: "1", summary: "tokens", provides: { factors: ["hardware_token"], steps: [], outcomes: [] }, scopes: { grants: [], needs: {} }, adapters: [] },
    factorPlugins: [token],
    validateSettings: () => [],
    requiredAdapters: () => [],
    validateStep: () => [],
    initCall: () => null,
    enterStep: () => null,
    stepStatus: () => "pending",
  };

  it("accepts the outside judge's kind and clears its counter", async () => {
    const t = setup();
    t.engine.use(tokenModule);
    const counter = { workspaceId: "ws_test", factor: "hardware_token", scope: "subject" as const, key: OWNER };
    for (let i = 0; i < 5; i++) await t.counters.recordFailure(counter, iso(T0 + i), LONG_AGO);
    await t.engine.unlock({ ...counter, memberId: "member_1" });
    assert.deepEqual(await t.counters.get(counter, LONG_AGO), []);
  });
});
