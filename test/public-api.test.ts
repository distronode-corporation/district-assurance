// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// The 1.0 public API (README.md, "What 1.0 promises"): the runtime exports of each entry point and
// the package's export map, pinned. Removing or renaming one is a breaking change and needs a new
// major version; adding one is a minor change and updates test/fixtures/public-api.json in the same
// pull request, with a CHANGELOG.md line.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import * as carrier from "../src/carrier/index.ts";
import * as root from "../src/index.ts";
import * as stripe from "../src/stripe/index.ts";
import * as testing from "../src/testing/index.ts";

const pinned = JSON.parse(readFileSync(new URL("./fixtures/public-api.json", import.meta.url), "utf8")) as Record<string, string[]>;
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, unknown> };

describe("public API (1.0)", () => {
  const entries: Array<[string, Record<string, unknown>]> = [
    ["district-assurance", root],
    ["district-assurance/testing", testing],
    ["district-assurance/stripe", stripe],
    ["district-assurance/carrier", carrier],
  ];

  for (const [name, module] of entries) {
    it(`${name} exports exactly the pinned names`, () => {
      assert.deepEqual(Object.keys(module).sort(), pinned[name]);
    });
  }

  it("pins every entry point and nothing else", () => {
    assert.deepEqual(Object.keys(pinned).sort(), entries.map(([name]) => name).sort());
  });

  it("the package's export map is the four entry points, the FlowConfig schema and package.json", () => {
    assert.deepEqual(Object.keys(manifest.exports), [".", "./testing", "./stripe", "./carrier", "./schema/flow-config.v1.json", "./package.json"]);
  });
});
