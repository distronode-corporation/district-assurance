// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Subject requests are read once: a getter (or a host changing the object while the engine waits)
// can never pass the subject key check with one key and gather, erase or name another.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { TEST_KNOWLEDGE_KEY } from "../src/testing/index.ts";
import { subjectKeyFor } from "../src/verify/knowledge.ts";
import { ACCOUNT, setup } from "./helpers.ts";

const SUBJECT = subjectKeyFor(TEST_KNOWLEDGE_KEY, ACCOUNT);
const OTHER = "f".repeat(64);

function flipping<T extends object>(base: T, key: string, first: unknown, then: unknown, n = 1): T {
  let reads = 0;
  return Object.defineProperty({ ...base }, key, {
    enumerable: true,
    get() {
      reads += 1;
      return reads <= n ? first : then;
    },
  });
}

function spied() {
  const t = setup();
  const keys: string[] = [];
  const list = t.records.listIntakeRecords.bind(t.records);
  const get = t.records.getSubject.bind(t.records);
  t.records.listIntakeRecords = async (ws, key) => (keys.push(key), list(ws, key));
  t.records.getSubject = async (ws, key) => (keys.push(key), get(ws, key));
  return { t, keys };
}

describe("subject requests: inputs are read once", () => {
  it("exports the subject it checked, and names that subject in the export", async () => {
    const { t, keys } = spied();
    const exported = await t.engine.exportSubject(flipping({ workspaceId: "ws_test" }, "subjectKey", SUBJECT, OTHER) as never);
    assert.equal(exported.body.subjectKey, SUBJECT);
    assert.deepEqual([...new Set(keys)], [SUBJECT]);
  });

  it("erases the subject it checked, never another one swapped in after the check", async () => {
    const { t, keys } = spied();
    await t.engine.eraseSubject(flipping({ workspaceId: "ws_test" }, "subjectKey", SUBJECT, OTHER) as never);
    assert.deepEqual([...new Set(keys)], [SUBJECT]);
  });
});
