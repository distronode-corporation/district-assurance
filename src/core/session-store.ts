// The in-memory session store: the reference implementation of `SessionStore`, for a host that
// runs one process, for tests and for the demo. Records are copied in and out, so a caller can
// never change what is stored except through `compareAndSet`. Keys are JSON tuples, so no pair of
// workspace and call ids can collide with another (`"a/b", "c"` is not `"a", "b/c"`).
import type { SessionStore, StoredSession, WriteHint } from "./adapters.ts";
import type { JsonValue } from "./canonical.ts";

const tupleKey = (workspaceId: string, id: string): string => JSON.stringify([workspaceId, id]);

export class MemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, StoredSession>();
  readonly #refs = new Map<string, string>();
  /** Per workspace, the calls whose latest write said their ledger entries are pending (INT-5). */
  readonly #pending = new Map<string, Set<string>>();

  async create(workspaceId: string, callId: string, record: JsonValue, hint?: WriteHint): Promise<boolean> {
    const key = tupleKey(workspaceId, callId);
    if (this.#sessions.has(key)) return false;
    this.#sessions.set(key, { version: 1, record: structuredClone(record) });
    this.#mark(workspaceId, callId, hint);
    return true;
  }

  async get(workspaceId: string, callId: string): Promise<StoredSession | null> {
    const stored = this.#sessions.get(tupleKey(workspaceId, callId));
    return stored === undefined ? null : structuredClone(stored);
  }

  async compareAndSet(
    workspaceId: string,
    callId: string,
    expectedVersion: number,
    record: JsonValue,
    hint?: WriteHint,
  ): Promise<{ ok: true; version: number } | { ok: false }> {
    const key = tupleKey(workspaceId, callId);
    const stored = this.#sessions.get(key);
    if (stored === undefined || stored.version !== expectedVersion) return { ok: false };
    const version = expectedVersion + 1;
    this.#sessions.set(key, { version, record: structuredClone(record) });
    this.#mark(workspaceId, callId, hint);
    return { ok: true, version };
  }

  async pendingCalls(workspaceId: string, limit: number): Promise<string[]> {
    const calls = this.#pending.get(workspaceId);
    if (calls === undefined) return [];
    const batch = [...calls].slice(0, limit);
    // Rotate: the listed calls go to the back, so a call that keeps failing cannot starve the rest.
    for (const callId of batch) {
      calls.delete(callId);
      calls.add(callId);
    }
    return batch;
  }

  async bindRef(workspaceId: string, ref: string, callId: string): Promise<boolean> {
    const key = tupleKey(workspaceId, ref);
    if (this.#refs.has(key)) return false;
    this.#refs.set(key, callId);
    return true;
  }

  async resolveRef(workspaceId: string, ref: string): Promise<string | null> {
    return this.#refs.get(tupleKey(workspaceId, ref)) ?? null;
  }

  async listCallsOwingAlerts(workspaceId: string): Promise<string[]> {
    const out: string[] = [];
    for (const [key, stored] of this.#sessions) {
      const [workspace, callId] = JSON.parse(key) as [string, string];
      if (workspace === workspaceId && (stored.record as { owesAlerts?: unknown } | null)?.owesAlerts === true) out.push(callId);
    }
    return out;
  }

  /** Keeps the pending mark with the write it came with; a write without a hint leaves it as it was. */
  #mark(workspaceId: string, callId: string, hint: WriteHint | undefined): void {
    if (hint === undefined) return;
    let calls = this.#pending.get(workspaceId);
    if (calls === undefined) {
      calls = new Set();
      this.#pending.set(workspaceId, calls);
    }
    if (hint.ledgerPending) calls.add(callId);
    else calls.delete(callId);
  }
}
