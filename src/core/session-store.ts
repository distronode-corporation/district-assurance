// The in-memory session store: the reference implementation of `SessionStore`, for a host that
// runs one process, for tests and for the demo. Records are copied in and out, so a caller can
// never change what is stored except through `compareAndSet`. Keys are JSON tuples, so no pair of
// workspace and call ids can collide with another (`"a/b", "c"` is not `"a", "b/c"`).
import type { SessionStore, StoredSession } from "./adapters.ts";
import type { JsonValue } from "./canonical.ts";

const tupleKey = (workspaceId: string, id: string): string => JSON.stringify([workspaceId, id]);

export class MemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, StoredSession>();
  readonly #refs = new Map<string, string>();

  async create(workspaceId: string, callId: string, record: JsonValue): Promise<boolean> {
    const key = tupleKey(workspaceId, callId);
    if (this.#sessions.has(key)) return false;
    this.#sessions.set(key, { version: 1, record: structuredClone(record) });
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
  ): Promise<{ ok: true; version: number } | { ok: false }> {
    const key = tupleKey(workspaceId, callId);
    const stored = this.#sessions.get(key);
    if (stored === undefined || stored.version !== expectedVersion) return { ok: false };
    const version = expectedVersion + 1;
    this.#sessions.set(key, { version, record: structuredClone(record) });
    return { ok: true, version };
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
}
