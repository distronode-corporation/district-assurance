// PIN records (VER-6, VER-12, ADR-29): Argon2id over the keyed HMAC.
//
// A PIN or duress PIN on file is `$pin1$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<tag>`:
// Argon2id (RFC 9106, `node:crypto`) of the 32 bytes of `HMAC-SHA256(knowledgeKey, "pin:" +
// subjectKey + ":" + pin)` (or `"duress:"`), with a random 16-byte salt, a 32-byte tag, and the
// salt and tag in unpadded base64. `pin1` names this construction; the parameters travel with the
// record. Without the knowledge key a record is useless, as before; with it, each guess also costs
// an Argon2id run. A record of the earlier format, the bare 64-hex HMAC, still verifies, and the
// PIN factor replaces it with an Argon2id record on the next match.
import { argon2, argon2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

import { hexDigestsEqual } from "../core/hash.ts";

/** Argon2id's cost for a new record: 19 MiB, 2 passes, 1 lane (the OWASP minimum for Argon2id). */
export const PIN_HASH_PARAMETERS: Readonly<PinHashParameters> = Object.freeze({ memory: 19456, passes: 2, parallelism: 1 });

/** Argon2id's cost: memory in KiB, passes over it, and lanes. */
export interface PinHashParameters {
  memory: number;
  passes: number;
  parallelism: number;
}

const SALT_BYTES = 16;
const TAG_BYTES = 32;
const RECORD = /^\$pin1\$argon2id\$v=19\$m=([1-9]\d{0,6}),t=([1-9]\d{0,2}),p=([1-9]\d?)\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/;
const LEGACY = /^[0-9a-f]{64}$/;
// The salt of the stand-in run for a record that is missing, refused or of the earlier format.
const STAND_IN_SALT = Buffer.alloc(SALT_BYTES);

const argon2Async = promisify(argon2);

type OnFile = { kind: "argon2id"; salt: Buffer; tag: Buffer } | { kind: "legacy"; digest: string } | { kind: "none" };

/** Unpadded base64, as the PHC string format writes it. */
function b64(bytes: Buffer): string {
  return bytes.toString("base64").replace(/=+$/, "");
}

/**
 * What is on file: an Argon2id record at today's cost, an earlier keyed HMAC, or nothing usable.
 * Anything else (another algorithm or version, another cost, a non-canonical number or base64, a
 * string that is not a record) is nothing: it never matches.
 */
function readRecord(stored: unknown): OnFile {
  if (typeof stored !== "string") return { kind: "none" };
  if (LEGACY.test(stored)) return { kind: "legacy", digest: stored };
  const m = RECORD.exec(stored);
  if (m === null) return { kind: "none" };
  const parameters = { memory: Number(m[1]), passes: Number(m[2]), parallelism: Number(m[3]) };
  const salt = Buffer.from(m[4]!, "base64");
  const tag = Buffer.from(m[5]!, "base64");
  // One spelling per record: base64 whose unused low bits are set reads as the same bytes.
  if (b64(salt) !== m[4] || b64(tag) !== m[5]) return { kind: "none" };
  for (const name of ["memory", "passes", "parallelism"] as const) {
    // Only today's cost: a downgrade is refused, and a dearer record is too, since running it at its
    // own cost would take longer than the stand-in an unknown subject gets (CWE-208).
    if (parameters[name] !== PIN_HASH_PARAMETERS[name]) return { kind: "none" };
  }
  return { kind: "argon2id", salt, tag };
}

function argonInput(keyedPin: string, salt: Buffer, parameters: PinHashParameters) {
  return { message: Buffer.from(keyedPin, "hex"), nonce: salt, tagLength: TAG_BYTES, ...parameters };
}

function format(salt: Buffer, tag: Buffer): string {
  const { memory, passes, parallelism } = PIN_HASH_PARAMETERS;
  return `$pin1$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${b64(salt)}$${b64(tag)}`;
}

/** A new record for a keyed PIN (64 lower-case hex, the HMAC), with a fresh random salt. Run off the main thread. */
export async function hashPinRecord(keyedPin: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  return format(salt, await argon2Async("argon2id", argonInput(keyedPin, salt, PIN_HASH_PARAMETERS)));
}

/** `hashPinRecord` at once, for loading records with bytes of the knowledge key (it blocks for one Argon2id run). */
export function hashPinRecordSync(keyedPin: string): string {
  const salt = randomBytes(SALT_BYTES);
  return format(salt, argon2Sync("argon2id", argonInput(keyedPin, salt, PIN_HASH_PARAMETERS)));
}

/**
 * Whether a keyed PIN matches the record on file, and whether the record should be replaced by an
 * Argon2id one (`upgrade`: an earlier keyed HMAC that matched). Every call does one Argon2id run
 * at today's cost, on the record or, for a record that is missing, refused or of the earlier
 * format, on a stand-in, so the time never says which it was. Tags and digests are compared
 * in constant time.
 */
export async function checkPinRecord(stored: unknown, keyedPin: string): Promise<{ match: boolean; upgrade: boolean }> {
  const onFile = readRecord(stored);
  if (onFile.kind === "argon2id") {
    const tag = await argon2Async("argon2id", argonInput(keyedPin, onFile.salt, PIN_HASH_PARAMETERS));
    return { match: timingSafeEqual(tag, onFile.tag), upgrade: false };
  }
  await argon2Async("argon2id", argonInput(keyedPin, STAND_IN_SALT, PIN_HASH_PARAMETERS));
  const match = onFile.kind === "legacy" && hexDigestsEqual(keyedPin, onFile.digest);
  return { match, upgrade: match };
}
