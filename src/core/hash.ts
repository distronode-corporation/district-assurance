// Hashing helpers on node:crypto. Hex output everywhere, lower case.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function hmacSha256Hex(key: string | Uint8Array, data: string): string {
  return createHmac("sha256", key).update(data).digest("hex");
}

/**
 * Compares two hex digests in constant time for equal lengths. Different lengths, or anything
 * that is not lower-case hex, compare unequal without throwing.
 */
export function hexDigestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length || !/^[0-9a-f]*$/.test(a) || !/^[0-9a-f]*$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
