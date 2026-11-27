// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Email addresses on file. The engine never takes an address from a call: the one it emails is the
// subject's verified `emailOnFile`, and this is the check it holds that address to before using it.

/** The characters RFC 5322 allows in an unquoted local part (its `atext`), and the dots between them. */
const LOCAL_PART = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
/** One DNS label: letters, digits and hyphens, 1 to 63, never starting or ending with a hyphen. */
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
/** A top-level domain: letters only (two or more), or an internationalised one in its ASCII form. */
const TOP_LEVEL = /^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$/;

/**
 * Whether a value is an address the engine will email: a string of at most 254 ASCII characters,
 * one `@`, an unquoted local part of 1 to 64 characters (RFC 5322 `dot-atom`), and a domain of two
 * or more DNS labels whose last is a top-level domain. Anything else (a quoted local part, an IP
 * literal, a space, a control character, a Unicode domain not in its `xn--` form) is refused, so
 * the address on file can never carry a header, a second recipient or a line break into an email.
 */
export function isEmailAddress(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 254) return false;
  const at = value.indexOf("@");
  if (at < 1 || at !== value.lastIndexOf("@")) return false;
  const local = value.slice(0, at);
  const labels = value.slice(at + 1).split(".");
  if (local.length > 64 || !LOCAL_PART.test(local) || labels.length < 2) return false;
  return labels.every((label) => LABEL.test(label)) && TOP_LEVEL.test(labels.at(-1)!);
}
