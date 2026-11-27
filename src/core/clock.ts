// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Time and identifiers are injected, so tests and the demo are deterministic and nothing in the
// engine reads the wall clock or a random source directly.
import { randomBytes } from "node:crypto";

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export interface IdGenerator {
  /** A new identifier, `prefix_` followed by an opaque url-safe string. */
  next(prefix: string): string;
}

/** 96 random bits per id, url-safe. */
export const randomIds: IdGenerator = {
  next: (prefix) => `${prefix}_${randomBytes(12).toString("base64url")}`,
};
