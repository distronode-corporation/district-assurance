// SPDX-FileCopyrightText: Distronode Corporation
//
// SPDX-License-Identifier: Apache-2.0

// An example door relay: the small program on a site's own network that Gate's `webhookRelay`
// adapter posts to. It holds only Gate's public key. It checks the grant (signature, audience,
// window, lifetime), refuses a grant id it has seen, and only then works the door, here a callback
// (a real one would pulse a relay: a Shelly `Switch.Set` with `toggle_after`, an ESPHome switch).
// Not hardened for production: it keeps seen grant ids in memory.
import type { JsonWebKey } from "node:crypto";
import { createServer, type Server } from "node:http";

import { SeenGrants, verifyAccessGrant, type AccessGrantBody, type Clock } from "../../../src/index.ts";

export interface DoorRelayOptions {
  /** The workspace whose doors this relay works: a grant issued by any other is refused. */
  workspaceId: string;
  /** This relay's id: the controller name grants must be addressed to. */
  audience: string;
  /** The engine's access key set (`engine.accessKeys()`). */
  keys: readonly JsonWebKey[];
  clock: Clock;
  /** Works the door for a grant. Resolves once it moved. */
  open(target: string, grant: AccessGrantBody): Promise<void>;
}

const MAX_BODY_BYTES = 16 * 1024;

export function createDoorRelay(options: DoorRelayOptions): Server {
  const seen = new SeenGrants();
  return createServer((req, res) => {
    const answer = (status: number, body: Record<string, unknown>): void => {
      res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
    };
    if (req.method !== "POST" || req.url !== "/unlock") return void answer(404, { error: "not_found" });
    // A grant is well under 2 KiB: stop keeping a body past 16 KiB, drain it, and refuse it.
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= MAX_BODY_BYTES) {
        chunks.push(c);
        return;
      }
      // Over the limit: answer at once and stop reading, rather than wait for a body that may never end.
      if (!res.headersSent) res.writeHead(413, { "content-type": "application/json", connection: "close" }).end(JSON.stringify({ error: "body_too_large" }));
      req.destroy();
    });
    req.on("end", () => {
      if (size > MAX_BODY_BYTES) return;
      let grant: unknown;
      try {
        grant = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return void answer(400, { error: "malformed" });
      }
      const now = options.clock.now();
      const check = verifyAccessGrant(grant, options.keys, { workspaceId: options.workspaceId, audience: options.audience, now });
      if (!check.ok) return void answer(401, { error: check.reason });
      if (!seen.accept(check.body, now)) return void answer(409, { error: "replay" });
      // A door callback that throws before it returns a promise is a door failure too, never a crash.
      Promise.resolve()
        .then(() => options.open(check.body.target, check.body))
        .then(
        () => answer(200, { state: "confirmed", ref: `${options.audience}:${check.body.grantId}` }),
        () => answer(502, { error: "door" }),
      );
    });
  });
}
