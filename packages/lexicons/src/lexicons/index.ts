/**
 * Standard Library — the agnostic, foundry-shipped lexicons.
 *
 * This registry slice contains ONLY the identity-tier lexicons:
 *   - kash.id.profile@1.0.0
 *   - kash.id.audit@1.0.0
 *   - kash.id.preferences@1.0.0
 *
 * Domain lexicons (Social, Trade, Neuron, third-party `app.*`) ship as
 * Extensions and live under `src/extensions/<domain>.ts`. Consumers
 * register what they need. The Core never auto-loads domain content —
 * that is the load-bearing rule of the Box-vs-Content separation.
 */

export * from "./kash-id-profile";
export * from "./kash-id-audit";
export * from "./kash-id-preferences";

import type { LexiconDef } from "../registry";
import {
  KASH_PROFILE_BODY_SCHEMA, KASH_PROFILE_ID, KASH_PROFILE_NSID, KASH_PROFILE_VERSION,
} from "./kash-id-profile";
import {
  KASH_AUDIT_BODY_SCHEMA, KASH_AUDIT_ID, KASH_AUDIT_NSID, KASH_AUDIT_VERSION,
} from "./kash-id-audit";
import {
  KASH_PREFERENCES_BODY_SCHEMA, KASH_PREFERENCES_ID, KASH_PREFERENCES_NSID, KASH_PREFERENCES_VERSION,
} from "./kash-id-preferences";

/**
 * The Standard Library — every identity-tier lexicon every Kash actor
 * needs to interoperate at the protocol layer.
 *
 * Bootstrap pattern:
 *
 * ```ts
 * import { LexiconRegistry } from "@kashscript/lexicons";
 * import { STANDARD_LIBRARY } from "@kashscript/lexicons";
 *
 * const registry = new LexiconRegistry().registerAll(STANDARD_LIBRARY);
 * ```
 */
export const STANDARD_LIBRARY: readonly LexiconDef[] = [
  {
    id: KASH_PROFILE_ID,
    nsid: KASH_PROFILE_NSID,
    semver: KASH_PROFILE_VERSION,
    bodySchema: KASH_PROFILE_BODY_SCHEMA,
    title: "Kash Profile",
    description: "Sovereign user profile — display name, bio, avatar, pinned PDS URLs.",
  },
  {
    id: KASH_AUDIT_ID,
    nsid: KASH_AUDIT_NSID,
    semver: KASH_AUDIT_VERSION,
    bodySchema: KASH_AUDIT_BODY_SCHEMA,
    title: "Kash Audit Entry",
    description: "Append-only ledger of identity lifecycle events.",
  },
  {
    id: KASH_PREFERENCES_ID,
    nsid: KASH_PREFERENCES_NSID,
    semver: KASH_PREFERENCES_VERSION,
    bodySchema: KASH_PREFERENCES_BODY_SCHEMA,
    title: "Kash Preferences",
    description: "App-agnostic settings — theme, language, AI consent flags.",
  },
];
