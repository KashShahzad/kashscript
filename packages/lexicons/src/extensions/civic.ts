/**
 * Civic Extension — governance-domain lexicons (Cliffhase-shaped).
 *
 *   kash.civic.permit@1.0.0           — a permit / licence issued by an agency
 *   kash.civic.petition@1.0.0         — a citizen petition with optional pledge
 *
 * Import path: `@kashscript/lexicons/extensions/civic`.
 *
 * Pairs with the Cliffhase program at
 * `apps/kashscript/app/studio/cliffhase`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 *  kash.civic.permit@1.0.0
 *
 *  A typed record of a permit / licence / certification issued by a
 *  government body. Holder presents this (or a ZK disclosure of part
 *  of it) to anyone who needs to confirm the credential.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_CIVIC_PERMIT_NSID    = "kash.civic.permit" as const;
export const KASH_CIVIC_PERMIT_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_CIVIC_PERMIT_ID      = "kash.civic.permit@1.0.0" as const;

export type PermitKind =
  | "driving"
  | "professional"
  | "business"
  | "import-export"
  | "construction"
  | "occupancy"
  | "food-handling"
  | "other";

export const KASH_CIVIC_PERMIT_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** Holder DID. */
    holderDid: S.string({ format: "did-ks" }),
    /** Issuing agency identifier — agency's own short code. */
    issuingAgency: S.string({ minLength: 1, maxLength: 64 }),
    /** Permit / licence number on the agency's system. */
    permitNumber: S.string({ minLength: 1, maxLength: 64 }),
    /** What kind of permit. */
    kind: S.enum(
      "driving", "professional", "business", "import-export",
      "construction", "occupancy", "food-handling", "other",
    ),
    /** ISO date when it was issued. */
    issuedAt: S.string({ format: "iso8601" }),
    /** ISO date when it expires — required so a verifier can check freshness. */
    expiresAt: S.string({ format: "iso8601" }),
    /** Scope of authority granted (free-text). */
    scope: S.string({ minLength: 1, maxLength: 500 }),
    /** Jurisdiction code (ISO-3166-2 or local extension). */
    jurisdiction: S.string({ minLength: 1, maxLength: 16 }),
    /** Optional pointer to the on-paper / on-system source record. */
    sourceUri: S.optional(S.string({ minLength: 1, maxLength: 500 })),
  },
  ["holderDid", "issuingAgency", "permitNumber", "kind", "issuedAt", "expiresAt", "scope", "jurisdiction"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.civic.petition@1.0.0
 *
 *  A citizen-initiated petition record. Other citizens sign their
 *  endorsement as separate envelopes referencing this record's cid.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_CIVIC_PETITION_NSID    = "kash.civic.petition" as const;
export const KASH_CIVIC_PETITION_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_CIVIC_PETITION_ID      = "kash.civic.petition@1.0.0" as const;

export const KASH_CIVIC_PETITION_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** Petition title — 1 sentence, displayed verbatim. */
    title: S.string({ minLength: 1, maxLength: 200 }),
    /** Long-form description. */
    body: S.string({ minLength: 1, maxLength: 50_000 }),
    /** Target agency / official the petition addresses. */
    targetAgency: S.string({ minLength: 1, maxLength: 200 }),
    /** Jurisdiction the petition belongs to. */
    jurisdiction: S.string({ minLength: 1, maxLength: 16 }),
    /** Optional ISO date by which the petitioner needs a response. */
    responseBy: S.optional(S.string({ format: "iso8601" })),
    /** Minimum signatures required for this petition to be valid in the host system. */
    quorumTarget: S.optional(S.number({ min: 1, max: 10_000_000 })),
    /** ISO date the petition was opened for signatures. */
    openedAt: S.string({ format: "iso8601" }),
  },
  ["title", "body", "targetAgency", "jurisdiction", "openedAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

export const CIVIC_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_CIVIC_PERMIT_ID,
    nsid: KASH_CIVIC_PERMIT_NSID,
    semver: KASH_CIVIC_PERMIT_VERSION,
    bodySchema: KASH_CIVIC_PERMIT_BODY_SCHEMA,
    title: "Civic Permit",
    description: "Government-issued permit / licence record.",
  },
  {
    id: KASH_CIVIC_PETITION_ID,
    nsid: KASH_CIVIC_PETITION_NSID,
    semver: KASH_CIVIC_PETITION_VERSION,
    bodySchema: KASH_CIVIC_PETITION_BODY_SCHEMA,
    title: "Civic Petition",
    description: "A citizen-initiated petition addressed to a government body.",
  },
];
