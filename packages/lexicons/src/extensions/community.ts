/**
 * Community Extension — community-domain lexicons (Acmecase-shaped).
 *
 *   kash.community.membership@1.0.0      — verifiable community-member record
 *   kash.community.aid-claim@1.0.0       — a member's claim against a mutual-aid pool
 *
 * Import path: `@kashscript/lexicons/extensions/community`.
 *
 * Pairs with the Acmecase program at
 * `apps/kashscript/app/studio/acmecase`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 *  kash.community.membership@1.0.0
 *
 *  A community (cooperative, mosque committee, building society)
 *  signs one record per current member. Holder selectively discloses
 *  membership to others without revealing their identity if desired.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_COMMUNITY_MEMBERSHIP_NSID    = "kash.community.membership" as const;
export const KASH_COMMUNITY_MEMBERSHIP_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_COMMUNITY_MEMBERSHIP_ID      = "kash.community.membership@1.0.0" as const;

export type MembershipStatus = "active" | "lapsed" | "suspended" | "honorary";

export const KASH_COMMUNITY_MEMBERSHIP_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** Member's DID — kept hidden in many disclosures. */
    memberDid: S.string({ format: "did-ks" }),
    /** Community's short codename (e.g., "f7-residents", "lahore-coop-1"). */
    communityCode: S.string({ minLength: 1, maxLength: 64, pattern: /^[a-z0-9][a-z0-9_-]*$/ }),
    /** Display name of the community. */
    communityName: S.string({ minLength: 1, maxLength: 200 }),
    /** Status of the membership at issue time. */
    status: S.enum("active", "lapsed", "suspended", "honorary"),
    /** ISO date the member joined. */
    joinedAt: S.string({ format: "iso8601" }),
    /** ISO date this attestation expires — invites periodic re-issue. */
    expiresAt: S.string({ format: "iso8601" }),
    /** Optional member role within the community. */
    role: S.optional(S.string({ minLength: 1, maxLength: 64 })),
  },
  ["memberDid", "communityCode", "communityName", "status", "joinedAt", "expiresAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.community.aid-claim@1.0.0
 *
 *  A member's signed claim against a community mutual-aid pool.
 *  Pairs with the SUBSCRIPTION-based pool in
 *  `packages/trade-sdk/use-cases/acmecase-mutual-aid`.
 * ───────────────────────────────────────────────────────────────── */

export const KASH_COMMUNITY_AID_CLAIM_NSID    = "kash.community.aid-claim" as const;
export const KASH_COMMUNITY_AID_CLAIM_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_COMMUNITY_AID_CLAIM_ID      = "kash.community.aid-claim@1.0.0" as const;

export type AidClaimKind =
  | "medical"
  | "rent"
  | "utilities"
  | "education"
  | "funeral"
  | "emergency"
  | "other";

export const KASH_COMMUNITY_AID_CLAIM_BODY_SCHEMA: ObjectSchema = S.object(
  {
    /** Claimant's DID. */
    claimantDid: S.string({ format: "did-ks" }),
    /** Pool's manifest id (the Trade SUBSCRIPTION manifest the claim draws from). */
    poolManifestId: S.string({ minLength: 1, maxLength: 200 }),
    /** Kind of need. */
    kind: S.enum("medical", "rent", "utilities", "education", "funeral", "emergency", "other"),
    /** Amount requested, in base units (decimal-stringified bigint to avoid JSON number loss). */
    amountBaseUnits: S.string({ minLength: 1, maxLength: 80, pattern: /^[0-9]+$/ }),
    /** Currency code (e.g., "PKR"). */
    currency: S.string({ minLength: 1, maxLength: 16 }),
    /** Free-text justification — what the claim is for. */
    justification: S.string({ minLength: 1, maxLength: 5_000 }),
    /** Optional pointer to supporting documents on a PDS. */
    supportingDocsCid: S.optional(S.string({ format: "cid" })),
    /** ISO date the claim was filed. */
    filedAt: S.string({ format: "iso8601" }),
  },
  ["claimantDid", "poolManifestId", "kind", "amountBaseUnits", "currency", "justification", "filedAt"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

export const COMMUNITY_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_COMMUNITY_MEMBERSHIP_ID,
    nsid: KASH_COMMUNITY_MEMBERSHIP_NSID,
    semver: KASH_COMMUNITY_MEMBERSHIP_VERSION,
    bodySchema: KASH_COMMUNITY_MEMBERSHIP_BODY_SCHEMA,
    title: "Community Membership",
    description: "Verifiable community-member record issued by a community admin.",
  },
  {
    id: KASH_COMMUNITY_AID_CLAIM_ID,
    nsid: KASH_COMMUNITY_AID_CLAIM_NSID,
    semver: KASH_COMMUNITY_AID_CLAIM_VERSION,
    bodySchema: KASH_COMMUNITY_AID_CLAIM_BODY_SCHEMA,
    title: "Community Aid Claim",
    description: "A member's signed claim against a community mutual-aid pool.",
  },
];
