/**
 * Lexicon: kash.id.profile@1.0.0
 *
 * Sovereign user profile. Single-record collection (rkey: "self" by convention).
 */

import { S, type ObjectSchema } from "../schema";
import type { CID } from "../types";

export const KASH_PROFILE_NSID    = "kash.id.profile" as const;
export const KASH_PROFILE_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_PROFILE_ID      = "kash.id.profile@1.0.0" as const;

/* ── types ──────────────────────────────────────────────────────── */

export type ProfileImageMime = "image/jpeg" | "image/png" | "image/webp" | "image/avif";

export interface ProfileBlobRef {
  readonly cid: CID;
  readonly mimeType: ProfileImageMime;
  readonly altText?: string;
}

export interface ProfileLink {
  readonly label: string;
  readonly url: string;
}

export interface KashProfileBody {
  /** Optional human-readable handle hint. The authoritative handle is in the DID Document's alsoKnownAs. */
  readonly handle?: string;
  /** Display name. 1–64 characters after NFC normalisation. */
  readonly displayName: string;
  /** Short bio. 0–280 characters. */
  readonly bio?: string;
  /** Avatar image blob reference. */
  readonly avatar?: ProfileBlobRef;
  /** Banner image blob reference. */
  readonly banner?: ProfileBlobRef;
  /** Free-form pronouns string. */
  readonly pronouns?: string;
  /** Human-readable location ("Islamabad, PK"). */
  readonly location?: string;
  /** Pinned PDS / relay URLs the author wants peers to discover. Max 8. */
  readonly pdsUrls?: readonly string[];
  /** External profile links. Max 8. */
  readonly links?: readonly ProfileLink[];
}

/* ── runtime schema ─────────────────────────────────────────────── */

const PROFILE_BLOB_REF: ObjectSchema = S.object(
  {
    cid:      S.string({ format: "cid" }),
    mimeType: S.enum("image/jpeg", "image/png", "image/webp", "image/avif"),
    altText:  S.optional(S.string({ maxLength: 420 })),
  },
  ["cid", "mimeType"],
);

const PROFILE_LINK: ObjectSchema = S.object(
  {
    label: S.string({ minLength: 1, maxLength: 32 }),
    url:   S.string({ format: "url" }),
  },
  ["label", "url"],
);

export const KASH_PROFILE_BODY_SCHEMA: ObjectSchema = S.object(
  {
    handle:      S.optional(S.string({ minLength: 1, maxLength: 64 })),
    displayName: S.string({ minLength: 1, maxLength: 64 }),
    bio:         S.optional(S.string({ maxLength: 280 })),
    avatar:      S.optional(PROFILE_BLOB_REF),
    banner:      S.optional(PROFILE_BLOB_REF),
    pronouns:    S.optional(S.string({ maxLength: 32 })),
    location:    S.optional(S.string({ maxLength: 64 })),
    pdsUrls:     S.optional(S.array(S.string({ format: "url" }), { maxItems: 8 })),
    links:       S.optional(S.array(PROFILE_LINK, { maxItems: 8 })),
  },
  ["displayName"],
);
