/**
 * Social Extension — domain lexicons (Indusland-shaped but Indusland-agnostic).
 *
 *   kash.social.post@1.0.0          — a post (text, media, optional Bento metadata).
 *   kash.social.interaction@1.0.0   — unified like / share / react event.
 *   kash.social.follow@1.0.0        — directed relationship between two DIDs.
 *
 * Import path: `@kashscript/lexicons/extensions/social`.
 *
 * This file is an **extension**: the Foundry core never auto-loads it.
 * Consumers explicitly register `SOCIAL_EXTENSION` against their
 * `LexiconRegistry` to opt in to social-domain validation.
 *
 * Data minimisation: every field that is not load-bearing for the specific
 * action is optional.
 */

import { RECORD_REF_SCHEMA, type RecordRef } from "../envelope";
import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 *  kash.social.post@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_SOCIAL_POST_NSID    = "kash.social.post" as const;
export const KASH_SOCIAL_POST_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_SOCIAL_POST_ID      = "kash.social.post@1.0.0" as const;

export type BentoAccent = "sun" | "poppy" | "sky" | "lilac" | "sage" | "rose";
export type BentoSize   = "small" | "medium" | "large";

export interface BentoMeta {
  readonly title?: string;
  readonly accent?: BentoAccent;
  readonly size?: BentoSize;
}

export type PostMediaMime =
  | "image/jpeg" | "image/png" | "image/webp" | "image/avif"
  | "video/mp4"  | "video/webm"
  | "audio/mpeg" | "audio/ogg";

export interface PostMediaRef {
  readonly cid: string;
  readonly mimeType: PostMediaMime;
  readonly altText?: string;
  readonly width?: number;
  readonly height?: number;
  readonly durationMs?: number;
}

export interface KashSocialPostBody {
  readonly text?: string;
  readonly media?: readonly PostMediaRef[];
  readonly bento?: BentoMeta;
  readonly replyTo?: RecordRef;
  readonly repostOf?: RecordRef;
  readonly mentions?: readonly string[];
  readonly tags?: readonly string[];
  readonly lang?: string;
}

const POST_MEDIA_REF: ObjectSchema = S.object(
  {
    cid:        S.string({ format: "cid" }),
    mimeType:   S.enum(
      "image/jpeg", "image/png", "image/webp", "image/avif",
      "video/mp4",  "video/webm",
      "audio/mpeg", "audio/ogg",
    ),
    altText:    S.optional(S.string({ maxLength: 420 })),
    width:      S.optional(S.number({ integer: true, min: 1, max: 16384 })),
    height:     S.optional(S.number({ integer: true, min: 1, max: 16384 })),
    durationMs: S.optional(S.number({ integer: true, min: 0, max: 86_400_000 })),
  },
  ["cid", "mimeType"],
);

const BENTO_META: ObjectSchema = S.object(
  {
    title:  S.optional(S.string({ minLength: 1, maxLength: 80 })),
    accent: S.optional(S.enum("sun", "poppy", "sky", "lilac", "sage", "rose")),
    size:   S.optional(S.enum("small", "medium", "large")),
  },
  [],
);

export const KASH_SOCIAL_POST_BODY_SCHEMA: ObjectSchema = S.object(
  {
    text:     S.optional(S.string({ maxLength: 1000 })),
    media:    S.optional(S.array(POST_MEDIA_REF, { maxItems: 8 })),
    bento:    S.optional(BENTO_META),
    replyTo:  S.optional(RECORD_REF_SCHEMA),
    repostOf: S.optional(RECORD_REF_SCHEMA),
    mentions: S.optional(S.array(S.string({ format: "did-ks" }), { maxItems: 16 })),
    tags:     S.optional(S.array(S.string({ minLength: 1, maxLength: 32, pattern: /^[a-z0-9][a-z0-9_-]*$/ }), { maxItems: 16 })),
    lang:     S.optional(S.string({ format: "bcp47" })),
  },
  [],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.social.interaction@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_SOCIAL_INTERACTION_NSID    = "kash.social.interaction" as const;
export const KASH_SOCIAL_INTERACTION_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_SOCIAL_INTERACTION_ID      = "kash.social.interaction@1.0.0" as const;

export type InteractionType = "like" | "share" | "react";

export interface KashSocialInteractionBody {
  readonly type: InteractionType;
  readonly target: RecordRef;
  readonly reaction?: string;
}

export const KASH_SOCIAL_INTERACTION_BODY_SCHEMA: ObjectSchema = S.object(
  {
    type:     S.enum("like", "share", "react"),
    target:   RECORD_REF_SCHEMA,
    reaction: S.optional(S.string({ minLength: 1, maxLength: 16 })),
  },
  ["type", "target"],
);

/* ─────────────────────────────────────────────────────────────────
 *  kash.social.follow@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_SOCIAL_FOLLOW_NSID    = "kash.social.follow" as const;
export const KASH_SOCIAL_FOLLOW_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_SOCIAL_FOLLOW_ID      = "kash.social.follow@1.0.0" as const;

export interface KashSocialFollowBody {
  readonly subject: string;
  readonly subjectHandle?: string;
}

export const KASH_SOCIAL_FOLLOW_BODY_SCHEMA: ObjectSchema = S.object(
  {
    subject:       S.string({ format: "did-ks" }),
    subjectHandle: S.optional(S.string({ minLength: 1, maxLength: 64 })),
  },
  ["subject"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

/** All Social-domain lexicons. Pass to `LexiconRegistry.registerAll()`. */
export const SOCIAL_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_SOCIAL_POST_ID,
    nsid: KASH_SOCIAL_POST_NSID,
    semver: KASH_SOCIAL_POST_VERSION,
    bodySchema: KASH_SOCIAL_POST_BODY_SCHEMA,
    title: "Social Post",
    description: "A post — text, media, and optional Bento-style tile metadata.",
  },
  {
    id: KASH_SOCIAL_INTERACTION_ID,
    nsid: KASH_SOCIAL_INTERACTION_NSID,
    semver: KASH_SOCIAL_INTERACTION_VERSION,
    bodySchema: KASH_SOCIAL_INTERACTION_BODY_SCHEMA,
    title: "Social Interaction",
    description: "Unified like / share / react event against a post.",
  },
  {
    id: KASH_SOCIAL_FOLLOW_ID,
    nsid: KASH_SOCIAL_FOLLOW_NSID,
    semver: KASH_SOCIAL_FOLLOW_VERSION,
    bodySchema: KASH_SOCIAL_FOLLOW_BODY_SCHEMA,
    title: "Social Follow",
    description: "Directed follow relationship between two DIDs.",
  },
];
