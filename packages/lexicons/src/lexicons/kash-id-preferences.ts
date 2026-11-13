/**
 * Lexicon: kash.id.preferences@1.0.0
 *
 * App-agnostic user preferences. Single-record collection (rkey: "self").
 *
 * Privacy-by-default: if `privacy.allowAI` is absent or any flag within it
 * is absent, the relevant flag defaults to FALSE. Oreoasis MUST NOT ingest
 * a user's records without `allowAI.neuronIngest === true`.
 */

import { S, type ObjectSchema } from "../schema";

export const KASH_PREFERENCES_NSID    = "kash.id.preferences" as const;
export const KASH_PREFERENCES_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_PREFERENCES_ID      = "kash.id.preferences@1.0.0" as const;

/* ── types ──────────────────────────────────────────────────────── */

export type ThemePref     = "light" | "dark" | "system";
export type Visibility    = "public" | "followers" | "private";
export type TimeFormat    = "12h" | "24h";

export interface AIConsent {
  /** May my records be used to train models? */
  readonly training: boolean;
  /** May my records be retrieved at inference time (RAG)? */
  readonly inference: boolean;
  /** May Oreoasis (Neuron) ingest my records into its context engine? */
  readonly neuronIngest: boolean;
  /** Optional list of NSIDs explicitly excluded from any AI use. */
  readonly excludedCollections?: readonly string[];
}

export interface PrivacyPreferences {
  /** Visibility of the profile to non-followers / public crawlers. */
  readonly profileVisibility: Visibility;
  /** Whether crawlers / federation peers may index this identity. */
  readonly indexable: boolean;
  /** AI consent flags — ALL DEFAULT FALSE if absent. */
  readonly allowAI?: AIConsent;
}

export interface NotificationPreferences {
  readonly handshakes: boolean;
  readonly keyRotations: boolean;
  readonly quorumActivity: boolean;
}

export interface UnitPreferences {
  /** ISO 4217 currency code (USD, PKR, EUR, …). */
  readonly currency: string;
  readonly timeFormat: TimeFormat;
  /** strftime-like template ("%Y-%m-%d"). */
  readonly dateFormat: string;
}

export interface KashPreferencesBody {
  /** BCP 47 language tag ("en", "ur-PK"). */
  readonly language?: string;
  readonly theme?: ThemePref;
  readonly privacy?: PrivacyPreferences;
  readonly notifications?: NotificationPreferences;
  readonly units?: UnitPreferences;
}

/* ── runtime schema ─────────────────────────────────────────────── */

const AI_CONSENT: ObjectSchema = S.object(
  {
    training:            S.boolean(),
    inference:           S.boolean(),
    neuronIngest:        S.boolean(),
    excludedCollections: S.optional(S.array(S.string({ format: "nsid" }), { maxItems: 64 })),
  },
  ["training", "inference", "neuronIngest"],
);

const PRIVACY: ObjectSchema = S.object(
  {
    profileVisibility: S.enum("public", "followers", "private"),
    indexable:         S.boolean(),
    allowAI:           S.optional(AI_CONSENT),
  },
  ["profileVisibility", "indexable"],
);

const NOTIFICATIONS: ObjectSchema = S.object(
  {
    handshakes:     S.boolean(),
    keyRotations:   S.boolean(),
    quorumActivity: S.boolean(),
  },
  ["handshakes", "keyRotations", "quorumActivity"],
);

const UNITS: ObjectSchema = S.object(
  {
    currency:   S.string({ format: "iso4217" }),
    timeFormat: S.enum("12h", "24h"),
    dateFormat: S.string({ minLength: 1, maxLength: 32 }),
  },
  ["currency", "timeFormat", "dateFormat"],
);

export const KASH_PREFERENCES_BODY_SCHEMA: ObjectSchema = S.object(
  {
    language:      S.optional(S.string({ format: "bcp47" })),
    theme:         S.optional(S.enum("light", "dark", "system")),
    privacy:       S.optional(PRIVACY),
    notifications: S.optional(NOTIFICATIONS),
    units:         S.optional(UNITS),
  },
  [],
);
