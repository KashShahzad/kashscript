/**
 * Shared brand types used across the lexicon framework. Kept local to
 * preserve the zero-dependency posture; the canonical did:kash types
 * live in `@kashscript/identity-core/types`.
 */

/** W3C DID restricted to the did:kash method emitted by `@kashscript/identity-core`. */
export type DID = `did:kash:${string}`;

/** CIDv1 multibase, base32, "bafy" prefix. */
export type CID = `bafy${string}`;

/** Lexicon ID — <nsid>@<semver>, e.g., "kash.id.profile@1.0.0". */
export type LexiconId = `${string}@${number}.${number}.${number}`;

/** Multibase-encoded byte string ("z"-prefixed base58-btc). */
export type Multibase = `z${string}`;

/** ISO-8601 timestamp with offset, e.g. "2026-05-09T12:34:56Z". */
export type Iso8601 = string;

/** Signature algorithm identifier. Phase-4 adds "es256"; Phase-5 adds "bls12-381-g2". */
export type SignatureAlgorithm = "ed25519" | "es256" | "bls12-381-g2";

/** Domain-Separation Tag for record-tier signatures (Identity Protocol §5.5). */
export const KASH_RECORD_DST = "kash-record-v1\n" as const;
export type KashRecordDST = typeof KASH_RECORD_DST;
