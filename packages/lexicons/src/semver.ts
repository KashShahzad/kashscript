/**
 * Semver parsing and forward-compat resolution for Lexicon IDs.
 * Lexicon ID syntax: <nsid>@<major>.<minor>.<patch> — e.g., "kash.id.profile@1.2.0".
 */

import type { LexiconId } from "./types";

export interface Semver {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
}

export interface ParsedLexiconId {
  readonly nsid: string;
  readonly semver: Semver;
}

const LEXICON_ID_RE = /^([a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+)@(\d+)\.(\d+)\.(\d+)$/;

/** Parse a Lexicon ID. Returns null on malformed input. */
export function parseLexiconId(id: string): ParsedLexiconId | null {
  const m = LEXICON_ID_RE.exec(id);
  if (!m) return null;
  return {
    nsid: m[1]!,
    semver: {
      major: Number.parseInt(m[2]!, 10),
      minor: Number.parseInt(m[3]!, 10),
      patch: Number.parseInt(m[4]!, 10),
    },
  };
}

/** Build a Lexicon ID string from parts. */
export function formatLexiconId(nsid: string, semver: Semver): LexiconId {
  return `${nsid}@${semver.major}.${semver.minor}.${semver.patch}` as LexiconId;
}

/** Lexicographic compare. Returns negative/zero/positive (like Array.sort). */
export function compareSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

/**
 * Is the `record` semver forward-compatible with the `consumer` semver?
 *
 * v1.0 evolution rule: any record minted under <nsid>@X.Y.Z is acceptable to
 * a consumer that knows <nsid>@X.*. Cross-major requires an explicit migrator
 * (out of scope for this layer — handled by the consumer at a higher level).
 */
export function isForwardCompatible(consumer: Semver, record: Semver): boolean {
  return consumer.major === record.major;
}
