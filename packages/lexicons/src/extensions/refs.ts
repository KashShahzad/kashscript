/**
 * The shared shapes of the public records (ECOSYSTEM d59, d60, d62(d)4; KS-N1).
 *
 * A public record is identified by its publisher's DID plus a path — `did:kash:<publisher>/<kind>/<slug>`
 * (d60(a), the form the rule and the adoption already take) — so the record says who answers for it,
 * and every other record cites it by that identifier. These constants are the one place the patterns
 * are written; `door`, `place` and `lists` import them.
 *
 * The regex sources are the ones the published JSON Schemas carry (`specs/schemas/*.schema.json`);
 * a test keeps them in step, so a change here is a change to a published format.
 */

import { S, type Schema, type StringSchema } from "../schema";

/** The body of a `did:kash`: a base58btc key, 32–48 characters (identity-core's `deriveDid`). */
export const DID_BODY_SOURCE = "[1-9A-HJ-NP-Za-km-z]{32,48}";
/** A slug: lowercase, digits and hyphens, at most 63 characters. */
export const SLUG_SOURCE = "[a-z0-9][a-z0-9-]{0,62}";

export const DID: StringSchema = S.string({ format: "did-ks" });
export const ISO: StringSchema = S.string({ format: "iso8601" });
export const HEX64: StringSchema = S.string({ pattern: /^[0-9a-f]{64}$/ });
export const SLUG: StringSchema = S.string({ pattern: /^[a-z0-9][a-z0-9-]{0,62}$/ });
export const TEXT = (max: number): Schema => S.string({ minLength: 1, maxLength: max });

/** `did:kash:<author>/rule/<slug>` — a rule's id (KS-Q1). */
export const RULE_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/rule\/[a-z0-9][a-z0-9-]{0,62}$/ });
/** `did:kash:<anchor>/adoption/<slug>` — an adoption's id (KS-Q1b). */
export const ADOPTION_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/adoption\/[a-z0-9][a-z0-9-]{0,62}$/ });
/** `did:kash:<publisher>/place/<slug>` — a place's id (d60). Never a coordinate. */
export const PLACE_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/place\/[a-z0-9][a-z0-9-]{0,62}$/ });
/** `did:kash:<host>/listing/<slug>` — a listing's id. */
export const LISTING_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/listing\/[a-z0-9][a-z0-9-]{0,62}$/ });
/** `did:kash:<publisher>/guide/<slug>` — a guide's id. */
export const GUIDE_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/guide\/[a-z0-9][a-z0-9-]{0,62}$/ });

/** The kinds of public record a DID URL may name. */
export const RECORD_KINDS = ["place", "listing", "guide", "rule", "adoption"] as const;
export type RecordKind = (typeof RECORD_KINDS)[number];

/** Any public record's id: `did:kash:<publisher>/<kind>/<slug>`, for one of the kinds above. */
export const RECORD_REF: StringSchema = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/(?:place|listing|guide|rule|adoption)\/[a-z0-9][a-z0-9-]{0,62}$/ });

/** A `did:kash`, or a DID URL under one (`did:kash:…/<path>/<slug>`), with or without a `#fragment` (a key id), as one whole string. */
export const DID_OR_URL_RE = /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}(?:\/[a-z][a-z0-9.-]*\/[a-z0-9][a-z0-9-]{0,62})?(?:#[A-Za-z0-9._-]{1,64})?$/;

/** The DID a record id or DID URL is under: `did:kash:abc…/place/x` → `did:kash:abc…`. */
export function didOf(id: string): string {
  const slash = id.indexOf("/");
  return slash === -1 ? id : id.slice(0, slash);
}

/** The kind a record id names, or null: `did:kash:abc…/place/x` → `place`. */
export function kindOf(id: string): RecordKind | null {
  const m = /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/([a-z]+)\/[a-z0-9][a-z0-9-]{0,62}$/.exec(id);
  const kind = m?.[1];
  return kind !== undefined && (RECORD_KINDS as readonly string[]).includes(kind) ? (kind as RecordKind) : null;
}

/**
 * A fault a pure check finds in a body that already has its lexicon's shape — the rules the schema
 * DSL cannot write (one field against another). The code is stable; the message is for a person.
 */
export interface RecordFault {
  readonly code: string;
  readonly path: readonly (string | number)[];
  readonly message: string;
}

export const fault = (code: string, path: readonly (string | number)[], message: string): RecordFault => ({ code, path, message });
