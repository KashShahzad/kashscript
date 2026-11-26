/**
 * The shared shapes of the public records (ECOSYSTEM d59, d60, d62(d)4; KS-N1; RW-19 B).
 *
 * A public record is identified by its publisher's DID plus a path — `<publisher DID>/<kind>/<slug>`
 * (d60(a), the form the rule and the adoption already take) — so the record says who answers for it,
 * and every other record cites it by that identifier. **Since RW-19 B (d97(h)) the publisher's DID is
 * a standard method:** `did:web` for an organisation on its own domain (d91(e)), or `did:key` for a
 * publisher signing with a self-certifying key; `did:kash`, the same key's house spelling, stays in
 * the grammar so every record and citation already written reads for ever. These constants are the
 * one place the patterns are written; `door`, `place` and `lists` import them.
 *
 * The regex sources are the ones the published JSON Schemas carry (`specs/schemas/*.schema.json`);
 * a test keeps them in step, so a change here is a change to a published format. The `did:key` and
 * `did:web` sources are identity-core's (`did-key.ts`, `did-web.ts`), copied because this package
 * stays zero-dependency; a test keeps those in step too.
 */

import { S, type Schema, type StringSchema } from "../schema";

/** The body of a `did:kash`: a base58btc key, 32–48 characters (identity-core's `deriveDid`). */
export const DID_BODY_SOURCE = "[1-9A-HJ-NP-Za-km-z]{32,48}";
/** A `did:key` (the standard spelling of a self-certifying key, RW-19 B) — identity-core's `DID_KEY_SOURCE`, copied. */
export const DID_KEY_SOURCE = "did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}";
/** A `did:web` (an organisation on its own domain, d91(e)) — identity-core's `DID_WEB_SOURCE`, copied. */
export const DID_WEB_SOURCE = "did:web:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?:%3A[0-9]{1,5})?(?::[A-Za-z0-9._-]{1,64}){0,8}";
/** A slug: lowercase, digits and hyphens, at most 63 characters. */
export const SLUG_SOURCE = "[a-z0-9][a-z0-9-]{0,62}";

/** A publisher who answers for a public record: `did:web`, `did:key`, or the `did:kash` house spelling (RW-19 B). */
export const PUBLISHER_DID_SOURCE = `(?:did:kash:${DID_BODY_SOURCE}|${DID_KEY_SOURCE}|${DID_WEB_SOURCE})`;
/** A self-certifying key of either spelling — what signs where no domain stands behind the name (d28). */
export const SELF_CERTIFYING_DID_SOURCE = `(?:did:kash:${DID_BODY_SOURCE}|${DID_KEY_SOURCE})`;

export const DID: StringSchema = S.string({ format: "did-ks" });
/** A public record's publisher, author, anchor or host (RW-19 B). */
export const PUBLISHER: StringSchema = S.string({ pattern: new RegExp(`^${PUBLISHER_DID_SOURCE}$`) });
/** A self-certifying key of either spelling — a trust list's publisher stays one, so the list's own signature checks from the identifier alone. */
export const SELF_CERTIFYING: StringSchema = S.string({ pattern: new RegExp(`^${SELF_CERTIFYING_DID_SOURCE}$`) });
export const ISO: StringSchema = S.string({ format: "iso8601" });
export const HEX64: StringSchema = S.string({ pattern: /^[0-9a-f]{64}$/ });
export const SLUG: StringSchema = S.string({ pattern: /^[a-z0-9][a-z0-9-]{0,62}$/ });
export const TEXT = (max: number): Schema => S.string({ minLength: 1, maxLength: max });

const recordRef = (kind: string): StringSchema => S.string({ pattern: new RegExp(`^${PUBLISHER_DID_SOURCE}\\/${kind}\\/${SLUG_SOURCE}$`) });

/** `<author DID>/rule/<slug>` — a rule's id (KS-Q1). */
export const RULE_REF: StringSchema = recordRef("rule");
/** `<anchor DID>/adoption/<slug>` — an adoption's id (KS-Q1b). */
export const ADOPTION_REF: StringSchema = recordRef("adoption");
/** `<publisher DID>/place/<slug>` — a place's id (d60). Never a coordinate. */
export const PLACE_REF: StringSchema = recordRef("place");
/** `<host DID>/listing/<slug>` — a listing's id. */
export const LISTING_REF: StringSchema = recordRef("listing");
/** `<publisher DID>/guide/<slug>` — a guide's id. */
export const GUIDE_REF: StringSchema = recordRef("guide");

/** The kinds of public record a DID URL may name. */
export const RECORD_KINDS = ["place", "listing", "guide", "rule", "adoption"] as const;
export type RecordKind = (typeof RECORD_KINDS)[number];

/** Any public record's id: `<publisher DID>/<kind>/<slug>`, for one of the kinds above. */
export const RECORD_REF: StringSchema = recordRef("(?:place|listing|guide|rule|adoption)");

/** A publisher DID, or a DID URL under one (`…/<path>/<slug>`), with or without a `#fragment` (a key id), as one whole string. */
export const DID_OR_URL_RE = new RegExp(`^${PUBLISHER_DID_SOURCE}(?:\\/[a-z][a-z0-9.-]*\\/${SLUG_SOURCE})?(?:#[A-Za-z0-9._-]{1,64})?$`);

/** The DID a record id or DID URL is under: `did:web:x.example/place/x` → `did:web:x.example`. */
export function didOf(id: string): string {
  const slash = id.indexOf("/");
  return slash === -1 ? id : id.slice(0, slash);
}

/** The kind a record id names, or null: `did:web:x.example/place/x` → `place`. */
export function kindOf(id: string): RecordKind | null {
  const m = new RegExp(`^${PUBLISHER_DID_SOURCE}\\/([a-z]+)\\/${SLUG_SOURCE}$`).exec(id);
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
