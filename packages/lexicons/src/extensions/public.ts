/**
 * The public records — everything `@kashscript/lexicons` holds that muffler may publish (ECOSYSTEM d59(a):
 * public, organisation-authored records, never a person's; KS-N1).
 *
 * This module is the one list muffler's guard admits, the cross-field checks for each kind in one call, and
 * the person-identity scan every public record passes before it is published. It is content, not a shape of
 * its own: the lexicons live in `door`, `place` and `lists`.
 *
 * What is **not** here, by design: the identity-tier standard library (`kash.id.*`, a person's own profile,
 * audit and preferences), the `social`, `zkp`, `education`, `civic` and `community` extensions (records
 * about or by people, kept for the apps that hold them), and the decision receipt (the person's own record,
 * in `@kashscript/predicate`). A guard that admits only this list refuses all of them by kind.
 *
 * Import path: `@kashscript/lexicons/extensions/public`.
 */

import type { LexiconDef } from "../registry";
import { DOOR_LEXICONS } from "./door";
import {
  KASH_GUIDE_NSID,
  KASH_LISTING_NSID,
  KASH_PLACE_NSID,
  KASH_PLACE_POINTER_NSID,
  PLACE_LEXICONS,
  guideFaults,
  listingFaults,
  placeFaults,
  placePointerFaults,
  type GuideBody,
  type ListingBody,
  type PlaceBody,
  type PlacePointerBody,
} from "./place";
import { KASH_STATUS_LIST_NSID, KASH_TRUST_LIST_NSID, LIST_LEXICONS, statusListFaults, trustListFaults, type StatusListBody, type TrustListBody } from "./lists";
import { DID_OR_URL_RE, type RecordFault } from "./refs";

/** Every public, organisation-authored lexicon the kernel knows: the door's, the places', the lists'. */
export const PUBLIC_RECORD_LEXICONS: readonly LexiconDef[] = [...DOOR_LEXICONS, ...PLACE_LEXICONS, ...LIST_LEXICONS];

/** Their NSIDs, each once. */
export const PUBLIC_RECORD_NSIDS: readonly string[] = [...new Set(PUBLIC_RECORD_LEXICONS.map((d) => d.nsid))];

export function isPublicRecordNsid(nsid: string): boolean {
  return PUBLIC_RECORD_NSIDS.includes(nsid);
}

/**
 * The cross-field rules for a public record whose body already has its lexicon's shape, by NSID. A rule's
 * and an adoption's meaning — the floor's refusals, bounds, the FEEL — is `@kashscript/predicate`'s, so for
 * them this returns nothing. An unknown NSID returns nothing too: whether it is admitted at all is the guard's call.
 */
export function publicRecordFaults(nsid: string, body: unknown): readonly RecordFault[] {
  switch (nsid) {
    case KASH_PLACE_NSID:
      return placeFaults(body as PlaceBody);
    case KASH_PLACE_POINTER_NSID:
      return placePointerFaults(body as PlacePointerBody);
    case KASH_LISTING_NSID:
      return listingFaults(body as ListingBody);
    case KASH_GUIDE_NSID:
      return guideFaults(body as GuideBody);
    case KASH_TRUST_LIST_NSID:
      return trustListFaults(body as TrustListBody);
    case KASH_STATUS_LIST_NSID:
      return statusListFaults(body as StatusListBody);
    default:
      return [];
  }
}

/* ── the person-identity scan ──────────────────────────────────────── */

export interface PersonIdentityFinding {
  /** Where in the body (object keys and array indexes). */
  readonly path: readonly (string | number)[];
  /** `an email address` · `a phone number` · `a DID`. */
  readonly what: string;
  /** The text that matched. */
  readonly found: string;
}

/**
 * A run of at least ten digits, written as a phone number is — never a date, a time or an amount.
 * Copied from `@kashscript/predicate`'s vocabulary (`phoneIn`), not imported: lexicons has no dependency.
 */
function phoneIn(text: string): string | null {
  const scrubbed = text.replace(/\d{4}-\d{2}-\d{2}(?:T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?/g, " ");
  for (const m of scrubbed.matchAll(/\+?\d[\d\s().-]{8,}\d/g)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 10 && !/^\d+\.\d+$/.test(m[0].trim())) return m[0];
  }
  return null;
}

/** An email, a phone number or a DID in free text. The same three as predicate's `CONTACT_PATTERNS`. */
const CONTACT_PATTERNS: readonly { readonly what: string; readonly find: (text: string) => string | null }[] = [
  { what: "an email address", find: (t) => /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.exec(t)?.[0] ?? null },
  { what: "a phone number", find: phoneIn },
  { what: "a DID", find: (t) => /did:[a-z0-9]+:[A-Za-z0-9._%-]+/.exec(t)?.[0] ?? null },
];

/**
 * Strings that are identifiers or encodings, not words — a DID or DID URL, a hex digest or key, a CID, a
 * base64url bitstring, a URL. A whole-string identifier is what the record's own fields hold (`publisher`,
 * `id`, `keyid`, `cid`); the scan leaves them alone and reads everything else as words.
 */
function isIdentifierOrEncoding(s: string): boolean {
  return DID_OR_URL_RE.test(s) || /^[0-9a-f]{32,}$/i.test(s) || /^bafy[a-z2-7]+$/.test(s) || /^u[A-Za-z0-9_-]{16,}$/.test(s);
}

const isUrl = (s: string): boolean => /^https?:\/\//.test(s);

/**
 * Find a person's identity in a public record: an email address, a phone number or a DID inside free text,
 * at any depth, keys included. Identifier fields — a whole DID, a hash, a CID — are left alone; a URL is read
 * for an email only (its digits are not a phone number). Returns the first finding, or null.
 *
 * This is the content half of the guard d59 asks for. The kind half — admitting only public, organisation-
 * authored lexicons — is `PUBLIC_RECORD_LEXICONS`. Neither can tell a person's key from an organisation's: no
 * directory exists, by design (d41); a key is an organisation's when a trust list says so (d91(f), KS-Q4).
 */
export function findPersonIdentity(value: unknown): PersonIdentityFinding | null {
  return scan(value, []);
}

function scan(value: unknown, path: readonly (string | number)[]): PersonIdentityFinding | null {
  if (typeof value === "string") return scanText(value, path);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = scan(value[i], [...path, i]);
      if (hit !== null) return hit;
    }
    return null;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const keyHit = scanText(k, [...path, k]);
      if (keyHit !== null) return keyHit;
      const hit = scan(v, [...path, k]);
      if (hit !== null) return hit;
    }
  }
  return null;
}

function scanText(text: string, path: readonly (string | number)[]): PersonIdentityFinding | null {
  if (isIdentifierOrEncoding(text)) return null;
  const patterns = isUrl(text) ? CONTACT_PATTERNS.filter((p) => p.what === "an email address") : CONTACT_PATTERNS;
  for (const { what, find } of patterns) {
    const found = find(text);
    if (found !== null) return { path, what, found };
  }
  return null;
}
