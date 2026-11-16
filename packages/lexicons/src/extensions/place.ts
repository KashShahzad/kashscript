/**
 * Place Extension — the public records about places and what is offered at them (ECOSYSTEM d59(a), d60,
 * d62(d)4, d69(c), d83(c), d93(e)2; KS-N1, folding in KS-R5).
 *
 *   kash.place@1.0.0
 *     A place: `did:kash:<publisher>/place/<slug>` (d60) — an island, a kasbah, a landmark, a landscape, a
 *     business's own premises or a meeting place. Indusland publishes landmarks and landscapes; a business
 *     publishes its own premises. **It carries no coordinate, no point and no polygon** — positions live in
 *     the template that draws them (d69(c); Indusland's geography, IL-V7) — so nothing here is a boundary
 *     or a claim on the land: the names are labels (d69).
 *
 *   kash.place.pointer@1.0.0
 *     A place that changes publisher gets a new identifier and a signed pointer from the old one; the old
 *     record is never rewritten (d60(a)). The pointer is the old publisher's record.
 *
 *   kash.listing@1.0.0
 *     An offering at one or more places, with its published price (d59(a); d93(e)2: the listing is a signed
 *     public record in muffler and lexicons). It has no rating, star, average, review or count (d62(c)7,
 *     d41, d43) — quality is shown as receipts and track record, never marked. It names no door and no
 *     sector of its own: its sector is an ISIC Revision 5 code, as a rule's address is (d85(c), d46).
 *
 *   kash.guide@1.0.0
 *     A publisher's text about places, with the records it cites (d59(a): guides and ebooks — Maktub's since
 *     d93). Its credits are chosen bylines (d51: art is commissioned and credited), never identifiers.
 *
 * Every shape is closed: a field this schema does not name is refused, so none can carry a score, a count, a
 * coordinate or a person's identity. The checks the schema DSL cannot write (one field against another) are
 * the `*Faults` functions beside each shape; `@kashscript/lexicons/extensions/public` runs them and the
 * person-identity scan for every public record, and muffler's guard runs that.
 *
 * Import path: `@kashscript/lexicons/extensions/place`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema, type StringSchema } from "../schema";
import { DID, GUIDE_REF, HEX64, ISO, LISTING_REF, PLACE_REF, RECORD_REF, TEXT, didOf, fault, type RecordFault } from "./refs";

/* ── shared pieces ─────────────────────────────────────────────────── */

const LANG = S.string({ format: "bcp47" });
/** Other names, by language (BCP 47): Urdu and Roman Urdu beside English, the launch languages. */
const NAMES = S.record(TEXT(120), LANG);

export interface MediaRef {
  readonly cid: string;
  readonly mimeType: string;
  readonly alt?: string;
}

/** A picture, a sound or a film by content address — never a person's likeness as a claim about them. */
export const MEDIA_REF_SCHEMA: ObjectSchema = S.object(
  { cid: S.string({ format: "cid" }), mimeType: S.string({ pattern: /^(?:image|audio|video)\/[a-z0-9.+-]+$/ }), alt: S.optional(TEXT(420)) },
  ["cid", "mimeType"],
);

/* ── kash.place@1.0.0 ──────────────────────────────────────────────── */

export const KASH_PLACE_NSID = "kash.place" as const;
export const KASH_PLACE_ID = "kash.place@1.0.0" as const;

/** d66(e)'s island and kasbah; d60(a)'s landmarks, landscapes and premises; d82's meeting places. */
export const PLACE_KINDS = ["island", "kasbah", "landmark", "landscape", "premises", "meeting-place"] as const;
export type PlaceKind = (typeof PLACE_KINDS)[number];

/** Every row is proposed until the publisher confirms it (IL-V7's table). */
export const PLACE_STATUSES = ["proposed", "confirmed"] as const;
export type PlaceStatus = (typeof PLACE_STATUSES)[number];

export interface PlaceBody {
  /** `did:kash:<publisher>/place/<slug>` (d60). */
  readonly id: string;
  /** The organisation that publishes it and answers for it. Never a person. */
  readonly publisher: string;
  readonly name: string;
  /** Other names, by BCP 47 language tag. */
  readonly names?: Readonly<Record<string, string>>;
  readonly kind: PlaceKind;
  /** An island a cluster of islands is named for (d69(c)): a place, never an office or a power. */
  readonly hub?: boolean;
  /** The hub its cluster is named for; a hub names its own. */
  readonly cluster?: string;
  /** The places it sits in — a kasbah's island, a premises' kasbah. */
  readonly within?: readonly string[];
  /** The region it is listed in, by name: a label over a list of places, never a boundary (d55(a), d69). */
  readonly region?: string;
  readonly status?: PlaceStatus;
  /** The public feature the name is pinned to (a GeoNames id, a gazetteer), or why there is none. */
  readonly source: string;
  readonly dates: { readonly published: string };
  /** Practice records say so inside what is signed. */
  readonly practice?: boolean;
}

export const KASH_PLACE_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: PLACE_REF,
    publisher: DID,
    name: TEXT(120),
    names: S.optional(NAMES),
    kind: S.enum(...PLACE_KINDS),
    hub: S.optional(S.boolean()),
    cluster: S.optional(PLACE_REF),
    within: S.optional(S.array(PLACE_REF, { minItems: 1, maxItems: 8 })),
    region: S.optional(TEXT(60)),
    status: S.optional(S.enum(...PLACE_STATUSES)),
    source: TEXT(240),
    dates: S.object({ published: ISO }, ["published"]),
    practice: S.optional(S.boolean()),
  },
  ["id", "publisher", "name", "kind", "source", "dates"],
);

export const KASH_PLACE_LEXICON: LexiconDef = {
  id: KASH_PLACE_ID,
  nsid: KASH_PLACE_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_PLACE_BODY_SCHEMA,
  title: "A place",
  description:
    "A place by its publisher's DID and a slug (d60): its name, kind, the hub and places it sits in, its region as a label, and the public source its name is pinned to. No coordinate, point or polygon — positions live in the template that draws them. Public, organisation-authored.",
};

/** The rules the shape cannot write. Call after the body has the shape. */
export function placeFaults(body: PlaceBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (didOf(body.id) !== body.publisher) out.push(fault("ID_PUBLISHER", ["id"], "a place's id is under its publisher's DID (d60)"));
  if (body.hub === true && body.cluster !== undefined && body.cluster !== body.id) {
    out.push(fault("HUB_CLUSTER", ["cluster"], "a hub names its own cluster (d69(c))"));
  }
  if (body.kind === "meeting-place" && body.region !== undefined) {
    out.push(fault("MEETING_PLACE_REGION", ["region"], "a meeting place stands outside every region (d82)"));
  }
  if (body.within?.includes(body.id)) out.push(fault("WITHIN_SELF", ["within"], "a place does not sit in itself"));
  return out;
}

/* ── kash.place.pointer@1.0.0 ──────────────────────────────────────── */

export const KASH_PLACE_POINTER_NSID = "kash.place.pointer" as const;
export const KASH_PLACE_POINTER_ID = "kash.place.pointer@1.0.0" as const;

export interface PlacePointerBody {
  /** The old id, under this publisher. Its record is never rewritten. */
  readonly from: string;
  /** The old publisher, who signs the pointer. */
  readonly publisher: string;
  /** The new id, under the new publisher. */
  readonly to: string;
  readonly movedAt: string;
  readonly note?: string;
}

export const KASH_PLACE_POINTER_BODY_SCHEMA: ObjectSchema = S.object(
  { from: PLACE_REF, publisher: DID, to: PLACE_REF, movedAt: ISO, note: S.optional(TEXT(400)) },
  ["from", "publisher", "to", "movedAt"],
);

export const KASH_PLACE_POINTER_LEXICON: LexiconDef = {
  id: KASH_PLACE_POINTER_ID,
  nsid: KASH_PLACE_POINTER_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_PLACE_POINTER_BODY_SCHEMA,
  title: "A place has a new publisher",
  description: "The old publisher's signed pointer from a place's old id to its new one under another publisher (d60(a)). The old record is never rewritten.",
};

export function placePointerFaults(body: PlacePointerBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (didOf(body.from) !== body.publisher) out.push(fault("FROM_PUBLISHER", ["from"], "the pointer is the old publisher's: `from` is under its DID"));
  if (didOf(body.to) === didOf(body.from)) out.push(fault("SAME_PUBLISHER", ["to"], "a pointer moves a place to another publisher; under the same one, the record simply stands"));
  return out;
}

/* ── kash.listing@1.0.0 ────────────────────────────────────────────── */

export const KASH_LISTING_NSID = "kash.listing" as const;
export const KASH_LISTING_ID = "kash.listing@1.0.0" as const;

/** What one unit of the price buys. */
export const PRICE_UNITS = ["night", "person", "seat", "vehicle", "item", "day", "hour", "fixed"] as const;
export type PriceUnit = (typeof PRICE_UNITS)[number];

/** An amount as a decimal string — never a float (`"4500"`, `"12.50"`). */
const DECIMAL = S.string({ pattern: /^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,8})?$/, maxLength: 32 });

/** ISIC Revision 5: a section (A–V) or a two-digit division — the same shape as a rule's address (d85(c)). */
const SECTOR = S.object(
  { classification: S.literal("ISIC"), revision: S.literal("5"), code: S.string({ pattern: /^([A-V]|\d{2})$/ }) },
  ["classification", "revision", "code"],
);

export interface ListingBody {
  /** `did:kash:<host>/listing/<slug>`. */
  readonly id: string;
  /** The host: an organisation with its own key and book (d93(e)1). */
  readonly host: string;
  /** The host's public name, as a trust list's label: a name a person can read. */
  readonly hostName?: string;
  readonly title: string;
  readonly summary: string;
  /** Where it is offered (d60 ids). */
  readonly places: readonly string[];
  readonly sector?: { readonly classification: "ISIC"; readonly revision: "5"; readonly code: string };
  readonly price: { readonly amount: string; readonly currency: string; readonly unit: PriceUnit };
  /** The `@kashscript/terms` agreement it is booked under. */
  readonly terms?: { readonly manifestId: string; readonly hash: string };
  /** The deposit, in words. Money moves on the parties' own rails, never here. */
  readonly deposit?: string;
  readonly leadDays?: number;
  readonly languages?: readonly string[];
  readonly media?: readonly MediaRef[];
  /** The host's own channel (https). A booking through it is the host's own customer (d63(a)). */
  readonly link?: string;
  readonly version: number;
  readonly dates: { readonly published: string; readonly validUntil?: string };
  readonly practice?: boolean;
}

export const KASH_LISTING_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: LISTING_REF,
    host: DID,
    hostName: S.optional(TEXT(120)),
    title: S.string({ minLength: 3, maxLength: 120 }),
    summary: S.string({ minLength: 10, maxLength: 1200 }),
    places: S.array(PLACE_REF, { minItems: 1, maxItems: 8 }),
    sector: S.optional(SECTOR),
    price: S.object({ amount: DECIMAL, currency: S.string({ format: "iso4217" }), unit: S.enum(...PRICE_UNITS) }, ["amount", "currency", "unit"]),
    terms: S.optional(S.object({ manifestId: TEXT(200), hash: HEX64 }, ["manifestId", "hash"])),
    deposit: S.optional(TEXT(400)),
    leadDays: S.optional(S.number({ integer: true, min: 0, max: 60 })),
    languages: S.optional(S.array(LANG, { minItems: 1, maxItems: 16 })),
    media: S.optional(S.array(MEDIA_REF_SCHEMA, { maxItems: 12 })),
    link: S.optional(S.string({ pattern: /^https:\/\/[^\s]+$/, maxLength: 2048 })),
    version: S.number({ integer: true, min: 1 }),
    dates: S.object({ published: ISO, validUntil: S.optional(ISO) }, ["published"]),
    practice: S.optional(S.boolean()),
  },
  ["id", "host", "title", "summary", "places", "price", "version", "dates"],
);

export const KASH_LISTING_LEXICON: LexiconDef = {
  id: KASH_LISTING_ID,
  nsid: KASH_LISTING_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_LISTING_BODY_SCHEMA,
  title: "A listing",
  description:
    "An offering at one or more places, by its host's DID and a slug: title, summary, places, an ISIC sector, the published price, the terms it is booked under, media and the host's own channel. No rating, review or count. Public, organisation-authored.",
};

export function listingFaults(body: ListingBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (didOf(body.id) !== body.host) out.push(fault("ID_HOST", ["id"], "a listing's id is under its host's DID"));
  if (body.dates.validUntil !== undefined && Date.parse(body.dates.validUntil) < Date.parse(body.dates.published)) {
    out.push(fault("DATES", ["dates", "validUntil"], "a listing ends after it is published"));
  }
  return out;
}

/* ── kash.guide@1.0.0 ──────────────────────────────────────────────── */

export const KASH_GUIDE_NSID = "kash.guide" as const;
export const KASH_GUIDE_ID = "kash.guide@1.0.0" as const;

export interface GuideSection {
  readonly heading: string;
  /** Markdown. */
  readonly text: string;
  readonly media?: readonly MediaRef[];
  readonly places?: readonly string[];
}

export interface GuideBody {
  /** `did:kash:<publisher>/guide/<slug>`. */
  readonly id: string;
  readonly publisher: string;
  readonly title: string;
  readonly summary?: string;
  readonly languages: readonly string[];
  /** The places it is about (d60 ids). */
  readonly places: readonly string[];
  /** The public records it cites — places, listings, guides, rules, adoptions — by id, and by hash when pinned. */
  readonly cites?: readonly { readonly id: string; readonly hash?: string }[];
  readonly sections: readonly GuideSection[];
  /** Chosen bylines (d51): a role and a name as the credited party gives it — never an identifier. */
  readonly credits?: readonly { readonly role: string; readonly name: string }[];
  readonly version: number;
  readonly dates: { readonly published: string; readonly updated?: string };
  readonly practice?: boolean;
}

/** A byline is words: never a DID, an address or anything with an `@` in it. */
const BYLINE = (max: number): StringSchema => S.string({ minLength: 1, maxLength: max, pattern: /^(?:(?!did:|@)[\s\S])*$/ });

const SECTION = S.object(
  {
    heading: TEXT(160),
    text: S.string({ minLength: 1, maxLength: 20_000 }),
    media: S.optional(S.array(MEDIA_REF_SCHEMA, { maxItems: 12 })),
    places: S.optional(S.array(PLACE_REF, { minItems: 1, maxItems: 16 })),
  },
  ["heading", "text"],
);

export const KASH_GUIDE_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: GUIDE_REF,
    publisher: DID,
    title: TEXT(160),
    summary: S.optional(TEXT(1200)),
    languages: S.array(LANG, { minItems: 1, maxItems: 16 }),
    places: S.array(PLACE_REF, { minItems: 1, maxItems: 64 }),
    cites: S.optional(S.array(S.object({ id: RECORD_REF, hash: S.optional(HEX64) }, ["id"]), { minItems: 1, maxItems: 64 })),
    sections: S.array(SECTION, { minItems: 1, maxItems: 64 }),
    credits: S.optional(S.array(S.object({ role: BYLINE(40), name: BYLINE(80) }, ["role", "name"]), { minItems: 1, maxItems: 16 })),
    version: S.number({ integer: true, min: 1 }),
    dates: S.object({ published: ISO, updated: S.optional(ISO) }, ["published"]),
    practice: S.optional(S.boolean()),
  },
  ["id", "publisher", "title", "languages", "places", "sections", "version", "dates"],
);

export const KASH_GUIDE_LEXICON: LexiconDef = {
  id: KASH_GUIDE_ID,
  nsid: KASH_GUIDE_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_GUIDE_BODY_SCHEMA,
  title: "A guide",
  description:
    "A publisher's text about places, in sections, with the places and public records it cites and chosen bylines for its makers. Public, organisation-authored; never a person's identifier.",
};

export function guideFaults(body: GuideBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (didOf(body.id) !== body.publisher) out.push(fault("ID_PUBLISHER", ["id"], "a guide's id is under its publisher's DID"));
  if (body.dates.updated !== undefined && Date.parse(body.dates.updated) < Date.parse(body.dates.published)) {
    out.push(fault("DATES", ["dates", "updated"], "a guide is updated after it is published"));
  }
  return out;
}

/* ── bundle ────────────────────────────────────────────────────────── */

/** Every place lexicon. All public and organisation-authored (d59). */
export const PLACE_LEXICONS: readonly LexiconDef[] = [KASH_PLACE_LEXICON, KASH_PLACE_POINTER_LEXICON, KASH_LISTING_LEXICON, KASH_GUIDE_LEXICON];
