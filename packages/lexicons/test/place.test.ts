/**
 * The place records (KS-N1; ECOSYSTEM d59(a), d60, d62(c)7, d69(c), d82, d93(e)2): a valid and an invalid
 * fixture for each lexicon, the fields a closed shape refuses — a coordinate, a rating, a phone — and the
 * cross-field rules the shape cannot write.
 */

import { describe, expect, test } from "bun:test";
import { validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import {
  KASH_GUIDE_ID,
  KASH_LISTING_ID,
  KASH_PLACE_ID,
  KASH_PLACE_POINTER_ID,
  PLACE_LEXICONS,
  guideFaults,
  listingFaults,
  placeFaults,
  placePointerFaults,
  type GuideBody,
  type ListingBody,
  type PlaceBody,
  type PlacePointerBody,
} from "../src/extensions/place";

const registry = new LexiconRegistry().registerAll(PLACE_LEXICONS);
const PUB = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const OTHER = "did:kash:7Yq9mKpR3vXsN2bLtH8wJcA4dFgE6uZiVnTkQoPrSxWy";
const AT = "2026-11-16T00:00:00Z";

const ok = (id: string, body: unknown) => {
  const r = validateBody(id, body, registry);
  return r.ok ? [] : r.errors;
};
const refused = (id: string, body: unknown): boolean => !validateBody(id, body, registry).ok;
const codes = (faults: readonly { code: string }[]) => faults.map((f) => f.code);

/* ── fixtures ──────────────────────────────────────────────────────── */

const skardu: PlaceBody = {
  id: `${PUB}/place/skardu`,
  publisher: PUB,
  name: "Skardu",
  names: { ur: "سکردو" },
  kind: "island",
  hub: true,
  cluster: `${PUB}/place/skardu`,
  region: "Bolor",
  status: "proposed",
  source: "GeoNames 1164709",
  dates: { published: AT },
};

const karimabad: PlaceBody = {
  id: `${PUB}/place/karimabad`,
  publisher: PUB,
  name: "Karimabad",
  kind: "kasbah",
  cluster: `${PUB}/place/skardu`,
  within: [`${PUB}/place/hunza`],
  region: "Bolor",
  source: "GeoNames 1174872",
  dates: { published: AT },
};

const rawal: PlaceBody = {
  id: `${PUB}/place/rawal`,
  publisher: PUB,
  name: "Rawal",
  kind: "meeting-place",
  source: "GeoNames 1176615 (Islamabad, where the founder places Rawal, 2026-10-26)",
  dates: { published: AT },
};

const premises: PlaceBody = {
  id: `${OTHER}/place/the-walled-city-kitchen`,
  publisher: OTHER,
  name: "The Walled City Kitchen",
  kind: "premises",
  within: [`${PUB}/place/lahore`],
  source: "The host's own premises, named by the host",
  dates: { published: AT },
  practice: true,
};

const pointer: PlacePointerBody = {
  from: `${PUB}/place/skardu`,
  publisher: PUB,
  to: `${OTHER}/place/skardu`,
  movedAt: AT,
  note: "The place is published by its own hosts' association from today.",
};

const listing: ListingBody = {
  id: `${OTHER}/listing/old-city-food-walk`,
  host: OTHER,
  hostName: "Karavan Tours",
  title: "Old City food walk",
  summary: "Three hours through the walled city's kitchens, with the people who cook there.",
  places: [`${PUB}/place/lahore`],
  sector: { classification: "ISIC", revision: "5", code: "79" },
  price: { amount: "4500", currency: "PKR", unit: "person" },
  terms: { manifestId: "kash-trade:booking/1", hash: "a".repeat(64) },
  deposit: "A quarter of the price, returned in full if the walk is called off by the host.",
  leadDays: 1,
  languages: ["en", "ur"],
  media: [{ cid: `bafy${"a".repeat(55)}`, mimeType: "image/jpeg", alt: "The spice market at dusk." }],
  link: "https://karavan.example/book/old-city-food-walk",
  version: 1,
  dates: { published: AT, validUntil: "2027-11-16T00:00:00Z" },
};

const guide: GuideBody = {
  id: `${PUB}/guide/bolor-in-autumn`,
  publisher: PUB,
  title: "Bolor in autumn",
  summary: "The valleys from Skardu to Hunza when the apricots are drying on the roofs.",
  languages: ["en", "ur"],
  places: [`${PUB}/place/skardu`, `${PUB}/place/hunza`],
  cites: [{ id: `${OTHER}/listing/old-city-food-walk` }, { id: `${PUB}/rule/signed-down-the-chain`, hash: "b".repeat(64) }],
  sections: [
    { heading: "Skardu", text: "The road in from Gilgit follows the river.", places: [`${PUB}/place/skardu`] },
    { heading: "Hunza", text: "Karimabad sits above the valley floor.", media: [{ cid: `bafy${"b".repeat(55)}`, mimeType: "image/webp" }] },
  ],
  credits: [{ role: "Photographs", name: "S. Mahmud" }],
  version: 2,
  dates: { published: AT, updated: "2026-11-17T00:00:00Z" },
};

/* ── kash.place ────────────────────────────────────────────────────── */

describe("kash.place@1.0.0", () => {
  test("an island, a kasbah, a meeting place and a business's premises have the shape", () => {
    for (const p of [skardu, karimabad, rawal, premises]) expect(ok(KASH_PLACE_ID, p)).toEqual([]);
    for (const p of [skardu, karimabad, rawal, premises]) expect(placeFaults(p)).toEqual([]);
  });
  test("it is a DID and a path — never a coordinate (d60): no point, no lat/lon, no polygon, no number at all", () => {
    expect(refused(KASH_PLACE_ID, { ...skardu, point: { lat: 35.3, lon: 75.63 } })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, lat: 35.3, lon: 75.63 })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, polygon: [[75.6, 35.3], [75.7, 35.3], [75.7, 35.4]] })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, id: `${PUB}/place/35.30,75.63` })).toBe(true);
  });
  test("the shape is closed: no person, no score, no count", () => {
    expect(refused(KASH_PLACE_ID, { ...skardu, owner: "Amina" })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, visits: 1200 })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, rating: 4.8 })).toBe(true);
  });
  test("its kind is one of six, and its names are by language", () => {
    expect(refused(KASH_PLACE_ID, { ...skardu, kind: "province" })).toBe(true);
    expect(refused(KASH_PLACE_ID, { ...skardu, names: { urdu: "سکردو" } })).toBe(true);
  });
  test("the rules the shape cannot write", () => {
    expect(codes(placeFaults({ ...skardu, publisher: OTHER }))).toEqual(["ID_PUBLISHER"]);
    expect(codes(placeFaults({ ...skardu, cluster: `${PUB}/place/hunza` }))).toEqual(["HUB_CLUSTER"]);
    expect(codes(placeFaults({ ...rawal, region: "Kasperia" }))).toEqual(["MEETING_PLACE_REGION"]);
    expect(codes(placeFaults({ ...karimabad, within: [karimabad.id] }))).toEqual(["WITHIN_SELF"]);
  });
});

/* ── kash.place.pointer ────────────────────────────────────────────── */

describe("kash.place.pointer@1.0.0", () => {
  test("the old publisher's pointer to the new id has the shape", () => {
    expect(ok(KASH_PLACE_POINTER_ID, pointer)).toEqual([]);
    expect(placePointerFaults(pointer)).toEqual([]);
  });
  test("it is dated, and it rewrites nothing: no name, no body of the place", () => {
    const { movedAt: _m, ...undated } = pointer;
    expect(refused(KASH_PLACE_POINTER_ID, undated)).toBe(true);
    expect(refused(KASH_PLACE_POINTER_ID, { ...pointer, name: "Skardu" })).toBe(true);
  });
  test("the rules the shape cannot write", () => {
    expect(codes(placePointerFaults({ ...pointer, publisher: OTHER }))).toEqual(["FROM_PUBLISHER"]);
    expect(codes(placePointerFaults({ ...pointer, to: `${PUB}/place/skardu-town` }))).toEqual(["SAME_PUBLISHER"]);
  });
});

/* ── kash.listing ──────────────────────────────────────────────────── */

describe("kash.listing@1.0.0", () => {
  test("an offering with its published price has the shape", () => {
    expect(ok(KASH_LISTING_ID, listing)).toEqual([]);
    expect(listingFaults(listing)).toEqual([]);
  });
  test("it has no rating field — nor a star, an average, a review or a count (d62(c)7, d41)", () => {
    for (const planted of [{ rating: 4.8 }, { stars: 5 }, { averageRating: 4.2 }, { reviews: [] }, { reviewCount: 31 }, { bookings: 120 }, { score: 9 }]) {
      expect(refused(KASH_LISTING_ID, { ...listing, ...planted })).toBe(true);
    }
  });
  test("it has no field for a person's contact details — the host's own channel is a link", () => {
    expect(refused(KASH_LISTING_ID, { ...listing, phone: "+92 300 1234567" })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, email: "bookings@karavan.example" })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, contact: { phone: "+92 300 1234567" } })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, link: "http://karavan.example/book" })).toBe(true);
  });
  test("the price is a decimal string in an ISO 4217 currency, per a named unit", () => {
    expect(refused(KASH_LISTING_ID, { ...listing, price: { amount: 4500, currency: "PKR", unit: "person" } })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, price: { amount: "4,500", currency: "PKR", unit: "person" } })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, price: { amount: "4500", currency: "Rs", unit: "person" } })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, price: { amount: "4500", currency: "PKR", unit: "head" } })).toBe(true);
  });
  test("it cites at least one place by d60's id, and names no door of its own — its sector is ISIC Revision 5", () => {
    expect(refused(KASH_LISTING_ID, { ...listing, places: [] })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, places: ["hunza"] })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, door: "sabaat" })).toBe(true);
    expect(refused(KASH_LISTING_ID, { ...listing, sector: { classification: "ISIC", revision: "4", code: "79" } })).toBe(true);
  });
  test("the rules the shape cannot write", () => {
    expect(codes(listingFaults({ ...listing, host: PUB }))).toEqual(["ID_HOST"]);
    expect(codes(listingFaults({ ...listing, dates: { published: AT, validUntil: "2026-01-01T00:00:00Z" } }))).toEqual(["DATES"]);
  });
});

/* ── kash.guide ────────────────────────────────────────────────────── */

describe("kash.guide@1.0.0", () => {
  test("a guide with its places, citations, sections and credits has the shape", () => {
    expect(ok(KASH_GUIDE_ID, guide)).toEqual([]);
    expect(guideFaults(guide)).toEqual([]);
  });
  test("it cites public records only, by their ids", () => {
    expect(refused(KASH_GUIDE_ID, { ...guide, cites: [{ id: `${PUB}/person/amina` }] })).toBe(true);
    expect(refused(KASH_GUIDE_ID, { ...guide, cites: [{ id: "https://example.invalid/record/1" }] })).toBe(true);
  });
  test("a credit is a chosen byline — never a DID or an address (d51, d59)", () => {
    expect(refused(KASH_GUIDE_ID, { ...guide, credits: [{ role: "Author", name: PUB }] })).toBe(true);
    expect(refused(KASH_GUIDE_ID, { ...guide, credits: [{ role: "Author", name: "amina@mail.example" }] })).toBe(true);
    expect(refused(KASH_GUIDE_ID, { ...guide, credits: [{ role: "Author", name: "Amina", did: PUB }] })).toBe(true);
  });
  test("it is in at least one language and about at least one place", () => {
    expect(refused(KASH_GUIDE_ID, { ...guide, languages: [] })).toBe(true);
    expect(refused(KASH_GUIDE_ID, { ...guide, places: [] })).toBe(true);
  });
  test("the rules the shape cannot write", () => {
    expect(codes(guideFaults({ ...guide, publisher: OTHER }))).toEqual(["ID_PUBLISHER"]);
    expect(codes(guideFaults({ ...guide, dates: { published: AT, updated: "2026-01-01T00:00:00Z" } }))).toEqual(["DATES"]);
  });
});
