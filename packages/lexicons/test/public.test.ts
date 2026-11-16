/**
 * The public records as one list (KS-N1; ECOSYSTEM d59): which lexicons muffler may publish, the person-
 * identity scan, and the published JSON Schemas kept in step.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getSchemaDefinition } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import { KASH_GUIDE_ID, KASH_LISTING_ID, KASH_PLACE_ID, KASH_PLACE_POINTER_ID } from "../src/extensions/place";
import { KASH_STATUS_LIST_ID, KASH_TRUST_LIST_ID } from "../src/extensions/lists";
import { PUBLIC_RECORD_LEXICONS, PUBLIC_RECORD_NSIDS, findPersonIdentity, isPublicRecordNsid, publicRecordFaults } from "../src/extensions/public";
import { STANDARD_LIBRARY } from "../src/lexicons";
import { SOCIAL_EXTENSION } from "../src/extensions/social";

const registry = new LexiconRegistry().registerAll(PUBLIC_RECORD_LEXICONS);
const SPECS = join(import.meta.dir, "..", "..", "..", "specs", "schemas");
const PUB = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";

describe("the public records — what muffler may publish (d59)", () => {
  test("eight kinds: the door's two, the places' four, the two lists", () => {
    expect([...PUBLIC_RECORD_NSIDS].sort()).toEqual(
      ["kash.adoption", "kash.guide", "kash.listing", "kash.place", "kash.place.pointer", "kash.rule", "kash.status-list", "kash.trust-list"].sort(),
    );
    expect(PUBLIC_RECORD_LEXICONS.map((d) => d.id)).toContain("kash.rule@1.2.0");
  });
  test("a person's own records are not among them: the identity tier, the social vocabulary, the decision", () => {
    for (const d of [...STANDARD_LIBRARY, ...SOCIAL_EXTENSION]) expect(isPublicRecordNsid(d.nsid)).toBe(false);
    expect(isPublicRecordNsid("kash.decision")).toBe(false);
    expect(isPublicRecordNsid("app.indusland.provider.profile")).toBe(false);
  });
  test("the cross-field checks answer by NSID, and a rule's or an adoption's meaning is left to predicate", () => {
    expect(publicRecordFaults("kash.place", { id: `${PUB}/place/x`, publisher: "did:kash:7Yq9mKpR3vXsN2bLtH8wJcA4dFgE6uZiVnTkQoPrSxWy" }).map((f) => f.code)).toEqual(["ID_PUBLISHER"]);
    expect(publicRecordFaults("kash.rule", {})).toEqual([]);
    expect(publicRecordFaults("kash.adoption", {})).toEqual([]);
    expect(publicRecordFaults("kash.id.profile", {})).toEqual([]);
  });
});

describe("findPersonIdentity — an email, a phone number or a DID in words", () => {
  test("finds the three, with the path", () => {
    expect(findPersonIdentity({ summary: "Ask for Amina, amina.k@tours.example" })).toMatchObject({ path: ["summary"], what: "an email address", found: "amina.k@tours.example" });
    expect(findPersonIdentity({ sections: [{ text: "Call +92 300 1234567 to book." }] })).toMatchObject({ path: ["sections", 0, "text"], what: "a phone number" });
    expect(findPersonIdentity({ note: `signed off by ${PUB} on the day` })).toMatchObject({ path: ["note"], what: "a DID" });
    expect(findPersonIdentity({ "amina@x.example": "a key that names a person" })).toMatchObject({ what: "an email address" });
  });
  test("leaves identifiers and encodings alone — a whole DID, a DID URL, a hash, a CID, a bitstring", () => {
    expect(findPersonIdentity({ publisher: PUB, id: `${PUB}/place/skardu`, hash: "a".repeat(64), cid: `bafy${"a".repeat(55)}`, encodedList: `u${"A".repeat(40)}` })).toBeNull();
    expect(findPersonIdentity({ keyid: `${PUB}#sig-1` })).toBeNull();
  });
  test("reads a date, a time, an amount and a URL's digits as what they are", () => {
    expect(findPersonIdentity({ dates: { published: "2026-11-16T00:00:00Z" }, price: { amount: "45000000.00000000" }, issuedAtUnix: 1763251200 })).toBeNull();
    expect(findPersonIdentity({ source: "GeoNames 1164709", link: "https://www.geonames.org/1164709/skardu.html" })).toBeNull();
    expect(findPersonIdentity({ link: "https://commons.example/w/index.php?curid=12345678901" })).toBeNull();
  });
  test("still finds an email inside a URL", () => {
    expect(findPersonIdentity({ link: "https://example.invalid/?u=amina@mail.example" })).toMatchObject({ what: "an email address" });
  });
});

describe("the published JSON Schemas stay in step with the lexicons", () => {
  for (const [id, file] of [
    [KASH_PLACE_ID, "place.schema.json"],
    [KASH_PLACE_POINTER_ID, "place-pointer.schema.json"],
    [KASH_LISTING_ID, "listing.schema.json"],
    [KASH_GUIDE_ID, "guide.schema.json"],
    [KASH_TRUST_LIST_ID, "trust-list.schema.json"],
    [KASH_STATUS_LIST_ID, "status-list.schema.json"],
  ] as const) {
    test(file, () => {
      const generated = getSchemaDefinition(id, registry);
      const published = JSON.parse(readFileSync(join(SPECS, file), "utf8"));
      expect(published).toEqual(JSON.parse(JSON.stringify(generated)));
    });
  }
});
