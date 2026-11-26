/**
 * RW-19 B — every example in the lexicons resolves under `did:web` (d97(h); d91(e); d71).
 *
 * The prompt's acceptance test. One example per re-issued lexicon, each valid
 * under its new version id, its publisher a `did:web` whose W3C resolution URL
 * derives on the publisher's own domain — derivation only, nothing fetched
 * (d28). The pointer example is d60(a)'s own mechanism carrying a place from
 * its old `did:kash` identifier to its `did:web` one. The trust list stays
 * under a self-certifying publisher, spelled `did:key`. And the superset
 * invariant: every record already written under `did:kash` still validates,
 * because the registry reads a 1.x record with the newest 1.x schema.
 */

import { describe, expect, test } from "bun:test";
import { DID_KEY_SOURCE as CORE_DID_KEY_SOURCE, DID_WEB_SOURCE as CORE_DID_WEB_SOURCE, deriveDidKey, didWebUrl, isDidWeb } from "@kashscript/identity-core";
import { validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import { KASH_ADOPTION_1_1_ID, KASH_RULE_1_3_ID } from "../src/extensions/door";
import { KASH_TRUST_LIST_1_1_ID } from "../src/extensions/lists";
import {
  KASH_GUIDE_1_1_ID,
  KASH_LISTING_1_1_ID,
  KASH_PLACE_1_1_ID,
  KASH_PLACE_POINTER_1_1_ID,
  placePointerFaults,
  type PlacePointerBody,
} from "../src/extensions/place";
import { PUBLIC_RECORD_LEXICONS, findPersonIdentity } from "../src/extensions/public";
import { DID_KEY_SOURCE, DID_WEB_SOURCE, didOf, kindOf } from "../src/extensions/refs";

const registry = new LexiconRegistry().registerAll(PUBLIC_RECORD_LEXICONS);
const AT = "2026-11-26T00:00:00Z";
const DATES = { published: "2026-11-26T00:00:00Z", renewBy: "2027-11-26T00:00:00Z", endsAt: "2028-11-26T00:00:00Z" };

/** The old spelling, as the records already written carry it. */
const OLD_KASH = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
/** A real `did:key`, derived — the standard spelling of a self-certifying key. */
const SELF = deriveDidKey({ type: "Ed25519", publicKey: Uint8Array.from({ length: 32 }, (_, i) => i + 1) });

const ok = (id: string, body: unknown) => {
  const r = validateBody(id, body, registry);
  return r.ok ? [] : r.errors;
};

/* ── the examples, re-issued under the new identifiers ─────────────── */

const EXAMPLES: ReadonlyArray<{ lexicon: string; body: Record<string, unknown>; id: string; url: string }> = [
  {
    lexicon: KASH_PLACE_1_1_ID,
    id: "did:web:indusland.xyz/place/skardu",
    url: "https://indusland.xyz/.well-known/did.json",
    body: {
      id: "did:web:indusland.xyz/place/skardu",
      publisher: "did:web:indusland.xyz",
      name: "Skardu",
      names: { ur: "سکردو" },
      kind: "island",
      region: "Bolor",
      source: "GeoNames 1164709",
      dates: { published: AT },
    },
  },
  {
    lexicon: KASH_LISTING_1_1_ID,
    id: "did:web:tours.example/listing/hunza-circuit",
    url: "https://tours.example/.well-known/did.json",
    body: {
      id: "did:web:tours.example/listing/hunza-circuit",
      host: "did:web:tours.example",
      title: "The Hunza circuit, four days",
      summary: "Four days from Islamabad through Hunza, booked as one circuit with the host's own vehicle.",
      // One place under the new identifier, one under the old: citations read for ever.
      places: ["did:web:indusland.xyz/place/skardu", `${OLD_KASH}/place/karimabad`],
      price: { amount: "185000", currency: "PKR", unit: "person" },
      version: 1,
      dates: { published: AT },
    },
  },
  {
    lexicon: KASH_GUIDE_1_1_ID,
    id: "did:web:indusland.xyz/guide/skardu-days",
    url: "https://indusland.xyz/.well-known/did.json",
    body: {
      id: "did:web:indusland.xyz/guide/skardu-days",
      publisher: "did:web:indusland.xyz",
      title: "Days in Skardu",
      languages: ["en", "ur"],
      places: ["did:web:indusland.xyz/place/skardu"],
      sections: [{ heading: "The lakes", text: "Satpara above the town, Kachura an hour out." }],
      version: 1,
      dates: { published: AT },
    },
  },
  {
    lexicon: KASH_RULE_1_3_ID,
    id: "did:web:campus.example/rule/internships-count",
    url: "https://campus.example/.well-known/did.json",
    body: {
      id: "did:web:campus.example/rule/internships-count",
      version: 1,
      author: "did:web:campus.example",
      title: "Internships that count",
      purpose: "Whether a supervised internship's accepted hours meet the campus's requirement.",
      visibility: "public",
      dates: DATES,
      decider: { role: "Internship office" },
      outcome: { grants: "The credit is recorded.", binds: false, sensitive: false, automaticYes: true },
      reasons: [
        { code: "met", outcome: "yes", text: "Every criterion is met." },
        { code: "missing", outcome: "not-yet", text: "An accepted record is missing." },
      ],
      contest: { windowDays: 30, answerDays: 14, how: "Reply to the receipt." },
      anotherWay: "Paper, read by a person at the office.",
      criteria: [
        {
          id: "hours",
          label: "Accepted hours",
          purpose: "The requirement is accepted supervised hours.",
          answer: { by: "receipts", query: [{ id: "hours", format: "dc+sd-jwt", meta: { vct_values: ["https://campus.example/vct/hours/1"] }, claims: [{ id: "at", path: ["at"] }] }] },
          condition: { feel: "count(receipts) >= 1", types: { at: "date" } },
        },
      ],
    },
  },
  {
    lexicon: KASH_ADOPTION_1_1_ID,
    id: "did:web:guild.example/adoption/internships-local",
    url: "https://guild.example/.well-known/did.json",
    body: {
      id: "did:web:guild.example/adoption/internships-local",
      anchor: "did:web:guild.example",
      rule: { id: "did:web:campus.example/rule/internships-count", version: 1, hash: "a".repeat(64) },
      parameters: { minWeeks: 8 },
      dates: { adopted: AT, renewBy: DATES.renewBy, endsAt: DATES.endsAt },
    },
  },
];

describe("RW-19 B — every example in the lexicons resolves under did:web", () => {
  for (const e of EXAMPLES) {
    test(`${e.lexicon}: ${e.id}`, () => {
      expect(ok(e.lexicon, e.body)).toEqual([]);
      const publisher = didOf(e.id);
      expect(isDidWeb(publisher)).toBe(true);
      expect(didWebUrl(publisher)).toBe(e.url);
      expect(kindOf(e.id)).not.toBeNull();
      expect(findPersonIdentity(e.body)).toBeNull();
    });
  }

  test("the pointer carries a place from its old did:kash identifier to its did:web one (d60(a))", () => {
    const pointer: PlacePointerBody = {
      from: `${OLD_KASH}/place/skardu`,
      publisher: OLD_KASH,
      to: "did:web:indusland.xyz/place/skardu",
      movedAt: AT,
      note: "Re-issued under the publisher's own domain (RW-19 B).",
    };
    expect(ok(KASH_PLACE_POINTER_1_1_ID, pointer)).toEqual([]);
    expect(placePointerFaults(pointer)).toEqual([]);
    expect(didWebUrl(didOf(pointer.to))).toBe("https://indusland.xyz/.well-known/did.json");
  });

  test("the trust list's publisher stays self-certifying, spelled did:key; a did:web publisher is refused", () => {
    const list = {
      format: "kashscript-trust-list/1",
      listId: "ecosystem",
      version: 1,
      publisher: SELF,
      issuedAtUnix: 1_767_225_600,
      validFromUnix: 1_767_225_600,
      validUntilUnix: 2_082_758_400,
      floor: { version: "floor/1" },
      issuers: [
        {
          issuerId: "did:web:tours.example",
          label: "Hunza Circuit Tours",
          keys: [{ keyid: `${SELF}#sig-1`, alg: "Ed25519" as const, publicKeyHex: "ab".repeat(32) }],
          dsts: ["application/vnd.oreoasis.work-record+json"],
          validFromUnix: 1_767_225_600,
          validUntilUnix: 2_082_758_400,
          class: "self-issuer",
          standing: "listed",
        },
      ],
    };
    expect(ok(KASH_TRUST_LIST_1_1_ID, list)).toEqual([]);
    expect(ok(KASH_TRUST_LIST_1_1_ID, { ...list, publisher: "did:web:indorania.org" })).not.toEqual([]);
  });
});

describe("RW-19 B — the superset invariant: what was written reads for ever (d97(h))", () => {
  test("a did:kash-rooted place body still validates, under both the old and the new version id", () => {
    const old = {
      id: `${OLD_KASH}/place/skardu`,
      publisher: OLD_KASH,
      name: "Skardu",
      kind: "island",
      source: "GeoNames 1164709",
      dates: { published: AT },
    };
    expect(ok("kash.place@1.0.0", old)).toEqual([]);
    expect(ok(KASH_PLACE_1_1_ID, old)).toEqual([]);
  });

  test("a did:key publisher roots a record where no domain stands behind the name", () => {
    const body = {
      id: `${SELF}/listing/walled-city-dinner`,
      host: SELF,
      title: "Dinner at the walled city kitchen",
      summary: "One sitting each evening, booked a day ahead, at the kitchen's own table.",
      places: [`${OLD_KASH}/place/lahore`],
      price: { amount: "4500", currency: "PKR", unit: "person" },
      version: 1,
      dates: { published: AT },
    };
    expect(ok(KASH_LISTING_1_1_ID, body)).toEqual([]);
    expect(didOf(body.id)).toBe(SELF);
  });
});

describe("RW-19 B — one grammar: the copied sources are identity-core's", () => {
  test("DID_KEY_SOURCE and DID_WEB_SOURCE match identity-core byte for byte", () => {
    expect(DID_KEY_SOURCE).toBe(CORE_DID_KEY_SOURCE);
    expect(DID_WEB_SOURCE).toBe(CORE_DID_WEB_SOURCE);
  });
  test("a derived did:key matches the schema source", () => {
    expect(new RegExp(`^${DID_KEY_SOURCE}$`).test(SELF)).toBe(true);
  });
});

describe("RW-19 B — the identity scan reads the new identifiers as identifiers, and words as words", () => {
  test("a did:web id, a did:key and a fragment keyid are left alone; an email beside them is still found", () => {
    expect(
      findPersonIdentity({ id: "did:web:indusland.xyz/place/skardu", publisher: "did:web:indusland.xyz", host: SELF, keyid: `${SELF}#sig-1` }),
    ).toBeNull();
    expect(findPersonIdentity({ publisher: "did:web:indusland.xyz", summary: "Ask for Amina, amina.k@tours.example" })).toMatchObject({
      what: "an email address",
    });
  });
});
