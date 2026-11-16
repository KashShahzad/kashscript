// Fixtures for the guard and the rebuilt-index tests: one of each public record kind, as an organisation
// would publish it. Copied in shape from the lexicons' own tests, never imported across packages. Every value
// is SAMPLE; the DIDs are test strings of the right form, not keys anyone holds.

export const PUB = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
export const OTHER = "did:kash:7Yq9mKpR3vXsN2bLtH8wJcA4dFgE6uZiVnTkQoPrSxWy";
export const AT = "2026-11-16T00:00:00Z";
export const NOW = 1_763_251_200; // 2026-11-16T00:00:00Z
export const DAY = 86_400;

export const skardu = {
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

export const hunza = {
  id: `${PUB}/place/hunza`,
  publisher: PUB,
  name: "Hunza",
  kind: "island",
  cluster: `${PUB}/place/skardu`,
  region: "Bolor",
  source: "GeoNames 1176774",
  dates: { published: AT },
};

export const pointer = {
  from: `${PUB}/place/lahore`,
  publisher: PUB,
  to: `${OTHER}/place/lahore`,
  movedAt: AT,
};

export const listing = {
  id: `${OTHER}/listing/old-city-food-walk`,
  host: OTHER,
  hostName: "Karavan Tours",
  title: "Old City food walk",
  summary: "Three hours through the walled city's kitchens, with the people who cook there.",
  places: [`${PUB}/place/lahore`],
  price: { amount: "4500", currency: "PKR", unit: "person" },
  link: "https://karavan.example/book/old-city-food-walk",
  version: 1,
  dates: { published: AT },
};

export const guide = {
  id: `${PUB}/guide/bolor-in-autumn`,
  publisher: PUB,
  title: "Bolor in autumn",
  languages: ["en", "ur"],
  places: [`${PUB}/place/skardu`, `${PUB}/place/hunza`],
  sections: [{ heading: "Skardu", text: "The road in from Gilgit follows the river." }],
  credits: [{ role: "Photographs", name: "S. Mahmud" }],
  version: 1,
  dates: { published: AT },
};

/** The rule fixture from the door's own tests — a 1.0.0 body, which the collection `kash.rule` reads as 1.2.0. */
export const rule = {
  id: `${PUB}/rule/door`,
  version: 1,
  author: PUB,
  title: "A door",
  purpose: "What it decides, and why it reads these receipts.",
  visibility: "public",
  dates: { published: "2026-10-01T00:00:00Z", renewBy: "2027-09-30T00:00:00Z", endsAt: "2028-09-30T00:00:00Z" },
  decider: { role: "Desk lead" },
  outcome: { grants: "A place.", binds: false, sensitive: false, automaticYes: true },
  reasons: [
    { code: "met", outcome: "yes", text: "Every criterion is met." },
    { code: "missing", outcome: "not-yet", text: "Something is missing." },
  ],
  contest: { windowDays: 30, answerDays: 14, how: "Reply to the receipt." },
  anotherWay: "Paper, read by a person at the desk.",
  criteria: [
    {
      id: "work",
      label: "Accepted work",
      purpose: "The door is for people whose work was accepted.",
      answer: { by: "receipts", query: [{ id: "work", format: "dc+sd-jwt", meta: { vct_values: ["https://example.invalid/vct/w/1"] }, claims: [{ id: "at", path: ["at"] }] }] },
      condition: { feel: "count(receipts) >= 1", types: { at: "date" } },
    },
  ],
};

/** A trust list with the three assertions: a listed self-issuer, and a removed assessor whose window has ended. */
export const trustList = (publisher: string, issuerDid: string) => ({
  format: "kashscript-trust-list/1",
  listId: "ecosystem-issuers",
  version: 1,
  publisher,
  issuedAtUnix: NOW,
  validFromUnix: NOW,
  validUntilUnix: NOW + 90 * DAY,
  floor: { version: "VISION §4 draft, 2026-10-18" },
  issuers: [
    {
      issuerId: issuerDid,
      label: "A workshop (sample)",
      keys: [],
      dsts: ["application/vnd.oreoasis.work-record+json"],
      validFromUnix: NOW - DAY,
      validUntilUnix: NOW + 365 * DAY,
      class: "self-issuer",
      standing: "listed",
      grade: 1,
    },
    {
      issuerId: "assessor-7",
      label: "An assessor that left (sample)",
      keys: [{ keyid: "assessor-7#k1", alg: "ES256", publicKeyHex: `02${"c".repeat(64)}` }],
      dsts: ["application/vnd.oreoasis.predicate+json"],
      validFromUnix: NOW - 400 * DAY,
      validUntilUnix: NOW - 30 * DAY,
      class: "assessor",
      standing: "removed",
    },
  ],
  practice: true,
});

export const statusList = (issuer: string, encodedList: string) => ({
  format: "kashscript-status-list/1",
  type: "BitstringStatusList",
  id: "https://lists.example/status/work-records/2026-q4",
  issuer,
  statusPurpose: "revocation",
  encodedList,
  issuedAtUnix: NOW,
  validUntilUnix: null,
});
