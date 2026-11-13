import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getSchemaDefinition, validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import { validate } from "../src/schema";
import { DOOR_LEXICONS, KASH_ADOPTION_ID, KASH_RULE_1_1_BODY_SCHEMA, KASH_RULE_1_1_ID, KASH_RULE_1_2_ID, KASH_RULE_BODY_SCHEMA, KASH_RULE_ID } from "../src/extensions/door";

const registry = new LexiconRegistry().registerAll(DOOR_LEXICONS);
const SPECS = join(import.meta.dir, "..", "..", "..", "specs", "schemas");
const DID = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";

const rule = {
  id: `${DID}/rule/door`,
  version: 1,
  author: DID,
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

const address = {
  sector: { classification: "ISIC", revision: "5", code: "Q" },
  anchorFamily: "knowledge",
  authority: { kind: "law", name: "A regulator" },
  journey: "learn",
  givens: {
    area: { text: "Any campus in Pakistan", countries: ["PK"], places: [`${DID}/place/main-campus`] },
    spaces: { text: "A host workplace", kinds: ["workplace"] },
    capitals: { text: "A qualified supervisor", needs: [{ kind: "people", what: "A site supervisor" }] },
    culture: { text: "The host's code of conduct", languages: ["en", "ur"] },
    economy: { text: "Paid or unpaid, stated in advance", level: "tertiary" },
    time: { text: "Three credit hours; reviewed yearly", renews: "P1Y" },
    relations: { text: "Other campuses' internship receipts", recognises: [{ rule: `${DID}/rule/other`, version: 2 }] },
  },
};

const adoption = {
  id: `${DID}/adoption/door-local`,
  anchor: DID,
  rule: { id: `${DID}/rule/door`, version: 1, hash: "a".repeat(64) },
  parameters: { minWeeks: 8 },
  dates: { adopted: "2026-10-05T00:00:00Z", renewBy: "2027-09-30T00:00:00Z", endsAt: "2028-09-30T00:00:00Z" },
};

const ok = (id: string, body: unknown) => {
  const r = validateBody(id, body, registry);
  return r.ok ? [] : r.errors;
};

describe("kash.rule@1.0.0, unchanged", () => {
  test("a well-formed rule has the shape", () => expect(ok(KASH_RULE_ID, rule)).toEqual([]));
  test("the shape is closed — no field a rule does not name", () => {
    expect(validateBody(KASH_RULE_ID, { ...rule, score: 1 }, registry).ok).toBe(false);
    expect(validate(KASH_RULE_BODY_SCHEMA, { ...rule, decider: { role: "Lead", name: "Amina" } }).ok).toBe(false);
  });
  test("the 1.0.0 schema itself still refuses the 1.1.0 fields — it is the frozen 1.0.0 shape", () => {
    expect(validate(KASH_RULE_BODY_SCHEMA, { ...rule, address }).ok).toBe(false);
  });
  test("a rule renews and ends — the dates are required (d43)", () => {
    const { endsAt: _e, ...dates } = rule.dates;
    expect(validateBody(KASH_RULE_ID, { ...rule, dates }, registry).ok).toBe(false);
  });
});

describe("kash.rule@1.1.0 — the address", () => {
  test("every 1.0.0 body is a 1.1.0 body", () => expect(ok(KASH_RULE_1_1_ID, rule)).toEqual([]));
  test("a rule with its address, subjects, bounds and draft has the shape", () => {
    const full = {
      ...rule,
      address,
      draft: false,
      parameters: { minWeeks: { type: "number", value: 6, bounds: { min: 6, max: 12 } }, track: { type: "string", value: "a", bounds: { allowed: ["a", "b"] } } },
      criteria: [{ ...rule.criteria[0], subject: "person" }],
    };
    expect(ok(KASH_RULE_1_1_ID, full)).toEqual([]);
  });
  test("a place is a DID and a path — never coordinates (d60)", () => {
    const bad = { ...rule, address: { ...address, givens: { ...address.givens, area: { text: "Here", places: ["33.68,73.04"] } } } };
    expect(validateBody(KASH_RULE_1_1_ID, bad, registry).ok).toBe(false);
  });
  test("the sector is ISIC Revision 5, named", () => {
    expect(validateBody(KASH_RULE_1_1_ID, { ...rule, address: { ...address, sector: { classification: "ISIC", revision: "4", code: "P" } } }, registry).ok).toBe(false);
    expect(validateBody(KASH_RULE_1_1_ID, { ...rule, address: { ...address, sector: { classification: "NACE", revision: "5", code: "Q" } } }, registry).ok).toBe(false);
  });
  test("a criterion's subject is one of four", () => {
    expect(validateBody(KASH_RULE_1_1_ID, { ...rule, criteria: [{ ...rule.criteria[0], subject: "citizen" }] }, registry).ok).toBe(false);
  });
});

describe("kash.rule@1.2.0 — the countersigner as holder (KS-Q11)", () => {
  const artifactQuery = (meta: Record<string, unknown>) => ({
    ...rule,
    criteria: [{ ...rule.criteria[0], answer: { by: "receipts", query: [{ id: "work", format: "kash-artifact", meta: { dst_values: ["application/vnd.oreoasis.work-record+json"], attestation: "countersigned", ...meta } }] } }],
  });
  test("every 1.1.0 body is a 1.2.0 body", () => {
    expect(ok(KASH_RULE_1_2_ID, rule)).toEqual([]);
    expect(ok(KASH_RULE_1_2_ID, { ...rule, address, criteria: [{ ...rule.criteria[0], subject: "person" }] })).toEqual([]);
  });
  test("meta.holder names the countersigner, and nothing else", () => {
    expect(ok(KASH_RULE_1_2_ID, artifactQuery({ holder: "countersigner" }))).toEqual([]);
    expect(validateBody(KASH_RULE_1_2_ID, artifactQuery({ holder: "requester" }), registry).ok).toBe(false);
    expect(validateBody(KASH_RULE_1_2_ID, artifactQuery({ holder: "did:kash:x" }), registry).ok).toBe(false);
  });
  // validateBody resolves the newest compatible minor, so the frozen shapes are read directly —
  // as predicate 0.2.0-alpha.0 reads KASH_RULE_1_1_BODY_SCHEMA: an old reader refuses the rule, never mis-binds it.
  test("1.1.0 and 1.0.0 stay frozen: neither reads meta.holder", () => {
    expect(validate(KASH_RULE_1_1_BODY_SCHEMA, artifactQuery({ holder: "countersigner" })).ok).toBe(false);
    expect(validate(KASH_RULE_BODY_SCHEMA, artifactQuery({ holder: "countersigner" })).ok).toBe(false);
    expect(validate(KASH_RULE_1_1_BODY_SCHEMA, artifactQuery({ holder_path: ["actor", "id"] })).ok).toBe(true);
  });
});

describe("kash.adoption@1.0.0", () => {
  test("a well-formed adoption has the shape", () => expect(ok(KASH_ADOPTION_ID, adoption)).toEqual([]));
  test("it has no field for a person", () => {
    expect(validateBody(KASH_ADOPTION_ID, { ...adoption, contact: "amina@anchor.example" }, registry).ok).toBe(false);
    expect(validateBody(KASH_ADOPTION_ID, { ...adoption, parameters: { minWeeks: { name: "Amina" } } }, registry).ok).toBe(false);
  });
  test("it renews and ends (d43)", () => {
    const { renewBy: _r, ...dates } = adoption.dates;
    expect(validateBody(KASH_ADOPTION_ID, { ...adoption, dates }, registry).ok).toBe(false);
  });
});

describe("the published JSON Schemas stay in step with the lexicons", () => {
  for (const [id, file] of [[KASH_RULE_1_2_ID, "rule.schema.json"], [KASH_ADOPTION_ID, "adoption.schema.json"]] as const) {
    test(file, () => {
      const generated = getSchemaDefinition(id, registry);
      const published = JSON.parse(readFileSync(join(SPECS, file), "utf8"));
      expect(published).toEqual(JSON.parse(JSON.stringify(generated)));
    });
  }
});
