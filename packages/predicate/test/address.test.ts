import { describe, expect, test } from "bun:test";
import { validate } from "@kashscript/lexicons/schema";
import { GIVENS, KASH_RULE_BODY_SCHEMA, type RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import { completeness } from "../src/address";
import { isicSection, ISIC_REV5 } from "../src/isic";
import { readRule, ruleHash, ruleRequest, signRule, validateRule } from "../src/rule";
import { checklist } from "../src/checklist";
import { route } from "../src/route";
import { validateAdoption } from "../src/adoption";
import { cpdRule, hiringAdoption, hiringRule, incomeRule, internshipRule, plantedViolations, productOriginRule } from "../src/fixtures";
import { AS_OF, party } from "./world";
import hiring100 from "./vectors/hiring-rule-1.0.0.json";
import internship100 from "./vectors/internship-rule-1.0.0.json";
import cpd100 from "./vectors/cpd-rule-1.0.0.json";
import income100 from "./vectors/income-rule-1.0.0.json";

/** The DIDs the 1.0.0 vectors were written with, from KS-Q1's committed fixtures (ae3ccd7). */
const A = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const B = "did:kash:DnaeU6DTGVNs3fgcy5XkzHLfCtuEB7Fo7B76ugLp3YxV5LQ7";

const fixtures: readonly (readonly [string, RuleBody1_1, unknown])[] = [
  ["hiring", hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` }), hiring100],
  ["internship", internshipRule({ campus: A }), internship100],
  ["CPD", cpdRule({ body: A, providerList: `${B}#providers` }), cpd100],
  ["income", incomeRule({ lender: A, predicateIssuer: B }), income100],
];

/** A 1.1.0 body with everything 1.1.0 added taken away: the address, the draft mark, the bounds, the subjects. */
function strip(rule: RuleBody1_1): RuleBody1_1 {
  const { address: _a, draft: _d, ...rest } = rule;
  return {
    ...rest,
    ...(rule.parameters !== undefined ? { parameters: Object.fromEntries(Object.entries(rule.parameters).map(([n, { bounds: _b, ...p }]) => [n, p])) } : {}),
    criteria: rule.criteria.map(({ subject: _s, ...c }) => c),
  };
}

describe("a 1.0.0 rule still validates (KS-Q1b must not break one)", () => {
  for (const [name, , vector] of fixtures) {
    test(`the frozen ${name} rule, byte for byte as KS-Q1 published it`, () => {
      expect(validate(KASH_RULE_BODY_SCHEMA, vector).ok).toBe(true);
      const v = validateRule(vector);
      expect(v.refusals).toEqual([]);
      expect(v.ok).toBe(true);
      expect(v.warnings.find((w) => w.code === "NO_ADDRESS")).toMatchObject({ answerable: false, answer: null });
      expect(v.completeness).toEqual({ addressed: false, complete: false, missing: [...GIVENS] });
    });
  }
  for (const [name, body, vector] of fixtures) {
    test(`the ${name} fixture, without what 1.1.0 added, is the 1.0.0 rule exactly`, async () => {
      expect(strip(body)).toEqual(vector as RuleBody1_1);
      expect(await ruleHash(strip(body))).toBe(await ruleHash(vector as RuleBody1_1));
    });
  }
  test("a 1.0.0 rule signs, is put to a person, checked and routed as before", async () => {
    const door = await party();
    const other = await party();
    const rule = await readRule(await signRule(strip(hiringRule({ author: door.did, predicateIssuer: other.did, assessorList: `${other.did}#assessors` })), door));
    expect(rule.body.address).toBeUndefined();
    const req = ruleRequest(rule, { nonce: "n-0123456789abcdef", responseUri: "https://door.practice.invalid/in" });
    expect(req.client_id).toBe(door.did);
    const list = await checklist(rule, [], { asOf: AS_OF });
    expect(list.draft).toBe(false);
    expect(list.rows.length).toBe(4);
  });
  test("the KS-Q1 planted violations are still refused, each for its reason, on an addressed rule", () => {
    for (const p of plantedViolations({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` })) {
      expect([p.name, validateRule(p.rule).refusals.map((r) => r.code)]).toEqual([p.name, expect.arrayContaining([p.refusedWith])]);
    }
  });
});

describe("the address (d85(c))", () => {
  for (const [name, body] of [...fixtures.map(([n, b]) => [n, b] as const), ["product origin", productOriginRule({ importer: A, chamberList: `${B}#chambers` })] as const]) {
    test(`the ${name} rule is addressed and complete — no warning for it, every given answered`, () => {
      const v = validateRule(body);
      expect(v.refusals).toEqual([]);
      expect(v.completeness).toEqual({ addressed: true, complete: true, missing: [] });
      expect(v.warnings.map((w) => w.code)).not.toContain("NO_ADDRESS");
      expect(v.warnings.map((w) => w.code)).not.toContain("INCOMPLETE");
      expect(isicSection(body.address!.sector.code)).not.toBeNull();
    });
  }
  test("the internship's address is the worked example on d85's page", () => {
    const a = internshipRule({ campus: A }).address!;
    expect([isicSection(a.sector.code), a.anchorFamily, a.authority.kind, a.journey]).toEqual(["Q", "knowledge", "law", "learn"]);
    expect(a.givens.area).toEqual({ text: "Any campus in Pakistan.", countries: ["PK"] });
    expect(internshipRule({ campus: A }).parameters!.minWeeks!.bounds).toEqual({ min: 6, max: 12 });
  });
  test("ISIC Revision 5: 22 sections and 87 divisions, each division under one section", () => {
    expect(Object.keys(ISIC_REV5)).toEqual("ABCDEFGHIJKLMNOPQRSTUV".split(""));
    const divisions = Object.values(ISIC_REV5).flatMap((s) => s.divisions);
    expect(divisions.length).toBe(87);
    expect(new Set(divisions).size).toBe(87);
    expect([isicSection("85"), isicSection("62"), isicSection("Q"), isicSection("04"), isicSection("W")]).toEqual(["Q", "K", "Q", null, null]);
  });
  test("an area is anywhere or it names countries and places; durations read; a place is a reference", () => {
    const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
    const g = base.address!.givens;
    const withGivens = (givens: object) => ({ ...base, address: { ...base.address!, givens: { ...g, ...givens } } });
    expect(validateRule(withGivens({ area: { text: "Remote, and Karachi.", anywhere: true, countries: ["PK"] } })).refusals.map((r) => r.code)).toContain("ADDRESS");
    expect(validateRule(withGivens({ time: { text: "Odd.", lasts: "P1Y2D" } })).refusals.map((r) => r.code)).toContain("ADDRESS");
    // d60: no coordinates, ever — the shape has no room for one.
    expect(validateRule(withGivens({ area: { text: "Here.", places: ["24.86,67.01"] } })).refusals.map((r) => r.code)).toContain("SHAPE");
    expect(validateRule(withGivens({ area: { text: "Korangi.", places: [`${B}/place/korangi`] } })).ok).toBe(true);
  });
  test("a person's identity has no place in a given", () => {
    const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
    const bad = { ...base, address: { ...base.address!, givens: { ...base.address!.givens, capitals: { text: "Ask Amina on amina.k@agency.example." } } } };
    expect(validateRule(bad).refusals.map((r) => r.code)).toContain("PERSON_IDENTITY");
  });
});

describe("an incomplete rule is a draft: readable and testable, never decided under", () => {
  const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
  const { culture: _c, economy: _e, ...five } = base.address!.givens;
  const draft: RuleBody1_1 = { ...base, address: { ...base.address!, givens: five }, draft: true };

  test("it validates as a draft, with the givens it is missing", () => {
    const v = validateRule(draft);
    expect(v.ok).toBe(true);
    expect(v.completeness).toEqual({ addressed: true, complete: false, missing: ["culture", "economy"] });
    expect(v.warnings.find((w) => w.code === "INCOMPLETE")).toMatchObject({ answerable: false, message: expect.stringContaining("culture, economy") });
    expect(completeness(draft).missing).toEqual(["culture", "economy"]);
  });
  test("without draft: true it is refused", () => {
    expect(validateRule({ ...draft, draft: false }).refusals.map((r) => r.code)).toContain("INCOMPLETE_NOT_DRAFT");
  });
  test("the person's side checks it, and says it is a draft; no request, route or adoption runs under it", async () => {
    const door = await party();
    const rule = await readRule(await signRule({ ...draft, id: `${door.did}/rule/contract-developer`, author: door.did }, door));
    const list = await checklist(rule, [], { asOf: AS_OF });
    expect(list.draft).toBe(true);
    expect(list.ready).toBe(false);
    expect(() => ruleRequest(rule, { nonce: "n-0123456789abcdef", responseUri: "https://door.practice.invalid/in" })).toThrow("draft");
    const check = { rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash }, byCriterion: {}, problems: [] } as unknown as Parameters<typeof route>[1];
    await expect(route(rule, check, { asOf: AS_OF })).rejects.toThrow("draft");
    const anchor = await party();
    expect(validateAdoption(hiringAdoption(anchor.did, rule), rule).refusals.map((r) => r.code)).toContain("DRAFT");
  });
});
