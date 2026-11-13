import { describe, expect, test } from "bun:test";
import type { Criterion1_1, RuleBody1_1, Subject } from "@kashscript/lexicons/extensions/door";
import { validateRule } from "../src/rule";
import { proxyTerms, refusedTerms } from "../src/vocabulary";
import { hiringRule, PRACTICE_VCT, productOriginRule } from "../src/fixtures";

const A = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const B = "did:kash:DnaeU6DTGVNs3fgcy5XkzHLfCtuEB7Fo7B76ugLp3YxV5LQ7";
const product = productOriginRule({ importer: A, chamberList: `${B}#chambers` });

/** The hiring rule with one more criterion about `subject`, reading one claim. */
function about(subject: Subject, claim: string, label = "A check of the subject"): RuleBody1_1 {
  const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
  const c: Criterion1_1 = {
    id: "extra",
    subject,
    label,
    purpose: "Read to prove the vocabulary knows its subject.",
    answer: { by: "receipts", query: [{ id: "extra", format: "dc+sd-jwt", meta: { vct_values: [PRACTICE_VCT.languageAssessment] }, claims: [{ id: "x", path: [claim] }] }] },
    condition: { feel: "count(receipts) >= 1", types: {} },
  };
  return { ...base, criteria: [...base.criteria, c] };
}
const refusals = (r: RuleBody1_1) => validateRule(r).refusals.map((x) => x.code);
const warnings = (r: RuleBody1_1) => validateRule(r).warnings.filter((w) => w.criterion === "extra").map((x) => x.code);

describe("d85(b) rule 1 binds when the subject is a person — tested both ways", () => {
  test("a product's country of origin is allowed; a person's is refused", () => {
    expect(validateRule(product)).toMatchObject({ ok: true, refusals: [] });
    const asPerson = { ...product, criteria: product.criteria.map((c) => ({ ...c, subject: "person" as const })) };
    expect(refusals(asPerson)).toContain("ASCRIBED_IDENTITY");
    // Its reasons speak of the goods' origin — allowed while every criterion is about a product, refused once one is about a person.
    expect(validateRule(asPerson).refusals.some((r) => r.path.startsWith("$.reasons"))).toBe(true);
  });
  test("a place's district is allowed; a person's is a proxy, answered in writing or refused", () => {
    expect(refusals(about("place", "district"))).toEqual([]);
    expect(warnings(about("place", "district"))).toEqual([]);
    expect(warnings(about("person", "district"))).toEqual(["RESIDENCE_PROXY"]);
    expect(refusals(about("person", "district"))).toEqual(["UNANSWERED_WARNING"]);
  });
  test("an organisation's nationality — where it is registered — is allowed; its owners' gender, or nationality, is refused", () => {
    expect(refusals(about("organisation", "nationality"))).toEqual([]);
    expect(refusals(about("organisation", "countryOfOrigin"))).toEqual([]);
    expect(refusals(about("organisation", "ownerGender"))).toContain("ASCRIBED_IDENTITY");
    expect(refusals(about("organisation", "womenOwned"))).toContain("ASCRIBED_IDENTITY");
    expect(refusals(about("organisation", "ownersNationality"))).toContain("ASCRIBED_IDENTITY");
    expect(refusals(about("person", "nationality"))).toContain("ASCRIBED_IDENTITY");
  });
  test("an organisation's people are people: their health is refused; a health licence is the organisation's", () => {
    expect(refusals(about("organisation", "healthLicence"))).toEqual([]);
    expect(refusals(about("organisation", "staffHealth"))).toContain("SENSITIVE_CATEGORY");
    expect(refusals(about("organisation", "staffReligion"))).toContain("SENSITIVE_CATEGORY");
  });
  test("institutions may be compared (rule 3); people are never scored", () => {
    expect(refusals(about("organisation", "rating"))).toEqual([]);
    expect(refusals(about("person", "rating"))).toContain("READS_A_SCORE");
  });
  test("a place may be a health facility; what describes those who live there is refused", () => {
    expect(refusals(about("place", "healthFacility"))).toEqual([]);
    expect(refusals(about("place", "majorityReligion"))).toContain("SENSITIVE_CATEGORY");
    expect(refusals(about("place", "ethnicity"))).toContain("ASCRIBED_IDENTITY");
    expect(refusals(about("place", "residentsNationality"))).toContain("ASCRIBED_IDENTITY");
  });
  test("every subject still refuses an ask for a refusal (node rule 10)", () => {
    for (const s of ["person", "organisation", "product", "place"] as const) expect(refusals(about(s, "rejectedShipments"))).toContain("ASKS_FOR_A_REFUSAL");
  });
  test("a 1.0.0 criterion, with no subject, is read as a person's — the strictest", () => {
    expect(refusedTerms("countryOfOrigin").map((h) => h.category)).toContain("ASCRIBED_IDENTITY");
    expect(refusedTerms("countryOfOrigin", "product")).toEqual([]);
    expect(proxyTerms("postcode").map((h) => h.category)).toEqual(["RESIDENCE_PROXY"]);
    expect(proxyTerms("postcode", "place")).toEqual([]);
    expect(proxyTerms("staffPostcode", "organisation").map((h) => h.category)).toEqual(["RESIDENCE_PROXY"]);
  });
});
