/**
 * One adoption for each fixture rule (KS-Q1b, d85(b) rule 8): an anchor adopts
 * the rule with its own values, inside the bounds the rule states. Each names
 * an anchor and numbers — never a person. Every value is SAMPLE.
 *
 *   hiring      → a smaller agency asks for two accepted projects, not three;
 *   internship  → a campus asks for eight approved weeks (the page's six to twelve);
 *   CPD         → a body asks for 150 hours in the cycle;
 *   income      → a lender looks for 750 a month.
 *
 * And the planted adoptions validation must refuse, each with its code.
 */

import type { AdoptionBody, RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import type { AdoptionRefusalCode } from "../adoption";
import { PRACTICE_ENDS, PRACTICE_RENEW } from "./types";

/** When every fixture anchor adopted its rule — after the rules were published, before `PRACTICE_AS_OF`. */
export const PRACTICE_ADOPTED = "2026-10-15T00:00:00Z";

type Rule = { readonly body: RuleBody; readonly hash: string };

/** An adoption of `rule` by `anchor`, with local values. */
export function practiceAdoption(anchor: string, rule: Rule, slug: string, parameters: AdoptionBody["parameters"], over: Partial<AdoptionBody> = {}): AdoptionBody {
  return {
    id: `${anchor}/adoption/${slug}`,
    anchor,
    rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
    parameters,
    dates: { adopted: PRACTICE_ADOPTED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    practice: true,
    ...over,
  };
}

/** The local values each fixture's adoption sets. */
export const ADOPTED_VALUES = {
  hiring: { minProjects: 2 },
  internship: { minWeeks: 8 },
  cpd: { minHours: 150 },
  income: { minMonthly: 750 },
} as const;

export const hiringAdoption = (anchor: string, rule: Rule, over: Partial<AdoptionBody> = {}): AdoptionBody => practiceAdoption(anchor, rule, "contract-developer", { ...ADOPTED_VALUES.hiring }, over);
export const internshipAdoption = (anchor: string, rule: Rule, over: Partial<AdoptionBody> = {}): AdoptionBody => practiceAdoption(anchor, rule, "internship-credit", { ...ADOPTED_VALUES.internship }, over);
export const cpdAdoption = (anchor: string, rule: Rule, over: Partial<AdoptionBody> = {}): AdoptionBody => practiceAdoption(anchor, rule, "cpd-cycle", { ...ADOPTED_VALUES.cpd }, over);
export const incomeAdoption = (anchor: string, rule: Rule, over: Partial<AdoptionBody> = {}): AdoptionBody => practiceAdoption(anchor, rule, "income-six-months", { ...ADOPTED_VALUES.income }, over);

export interface PlantedAdoption {
  readonly name: string;
  readonly body: unknown;
  readonly refusedWith: AdoptionRefusalCode;
}

/** Adoptions of the hiring rule (or the CPD rule, for a string value) that validation refuses, each for its reason. */
export function plantedAdoptions(anchor: string, hiring: Rule, cpd: Rule): PlantedAdoption[] {
  const a = (parameters: AdoptionBody["parameters"], over: Partial<AdoptionBody> = {}) => practiceAdoption(anchor, hiring, "planted", parameters, over);
  return [
    { name: "a value below the bounds", refusedWith: "OUT_OF_BOUNDS", body: a({ minProjects: 1 }) },
    { name: "a value above the bounds", refusedWith: "OUT_OF_BOUNDS", body: a({ window: "P60M" }) },
    { name: "a value of the wrong type", refusedWith: "OUT_OF_BOUNDS", body: a({ minProjects: "two" }) },
    { name: "a value outside the allowed list", refusedWith: "OUT_OF_BOUNDS", body: practiceAdoption(anchor, cpd, "planted", { cycle: "P2Y" }) },
    { name: "a parameter the rule does not have", refusedWith: "NOT_ADOPTABLE", body: a({ minClients: 2 }) },
    { name: "a person's email in a value", refusedWith: "PERSON_IDENTITY", body: practiceAdoption(anchor, cpd, "planted", { cycle: "amina.k@agency.example" }) },
    { name: "a field for a person", refusedWith: "SHAPE", body: { ...a({ minProjects: 2 }), person: { name: "Amina" } } },
    { name: "another rule's hash", refusedWith: "RULE_MISMATCH", body: a({ minProjects: 2 }, { rule: { id: hiring.body.id, version: hiring.body.version, hash: "0".repeat(64) } }) },
    { name: "an id under another DID", refusedWith: "ID_MISMATCH", body: a({ minProjects: 2 }, { id: `${hiring.body.author}/adoption/planted` }) },
    { name: "outliving the rule", refusedWith: "DATES", body: a({ minProjects: 2 }, { dates: { adopted: PRACTICE_ADOPTED, renewBy: PRACTICE_RENEW, endsAt: "2029-10-01T00:00:00Z" } }) },
  ];
}

/** An adoption that sets a parameter the rulebook fixes — the internship's course code has no bounds. */
export function fixedParameterAdoption(anchor: string, internship: Rule): PlantedAdoption {
  return { name: "a parameter the rulebook fixes", refusedWith: "NOT_ADOPTABLE", body: practiceAdoption(anchor, internship, "planted", { course: "LOCAL-101" }) };
}
