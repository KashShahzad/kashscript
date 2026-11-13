/**
 * Planted violations — one rule for each case of P4's second rule and node
 * rule 10, and for the other refusals validation makes. Each is the hiring
 * rule with one thing changed, and names the code it must be refused with.
 * A test proves every one is refused, and refused for that reason. KS-Q1b adds
 * a person's nationality (now refused, d85(b) rule 1), an address that is not
 * complete and not a draft, a criterion with no subject, a bad sector, and a
 * threshold outside its own bounds.
 */

import type { Criterion1_1 as Criterion, RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { DECISION_VCT } from "../constants";
import type { RefusalCode } from "../rule";
import { hiringRule, type HiringParties } from "./hiring";
import { PRACTICE_VCT } from "./types";

export interface PlantedViolation {
  readonly name: string;
  readonly rule: RuleBody;
  readonly refusedWith: RefusalCode;
}

/** A criterion reading one SD-JWT claim — the shape most violations take. */
function reads(id: string, label: string, claimPath: readonly string[], over: Partial<Criterion> = {}): Criterion {
  return {
    id,
    label,
    subject: "person",
    purpose: "Planted to prove validation refuses it — no door may ask this.",
    answer: {
      by: "receipts",
      query: [{ id, format: "dc+sd-jwt", meta: { vct_values: [PRACTICE_VCT.languageAssessment] }, claims: [{ id: "x", path: [...claimPath] }] }],
    },
    condition: { feel: "count(receipts) >= 1", types: {} },
    ...over,
  };
}

function withCriterion(p: HiringParties, c: Criterion, over: Partial<RuleBody> = {}): RuleBody {
  const base = hiringRule(p, over);
  return { ...base, criteria: [...base.criteria, c] };
}

export function plantedViolations(p: HiringParties): PlantedViolation[] {
  const out: PlantedViolation[] = [];
  const add = (name: string, refusedWith: RefusalCode, rule: RuleBody): void => {
    out.push({ name, rule, refusedWith });
  };

  // Node rule 10 — an ask for a refusal, three ways.
  add(
    "asks for another door's no",
    "ASKS_FOR_A_REFUSAL",
    withCriterion(p, {
      id: "previous-door",
      subject: "person",
      label: "What another door decided about you",
      purpose: "Planted to prove validation refuses it — no door may ask this.",
      answer: {
        by: "receipts",
        query: [{ id: "previous-door", format: "dc+sd-jwt", meta: { vct_values: [DECISION_VCT] }, claims: [{ id: "outcome", path: ["decision", "outcome"], values: ["no"] }] }],
      },
      condition: { feel: "count(receipts) >= 1", types: {} },
    }),
  );
  add("asks whether you were rejected before", "ASKS_FOR_A_REFUSAL", withCriterion(p, reads("history", "Applications history", ["previouslyRejected"])));
  add(
    "proves an absence",
    "PROVES_ABSENCE",
    withCriterion(p, { ...reads("no-complaints", "No complaints on record", ["complaint"]), condition: { feel: "count(receipts) = 0", types: {} } }),
  );

  // P4's second rule — a sensitive category (GDPR art. 9), one of each.
  for (const [cat, path] of [
    ["racial or ethnic origin", ["racialOrigin"]],
    ["religious belief", ["religion"]],
    ["political opinion", ["politicalOpinion"]],
    ["trade-union membership", ["tradeUnion", "member"]],
    ["genetic data", ["genetic", "markers"]],
    ["biometric data", ["biometricTemplate"]],
    ["health", ["healthRecord"]],
    ["sex life or orientation", ["sexualOrientation"]],
  ] as const) {
    add(`asks for ${cat}`, "SENSITIVE_CATEGORY", withCriterion(p, reads("extra", "An extra check", path)));
  }

  // P4's second rule — an ascribed identity, one of each.
  for (const [what, path] of [
    ["birth", ["placeOfBirth"]],
    ["descent", ["fatherName"]],
    ["sect", ["sect"]],
    ["caste", ["caste"]],
    ["ethnicity", ["ethnicity"]],
    ["gender", ["gender"]],
  ] as const) {
    add(`asks for ${what}`, "ASCRIBED_IDENTITY", withCriterion(p, reads("extra", "An extra check", path)));
  }

  // P4's second rule — a criterion with no stated purpose.
  const base = hiringRule(p);
  add("a criterion with no purpose", "NO_PURPOSE", { ...base, criteria: base.criteria.map((c, i) => (i === 0 ? { ...c, purpose: c.label } : c)) });

  // Node rule 3 and d43 — a score.
  add("reads a score", "READS_A_SCORE", withCriterion(p, reads("extra", "An extra check", ["creditScore"])));

  // A person's identity in a rule.
  add("names a person", "PERSON_IDENTITY", hiringRule(p, { decider: { role: "Amina, amina.k@agency.example" } }));

  // P3 — an automatic yes on an outcome that binds.
  add("an automatic yes that binds", "AUTOMATIC_YES_ON_BINDING", hiringRule(p, { outcome: { grants: "A contract.", binds: true, sensitive: false, automaticYes: true } }));

  // A known proxy left unanswered.
  add("a residence proxy, unanswered", "UNANSWERED_WARNING", withCriterion(p, { ...reads("area", "Where you live", ["postcode"]), purpose: "Planted: a proxy the author must answer in writing." }));

  // The condition: a number is a score; a clock is not deterministic; FEEL outside the subset.
  add("a condition that is a number", "FEEL_INVALID", withCriterion(p, { ...reads("extra", "An extra check", ["level"]), condition: { feel: "count(receipts)", types: {} } }));
  add("a condition that reads a clock", "FEEL_OUTSIDE_SUBSET", withCriterion(p, { ...reads("extra", "An extra check", ["level"]), condition: { feel: "today() > date(asOf)", types: {} } }));

  // d43 — a rule that never really expires.
  add("lives five years", "DATES", hiringRule(p, { dates: { published: "2026-10-01T00:00:00Z", renewBy: "2027-09-30T00:00:00Z", endsAt: "2031-10-01T00:00:00Z" } }));

  // d85(b) rule 1 — a person's nationality is an ascribed identity (KS-Q1b; it was a warning in KS-Q1).
  add("asks for a person's nationality", "ASCRIBED_IDENTITY", withCriterion(p, reads("extra", "An extra check", ["nationality"])));
  add("asks for a person's country of origin", "ASCRIBED_IDENTITY", withCriterion(p, reads("extra", "An extra check", ["countryOfOrigin"])));

  // d85(c) — the address: complete or a draft; every criterion's subject named; a real sector.
  const full = hiringRule(p);
  const { relations: _relations, ...sixGivens } = full.address!.givens;
  add("an address missing a given, not a draft", "INCOMPLETE_NOT_DRAFT", { ...full, address: { ...full.address!, givens: sixGivens } });
  add("an addressed criterion with no subject", "SUBJECT", { ...full, criteria: full.criteria.map((c, i) => (i === 0 ? (({ subject: _s, ...rest }) => rest)(c) : c)) });
  add("a sector that is not in ISIC Rev 5", "ADDRESS", { ...full, address: { ...full.address!, sector: { classification: "ISIC", revision: "5", code: "04" } } });

  // d85(b) rule 8 — a rule's own value sits inside its bounds.
  add("a threshold outside its own bounds", "BOUNDS", { ...full, parameters: { ...full.parameters, minProjects: { type: "number", value: 3, bounds: { min: 4, max: 6 } } } });

  // A format this version cannot read.
  add(
    "an mdoc query",
    "DCQL_FORMAT_UNREADABLE",
    withCriterion(p, { ...reads("extra", "An extra check", ["level"]), answer: { by: "receipts", query: [{ id: "extra", format: "mso_mdoc", claims: [{ id: "x", path: ["level"] }] }] } }),
  );
  return out;
}

/** The proxy rule with the author's written answer — it validates, and the answer publishes with it. */
export function answeredProxyRule(p: HiringParties): RuleBody {
  const planted = plantedViolations(p).find((v) => v.refusedWith === "UNANSWERED_WARNING")!.rule;
  return {
    ...planted,
    answers: [
      ...(planted.answers ?? []),
      { criterion: "area", code: "RESIDENCE_PROXY", text: "Practice only: the trial is on-site, so the desk reads the postcode district to plan travel cover, never to select." },
    ],
  };
}
