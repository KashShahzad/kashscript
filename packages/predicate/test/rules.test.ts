import { describe, expect, test } from "bun:test";
import { FORBIDDEN_NEED_PATTERN } from "@kashscript/attest/exchange";
import { answeredProxyRule, cpdRule, hiringRule, incomeRule, internshipRule, plantedViolations } from "../src/fixtures";
import { readRule, ruleHash, signRule, validateRule, RuleError } from "../src/rule";
import { refusedTerms, proxyTerms, tokens, VOCABULARY } from "../src/vocabulary";
import { ruleToDcql } from "../src/dcql";
import { party } from "./world";

const door = await party();
const other = await party();
const hp = { author: door.did, predicateIssuer: other.did, assessorList: `${other.did}#assessors` };

describe("the four fixtures validate", () => {
  for (const [name, rule] of [
    ["hiring", hiringRule(hp)],
    ["internship (HEC credit)", internshipRule({ campus: door.did })],
    ["CPD (an ICAP cycle)", cpdRule({ body: door.did, providerList: `${other.did}#providers` })],
    ["income", incomeRule({ lender: door.did, predicateIssuer: other.did })],
  ] as const) {
    test(name, () => {
      const v = validateRule(rule);
      expect(v.refusals).toEqual([]);
      expect(v.ok).toBe(true);
      expect(rule.practice).toBe(true);
    });
  }
  test("the internship's single issuer raises a warning, and the campus's written answer publishes with the rule", () => {
    const v = validateRule(internshipRule({ campus: door.did }));
    expect(v.warnings.map((w) => [w.code, w.answer !== null])).toEqual([["SINGLE_ISSUER", true]]);
  });
});

describe("every planted violation is refused, and for its reason", () => {
  const planted = plantedViolations(hp);
  test("one for each case of P4's second rule and node rule 10, and the other refusals", () => {
    expect(planted.length).toBeGreaterThanOrEqual(26);
    const cases = new Set(planted.map((p) => p.refusedWith));
    for (const c of ["ASKS_FOR_A_REFUSAL", "PROVES_ABSENCE", "SENSITIVE_CATEGORY", "ASCRIBED_IDENTITY", "NO_PURPOSE", "READS_A_SCORE", "PERSON_IDENTITY", "AUTOMATIC_YES_ON_BINDING", "UNANSWERED_WARNING"] as const) {
      expect(cases.has(c)).toBe(true);
    }
  });
  for (const p of planted) {
    test(p.name, async () => {
      const v = validateRule(p.rule);
      expect(v.ok).toBe(false);
      expect(v.refusals.map((r) => r.code)).toContain(p.refusedWith);
      // A refused rule can never be signed.
      await expect(signRule(p.rule, door)).rejects.toBeInstanceOf(RuleError);
    });
  }
  test("the same proxy, answered in writing, validates — and the answer is part of what is signed", async () => {
    const rule = answeredProxyRule(hp);
    expect(validateRule(rule).ok).toBe(true);
    const read = await readRule(await signRule(rule, door));
    expect(read.body.answers?.some((a) => a.code === "RESIDENCE_PROXY")).toBe(true);
  });
});

describe("no false refusals from plain words", () => {
  test("a date, a time or an amount in the text is not a phone number; a phone number is", () => {
    const dated = hiringRule(hp, { purpose: "Under the policy of 2025-09-25, reviewed 2026-10-01T09:00:00Z; fees from 1500.50 a month." });
    expect(validateRule(dated).ok).toBe(true);
    const phoned = hiringRule(hp, { decider: { role: "Lead, call +92 300 1234567" } });
    expect(validateRule(phoned).refusals.map((r) => r.code)).toContain("PERSON_IDENTITY");
  });
  test("a label that only mentions a proxy word asks for nothing; a claim that reads one does", () => {
    const base = hiringRule(hp);
    const labelled = { ...base, criteria: base.criteria.map((c, i) => (i === 0 ? { ...c, label: "Three projects, signed off after a face-to-face review at your address" } : c)) };
    const v = validateRule(labelled);
    expect(v.ok).toBe(true);
    expect(v.warnings).toEqual([]);
  });
});

describe("the vocabulary", () => {
  test("reads every spelling, and nothing that only contains a word", () => {
    expect(tokens("placeOfBirth")).toEqual(["place", "of", "birth"]);
    expect(refusedTerms("place_of_birth").map((h) => h.category)).toEqual(["ASCRIBED_IDENTITY"]);
    for (const innocent of ["original", "insect", "orientation week", "sextant", "raceway", "unionised", "sector", "origination"]) {
      expect(refusedTerms(innocent)).toEqual([]);
    }
    expect(proxyTerms("postal_code").map((h) => h.category)).toEqual(["RESIDENCE_PROXY"]);
  });
  test("refuses everything attest's ask refuses, so an ask and a rule agree (d36)", () => {
    const re = new RegExp(FORBIDDEN_NEED_PATTERN, "i");
    const askTerms = ["origin", "origins", "ethnic", "ethnicity", "sect", "sects", "sectarian", "caste", "castes", "ancestry", "ancestral", "ancestor", "ancestors"];
    for (const t of askTerms) {
      expect(re.test(t)).toBe(true);
      expect(refusedTerms(t).length).toBeGreaterThan(0);
    }
    expect(VOCABULARY.refuse.ASCRIBED_IDENTITY).toContain("biradari");
  });
});

describe("the signed rule", () => {
  test("is signed by its author as itself, and checks with nothing but its own DID", async () => {
    const body = hiringRule(hp);
    const env = await signRule(body, door);
    const read = await readRule(env);
    expect(read.hash).toBe(await ruleHash(body));
    await expect(signRule(body, other)).rejects.toThrow("author's own key");
    const forged = { ...env, payload: Buffer.from(JSON.stringify({ ...body, title: "Changed" })).toString("base64") };
    await expect(readRule(forged)).rejects.toBeInstanceOf(RuleError);
  });
  test("its DCQL query: one required credential set per criterion, with the predicate as an option", async () => {
    const body = hiringRule(hp);
    const q = ruleToDcql(body, await ruleHash(body));
    expect(q.credential_sets.length).toBe(body.criteria.length);
    expect(q.credential_sets.every((s) => s.required)).toBe(true);
    expect(q.credential_sets[0]!.options).toEqual([["projects"], ["projects_predicate"]]);
    expect(q.credentials.map((c) => c.id)).toEqual(["projects", "projects_predicate", "react", "english", "availability_word"]);
    expect(q.credentials.every((c) => /^[A-Za-z0-9_-]+$/.test(c.id))).toBe(true);
  });
});
