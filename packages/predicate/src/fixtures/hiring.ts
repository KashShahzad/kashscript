/**
 * The hiring rule (KS-Q1's first fixture; OA-Q3 answers it end to end):
 *   1. three projects accepted by clients in the last 24 months — countersigned
 *      work records (Client Sign-off's approvals), or Oreoasis's predicate;
 *   2. React in one of them;
 *   3. English at B2 or above, from an assessor on a listed trust list;
 *   4. availability, on the applicant's own word.
 * A yes grants a paid trial project and binds no one, so the author's signed
 * rule carries the standing yes.
 *
 * Its address (KS-Q1b, d85(c)): ISIC Rev 5 division 62 (computer programming),
 * the work family, the organisation's own rule, the earn-and-spend journey, and
 * all seven givens. Three thresholds carry bounds, so an anchor may adopt it
 * with its own values (d85(b) rule 8). Every bound is SAMPLE.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { TA_TRUST_LIST } from "../constants";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, PRACTICE_VCT, WORK_RECORD_TYPE } from "./types";

export interface HiringParties {
  /** The hiring organisation — the door, the rule's author, the decider. */
  readonly author: string;
  /** Oreoasis's issuer, whose predicate may answer the projects row. */
  readonly predicateIssuer: string;
  /** The trust list that names language assessors: `<publisher DID>#<list id>`. */
  readonly assessorList: string;
}

const PROJECT_CLAIMS = [
  { id: "acceptedAt", path: ["timestamp"] },
  { id: "skills", path: ["meta", "stack"] },
  { id: "shape", path: ["shape"], values: ["accepted"] },
] as const;

export function hiringRule(p: HiringParties, over: Partial<RuleBody> = {}): RuleBody {
  return {
    id: `${p.author}/rule/contract-developer`,
    version: 1,
    author: p.author,
    title: "Contract developer — paid trial project",
    purpose: "We hire developers for client work. Accepted client projects show the work was delivered; React is what the trial uses; the client calls are in English.",
    visibility: "public",
    parameters: {
      minProjects: { type: "number", value: 3, bounds: { min: 2, max: 5 } },
      window: { type: "years and months duration", value: "P24M", bounds: { min: "P12M", max: "P36M" } },
      startWithin: { type: "days and time duration", value: "P28D", bounds: { min: "P7D", max: "P56D" } },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "Hiring lead" },
    outcome: { grants: "An invitation to a paid trial project.", binds: false, sensitive: false, automaticYes: true },
    reasons: [
      { code: "meets-all", outcome: "yes", text: "Every criterion is met: you are invited to the paid trial project." },
      { code: "missing-evidence", outcome: "not-yet", text: "Something the rule asks for is missing; the list says what, and who may supply it." },
      { code: "not-met", outcome: "no", text: "A criterion is not met, as the hiring lead explains with the receipts they read." },
    ],
    contest: { windowDays: 30, answerDays: 14, how: "Reply to the decision receipt, or write to the hiring desk's address on the door's page. A person who did not make the first decision answers." },
    anotherWay: "Send your work by any route the door's page lists — a portfolio and two references — and the hiring lead reads it in person.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "62" },
      anchorFamily: "work",
      authority: { kind: "institution", name: "The hiring organisation (practice)" },
      journey: "earn-and-spend",
      givens: {
        area: { text: "Remote client work, from anywhere.", anywhere: true },
        spaces: { text: "Online: the trial project is remote.", kinds: ["online"] },
        capitals: {
          text: "A hiring lead to read what the rule cannot, and the trial project's repository.",
          needs: [
            { kind: "people", what: "A hiring lead" },
            { kind: "systems", what: "The trial project's repository" },
          ],
        },
        culture: { text: "The organisation's code of conduct for contractors; client calls are in English.", codes: [{ title: "Contractor code of conduct (practice)" }], languages: ["en"] },
        economy: { text: "A paid trial project, priced in writing before it starts.", level: "quaternary" },
        time: { text: "Projects from the last 24 months; a trial of up to four weeks; the rule is reviewed yearly.", lasts: "P28D", renews: "P1Y" },
        relations: { text: "Accepts Client Sign-off's countersigned work records, Oreoasis's predicate, and assessors on the listed trust list." },
      },
    },
    criteria: [
      {
        id: "projects",
        subject: "person",
        label: "Three projects accepted by clients in the last 24 months",
        purpose: "Client work is what we hire for; a client's countersigned acceptance shows the work was delivered and taken.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "projects",
              format: "kash-artifact",
              multiple: true,
              meta: { dst_values: [WORK_RECORD_TYPE], attestation: "countersigned", holder_path: ["actor", "id"] },
              claims: [...PROJECT_CLAIMS],
            },
          ],
        },
        predicate: { issuers: [{ id: p.predicateIssuer, name: "Oreoasis (practice)" }], freshDays: 31 },
        condition: { feel: "count(receipts[acceptedAt >= asOf - window]) >= minProjects", types: { acceptedAt: "date and time" } },
      },
      {
        id: "react",
        subject: "person",
        label: "React in one of those projects",
        purpose: "The trial project is built in React, so one accepted project should have used it.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "react",
              format: "kash-artifact",
              multiple: true,
              meta: { dst_values: [WORK_RECORD_TYPE], attestation: "countersigned", holder_path: ["actor", "id"] },
              claims: [...PROJECT_CLAIMS],
            },
          ],
        },
        condition: {
          feel: 'some p in receipts[acceptedAt >= asOf - window] satisfies list contains(p.skills, "React")',
          types: { acceptedAt: "date and time", skills: "list of string" },
        },
      },
      {
        id: "english",
        subject: "person",
        label: "English at B2 or above, from a listed assessor",
        purpose: "Client calls and written briefs are in English; an independent assessor's level shows it without an interview.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "english",
              format: "dc+sd-jwt",
              meta: { vct_values: [PRACTICE_VCT.languageAssessment] },
              trusted_authorities: [{ type: TA_TRUST_LIST, values: [p.assessorList] }],
              claims: [
                { id: "language", path: ["language"], values: ["en"] },
                { id: "framework", path: ["framework"], values: ["CEFR"] },
                { id: "level", path: ["level"] },
              ],
            },
          ],
          names: { [p.assessorList]: "the practice list of language assessors" },
        },
        condition: { feel: 'some r in receipts satisfies r.level in ("B2", "C1", "C2")', types: { level: "string" } },
      },
      {
        id: "availability",
        subject: "person",
        label: "Available to start within four weeks",
        purpose: "The trial project starts within the month, and only the applicant can say when they are free.",
        answer: { by: "own-word", statement: "I can start the trial project on or before the date I give.", fields: { availableFrom: "date" } },
        condition: { feel: "availableFrom <= date(asOf + startWithin)", types: {} },
      },
    ],
    practice: true,
    ...over,
  };
}

/** The same rule, private: its queries stay public; its thresholds are sealed (with no bounds — a sealed value is never adopted) and the desk holds the openings. */
export function privateHiringRule(p: HiringParties, sealed: Readonly<Record<string, string>>): RuleBody {
  const base = hiringRule(p);
  const parameters = Object.fromEntries(Object.entries(base.parameters ?? {}).map(([n, prm]) => [n, { type: prm.type, sealed: sealed[n]! }]));
  return { ...base, id: `${p.author}/rule/contract-developer-private`, visibility: "private", parameters };
}
