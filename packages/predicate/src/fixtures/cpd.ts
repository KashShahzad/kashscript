/**
 * The CPD rule — a professional body's continuing-development cycle (KS-Q1's
 * third fixture; the shape of an ICAP cycle).
 *
 * **Every figure here is SAMPLE.** ICAP's own figures are not in this
 * repository and none are invented; KS-Q3 writes the real rule from the
 * directive, criterion by criterion beside its clause. The shape: hours over a
 * cycle, part of them structured, each accepted by a provider on a listed
 * trust list, and the member's own declaration.
 *
 * Its address: ISIC Rev 5 division 69 (legal and accounting activities), the
 * work family (a guild), the body as the institution, the learn journey. Its
 * hours carry SAMPLE bounds; the cycle is the body's to fix, so its one
 * allowed value is the rule's own.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { TA_TRUST_LIST } from "../constants";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, PRACTICE_VCT } from "./types";

export interface CpdParties {
  /** The professional body. */
  readonly body: string;
  /** The trust list naming CPD providers: `<publisher DID>#<list id>`. */
  readonly providerList: string;
}

const CPD_QUERY_CLAIMS = [
  { id: "record", path: ["recordId"] },
  { id: "hours", path: ["hours"] },
  { id: "structured", path: ["structured"] },
  { id: "completedOn", path: ["completedOn"] },
] as const;

export function cpdRule(p: CpdParties, over: Partial<RuleBody> = {}): RuleBody {
  const query = (id: string) => ({
    id,
    format: "dc+sd-jwt",
    multiple: true,
    meta: { vct_values: [PRACTICE_VCT.cpdRecord] },
    trusted_authorities: [{ type: TA_TRUST_LIST, values: [p.providerList] }],
    claims: [...CPD_QUERY_CLAIMS],
  });
  return {
    id: `${p.body}/rule/cpd-cycle`,
    version: 1,
    author: p.body,
    title: "CPD cycle confirmation (SAMPLE figures)",
    purpose: "The body confirms a member's continuing professional development for the cycle from providers' accepted records. SAMPLE figures, not the body's own.",
    visibility: "public",
    parameters: {
      cycle: { type: "years and months duration", value: "P3Y", bounds: { allowed: ["P3Y"] } },
      minHours: { type: "number", value: 120, bounds: { min: 100, max: 150 } },
      minStructured: { type: "number", value: 60, bounds: { min: 40, max: 80 } },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "CPD officer" },
    outcome: { grants: "Confirmation that this cycle's CPD requirement is met.", binds: false, sensitive: false, automaticYes: true },
    reasons: [
      { code: "cycle-met", outcome: "yes", text: "The cycle's hours and structured hours are met, from listed providers." },
      { code: "hours-short", outcome: "not-yet", text: "The records do not yet reach the cycle's hours or structured hours." },
      { code: "not-confirmed", outcome: "no", text: "The CPD officer does not confirm the cycle, for the reason they give." },
    ],
    contest: { windowDays: 30, answerDays: 30, how: "Ask the body's CPD office for a review; an officer who did not make the first decision answers." },
    anotherWay: "Certificates of attendance and a signed log, sent to the CPD office, are read by an officer.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "69" },
      anchorFamily: "work",
      authority: { kind: "institution", name: "The professional body (practice)" },
      journey: "learn",
      givens: {
        area: { text: "Wherever the body's members practise.", anywhere: true },
        spaces: { text: "Wherever listed providers run courses and events, in person or online.", kinds: ["premises", "online"] },
        capitals: {
          text: "Providers on the body's list, and a CPD officer.",
          needs: [
            { kind: "people", what: "A CPD officer" },
            { kind: "systems", what: "The body's list of CPD providers" },
          ],
        },
        culture: { text: "The body's code of ethics (practice).", codes: [{ title: "The body's code of ethics (practice)" }] },
        economy: { text: "Members pay providers directly; checking the cycle is free.", level: "quaternary" },
        time: { text: "A three-year cycle; the rule is reviewed yearly.", lasts: "P3Y", renews: "P1Y" },
        relations: { text: "Recognises the providers on the body's trust list." },
      },
    },
    criteria: [
      {
        id: "cycle-hours",
        subject: "person",
        label: "The cycle's hours, from listed providers",
        purpose: "The body requires a number of development hours in each cycle; providers' accepted records show them.",
        answer: { by: "receipts", query: [query("cycle-hours")], names: { [p.providerList]: "the practice list of CPD providers" } },
        condition: { feel: "sum(receipts[completedOn > date(asOf) - cycle].hours) >= minHours", types: { hours: "number", completedOn: "date" } },
      },
      {
        id: "structured-hours",
        subject: "person",
        label: "Part of them structured",
        purpose: "Part of the hours must be structured learning — courses or events a provider ran, not reading alone.",
        answer: { by: "receipts", query: [query("structured-hours")], names: { [p.providerList]: "the practice list of CPD providers" } },
        condition: {
          feel: "sum(receipts[completedOn > date(asOf) - cycle and structured].hours) >= minStructured",
          types: { hours: "number", completedOn: "date", structured: "boolean" },
        },
      },
      {
        id: "declaration",
        subject: "person",
        label: "The member's declaration",
        purpose: "The member declares the records are their own and complete for the cycle, as the body's rules ask every member to.",
        answer: { by: "own-word", statement: "These records are my own and complete for this cycle.", fields: { declared: "boolean" } },
        condition: { feel: "declared = true", types: {} },
      },
    ],
    practice: true,
    ...over,
  };
}
