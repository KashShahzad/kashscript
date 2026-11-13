/**
 * The income rule — income a person can show (KS-Q1's fourth fixture; DD-Q1
 * builds Income You Can Show from it): at least a SAMPLE amount each month for
 * six months, from at least two payers, each payment confirmed by its payer —
 * or Duedale's predicate, *meets the income rule, version 1*.
 *
 * **It binds the person** — credit — so P3 sends every complete packet to a
 * named person, and validation refuses an automatic yes. **The figures are
 * SAMPLE.** Practice only until the lawyer reads Duedale's line (d63(f), d75).
 *
 * Its address: ISIC Rev 5 division 64 (financial service activities), the
 * work family, the lender as the institution, the earn-and-spend journey. An
 * automatic *not yet* is allowed on it although it binds (d85(e)): a not yet
 * refuses nothing.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, PRACTICE_VCT } from "./types";

export interface IncomeParties {
  /** The lender. */
  readonly lender: string;
  /** Duedale's issuer, whose predicate may answer the monthly row. */
  readonly predicateIssuer: string;
}

export function incomeRule(p: IncomeParties, over: Partial<RuleBody> = {}): RuleBody {
  const query = (id: string) => ({
    id,
    format: "dc+sd-jwt",
    multiple: true,
    meta: { vct_values: [PRACTICE_VCT.paymentConfirmed] },
    claims: [
      { id: "record", path: ["recordId"] },
      { id: "amount", path: ["amount"] },
      { id: "currency", path: ["currency"], values: ["USD"] },
      { id: "paidOn", path: ["paidOn"] },
    ],
  });
  return {
    id: `${p.lender}/rule/income-six-months`,
    version: 1,
    author: p.lender,
    title: "Income you can show — six months (SAMPLE)",
    purpose: "A lender reviews a loan against income the applicant's payers confirmed. SAMPLE figures; practice only.",
    visibility: "public",
    parameters: {
      minMonthly: { type: "number", value: 1000, bounds: { min: 500, max: 5000 } },
      minPayers: { type: "number", value: 2, bounds: { min: 1, max: 3 } },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "Credit officer" },
    outcome: { grants: "A loan offer, made by a credit officer.", binds: true, sensitive: false, automaticYes: false },
    reasons: [
      { code: "income-shown", outcome: "yes", text: "The confirmed income meets the rule; the credit officer makes the offer." },
      { code: "months-missing", outcome: "not-yet", text: "Some months, or a second payer, are not yet confirmed." },
      { code: "declined-after-review", outcome: "no", text: "The credit officer does not make an offer, for the reason they give." },
    ],
    contest: { windowDays: 30, answerDays: 14, how: "Ask for a review at the lender's desk; an officer who did not make the first decision answers, with a fresh assessment." },
    anotherWay: "Bank statements or payslips, brought to the lender's office, are read by a credit officer.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "64" },
      anchorFamily: "work",
      authority: { kind: "institution", name: "The lender (practice)" },
      journey: "earn-and-spend",
      givens: {
        area: { text: "Where the lender is licensed to lend — practice only." },
        spaces: { text: "Online, and the lender's office for the other way.", kinds: ["online", "premises"] },
        capitals: { text: "A credit officer, and the payers' own confirmations.", needs: [{ kind: "people", what: "A credit officer" }] },
        culture: { text: "The lender's fair-lending code (practice).", codes: [{ title: "Fair-lending code (practice)" }] },
        economy: { text: "A loan on terms the credit officer offers in writing.", level: "tertiary" },
        time: { text: "Six months of income; the rule is reviewed yearly.", lasts: "P6M", renews: "P1Y" },
        relations: { text: "Accepts Duedale's predicate for the monthly row." },
      },
    },
    criteria: [
      {
        id: "monthly",
        subject: "person",
        label: "At least the monthly amount, each month for six months",
        purpose: "The loan's repayment is monthly, so the rule looks for income arriving every month, as the payers confirmed it.",
        answer: { by: "receipts", query: [query("monthly")] },
        predicate: { issuers: [{ id: p.predicateIssuer, name: "Duedale (practice)" }], freshDays: 31 },
        condition: {
          feel: "every m in [1, 2, 3, 4, 5, 6] satisfies sum(receipts[paidOn > date(asOf) - m * duration(\"P1M\") and paidOn <= date(asOf) - (m - 1) * duration(\"P1M\")].amount) >= minMonthly",
          types: { amount: "number", paidOn: "date" },
        },
      },
      {
        id: "payers",
        subject: "person",
        label: "From at least two payers",
        purpose: "Income from more than one payer is what the lender's rule treats as steady; each payer confirms their own payments.",
        answer: { by: "receipts", query: [query("payers")] },
        condition: { feel: "count(distinct values(receipts[paidOn > date(asOf) - duration(\"P6M\")].issuer)) >= minPayers", types: { paidOn: "date" } },
      },
    ],
    practice: true,
    ...over,
  };
}
