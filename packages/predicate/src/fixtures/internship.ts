/**
 * The internship rule — credit for a supervised internship (KS-Q1's second
 * fixture; OA-N2 builds from it). HEC's notice of 2025-09-25 requires at least
 * three credit hours of supervised internship in every undergraduate programme,
 * and says nothing about how the internship is verified; the campus decides.
 *
 * **Every threshold here is SAMPLE** — OA-E3's shape (weeks, each approved by
 * the site supervisor; a final review countersigned from the campus's own
 * account), never a campus's real figures. **Never attendance** (d74(d)): the
 * record holds approved weeks and a review, not presence.
 *
 * The campus is the only issuer it accepts, which validation warns is a proxy
 * risk; the fixture carries the campus's written answer.
 *
 * Its address is the worked example on d85's page (*The Auditable Society*):
 * Education (ISIC Rev 5 division 85), the knowledge family, the law (the
 * higher-education regulator), the learn journey; any campus in Pakistan, a
 * host workplace, a qualified supervisor, the host's code of conduct, paid or
 * unpaid stated in advance, three credit hours reviewed yearly. Its local
 * parameter is the page's: minimum weeks, between six and twelve.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { TA_ISSUER } from "../constants";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, PRACTICE_VCT } from "./types";

const HEC_NOTICE = "https://www.hec.gov.pk/english/news/news/Pages/HEC-Announces-Mandatory-Professional-Certifications-&-Internships-for-Undergraduate-Degrees.aspx";

export interface InternshipParties {
  /** The campus — the door, the issuer of its own internship records, the decider. */
  readonly campus: string;
}

export function internshipRule(p: InternshipParties, over: Partial<RuleBody> = {}): RuleBody {
  return {
    id: `${p.campus}/rule/internship-credit`,
    version: 1,
    author: p.campus,
    title: "Internship credit (SAMPLE rule)",
    purpose: "The campus awards the internship course's credit hours for a supervised internship its own record shows was completed. SAMPLE figures until the campus supplies its own.",
    visibility: "public",
    parameters: {
      minWeeks: { type: "number", value: 6, bounds: { min: 6, max: 12 } },
      minHours: { type: "number", value: 120, bounds: { min: 80, max: 240 } },
      course: { type: "string", value: "SAMPLE-INT-300" },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "Internship coordinator" },
    outcome: { grants: "The internship course's three credit hours (SAMPLE course code).", binds: false, sensitive: false, automaticYes: true },
    reasons: [
      { code: "supervised-and-reviewed", outcome: "yes", text: "The internship record shows the weeks approved and the final review signed: the credit is awarded." },
      { code: "record-incomplete", outcome: "not-yet", text: "The record does not yet show every approved week, the hours, or the final review." },
      { code: "not-awarded", outcome: "no", text: "The coordinator does not award the credit, for the reason they give." },
      { code: "partial-credit", outcome: "partial", text: "The coordinator awards part of the credit, for the reason they give." },
    ],
    contest: { windowDays: 30, answerDays: 21, how: "Ask the department office for a review; the head of department, who did not make the first decision, answers." },
    anotherWay: "A signed paper logbook and the academic supervisor's letter, handed to the department office, are read by the coordinator in person.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "85" },
      anchorFamily: "knowledge",
      authority: { kind: "law", name: "The higher-education regulator (HEC)", url: HEC_NOTICE },
      journey: "learn",
      givens: {
        area: { text: "Any campus in Pakistan.", countries: ["PK"] },
        spaces: { text: "A host workplace.", kinds: ["workplace"] },
        capitals: { text: "A qualified supervisor at the host.", needs: [{ kind: "people", what: "A qualified site supervisor" }] },
        culture: { text: "The host's code of conduct.", codes: [{ title: "The host's code of conduct" }] },
        economy: { text: "Paid or unpaid, stated in advance." },
        time: { text: "Three credit hours; reviewed yearly.", renews: "P1Y" },
        relations: {
          text: "Sits within HEC's supervised-internship requirement; another campus's internship receipts are read by the coordinator on the other way (SAMPLE).",
          within: [{ id: "HEC: supervised internship for undergraduate degrees (2025-09-25)" }],
        },
      },
    },
    criteria: [
      {
        id: "supervised-internship",
        subject: "person",
        label: "The weeks approved by the site supervisor, and the final review signed",
        purpose: "The credit is for a supervised internship: each week approved where it happened, and reviewed by the academic supervisor at the end.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "supervised-internship",
              format: "dc+sd-jwt",
              meta: { vct_values: [PRACTICE_VCT.internshipRecord] },
              trusted_authorities: [{ type: TA_ISSUER, values: [p.campus] }],
              claims: [
                { id: "weeksApproved", path: ["weeks", null, "approvedOn"] },
                { id: "finalReviewOn", path: ["finalReviewOn"] },
                { id: "hoursStated", path: ["hoursStated"] },
              ],
            },
          ],
          names: { [p.campus]: "the campus (practice)" },
        },
        condition: {
          feel: "some r in receipts satisfies count(r.weeksApproved) >= minWeeks and r.hoursStated >= minHours and r.finalReviewOn <= date(asOf)",
          types: { weeksApproved: "list of date", finalReviewOn: "date", hoursStated: "number" },
        },
        basis: {
          title: "HEC: professional certifications and internships for undergraduate degrees (2025-09-25)",
          url: HEC_NOTICE,
          clause: "at least three credit hours of supervised internship",
        },
      },
      {
        id: "course",
        subject: "person",
        label: "The course this credit counts toward",
        purpose: "The credit is recorded against one course; the student names the course code their programme lists.",
        answer: { by: "own-word", statement: "The internship counts toward this course on my programme.", fields: { courseCode: "string" } },
        condition: { feel: "courseCode = course", types: {} },
      },
    ],
    answers: [
      {
        criterion: "supervised-internship",
        code: "SINGLE_ISSUER",
        text: "The credit is the campus's own course credit, and only the campus keeps the record of its own supervised internships; the paper route covers anyone whose record the campus does not hold.",
      },
    ],
    practice: true,
    ...over,
  };
}
