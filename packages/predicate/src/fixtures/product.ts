/**
 * The product-origin rule (KS-Q1b): a buyer's door that reads where **a
 * product** comes from — goods eligible for a preferential rate only when they
 * originate in a country the scheme lists. A certificate of origin from a
 * listed chamber shows it.
 *
 * It validates because the criterion's subject is a product: d85(b) rule 1
 * binds when the subject is a person, and a product's country of origin is not
 * who anyone is. The same criterion about a person is refused (a test proves
 * both). **Everything here is SAMPLE** — the scheme, its list and the chambers
 * are practice; no real scheme's rules of origin are claimed.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { TA_TRUST_LIST } from "../constants";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, PRACTICE_VCT } from "./types";

export interface ProductOriginParties {
  /** The importer — the door, the rule's author. */
  readonly importer: string;
  /** The trust list naming the chambers that certify origin: `<publisher DID>#<list id>`. */
  readonly chamberList: string;
}

export function productOriginRule(p: ProductOriginParties, over: Partial<RuleBody> = {}): RuleBody {
  return {
    id: `${p.importer}/rule/preferential-origin`,
    version: 1,
    author: p.importer,
    title: "Goods of listed origin — the preferential rate (SAMPLE)",
    purpose: "The importer books a shipment at the preferential rate only when the goods originate in a country the scheme lists. SAMPLE scheme; practice only.",
    visibility: "public",
    parameters: {
      origin: { type: "string", value: "PK", bounds: { allowed: ["PK", "LK", "PH"] } },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "Customs officer" },
    outcome: { grants: "The shipment is booked at the preferential rate.", binds: false, sensitive: false, automaticYes: true },
    reasons: [
      { code: "origin-shown", outcome: "yes", text: "A listed chamber's certificate shows the goods originate in a listed country." },
      { code: "certificate-missing", outcome: "not-yet", text: "No certificate of origin from a listed chamber is shown yet." },
      { code: "origin-not-listed", outcome: "no", text: "The customs officer does not book the preferential rate, for the reason they give." },
    ],
    contest: { windowDays: 30, answerDays: 14, how: "Ask the importer's customs desk for a review; an officer who did not make the first decision answers." },
    anotherWay: "A paper certificate of origin, sent to the customs desk, is read by an officer.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "13" },
      anchorFamily: "work",
      authority: { kind: "law", name: "The scheme's rules of origin (SAMPLE)" },
      journey: "earn-and-spend",
      givens: {
        area: { text: "Goods shipped from a listed country to the importer.", countries: ["PK", "LK", "PH"] },
        spaces: { text: "The supplier's premises and the port of loading.", kinds: ["premises", "site"] },
        capitals: { text: "A chamber that certifies origin, and a customs officer.", needs: [{ kind: "systems", what: "The chambers' trust list" }, { kind: "people", what: "A customs officer" }] },
        culture: { text: "The scheme's rules of origin (SAMPLE).", codes: [{ title: "Rules of origin (SAMPLE)" }] },
        economy: { text: "Goods traded at the preferential rate the scheme sets.", level: "secondary" },
        time: { text: "Each shipment; the rule is reviewed yearly.", renews: "P1Y" },
        relations: { text: "Recognises certificates from the chambers on the listed trust list." },
      },
    },
    criteria: [
      {
        id: "origin",
        subject: "product",
        label: "The goods' country of origin, from a listed chamber",
        purpose: "The preferential rate applies only to goods originating in a listed country; a chamber's certificate shows where they were made.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "origin",
              format: "dc+sd-jwt",
              meta: { vct_values: [PRACTICE_VCT.originCertificate] },
              trusted_authorities: [{ type: TA_TRUST_LIST, values: [p.chamberList] }],
              claims: [
                { id: "countryOfOrigin", path: ["countryOfOrigin"] },
                { id: "issuedOn", path: ["issuedOn"] },
              ],
            },
          ],
          names: { [p.chamberList]: "the practice list of chambers" },
        },
        condition: { feel: "some r in receipts satisfies r.countryOfOrigin = origin", types: { countryOfOrigin: "string" } },
      },
    ],
    practice: true,
    ...over,
  };
}
