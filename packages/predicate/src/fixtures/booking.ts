/**
 * The booking review rule (KS-Q11, `kash.rule@1.2.0`): a door that grants the
 * right to write one review to the guest who accepted a delivered booking.
 *
 * The receipt is Oreoasis's `booking.delivered/1` (OA-V1): a work record the
 * host's book signs, and the guest countersigns with a key made for that one
 * relationship. The payload names only the host, and the host asked for the
 * acceptance — so the query names its holder as **the countersigner**: the one
 * key whose acceptance in the bundle verifies. The guest signs the presentation
 * with it, and a desk issues its decision to it.
 *
 * Practice: SAMPLE windows, any host's book (no issuer list), no real door. The
 * shape follows Indusland's `review-right@1` (IL-V5) without copying its words.
 */

import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { PRACTICE_ENDS, PRACTICE_PUBLISHED, PRACTICE_RENEW, WORK_RECORD_TYPE } from "./types";

/** OA-V1's profile, pinned in the query. */
export const BOOKING_DELIVERED_PROFILE = "booking.delivered/1" as const;

export interface BookingParties {
  /** The organisation whose desk grants the review — the rule's author and decider. */
  readonly author: string;
}

export function bookingReviewRule(p: BookingParties, over: Partial<RuleBody> = {}): RuleBody {
  return {
    id: `${p.author}/rule/booking-review`,
    version: 1,
    author: p.author,
    title: "Write a review of a delivered booking",
    purpose: "A review is written only by someone a host delivered a booking to. The host's signed receipt, accepted by the guest, shows the booking was delivered and to whom it was handed.",
    visibility: "public",
    parameters: {
      writeWindow: { type: "days and time duration", value: "P30D", bounds: { min: "P7D", max: "P60D" } },
    },
    dates: { published: PRACTICE_PUBLISHED, renewBy: PRACTICE_RENEW, endsAt: PRACTICE_ENDS },
    decider: { role: "Reviews desk" },
    outcome: { grants: "The right to write one review of this booking.", binds: false, sensitive: false, automaticYes: true },
    reasons: [
      { code: "delivered-and-accepted", outcome: "yes", text: "A delivered booking you accepted, within the writing window: you may write one review." },
      { code: "no-receipt", outcome: "not-yet", text: "No delivered booking you accepted was shown, or its writing window has passed." },
      { code: "not-met", outcome: "no", text: "The reviews desk explains, with the receipt it read, why this booking does not open a review." },
    ],
    contest: { windowDays: 30, answerDays: 14, how: "Reply to the decision receipt, or write to the reviews desk's address on the door's page. A person who did not make the first decision answers." },
    anotherWay: "Ask the reviews desk to read the booking with you; the host's own confirmation, on paper, is read by a person.",
    address: {
      sector: { classification: "ISIC", revision: "5", code: "55" },
      anchorFamily: "movement",
      authority: { kind: "institution", name: "The reviews desk (practice)" },
      journey: "leisure",
      givens: {
        area: { text: "Wherever the host delivered the booking.", anywhere: true },
        spaces: { text: "The host's premises, or online for a booking delivered there.", kinds: ["premises", "online"] },
        capitals: { text: "A reviews desk to read what the rule cannot.", needs: [{ kind: "people", what: "A reviews desk" }] },
        culture: { text: "The door's review guidelines: about the booking, never the people in it.", codes: [{ title: "Review guidelines (practice)" }] },
        economy: { text: "Free to write; the review is the guest's own.", level: "tertiary" },
        time: { text: "Thirty days from the end of the booking's window; the rule is reviewed yearly.", lasts: "P30D", renews: "P1Y" },
        relations: { text: "Reads Oreoasis's delivered-booking receipts, accepted by the guest." },
      },
    },
    criteria: [
      {
        id: "delivered",
        subject: "person",
        label: "A delivered booking you accepted",
        purpose: "Only someone the booking was delivered to may review it; the host's receipt, countersigned by the one who received it, shows that.",
        answer: {
          by: "receipts",
          query: [
            {
              id: "delivered",
              format: "kash-artifact",
              meta: { dst_values: [WORK_RECORD_TYPE], attestation: "countersigned", holder: "countersigner" },
              claims: [
                { id: "profile", path: ["meta", "profile"], values: [BOOKING_DELIVERED_PROFILE] },
                { id: "shape", path: ["shape"], values: ["accepted"] },
                { id: "windowEnd", path: ["meta", "window", "end"] },
              ],
            },
          ],
        },
        condition: { feel: "count(receipts[windowEnd >= asOf - writeWindow]) >= 1", types: { windowEnd: "date and time" } },
      },
    ],
    practice: true,
    ...over,
  };
}
