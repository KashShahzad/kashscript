/**
 * RW-15 — a door reads a receipt's copy (`specs/attestation/README.md` §2.4a, §3 G1): the host's copy of a
 * delivered booking, one per verifier, answers a rule written for copies; the old form — the raw countersigned
 * record as a `kash-artifact` — still answers the KS-Q11 fixture; two desks' presentations share nothing to
 * join on; and a decision copy's `_sd` has one shape whatever the outcome.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { ATTESTATION_VCT, copyClaimsOfCountersigned } from "@kashscript/attest/attestation";
import { decodeJws, issueSdJwt, linkabilityBetween, parseSdJwt, sharedValues } from "@kashscript/attest/sd-jwt";
import type { Criterion1_1, RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import type { CountersignBundle } from "@kashscript/attest/countersign";
import { DECISION_SD_SLOTS, decidePerson, decisionFromRoute, issueDecision } from "../src/decision";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { route } from "../src/route";
import { readRule, ruleRequest, signRule, validateRule, type ReadRule } from "../src/rule";
import { BOOKING_DELIVERED_PROFILE, bookingReviewRule } from "../src/fixtures";
import { AS_OF, DAY, T0, bookingDelivered, party, type Party } from "./world";

type Artifact = Record<string, unknown>;

/** The booking review fixture, answered by the host's copy instead of the raw record: the same door, the copy's claims. */
function copyRule(author: string): RuleBody1_1 {
  const base = bookingReviewRule({ author });
  const c = base.criteria[0]! as Criterion1_1;
  const byCopy: Criterion1_1 = {
    ...c,
    label: "A delivered booking you accepted — the host's copy",
    purpose: "Only someone the booking was delivered to may review it; the host's copy says a booking was delivered and accepted, and is bound to the guest's key for this desk.",
    answer: {
      by: "receipts",
      query: [
        {
          id: "delivered",
          format: "dc+sd-jwt",
          meta: { vct_values: [ATTESTATION_VCT] },
          claims: [
            { id: "kind", path: ["attestation", "kind"], values: ["receipt"] },
            { id: "outcome", path: ["attestation", "outcome"], values: ["accepted"] },
            { id: "profile", path: ["attestation", "profile"], values: [BOOKING_DELIVERED_PROFILE] },
          ],
        },
      ],
    },
    condition: { feel: "count(receipts) >= 1", types: {} },
  };
  return { ...base, id: `${author}/rule/booking-review-by-copy`, parameters: {}, criteria: [byCopy] };
}

/** What every copy of a kind shows by construction — the class (§3 G1). */
const classOf = (issuer: string, iat: number, exp: number): Set<string> =>
  new Set([issuer, ATTESTATION_VCT, "dc+sd-jwt", "kb+jwt", "EdDSA", "sha-256", "receipt", "accepted", BOOKING_DELIVERED_PROFILE, String(iat), String(exp), "OKP", "Ed25519", "1"]);

let host: Party;
let guest: Party;
let booking: CountersignBundle;

beforeAll(async () => {
  [host, guest] = await Promise.all([party(), party()]);
  booking = await bookingDelivered(host, guest, { start: T0 - 5 * DAY, end: T0 - 2 * DAY });
});

async function copyFor(holder: Party): Promise<string> {
  const { claims, sdProperties, decoys } = await copyClaimsOfCountersigned(booking, { issuer: host.did, holderKey: holder.publicKey, iatUnix: T0 - DAY, grade: 1 });
  return issueSdJwt({ header: { kid: host.did }, claims, sdProperties, decoys, signer: host });
}

describe("a door reads the host's copy, one per desk (RW-15)", () => {
  test("the copy rule validates; copy A checks at desk 1 and copy B at desk 2; the two presentations share nothing beyond the class", async () => {
    const presentations: string[] = [];
    const visible = { iat: 0, exp: 0 };
    // Two doors, visited minutes apart: a binding's time belongs to its one presentation (§3 G1).
    for (const [nonce, boundAt] of [["door-nonce-rw15-0001", T0], ["door-nonce-rw15-0002", T0 + 137]] as const) {
      const desk = await party();
      const holder = await party();
      expect(validateRule(copyRule(desk.did)).ok).toBe(true);
      const rule: ReadRule = await readRule(await signRule(copyRule(desk.did), desk));
      const request = ruleRequest(rule, { nonce, responseUri: "https://desk.practice.invalid/in" });
      const held = await copyFor(holder);
      const payload = decodeJws(parseSdJwt(held)!.issuerJwt)!.payload;
      visible.iat = payload.iat as number;
      visible.exp = payload.exp as number;
      const entries: PacketEntry[] = [{ kind: "sd-jwt", queryId: "delivered", held, signer: holder }];
      const packet = await buildPacket({ rule, request, entries, iatUnix: boundAt });
      const check = await checkPacket({ rule, request, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
      expect(check.problems).toEqual([]);
      expect(check.byCriterion.delivered!.receipts.length).toBe(1);
      expect(check.byCriterion.delivered!.receipts[0]!.view.issuer).toBe(host.did);
      const routed = await route(rule, check, { asOf: AS_OF });
      expect(routed.route).toBe("automatic-yes");
      const presentation = packet.vp_token.delivered![0] as string;
      // The counterparty — the guest's key for the host — never travels: the door sees the guest's key for this desk alone.
      expect(presentation).not.toContain(guest.did);
      presentations.push(presentation);
    }
    const cls = classOf(host.did, visible.iat, visible.exp);
    const shared = await sharedValues(presentations[0]!, presentations[1]!);
    expect(shared.filter((s) => !cls.has(s.value))).toEqual([]);
    expect(await linkabilityBetween(presentations[0]!, presentations[1]!)).toEqual([]);
  });

  test("the old form keeps verifying: the same booking answers the KS-Q11 fixture as a raw kash-artifact, bound by the guest", async () => {
    const desk = await party();
    const rule = await readRule(await signRule(bookingReviewRule({ author: desk.did }), desk));
    const request = ruleRequest(rule, { nonce: "door-nonce-rw15-0003", responseUri: "https://desk.practice.invalid/in" });
    const entries: PacketEntry[] = [{ kind: "artifact", queryId: "delivered", artifact: booking as unknown as Artifact, signer: guest }];
    const packet = await buildPacket({ rule, request, entries, iatUnix: T0 });
    const check = await checkPacket({ rule, request, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
    expect(check.problems).toEqual([]);
    expect(check.byCriterion.delivered!.receipts.length).toBe(1);
    expect((await route(rule, check, { asOf: AS_OF })).route).toBe("automatic-yes");
  });

  test("a rule that reads the record's own dates reads the old form: the copy carries none of them", async () => {
    const desk = await party();
    const holder = await party();
    const rule = await readRule(await signRule(bookingReviewRule({ author: desk.did }), desk));
    const held = await copyFor(holder);
    // The fixture's query is a kash-artifact query; a copy is a dc+sd-jwt and never fits it.
    const request = ruleRequest(rule, { nonce: "door-nonce-rw15-0004", responseUri: "https://desk.practice.invalid/in" });
    await expect(buildPacket({ rule, request, entries: [{ kind: "sd-jwt", queryId: "delivered", held, signer: holder }], iatUnix: T0 })).rejects.toThrow("is answered by artifact");
    const payload = decodeJws(parseSdJwt(held)!.issuerJwt)!.payload;
    expect(JSON.stringify(payload)).not.toContain("window");
  });

  test("a decision copy's _sd holds eight digests whether it is a yes or a no", async () => {
    const [desk, seat, person, holder] = await Promise.all([party(), party(), party(), party()]);
    const rule = await readRule(await signRule(copyRule(desk.did), desk));
    const request = ruleRequest(rule, { nonce: "door-nonce-rw15-0005", responseUri: "https://desk.practice.invalid/in" });
    const packet = await buildPacket({ rule, request, entries: [{ kind: "sd-jwt", queryId: "delivered", held: await copyFor(holder), signer: holder }], iatUnix: T0 });
    const check = await checkPacket({ rule, request, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
    const routed = await route(rule, check, { asOf: AS_OF });
    const yes = decisionFromRoute(routed, rule, { decidedAt: AS_OF });
    const no = await decidePerson({ rule, outcome: "no", reasons: ["not-met"], fired: [], missing: ["delivered"], reliedOn: [], refusal: { unmet: ["delivered"], receiptsRead: true }, seat: { role: "Reviews desk", did: seat.did, signer: seat }, decidedAt: AS_OF });
    const sdOf = async (body: typeof yes) => {
      const held = await issueDecision({ body, rule, issuer: desk, holderPublicKey: person.publicKey, iatUnix: T0, expUnix: T0 + 365 * DAY });
      return (decodeJws(parseSdJwt(held)!.issuerJwt)!.payload._sd as string[]).length;
    };
    expect(await sdOf(yes)).toBe(DECISION_SD_SLOTS);
    expect(await sdOf(no)).toBe(DECISION_SD_SLOTS);
    expect(DECISION_SD_SLOTS).toBe(8);
  });
});
