/**
 * RW-14 — node rule 10 reaches the attestation (`specs/attestation/README.md` §1.5): a rule reads one only as
 * accepted. A not yet, a finding or a contest is never something a door asks to see against someone (P4.2; d43).
 */

import { describe, expect, test } from "bun:test";
import type { Criterion1_1, RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import { ATTESTATION_DST, ATTESTATION_VCT } from "@kashscript/attest/attestation";
import { validateRule } from "../src/rule";
import { hiringRule } from "../src/fixtures";

const A = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const B = "did:kash:DnaeU6DTGVNs3fgcy5XkzHLfCtuEB7Fo7B76ugLp3YxV5LQ7";

type Query = Extract<Criterion1_1["answer"], { by: "receipts" }>["query"][number];

/** The hiring rule with one more criterion answered by one attestation query. */
function reading(query: Query): RuleBody1_1 {
  const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
  const c: Criterion1_1 = {
    id: "accepted-work",
    subject: "person",
    label: "Work a client accepted",
    purpose: "The door reads one accepted delivery, as a sample of the applicant's work.",
    answer: { by: "receipts", query: [query] },
    condition: { feel: "count(receipts) >= 1", types: {} },
  };
  return { ...base, criteria: [...base.criteria, c] };
}
const refusals = (r: RuleBody1_1) => validateRule(r).refusals.map((x) => x.code);

describe("node rule 10 reads an attestation only as accepted", () => {
  test("a copy pinned to accepted is not an ask for a refusal", () => {
    expect(refusals(reading({ id: "accepted-work", format: "dc+sd-jwt", meta: { vct_values: [ATTESTATION_VCT] }, claims: [{ id: "outcome", path: ["attestation", "outcome"], values: ["accepted"] }] }))).not.toContain("ASKS_FOR_A_REFUSAL");
  });
  test("a copy pinned to not yet, or not pinned at all, is refused", () => {
    expect(refusals(reading({ id: "accepted-work", format: "dc+sd-jwt", meta: { vct_values: [ATTESTATION_VCT] }, claims: [{ id: "outcome", path: ["attestation", "outcome"], values: ["not-yet"] }] }))).toContain("ASKS_FOR_A_REFUSAL");
    expect(refusals(reading({ id: "accepted-work", format: "dc+sd-jwt", meta: { vct_values: [ATTESTATION_VCT] }, claims: [{ id: "kind", path: ["attestation", "kind"], values: ["receipt"] }] }))).toContain("ASKS_FOR_A_REFUSAL");
  });
  test("a contest or a finding cannot be asked for — their outcomes are never accepted", () => {
    expect(refusals(reading({ id: "accepted-work", format: "dc+sd-jwt", meta: { vct_values: [ATTESTATION_VCT] }, claims: [{ id: "outcome", path: ["attestation", "outcome"], values: ["refused"] }] }))).toContain("ASKS_FOR_A_REFUSAL");
    expect(refusals(reading({ id: "accepted-work", format: "dc+sd-jwt", meta: { vct_values: [ATTESTATION_VCT] }, claims: [{ id: "outcome", path: ["attestation", "outcome"], values: ["finding"] }] }))).toContain("ASKS_FOR_A_REFUSAL");
  });
  test("the record of truth, read as a countersigned artifact, is pinned at [\"outcome\"]", () => {
    const meta = { dst_values: [ATTESTATION_DST], attestation: "countersigned" as const };
    expect(refusals(reading({ id: "accepted-work", format: "kash-artifact", meta, claims: [{ id: "outcome", path: ["outcome"], values: ["accepted"] }] }))).not.toContain("ASKS_FOR_A_REFUSAL");
    expect(refusals(reading({ id: "accepted-work", format: "kash-artifact", meta, claims: [{ id: "outcome", path: ["outcome"], values: ["accepted", "not-yet"] }] }))).toContain("ASKS_FOR_A_REFUSAL");
  });
});
