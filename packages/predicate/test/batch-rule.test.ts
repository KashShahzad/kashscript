/**
 * PY-5 — a batch accepted on a sample (attest's kash.attestation@1.1.0) is read by a rule only as accepted.
 * What was found short is a count of faults in someone's work, and its bound a rate of them (d43: no personal
 * error counts): no rule reads which positions fell short, and a rule about a person reads nothing of a batch
 * but that it was accepted. A rule about an organisation's deliveries or a product may read the batch's bound.
 */

import { describe, expect, test } from "bun:test";
import type { Criterion1_1, RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import { ATTESTATION_DST } from "@kashscript/attest/attestation";
import { validateRule } from "../src/rule";
import { hiringRule } from "../src/fixtures";

const A = "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt";
const B = "did:kash:DnaeU6DTGVNs3fgcy5XkzHLfCtuEB7Fo7B76ugLp3YxV5LQ7";

type Query = Extract<Criterion1_1["answer"], { by: "receipts" }>["query"][number];
type Claim = NonNullable<Query["claims"]>[number];

const meta = { dst_values: [ATTESTATION_DST], attestation: "countersigned" as const };
const accepted: Claim = { id: "outcome", path: ["outcome"], values: ["accepted"] };

/** The hiring rule with one more criterion, about `subject`, answered by one batch record. */
function reading(subject: "person" | "organisation" | "product", claims: Claim[]): RuleBody1_1 {
  const base = hiringRule({ author: A, predicateIssuer: B, assessorList: `${B}#assessors` });
  const c: Criterion1_1 = {
    id: "accepted-batch",
    subject,
    label: "A batch the client accepted",
    purpose: "The door reads one batch of delivered work that the client accepted on a drawn sample.",
    answer: { by: "receipts", query: [{ id: "accepted-batch", format: "kash-artifact", meta, claims: [accepted, ...claims] }] },
    condition: { feel: "count(receipts) >= 1", types: {} },
  };
  return { ...base, criteria: [...base.criteria, c] };
}
const refusals = (r: RuleBody1_1) => validateRule(r).refusals;
const codes = (r: RuleBody1_1) => refusals(r).map((x) => x.code);

describe("a rule reads a batch acceptance only as accepted", () => {
  test("reading only that a batch was accepted is allowed, whatever the subject", () => {
    for (const s of ["person", "organisation", "product"] as const) expect(codes(reading(s, []))).not.toContain("READS_A_SCORE");
  });

  test("no rule reads which positions were found short — not even about a product, and not by reading the whole batch or a wildcard", () => {
    for (const s of ["person", "organisation", "product"] as const) {
      for (const path of [["batch", "found"], ["batch"], ["batch", null]] as Claim["path"][]) {
        const r = refusals(reading(s, [{ id: "found", path }]));
        expect(r.map((x) => x.code)).toContain("READS_A_SCORE");
        expect(r.find((x) => x.code === "READS_A_SCORE")!.message).toContain("found short");
      }
    }
  });

  test("a rule about a person reads nothing of a batch: not its bound, not its size, not its plan", () => {
    for (const path of [["batch", "bound"], ["batch", "seal", "size"], ["batch", "seal", "plan", "limit"]]) {
      const r = refusals(reading("person", [{ id: "x", path }]));
      expect(r.map((x) => x.code)).toContain("READS_A_SCORE");
      expect(r.find((x) => x.code === "READS_A_SCORE")!.message).toContain("nothing of a batch but that it was accepted");
    }
  });

  test("a rule about an organisation's deliveries, or a product, may read the bound", () => {
    for (const s of ["organisation", "product"] as const) expect(codes(reading(s, [{ id: "bound", path: ["batch", "bound"] }]))).not.toContain("READS_A_SCORE");
  });

  test("the outcome pin still binds a batch record: a batch's not yet is never asked for", () => {
    const base = reading("organisation", []);
    const c = base.criteria[base.criteria.length - 1]!;
    if (c.answer.by !== "receipts") throw new Error("unreachable");
    const notYet: RuleBody1_1 = {
      ...base,
      criteria: [...base.criteria.slice(0, -1), { ...c, answer: { by: "receipts", query: [{ ...c.answer.query[0]!, claims: [{ id: "outcome", path: ["outcome"], values: ["not-yet"] }] }] } }],
    };
    expect(codes(notYet)).toContain("ASKS_FOR_A_REFUSAL");
  });
});
