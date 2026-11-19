/**
 * RW-14 — `kash.decision@1.2.0`: a decision cites the mandate its signature was made under (d91(a);
 * `specs/attestation/README.md` §1.6, `specs/decision.md` v3). The shape across versions comes from the
 * conformance cases; the checks that need a signed rule, and the worked example, are here.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { validate } from "@kashscript/lexicons/schema";
import { signEnvelope, verifyEnvelope, type DsseEnvelope } from "@kashscript/attest/dsse";
import { resolveDidKey } from "@kashscript/attest/signing";
import { checkMandate, MANDATE_DST, MANDATE_ID_PATTERN as ATTEST_MANDATE_ID_PATTERN, payloadSha256, type MandateBody } from "@kashscript/attest/attestation";
import {
  decidePerson,
  decisionFromRoute,
  KASH_DECISION_1_2_BODY_SCHEMA,
  KASH_DECISION_1_2_ID,
  KASH_DECISION_BODY_SCHEMA,
  KASH_DECISION_ID,
  MANDATE_ID_PATTERN,
  readDecision,
  validateDecision,
  type DecisionBody,
} from "../src/decision";
import { readRule, signRule, type ReadRule } from "../src/rule";
import { incomeRule, hiringRule } from "../src/fixtures";
import { AS_OF, party, type Party } from "./world";

const SPECS = join(import.meta.dir, "..", "..", "..", "specs");
const readJson = <T = unknown>(...p: string[]): T => JSON.parse(readFileSync(join(...p), "utf8")) as T;

interface DecisionTck {
  readonly lexicon: string;
  readonly cases: readonly { readonly name: string; readonly valid: Record<string, boolean>; readonly body: unknown }[];
}

describe("kash.decision@1.2.0 across versions (specs/attestation/tck)", () => {
  const file = readJson<DecisionTck>(SPECS, "attestation", "tck", "kash.decision@1.2.0", "cases.json");
  test("the file names the version", () => {
    expect(file.lexicon).toBe(KASH_DECISION_1_2_ID);
  });
  for (const c of file.cases) {
    test(c.name, () => {
      expect(validate(KASH_DECISION_BODY_SCHEMA, c.body).ok).toBe(c.valid[KASH_DECISION_ID] === true);
      expect(validate(KASH_DECISION_1_2_BODY_SCHEMA, c.body).ok).toBe(c.valid[KASH_DECISION_1_2_ID] === true);
      expect(Object.keys(c.valid).sort()).toEqual([KASH_DECISION_ID, KASH_DECISION_1_2_ID].sort());
    });
  }
  test("every case valid under 1.1.0 is valid under 1.2.0 — a 1.1.0 body is a 1.2.0 body", () => {
    for (const c of file.cases) if (c.valid[KASH_DECISION_ID]) expect(c.valid[KASH_DECISION_1_2_ID]).toBe(true);
  });
  test("predicate and attest write one mandate id pattern", () => {
    expect(MANDATE_ID_PATTERN.source).toBe(ATTEST_MANDATE_ID_PATTERN.source);
  });
});

describe("a decision's signature cites its mandate (d91(a))", () => {
  let lender: Party;
  let seat: Party;
  let other: Party;
  let income: ReadRule;
  let hiring: ReadRule;
  const H = "4358664030978fc689356b0390c938a7137186c1a71ac916c50780ab26544950";
  beforeAll(async () => {
    [lender, seat, other] = await Promise.all([party(), party(), party()]);
    income = await readRule(await signRule(incomeRule({ lender: lender.did, predicateIssuer: other.did }), lender));
    hiring = await readRule(await signRule(hiringRule({ author: lender.did, predicateIssuer: other.did, assessorList: `${other.did}#assessors` }), lender));
  });
  const person = (mandateId: string): Promise<DecisionBody> =>
    decidePerson({
      rule: income,
      outcome: "yes",
      reasons: ["income-shown"],
      fired: income.body.criteria.map((c) => c.id),
      missing: [],
      reliedOn: [],
      seat: { role: "Credit officer", did: seat.did, signer: seat, mandate: { id: mandateId, hash: H } },
      decidedAt: AS_OF,
    });

  test("a seat's decision citing the lender's mandate validates — and says the mandate itself was not read", async () => {
    const b = await person(`${lender.did}/mandate/credit-officer-seat`);
    expect(b.decidedBy).toMatchObject({ kind: "person", mandate: { id: `${lender.did}/mandate/credit-officer-seat`, hash: H } });
    const v = await validateDecision(b, income);
    expect(v.refusals).toEqual([]);
    expect(v.notChecked?.join(" ")).toContain("not presented");
  });
  test("a presented mandate is checked whole: the lender's, to this seat, a seat's, covering this outcome, in force", async () => {
    const id = `${lender.did}/mandate/credit-officer-seat`;
    const base: MandateBody = {
      id,
      principal: lender.did,
      delegate: { key: seat.did, kind: "seat", role: "Credit officer" },
      scope: { kinds: ["decision"], outcomes: ["accepted", "not-yet", "refused"] },
      dates: { from: "2026-10-01T00:00:00Z", until: "2027-09-30T00:00:00Z" },
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "7", statusListCredential: "https://lender.example/status/mandates" },
      practice: true,
    };
    const check = async (m: MandateBody, signer: Party = lender) => {
      const envelope = await signEnvelope(m, MANDATE_DST, signer, { canonical: true });
      const b = await decidePerson({ rule: income, outcome: "yes", reasons: ["income-shown"], fired: income.body.criteria.map((c) => c.id), missing: [], reliedOn: [], seat: { role: "Credit officer", did: seat.did, signer: seat, mandate: { id: m.id, hash: await payloadSha256(envelope) } }, decidedAt: AS_OF });
      return validateDecision(b, income, undefined, { mandate: envelope });
    };
    const fair = await check(base);
    expect(fair.refusals).toEqual([]);
    expect(fair.notChecked).toBeUndefined();
    const refused = async (m: MandateBody, signer?: Party) => (await check(m, signer)).refusals.map((r) => r.message).join(" | ");
    expect(await refused({ ...base, delegate: { key: other.did, kind: "seat" } })).toContain("its delegate is not the deciding seat");
    expect(await refused({ ...base, delegate: { key: seat.did, kind: "desk" }, scope: { kinds: ["decision"], outcomes: ["accepted"] } })).toContain("its mandate is a seat's");
    expect(await refused({ ...base, scope: { kinds: ["decision"], outcomes: ["not-yet"] } })).toContain("does not cover accepted");
    expect(await refused({ ...base, dates: { from: "2026-11-01T00:00:00Z", until: "2027-10-31T00:00:00Z" } })).toContain("outside its dates");
    expect(await refused(base, other)).toContain("signature on it does not check");
  });
  test("the seat signs the citation: change the mandate and the signature fails", async () => {
    const b = await person(`${lender.did}/mandate/credit-officer-seat`);
    const changed = { ...b, decidedBy: { ...b.decidedBy, mandate: { id: `${lender.did}/mandate/credit-officer-seat`, hash: "f".repeat(64) } } };
    expect((await validateDecision(changed, income)).refusals.map((r) => r.code)).toContain("SEAT_SIGNATURE");
  });
  test("a mandate another organisation granted is refused", async () => {
    const b = await person(`${other.did}/mandate/credit-officer-seat`);
    expect((await validateDecision(b, income)).refusals.map((r) => r.code)).toEqual(["MANDATE_MISMATCH"]);
  });
  test("without a mandate, a seat signs exactly what 1.1.0 signed", async () => {
    const b = await decidePerson({ rule: income, outcome: "yes", reasons: ["income-shown"], fired: income.body.criteria.map((c) => c.id), missing: [], reliedOn: [], seat: { role: "Credit officer", did: seat.did, signer: seat }, decidedAt: AS_OF });
    expect(b.decidedBy).not.toHaveProperty("mandate");
    expect(validate(KASH_DECISION_BODY_SCHEMA, b).ok).toBe(true);
    expect((await validateDecision(b, income)).refusals).toEqual([]);
  });
  test("a standing decision cites no mandate — its copy is the deciding organisation's own signature", async () => {
    // A route's result, as `route` returns it for an automatic yes — only the fields decisionFromRoute reads.
    const r = {
      route: "automatic-yes",
      reasons: [hiring.body.reasons.find((x) => x.outcome === "yes")!.code],
      fired: hiring.body.criteria.map((c) => c.id),
      missing: [],
      reliedOn: [],
      adoption: null,
    } as unknown as Parameters<typeof decisionFromRoute>[0];
    const b = decisionFromRoute(r, hiring, { decidedAt: AS_OF });
    expect(b.decidedBy).toEqual({ kind: "standing", standing: `standing:${lender.did}` });
    expect((await validateDecision(b, hiring)).refusals).toEqual([]);
    const cited = { ...b, decidedBy: { ...b.decidedBy, mandate: { id: `${lender.did}/mandate/desk`, hash: H } } };
    expect((await validateDecision(cited, hiring)).refusals.map((x) => x.code)).toContain("SHAPE");
  });
});

describe("the worked example: decision-person-mandate", () => {
  const dir = join(SPECS, "attestation", "examples", "decision-person-mandate");
  const ruleEnvelope = readJson<DsseEnvelope>(dir, "rule.dsse.json");
  const mandate = readJson<MandateBody>(dir, "mandate.body.json");
  const mandateEnvelope = readJson<DsseEnvelope>(dir, "mandate.dsse.json");
  const body = readJson<DecisionBody>(dir, "decision.body.json");
  const copy = readFileSync(join(dir, "copy.sd-jwt.txt"), "utf8").trim();
  const context = readJson<{ checkAt: number; lender: string; seat: string }>(dir, "context.json");

  test("the decision validates under its rule, with the seat's signature over the citation and the mandate checked whole", async () => {
    const rule = await readRule(ruleEnvelope);
    expect(rule.body.author).toBe(context.lender);
    const v = await validateDecision(body, rule, undefined, { mandate: mandateEnvelope });
    expect(v.refusals).toEqual([]);
    expect(v.notChecked).toBeUndefined();
    expect(validate(KASH_DECISION_BODY_SCHEMA, body).ok).toBe(false);
    expect(validate(KASH_DECISION_1_2_BODY_SCHEMA, body).ok).toBe(true);
  });
  test("the cited mandate is the lender's, to this seat, for decisions, in force, and signed by the lender alone", async () => {
    expect(checkMandate(mandate).ok).toBe(true);
    expect(mandateEnvelope.payloadType).toBe(MANDATE_DST);
    const cited = body.decidedBy.kind === "person" ? body.decidedBy.mandate : undefined;
    expect(cited).toEqual({ id: mandate.id, hash: await payloadSha256(mandateEnvelope) });
    expect(mandate.principal).toBe(context.lender);
    expect(body.decidedBy.kind === "person" && body.decidedBy.seat).toBe(mandate.delegate.key);
    expect(mandate.scope.kinds).toContain("decision");
    expect(mandate.scope.outcomes).toContain("accepted"); // a decision's yes, in d91's words
    const at = Date.parse(body.decidedAt);
    expect(at >= Date.parse(mandate.dates.from) && at < Date.parse(mandate.dates.until)).toBe(true);
    const v = await verifyEnvelope(mandateEnvelope, resolveDidKey);
    expect(v.verifiedKeyids).toEqual([context.lender]);
  });
  test("the person's copy reads, and the citation travels inside decidedBy — disclosed only if they choose", async () => {
    const read = await readDecision(copy, { nowSec: context.checkAt });
    expect(read?.ok).toBe(true);
    expect(read?.issuer).toBe(context.lender);
    expect(read?.decision.decidedBy).toEqual(body.decidedBy);
    expect(read?.disclosed).toContain("decidedBy");
  });
});
