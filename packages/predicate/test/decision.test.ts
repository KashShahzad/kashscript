import { beforeAll, describe, expect, test } from "bun:test";
import { decidePerson, decisionFromRoute, issueDecision, validateDecision, type DecisionBody } from "../src/decision";
import { readRule, signRule, type ReadRule } from "../src/rule";
import { hiringRule, incomeRule } from "../src/fixtures";
import { AS_OF, DAY, party, T0, type Party } from "./world";

let door: Party;
let seat: Party;
let hiring: ReadRule;
let income: ReadRule;

beforeAll(async () => {
  const other = await party();
  [door, seat] = await Promise.all([party(), party()]);
  hiring = await readRule(await signRule(hiringRule({ author: door.did, predicateIssuer: other.did, assessorList: `${other.did}#assessors` }), door));
  income = await readRule(await signRule(incomeRule({ lender: door.did, predicateIssuer: other.did }), door));
});

const H = "e".repeat(64);
function automatic(rule: ReadRule, over: Partial<DecisionBody> = {}): DecisionBody {
  return {
    rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
    outcome: "yes",
    reasons: [rule.body.reasons.find((r) => r.outcome === "yes")!.code],
    rows: { fired: rule.body.criteria.map((c) => c.id), missing: [] },
    reliedOn: [H],
    decidedBy: { kind: "standing", standing: `standing:${rule.body.author}` },
    automatic: true,
    decidedAt: AS_OF,
    contestUntil: new Date(Date.parse(AS_OF) + rule.body.contest.windowDays * DAY * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    practice: true,
    ...over,
  };
}
const codes = async (body: unknown, rule: ReadRule) => (await validateDecision(body, rule)).refusals.map((r) => r.code);

describe("the decision receipt's validation (P3, node rules 10–11)", () => {
  test("an automatic yes on a rule that only grants validates", async () => {
    expect(await codes(automatic(hiring), hiring)).toEqual([]);
  });
  test("an automatic no is refused — only a person refuses", async () => {
    expect(await codes(automatic(hiring, { outcome: "no", reasons: ["not-met"], refusal: { unmet: ["projects"], receiptsRead: true } }), hiring)).toContain("AUTOMATIC_REFUSAL");
  });
  test("an automatic partial grant is refused", async () => {
    const internshipLike = automatic(hiring, { outcome: "partial", reasons: ["meets-all"], refusal: { unmet: ["react"], receiptsRead: true } });
    expect(await codes(internshipLike, hiring)).toContain("AUTOMATIC_REFUSAL");
  });
  test("an automatic yes on a rule that binds is refused — credit is a person's decision", async () => {
    expect(await codes(automatic(income), income)).toEqual(expect.arrayContaining(["AUTOMATIC_YES_ON_BINDING", "AUTOMATIC_YES_NOT_STANDING"]));
  });
  test("an automatic yes on a sensitive rule is refused", async () => {
    const sensitive = { ...hiring, body: { ...hiring.body, outcome: { ...hiring.body.outcome, sensitive: true } } };
    expect(await codes(automatic(sensitive), sensitive)).toContain("AUTOMATIC_YES_ON_SENSITIVE");
  });
  test("a receipt's content cannot ride in a decision — the shape is closed and reliedOn holds hashes only", async () => {
    expect(await codes(automatic(hiring, { reliedOn: ['{"level":"B2"}'] }), hiring)).toContain("SHAPE");
    expect(await codes({ ...automatic(hiring), receipts: [{ level: "B2" }] }, hiring)).toContain("SHAPE");
    expect(await codes({ ...automatic(hiring), score: 0.9 }, hiring)).toContain("SHAPE");
  });
  test("the standing must be the rule author's, and only an automatic decision has one", async () => {
    expect(await codes(automatic(hiring, { decidedBy: { kind: "standing", standing: `standing:${seat.did}` } }), hiring)).toContain("STANDING_MISMATCH");
    expect(await codes(automatic(hiring, { automatic: false }), hiring)).toContain("STANDING_MISMATCH");
  });
  test("a reason must be the rule's own, for the same outcome (node rule 11)", async () => {
    expect(await codes(automatic(hiring, { reasons: ["because"] }), hiring)).toContain("REASON_NOT_IN_RULE");
    expect(await codes(automatic(hiring, { reasons: ["missing-evidence"] }), hiring)).toContain("REASON_NOT_IN_RULE");
  });
  test("a decision names its rule's exact version and hash", async () => {
    expect(await codes(automatic(hiring, { rule: { id: hiring.body.id, version: 2, hash: hiring.hash } }), hiring)).toContain("RULE_MISMATCH");
    expect(await codes(automatic(hiring, { rule: { id: hiring.body.id, version: 1, hash: H } }), hiring)).toContain("RULE_MISMATCH");
  });
  test("a not yet says what is missing; the contest window is the rule's", async () => {
    expect(await codes(automatic(hiring, { outcome: "not-yet", reasons: ["missing-evidence"], rows: { fired: [], missing: [] } }), hiring)).toContain("NOT_YET_NAMES_NOTHING");
    expect(await codes(automatic(hiring, { contestUntil: AS_OF }), hiring)).toContain("CONTEST_WINDOW");
  });
});

describe("a named person's decision", () => {
  const refuse = (over: Partial<Parameters<typeof decidePerson>[0]> = {}) =>
    decidePerson({
      rule: income,
      outcome: "no",
      reasons: ["declined-after-review"],
      fired: ["payers"],
      missing: ["monthly"],
      reliedOn: [H],
      refusal: { unmet: ["monthly"], receiptsRead: true },
      seat: { role: "Credit officer", did: seat.did, signer: seat },
      decidedAt: AS_OF,
      ...over,
    });

  test("a refusal names the unmet criterion, confirms the receipts were read, and carries the seat's signature", async () => {
    const d = await refuse();
    expect(await codes(d, income)).toEqual([]);
    expect(d.automatic).toBe(false);
    expect(d.decidedBy.kind === "person" && d.decidedBy.role).toBe("Credit officer");
  });
  test("a refusal that names no unmet criterion is refused — a refusal is never pre-filled", async () => {
    const { refusal: _drop, ...noRefusal } = await refuse();
    expect(await codes(noRefusal, income)).toContain("REFUSAL_UNEXPLAINED");
    expect(await codes({ ...(await refuse()), refusal: { unmet: ["monthly"], receiptsRead: false } }, income)).toContain("SHAPE");
  });
  test("a changed decision breaks the seat's signature", async () => {
    const d = await refuse();
    expect(await codes({ ...d, outcome: "partial" as const }, income)).toContain("SEAT_SIGNATURE");
    expect(await codes({ ...d, reliedOn: ["f".repeat(64)] }, income)).toContain("SEAT_SIGNATURE");
  });
  test("a person may say yes on a binding rule, and the receipt goes to the person", async () => {
    const signed = await decidePerson({ rule: income, outcome: "yes", reasons: ["income-shown"], fired: ["monthly", "payers"], missing: [], reliedOn: [H], seat: { role: "Credit officer", did: seat.did, signer: seat }, decidedAt: AS_OF });
    expect(await codes(signed, income)).toEqual([]);
    expect(signed.automatic).toBe(false);
    const person = await party();
    const held = await issueDecision({ body: signed, rule: income, issuer: door, holderPublicKey: person.publicKey, iatUnix: T0, expUnix: T0 + 365 * DAY });
    expect(held.split("~").length).toBeGreaterThan(2);
  });
  test("an automatic draft is never made for a route to a person", async () => {
    const routed = { route: "to-a-person" } as Parameters<typeof decisionFromRoute>[0];
    expect(() => decisionFromRoute(routed, income, { decidedAt: AS_OF })).toThrow();
  });
});
