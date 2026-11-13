import { beforeAll, describe, expect, test } from "bun:test";
import { issueSdJwt, jwkOf } from "@kashscript/attest/sd-jwt";
import { checklist } from "../src/checklist";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { route } from "../src/route";
import { decidePerson, decisionFromRoute, validateDecision } from "../src/decision";
import { readRule, ruleRequest, signRule, type ReadRule } from "../src/rule";
import { readAdoption, signAdoption, type ReadAdoption } from "../src/adoption";
import { cpdRule, incomeAdoption, incomeRule, internshipRule, PRACTICE_VCT, registerPracticeTypes } from "../src/fixtures";
import { AS_OF, criterionPredicate, DAY, dateOf, party, T0, trustList, type Party } from "./world";

/** An SD-JWT receipt from `issuer` to a fresh copy key; every claim but the pinned ones is selectively disclosable. */
async function receipt(issuer: Party, vct: string, claims: Record<string, unknown>, sd: Record<string, unknown>): Promise<{ held: string; key: Party }> {
  const key = await party();
  const held = await issueSdJwt({
    header: { kid: issuer.did },
    claims: { iss: issuer.did, iat: T0 - 40 * DAY - ((T0 - 40 * DAY) % DAY), exp: T0 + 365 * DAY, vct, cnf: { jwk: jwkOf(key.publicKey) }, practice: true, ...claims },
    sdProperties: sd,
    signer: issuer,
  });
  return { held, key };
}

async function run(rule: ReadRule, entries: PacketEntry[], ctx: Parameters<typeof checkPacket>[0]["ctx"] = {}, adoption?: ReadAdoption) {
  const req = ruleRequest(rule, { nonce: "door-nonce-0123456789", responseUri: "https://desk.practice.invalid/in", ...(adoption !== undefined ? { adoption } : {}) });
  const packet = await buildPacket({ rule, request: req, entries, iatUnix: T0 });
  const check = await checkPacket({ rule, request: req, vp_token: packet.vp_token, ctx, asOf: AS_OF });
  return { check, routed: await route(rule, check, { asOf: AS_OF, ...(adoption !== undefined ? { adoption } : {}) }) };
}

describe("internship credit (HEC) — the campus's record, never attendance", () => {
  let campus: Party;
  let stranger: Party;
  let rule: ReadRule;
  beforeAll(async () => {
    registerPracticeTypes();
    [campus, stranger] = await Promise.all([party(), party()]);
    rule = await readRule(await signRule(internshipRule({ campus: campus.did }), campus));
  });
  const record = (iss: Party, weeks: number, hours = 160) =>
    receipt(iss, PRACTICE_VCT.internshipRecord, {}, {
      weeks: Array.from({ length: weeks }, (_, i) => ({ week: i + 1, approvedOn: dateOf(T0 - (90 - 7 * i) * DAY) })),
      finalReviewOn: dateOf(T0 - 10 * DAY),
      hoursStated: hours,
    });
  const word = async (courseCode: string): Promise<PacketEntry> => ({ kind: "own-word", queryId: "course_word", fields: { courseCode }, signer: await party() });

  test("the weeks approved, the hours stated and the review signed → credit, automatically", async () => {
    const r = await record(campus, 8);
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "supervised-internship", held: r.held, signer: r.key }, await word("SAMPLE-INT-300")]);
    expect(routed.route).toBe("automatic-yes");
    expect(routed.reasons).toEqual(["supervised-and-reviewed"]);
  });
  test("too few approved weeks → not yet", async () => {
    const r = await record(campus, 4);
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "supervised-internship", held: r.held, signer: r.key }, await word("SAMPLE-INT-300")]);
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["supervised-internship"]);
  });
  test("a record from anyone but the campus is not the campus's record", async () => {
    const r = await record(stranger, 8);
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "supervised-internship", held: r.held, signer: r.key }, await word("SAMPLE-INT-300")]);
    expect(routed.missing.map((m) => m.criterion)).toEqual(["supervised-internship"]);
  });
  test("another course's code is not this course", async () => {
    const r = await record(campus, 8);
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "supervised-internship", held: r.held, signer: r.key }, await word("SAMPLE-OTHER-101")]);
    expect(routed.missing.map((m) => m.criterion)).toEqual(["course"]);
  });
  test("a refusal or partial credit is a named person's, with the unmet criterion and the receipts read", async () => {
    const seat = await party();
    const partial = await decidePerson({
      rule,
      outcome: "partial",
      reasons: ["partial-credit"],
      fired: ["course"],
      missing: ["supervised-internship"],
      reliedOn: ["d".repeat(64)],
      refusal: { unmet: ["supervised-internship"], receiptsRead: true },
      seat: { role: "Internship coordinator", did: seat.did, signer: seat },
      decidedAt: AS_OF,
    });
    expect((await validateDecision(partial, rule)).ok).toBe(true);
    expect(partial.decidedBy.kind).toBe("person");
    expect(JSON.stringify(partial)).not.toContain("Amina");
  });
});

describe("a CPD cycle (an ICAP-shaped rule, SAMPLE figures)", () => {
  let body: Party;
  let provider: Party;
  let rule: ReadRule;
  let list: Awaited<ReturnType<typeof trustList>>;
  beforeAll(async () => {
    registerPracticeTypes();
    const publisher = await party();
    [body, provider] = await Promise.all([party(), party()]);
    list = await trustList(publisher, "providers", [{ did: provider.did, label: "A practice CPD provider", dsts: [PRACTICE_VCT.cpdRecord] }]);
    rule = await readRule(await signRule(cpdRule({ body: body.did, providerList: `${publisher.did}#providers` }), body));
  });
  let n = 0;
  const activity = (hours: number, structured: boolean, daysAgo: number, recordId = `cpd-${++n}`) =>
    receipt(provider, PRACTICE_VCT.cpdRecord, {}, { recordId, hours, structured, completedOn: dateOf(T0 - daysAgo * DAY) });
  const declare = async (declared: boolean): Promise<PacketEntry> => ({ kind: "own-word", queryId: "declaration_word", fields: { declared }, signer: await party() });

  test("hours and structured hours over the cycle, each sent once → confirmed", async () => {
    const acts = await Promise.all([activity(40, true, 100), activity(30, true, 400), activity(50, false, 700), activity(10, false, 20)]);
    const entries: PacketEntry[] = acts.map((a) => ({ kind: "sd-jwt", queryId: "cycle-hours", held: a.held, signer: a.key }));
    const { routed, check } = await run(rule, [...entries, await declare(true)], { trustLists: [list] });
    expect(check.problems).toEqual([]);
    // One record counts toward both rows, sent once.
    expect(routed.rows.find((r) => r.criterion === "structured-hours")!.met).toBe(true);
    expect(routed.route).toBe("automatic-yes");
  });
  test("an activity outside the cycle never counts", async () => {
    const acts = await Promise.all([activity(100, true, 1200), activity(30, true, 30)]);
    const entries: PacketEntry[] = acts.map((a) => ({ kind: "sd-jwt", queryId: "cycle-hours", held: a.held, signer: a.key }));
    const { routed } = await run(rule, [...entries, await declare(true)], { trustLists: [list] });
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion).sort()).toEqual(["cycle-hours", "structured-hours"]);
  });
  test("one record shown in two unlinkable copies counts once", async () => {
    const copies = await Promise.all([activity(70, true, 100, "cpd-same"), activity(70, true, 100, "cpd-same")]);
    const entries: PacketEntry[] = copies.map((a) => ({ kind: "sd-jwt", queryId: "cycle-hours", held: a.held, signer: a.key }));
    const { routed } = await run(rule, [...entries, await declare(true)], { trustLists: [list] });
    expect(routed.missing.map((m) => m.criterion)).toEqual(["cycle-hours"]); // 70, not 140
  });
  test("a rule that counts SD-JWT receipts without reading their record id is refused", async () => {
    const { validateRule } = await import("../src/rule");
    const r = cpdRule({ body: body.did, providerList: "did:kash:21UhTqUdjZYWvw3jPz5emqdYskRqdQBLofo3MupZN3Jt#providers" });
    const stripped = { ...r, criteria: r.criteria.map((c) => (c.answer.by === "receipts" ? { ...c, answer: { ...c.answer, query: c.answer.query.map((q) => ({ ...q, claims: (q.claims ?? []).filter((cl) => cl.id !== "record") })) } } : c)) };
    expect(validateRule(stripped).refusals.map((x) => x.code)).toContain("COUNTS_COPIES");
  });
  test("an unlisted provider's hours are not counted", async () => {
    const rogue = await party();
    const a = await receipt(rogue, PRACTICE_VCT.cpdRecord, {}, { recordId: "rogue-1", hours: 200, structured: true, completedOn: dateOf(T0 - 10 * DAY) });
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "cycle-hours", held: a.held, signer: a.key }, await declare(true)], { trustLists: [list] });
    expect(routed.route).toBe("not-yet");
  });
  test("without the member's declaration it is not yet complete", async () => {
    const acts = await Promise.all([activity(80, true, 100), activity(60, true, 200)]);
    const entries: PacketEntry[] = acts.map((a) => ({ kind: "sd-jwt", queryId: "cycle-hours", held: a.held, signer: a.key }));
    const { routed } = await run(rule, [...entries, await declare(false)], { trustLists: [list] });
    expect(routed.missing.map((m) => m.criterion)).toEqual(["declaration"]);
  });
});

describe("income you can show — it binds the person, so a person decides", () => {
  let lender: Party;
  let duedale: Party;
  let payers: Party[];
  let rule: ReadRule;
  beforeAll(async () => {
    registerPracticeTypes();
    [lender, duedale] = await Promise.all([party(), party()]);
    payers = await Promise.all([party(), party()]);
    rule = await readRule(await signRule(incomeRule({ lender: lender.did, predicateIssuer: duedale.did }), lender));
  });
  let n = 0;
  const payment = (payer: Party, amount: number, daysAgo: number) =>
    receipt(payer, PRACTICE_VCT.paymentConfirmed, { currency: "USD" }, { recordId: `pay-${++n}`, amount, paidOn: dateOf(T0 - daysAgo * DAY) });

  test("six months from two payers → every row met, and the route is to a person, never automatic", async () => {
    const months = [10, 40, 70, 100, 130, 160];
    const pays = await Promise.all(months.flatMap((d, i) => [payment(payers[0]!, 700, d), payment(payers[1]!, 500, d + 1 + (i % 2))]));
    const { routed } = await run(rule, pays.map((p): PacketEntry => ({ kind: "sd-jwt", queryId: "monthly", held: p.held, signer: p.key })));
    expect([...routed.fired].sort()).toEqual(["monthly", "payers"]);
    expect(routed.route).toBe("to-a-person");
    expect(routed.why).toContain("binds");
    expect(() => decisionFromRoute(routed, rule, { decidedAt: AS_OF })).toThrow("a person decides");
  });
  test("a month with no confirmed payment → not yet", async () => {
    const pays = await Promise.all([10, 40, 70, 100, 130].map((d) => payment(payers[0]!, 2000, d)));
    const { routed } = await run(rule, pays.map((p): PacketEntry => ({ kind: "sd-jwt", queryId: "monthly", held: p.held, signer: p.key })));
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion).sort()).toEqual(["monthly", "payers"]);
  });
  test("d85(e): that not yet is automatic although the rule binds — its receipt validates; an automatic yes is still refused", async () => {
    const pays = await Promise.all([10, 40, 70, 100, 130].map((d) => payment(payers[0]!, 2000, d)));
    const { routed } = await run(rule, pays.map((p): PacketEntry => ({ kind: "sd-jwt", queryId: "monthly", held: p.held, signer: p.key })));
    expect(rule.body.outcome.binds).toBe(true);
    expect(routed.told).toBe("automatic");
    const d = decisionFromRoute(routed, rule, { decidedAt: AS_OF });
    expect(d).toMatchObject({ outcome: "not-yet", automatic: true, reasons: ["months-missing"], decidedBy: { kind: "standing", standing: `standing:${lender.did}` } });
    expect(await validateDecision(d, rule)).toEqual({ ok: true, refusals: [] });
    const yes = { ...d, outcome: "yes" as const, reasons: ["income-shown"], rows: { fired: ["monthly", "payers"], missing: [] } };
    expect((await validateDecision(yes, rule)).refusals.map((r) => r.code)).toEqual(expect.arrayContaining(["AUTOMATIC_YES_ON_BINDING", "AUTOMATIC_YES_NOT_STANDING"]));
  });
  test("a lender that adopted the rule at 750 a month: 800 from two payers meets it there, and not under the rule's 1000 — a person still decides", async () => {
    const anchor = await party();
    const adoption = await readAdoption(await signAdoption(incomeAdoption(anchor.did, rule), rule, anchor), rule);
    const months = [10, 40, 70, 100, 130, 160];
    const pays = await Promise.all(months.flatMap((d) => [payment(payers[0]!, 400, d), payment(payers[1]!, 400, d + 1)]));
    const es = pays.map((p): PacketEntry => ({ kind: "sd-jwt", queryId: "monthly", held: p.held, signer: p.key }));
    const own = await run(rule, es);
    expect(own.routed.missing.map((m) => m.criterion)).toEqual(["monthly"]);
    const adopted = await run(rule, es, {}, adoption);
    expect([...adopted.routed.fired].sort()).toEqual(["monthly", "payers"]);
    expect(adopted.routed.route).toBe("to-a-person");
  });
  test("Duedale's predicate (meets the income rule, version 1) answers the monthly row", async () => {
    const copy = await party();
    const pred = await criterionPredicate(duedale, copy, rule, "monthly");
    const pays = await Promise.all([payment(payers[0]!, 10, 20), payment(payers[1]!, 10, 30)]);
    const { routed } = await run(rule, [{ kind: "sd-jwt", queryId: "monthly_predicate", held: pred, signer: copy }, ...pays.map((p): PacketEntry => ({ kind: "sd-jwt", queryId: "payers", held: p.held, signer: p.key }))]);
    expect(routed.rows.find((r) => r.criterion === "monthly")!.via).toBe("predicate");
    expect(routed.route).toBe("to-a-person");
  });
  test("the person's own page shows the checklist before anything is sent", async () => {
    const pays = await Promise.all([payment(payers[0]!, 1500, 10), payment(payers[1]!, 1500, 40)]);
    const list = await checklist(rule, pays.map((p, i) => ({ ref: `pay${i}`, value: p.held })), { asOf: AS_OF });
    expect(list.rows.find((r) => r.criterion === "payers")!.state).toBe("answered");
    expect(list.rows.find((r) => r.criterion === "monthly")!.state).toBe("missing");
  });
});
