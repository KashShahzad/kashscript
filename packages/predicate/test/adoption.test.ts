import { beforeAll, describe, expect, test } from "bun:test";
import { KASH_ADOPTION_BODY_SCHEMA } from "@kashscript/lexicons/extensions/door";
import { signEnvelope } from "@kashscript/attest/dsse";
import { adoptableParameters, ADOPTION_PAYLOAD_TYPE, adoptionHash, readAdoption, signAdoption, validateAdoption, type ReadAdoption } from "../src/adoption";
import { checklist } from "../src/checklist";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { route } from "../src/route";
import { decisionFromRoute, issueDecision, readDecision, validateDecision } from "../src/decision";
import { openRuleRequest, readRule, ruleRequest, signRule, type ReadRule } from "../src/rule";
import {
  ADOPTED_VALUES,
  cpdAdoption,
  cpdRule,
  fixedParameterAdoption,
  hiringAdoption,
  incomeAdoption,
  incomeRule,
  internshipAdoption,
  internshipRule,
  plantedAdoptions,
  practiceAdoption,
  privateHiringRule,
} from "../src/fixtures";
import { AS_OF, criterionPredicate, DAY, englishCert, hiringWorld, party, T0, type HiringWorld, type Party } from "./world";

let w: HiringWorld;
let anchor: Party;
let adoption: ReadAdoption;
let internship: ReadRule;
let cpd: ReadRule;
let income: ReadRule;
let certKey: Party;
let cert: string;
let wordKey: Party;

beforeAll(async () => {
  w = await hiringWorld();
  [anchor, certKey, wordKey] = await Promise.all([party(), party(), party()]);
  adoption = await readAdoption(await signAdoption(hiringAdoption(anchor.did, w.rule), w.rule, anchor), w.rule);
  const [campus, body, lender, other] = await Promise.all([party(), party(), party(), party()]);
  internship = await readRule(await signRule(internshipRule({ campus: campus.did }), campus));
  cpd = await readRule(await signRule(cpdRule({ body: body.did, providerList: `${other.did}#providers` }), body));
  income = await readRule(await signRule(incomeRule({ lender: lender.did, predicateIssuer: other.did }), lender));
  cert = await englishCert(w.assessor, certKey);
});

const RESPONSE = "https://anchor.practice.invalid/answer";
const NONCE = "n-anchor-0123456789";
const asAnchor = () => ruleRequest(w.rule, { nonce: NONCE, responseUri: RESPONSE, adoption });

function entries(projects: readonly unknown[]): PacketEntry[] {
  return [
    ...projects.map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as Record<string, unknown>, signer: w.doer })),
    { kind: "sd-jwt", queryId: "english", held: cert, signer: certKey },
    { kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: wordKey },
  ];
}

async function desk(es: PacketEntry[], under?: ReadAdoption) {
  const req = ruleRequest(w.rule, { nonce: NONCE, responseUri: RESPONSE, ...(under !== undefined ? { adoption: under } : {}) });
  const packet = await buildPacket({ rule: w.rule, request: req, entries: es, iatUnix: T0 });
  const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: { trustLists: [w.list] }, asOf: AS_OF });
  return route(w.rule, check, { asOf: AS_OF, ...(under !== undefined ? { adoption: under } : {}) });
}

describe("an anchor adopts a rule with its own values, within the rule's bounds (d85(b) rule 8)", () => {
  test("each fixture rule has one adoption, which validates", async () => {
    for (const [rule, body] of [
      [w.rule, hiringAdoption(anchor.did, w.rule)],
      [internship, internshipAdoption(anchor.did, internship)],
      [cpd, cpdAdoption(anchor.did, cpd)],
      [income, incomeAdoption(anchor.did, income)],
    ] as const) {
      expect(validateAdoption(body, rule)).toEqual({ ok: true, refusals: [] });
    }
  });
  test("only a public rule's bounded parameters are adoptable — the rest the rulebook fixes", async () => {
    expect(adoptableParameters(w.rule.body).sort()).toEqual(["minProjects", "startWithin", "window"]);
    expect(adoptableParameters(internship.body).sort()).toEqual(["minHours", "minWeeks"]);
    expect(adoptableParameters(privateHiringRule(w.parties, { minProjects: "a".repeat(64), window: "b".repeat(64), startWithin: "c".repeat(64) }))).toEqual([]);
    expect(validateAdoption(fixedParameterAdoption(anchor.did, internship).body, internship).refusals.map((r) => r.code)).toEqual(["NOT_ADOPTABLE"]);
  });
  test("every planted adoption is refused, for its reason", () => {
    for (const p of plantedAdoptions(anchor.did, w.rule, cpd)) {
      const rule = (p.body as { rule: { id: string } }).rule.id === cpd.body.id ? cpd : w.rule;
      expect([p.name, validateAdoption(p.body, rule).refusals.map((r) => r.code)]).toEqual([p.name, expect.arrayContaining([p.refusedWith])]);
    }
  });
  test("an adoption names an anchor and numbers — its shape has no field for a person", () => {
    expect(Object.keys(KASH_ADOPTION_BODY_SCHEMA.properties).sort()).toEqual(["anchor", "dates", "id", "parameters", "practice", "rule"]);
  });
  test("it is signed by its anchor as itself, and reads offline from the anchor's DID", async () => {
    expect(adoption.body.anchor).toBe(anchor.did);
    expect(adoption.hash).toBe(await adoptionHash(adoption.body));
    expect(adoption.envelope.payloadType).toBe(ADOPTION_PAYLOAD_TYPE);
    await expect(signAdoption(hiringAdoption(anchor.did, w.rule), w.rule, w.door)).rejects.toThrow("its anchor's own key");
    // Someone else's signature over the anchor's adoption does not read.
    const forged = await signEnvelope(hiringAdoption(anchor.did, w.rule), ADOPTION_PAYLOAD_TYPE, w.stranger, { canonical: true });
    await expect(readAdoption(forged, w.rule)).rejects.toThrow("not signed by its anchor");
    // An adoption is read against the rule it adopts.
    await expect(readAdoption(adoption.envelope, internship)).rejects.toThrow("does not validate");
  });
});

describe("the evaluator reads the adoption's values", () => {
  test("two accepted projects: not yet under the rule's three — an automatic yes under the anchor's two", async () => {
    const two = w.projects.slice(0, 2);
    const own = await desk(entries(two));
    expect(own.route).toBe("not-yet");
    expect(own.missing.map((m) => m.criterion)).toEqual(["projects"]);
    const adopted = await desk(entries(two), adoption);
    expect(adopted.route).toBe("automatic-yes");
    expect(adopted.adoption).toEqual({ id: adoption.body.id, anchor: anchor.did, hash: adoption.hash });
    expect(adopted.why).toContain("adopting anchor");
    expect(ADOPTED_VALUES.hiring.minProjects).toBe(2);
  });
  test("the person's checklist reads the same values", async () => {
    const held = w.projects.slice(0, 2).map((v, i) => ({ ref: `p${i}`, value: v }));
    const own = await checklist(w.rule, held, { asOf: AS_OF });
    const adopted = await checklist(w.rule, held, { asOf: AS_OF, adoption });
    expect(own.rows.find((r) => r.criterion === "projects")!.state).toBe("missing");
    expect(adopted.rows.find((r) => r.criterion === "projects")!.state).toBe("answered");
    expect(adopted.adoption).toEqual({ id: adoption.body.id, anchor: anchor.did, hash: adoption.hash });
  });
  test("an issuer's predicate, given under the rule's own values, does not answer a criterion the anchor set", async () => {
    const copy = await party();
    const pred = await criterionPredicate(w.oreoasis, copy, w.rule, "projects");
    const react: PacketEntry = { kind: "artifact", queryId: "react", artifact: w.projects[0] as unknown as Record<string, unknown>, signer: w.doer };
    const es: PacketEntry[] = [{ kind: "sd-jwt", queryId: "projects_predicate", held: pred, signer: copy }, react, ...entries([])];
    expect((await desk(es)).route).toBe("automatic-yes");
    const adopted = await desk(es, adoption);
    expect(adopted.route).toBe("not-yet");
    expect(adopted.rows.find((r) => r.criterion === "projects")!.via).not.toBe("predicate");
  });
  test("an adoption not in force is never decided under", async () => {
    const later = await readAdoption(
      await signAdoption(practiceAdoption(anchor.did, w.rule, "later", { minProjects: 2 }, { dates: { adopted: "2026-12-01T00:00:00Z", renewBy: "2027-09-30T00:00:00Z", endsAt: "2028-09-30T00:00:00Z" } }), w.rule, anchor),
      w.rule,
    );
    const check = { rule: { id: w.rule.body.id, version: w.rule.body.version, hash: w.rule.hash }, byCriterion: {}, problems: [] } as unknown as Parameters<typeof route>[1];
    await expect(route(w.rule, check, { asOf: AS_OF, adoption: later })).rejects.toThrow("not in force");
    await expect(openRuleRequest(ruleRequest(w.rule, { nonce: NONCE, responseUri: RESPONSE, adoption: later }), T0)).rejects.toThrow("not in force");
  });
});

describe("the request comes from the anchor, and carries its adoption", () => {
  test("the anchor's request names it as the viewer, and the person's side verifies the adoption", async () => {
    const req = asAnchor();
    expect(req.client_id).toBe(anchor.did);
    expect(req.kash_adoption_sha256).toBe(adoption.hash);
    const opened = await openRuleRequest(JSON.parse(JSON.stringify(req)), T0);
    expect(opened.adoption?.hash).toBe(adoption.hash);
    expect(opened.adoption?.body.parameters).toEqual({ minProjects: 2 });
  });
  test("a request carrying the adoption from anyone but its anchor is refused", async () => {
    await expect(openRuleRequest({ ...asAnchor(), client_id: w.door.did }, T0)).rejects.toThrow("not from the anchor");
    await expect(openRuleRequest({ ...asAnchor(), kash_adoption_sha256: "0".repeat(64) }, T0)).rejects.toThrow("digest");
  });
  test("an adoption of another rule is not this door's", () => {
    expect(() => ruleRequest(internship, { nonce: NONCE, responseUri: RESPONSE, adoption })).toThrow("another rule");
  });
});

describe("the decision under an adoption is the anchor's (d85(d))", () => {
  test("an automatic yes is signed as the anchor's standing, names the adoption, and is issued by the anchor", async () => {
    const routed = await desk(entries(w.projects.slice(0, 2)), adoption);
    const d = decisionFromRoute(routed, w.rule, { decidedAt: AS_OF });
    expect(d.decidedBy).toEqual({ kind: "standing", standing: `standing:${anchor.did}` });
    expect(d.adoption).toEqual({ id: adoption.body.id, hash: adoption.hash });
    expect(await validateDecision(d, w.rule, adoption)).toEqual({ ok: true, refusals: [] });
    // Checked without the adoption it names, or as the author's standing, it does not hold.
    expect((await validateDecision(d, w.rule)).refusals.map((r) => r.code)).toEqual(expect.arrayContaining(["ADOPTION_MISMATCH", "STANDING_MISMATCH"]));
    const authors = { ...d, decidedBy: { kind: "standing" as const, standing: `standing:${w.door.did}` } };
    expect((await validateDecision(authors, w.rule, adoption)).refusals.map((r) => r.code)).toEqual(["STANDING_MISMATCH"]);
    const { adoption: _a, ...unnamed } = d;
    expect((await validateDecision(unnamed, w.rule, adoption)).refusals.map((r) => r.code)).toEqual(["ADOPTION_MISMATCH"]);

    const person = await party();
    const by = (issuer: Party) => issueDecision({ body: d, rule: w.rule, adoption, issuer, holderPublicKey: person.publicKey, iatUnix: T0, expUnix: T0 + 365 * DAY });
    await expect(by(w.door)).rejects.toThrow("the anchor that adopted the rule");
    const held = await by(anchor);
    const read = await readDecision(held, { nowSec: T0 });
    expect(read?.issuer).toBe(anchor.did);
    expect(read?.decision.adoption).toEqual({ id: adoption.body.id, hash: adoption.hash });
  });
});
