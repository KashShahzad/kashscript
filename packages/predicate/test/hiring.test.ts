import { beforeAll, describe, expect, test } from "bun:test";
import { linkabilityBetween } from "@kashscript/attest/sd-jwt";
import { checklist } from "../src/checklist";
import { buildPacket, checkPacket, PacketError, type PacketEntry } from "../src/packet";
import { route } from "../src/route";
import { decisionFromRoute, issueDecision, readDecision, validateDecision } from "../src/decision";
import { ruleRequest, openRuleRequest, readRule, signRule, sealParameter } from "../src/rule";
import { privateHiringRule } from "../src/fixtures";
import { AS_OF, criterionPredicate, DAY, englishCert, hiringWorld, party, statusList, T0, workRecord, type HiringWorld, type Party } from "./world";

let w: HiringWorld;
let copyA: Party;
let copyB: Party;
let wordKey: Party;
let certA: string;
let certB: string;

beforeAll(async () => {
  w = await hiringWorld();
  [copyA, copyB, wordKey] = await Promise.all([party(), party(), party()]);
  certA = await englishCert(w.assessor, copyA);
  certB = await englishCert(w.assessor, copyB);
});

const ctx = () => ({ trustLists: [w.list] });
const request = (nonce = "n-0123456789abcdef") => ruleRequest(w.rule, { nonce, responseUri: "https://door.practice.invalid/answer" });

function goodEntries(over: Partial<Record<"projects" | "english" | "word", PacketEntry[]>> = {}): PacketEntry[] {
  return [
    ...(over.projects ?? w.projects.map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Record<string, unknown>, signer: w.doer }))),
    ...(over.english ?? [{ kind: "sd-jwt", queryId: "english", held: certA, signer: copyA } as PacketEntry]),
    ...(over.word ?? [{ kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: wordKey } as PacketEntry]),
  ];
}

async function desk(entries: PacketEntry[], req = request()) {
  const packet = await buildPacket({ rule: w.rule, request: req, entries, iatUnix: T0 });
  const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: ctx(), asOf: AS_OF });
  return { packet, check, routed: await route(w.rule, check, { asOf: AS_OF }) };
}

describe("the person's side — the checklist", () => {
  test("with every receipt held, every row is answered or stated, and the projects row is minimal", async () => {
    const held: { ref: string; value: unknown }[] = [...w.projects, w.old].map((v, i) => ({ ref: `p${i}`, value: v }));
    held.push({ ref: "cert", value: certA });
    const list = await checklist(w.rule, held, { asOf: AS_OF, trustLists: [w.list], ownWord: { availability: { availableFrom: "2026-11-15" } } });
    const row = (id: string) => list.rows.find((r) => r.criterion === id)!;
    expect(row("projects").state).toBe("answered");
    expect(row("projects").receipts.length).toBe(3);
    expect(row("projects").receipts).not.toContain("p3"); // older than 24 months: never counted
    expect(row("react").state).toBe("answered");
    expect(row("react").receipts).toEqual(["p0"]); // minimal: one React project is enough
    expect(row("english").state).toBe("answered");
    expect(row("availability").state).toBe("own-word");
    expect(row("availability").holds).toBe(true);
    expect(list.ready).toBe(true);
  });

  test("what is missing says which issuers the rule accepts — never a count", async () => {
    const list = await checklist(w.rule, [{ ref: "p0", value: w.projects[0] }], { asOf: AS_OF, trustLists: [w.list] });
    const projects = list.rows.find((r) => r.criterion === "projects")!;
    expect(projects.state).toBe("missing");
    expect(projects.accepts.issuers.map((i) => i.name)).toEqual(["Oreoasis (practice)"]);
    expect(projects.accepts.anyIssuer).toBe(true);
    // The evaluator adds no number of its own — only the author's label carries one.
    expect(projects.words.replace(projects.label, "")).not.toMatch(/\d/);
    const english = list.rows.find((r) => r.criterion === "english")!;
    expect(english.state).toBe("missing");
    expect(english.accepts.lists[0]!.name).toBe("the practice list of language assessors");
    expect(list.ready).toBe(false);
  });

  test("availability more than four weeks away is stated but does not hold", async () => {
    const list = await checklist(w.rule, [], { asOf: AS_OF, ownWord: { availability: { availableFrom: "2027-02-01" } } });
    expect(list.rows.find((r) => r.criterion === "availability")!.holds).toBe(false);
  });

  test("a stopped work record never counts (d43 §4.6)", async () => {
    const stopped = await workRecord(w.doer, w.clients[0]!, { at: T0 - 50 * DAY, stack: ["React"], status: "stopped" });
    const held = [w.projects[1], w.projects[2], stopped].map((v, i) => ({ ref: `p${i}`, value: v }));
    const list = await checklist(w.rule, held, { asOf: AS_OF });
    expect(list.rows.find((r) => r.criterion === "projects")!.state).toBe("missing");
    expect(list.rows.find((r) => r.criterion === "react")!.state).toBe("missing");
  });

  test("the person's side opens the door's request: the rule verifies, and the query is exactly the rule's", async () => {
    const req = request();
    const opened = await openRuleRequest(JSON.stringify(req), T0);
    expect(opened.rule.hash).toBe(w.rule.hash);
    await expect(openRuleRequest({ ...req, dcql_query: { credentials: [], credential_sets: [] } }, T0)).rejects.toThrow("asks for more than the rule says");
    await expect(openRuleRequest({ ...req, client_id: w.stranger.did }, T0)).rejects.toThrow("not from the rule's author");
    await expect(openRuleRequest(req, T0 + 3 * 366 * DAY)).rejects.toThrow("not in force");
  });
});

describe("the packet and the desk — valid packets", () => {
  test("receipts, a listed assessor's level and the person's word → an automatic yes, signed as the author's standing decision", async () => {
    const { check, routed } = await desk(goodEntries());
    expect(check.problems).toEqual([]);
    expect(routed.route).toBe("automatic-yes");
    expect([...routed.fired].sort()).toEqual(["availability", "english", "projects", "react"]);
    expect(routed.reasons).toEqual(["meets-all"]);
    expect(routed.told).toBe("automatic");
    expect(routed.mayAskForPerson).toBe(true);
    const decision = decisionFromRoute(routed, w.rule, { decidedAt: AS_OF });
    expect(decision.decidedBy).toEqual({ kind: "standing", standing: `standing:${w.door.did}` });
    expect((await validateDecision(decision, w.rule)).ok).toBe(true);
    expect(decision.reliedOn.every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true);
  });

  test("Oreoasis's predicate answers the projects row in place of the receipts", async () => {
    const copy = await party();
    const pred = await criterionPredicate(w.oreoasis, copy, w.rule, "projects");
    const react: PacketEntry = { kind: "artifact", queryId: "react", artifact: w.projects[0] as unknown as Record<string, unknown>, signer: w.doer };
    const { routed } = await desk(goodEntries({ projects: [{ kind: "sd-jwt", queryId: "projects_predicate", held: pred, signer: copy }, react] }));
    expect(routed.route).toBe("automatic-yes");
    expect(routed.rows.find((r) => r.criterion === "projects")!.via).toBe("predicate");
  });

  test("only the claims the query reads are disclosed", async () => {
    const { packet } = await desk(goodEntries());
    const pres = packet.vp_token.english![0] as string;
    const disclosures = pres.split("~").slice(1, -1).map((d) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(d.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)))));
    expect(disclosures.map((d) => d[1])).toEqual(["level"]); // assessedOn stays hidden
  });

  test("two viewers receive two copies and two keys, and share nothing that links them (d62(d)3)", async () => {
    const other = await party();
    const reqA = request("viewer-a-0123456789");
    const reqB = { ...request("viewer-b-0123456789"), client_id: other.did };
    const a = await buildPacket({ rule: w.rule, request: reqA, entries: [{ kind: "sd-jwt", queryId: "english", held: certA, signer: copyA }], iatUnix: T0 });
    const b = await buildPacket({ rule: w.rule, request: reqB, entries: [{ kind: "sd-jwt", queryId: "english", held: certB, signer: copyB }], iatUnix: T0 + 777 });
    // No copy, key, digest, salt, status index or time in common. The one shared thing is
    // the level the rule reads — "B2", which every B2 holder discloses alike.
    const shared = await linkabilityBetween(a.vp_token.english![0] as string, b.vp_token.english![0] as string);
    expect(shared.map((c) => c.kind)).toEqual(["disclosed-value"]);
  });
});

describe("the packet and the desk — invalid packets are never counted, and never refused", () => {
  test("two projects only → not yet, naming what is missing and who may supply it", async () => {
    const two = w.projects.slice(0, 2).map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Record<string, unknown>, signer: w.doer }));
    const { routed } = await desk(goodEntries({ projects: two }));
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["projects"]);
    expect(routed.missing[0]!.accepts.issuers[0]!.id).toBe(w.oreoasis.did);
    expect(routed.reasons).toEqual(["missing-evidence"]);
    const d = decisionFromRoute(routed, w.rule, { decidedAt: AS_OF });
    expect((await validateDecision(d, w.rule)).ok).toBe(true);
  });

  test("a tampered record does not check", async () => {
    const t = JSON.parse(JSON.stringify(w.projects[2]));
    const bytes = JSON.parse(atob(t.subject.payload));
    bytes.meta.stack = ["React"];
    t.subject.payload = btoa(JSON.stringify(bytes));
    const entries = goodEntries({ projects: [...w.projects.slice(0, 2), t].map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as Record<string, unknown>, signer: w.doer })) });
    const { check, routed } = await desk(entries);
    expect(check.problems.some((p) => /does not check|another record/.test(p.why))).toBe(true);
    expect(routed.route).toBe("not-yet");
  });

  test("a record bound by someone other than its holder is not counted", async () => {
    const entries = goodEntries({ projects: w.projects.map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Record<string, unknown>, signer: w.stranger })) });
    const { check, routed } = await desk(entries);
    expect(check.problems.some((p) => p.why.includes("not signed by the record's holder"))).toBe(true);
    expect(routed.route).toBe("not-yet");
  });

  test("the wrong nonce, or the wrong audience, does not bind", async () => {
    const req = request();
    const packet = await buildPacket({ rule: w.rule, request: { ...req, nonce: "another-nonce-123456" }, entries: goodEntries(), iatUnix: T0 });
    const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: ctx(), asOf: AS_OF });
    expect(check.problems.length).toBeGreaterThan(0);
    expect((await route(w.rule, check, { asOf: AS_OF })).route).toBe("not-yet");
    const other = await buildPacket({ rule: w.rule, request: { ...req, client_id: w.stranger.did }, entries: goodEntries(), iatUnix: T0 });
    const check2 = await checkPacket({ rule: w.rule, request: req, vp_token: other.vp_token, ctx: ctx(), asOf: AS_OF });
    expect(check2.problems.some((p) => /AUDIENCE_MISMATCH|another viewer/.test(p.why))).toBe(true);
  });

  test("an assessor no pinned list names is not accepted", async () => {
    const stranger = await englishCert(w.stranger, copyA);
    const { routed } = await desk(goodEntries({ english: [{ kind: "sd-jwt", queryId: "english", held: stranger, signer: copyA }] }));
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["english"]);
  });

  test("an expired certificate never counts (d27.5)", async () => {
    const expired = await englishCert(w.assessor, copyA, { exp: T0 - DAY });
    const { routed } = await desk(goodEntries({ english: [{ kind: "sd-jwt", queryId: "english", held: expired, signer: copyA }] }));
    expect(routed.missing.map((m) => m.criterion)).toEqual(["english"]);
  });

  test("a revoked certificate never counts", async () => {
    const revoked = await englishCert(w.assessor, copyA, { statusIndex: 7 });
    const list = await statusList(w.assessor, [7]);
    const req = request();
    const packet = await buildPacket({ rule: w.rule, request: req, entries: goodEntries({ english: [{ kind: "sd-jwt", queryId: "english", held: revoked, signer: copyA }] }), iatUnix: T0 });
    const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: { trustLists: [w.list], statusLists: [list] }, asOf: AS_OF });
    expect(check.problems.some((p) => p.why.includes("revoked"))).toBe(true);
    expect((await route(w.rule, check, { asOf: AS_OF })).route).toBe("not-yet");
  });

  test("a B1 level is not B2", async () => {
    const b1 = await englishCert(w.assessor, copyA, { level: "B1" });
    const { routed } = await desk(goodEntries({ english: [{ kind: "sd-jwt", queryId: "english", held: b1, signer: copyA }] }));
    expect(routed.missing.map((m) => m.criterion)).toEqual(["english"]);
  });

  test("one copy cannot be shown twice in a packet", async () => {
    await expect(
      buildPacket({ rule: w.rule, request: request(), entries: goodEntries({ english: [{ kind: "sd-jwt", queryId: "english", held: certA, signer: copyA }, { kind: "sd-jwt", queryId: "projects_predicate", held: certA, signer: copyA }] }), iatUnix: T0 }),
    ).rejects.toBeInstanceOf(PacketError);
  });

  test("the person's word for another rule is not this rule's word", async () => {
    const otherRule = await readRule(await signRule({ ...w.body, id: `${w.door.did}/rule/other` }, w.door));
    const req = request();
    const foreign = await buildPacket({ rule: otherRule, request: req, entries: [{ kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: wordKey }], iatUnix: T0 });
    const packet = await buildPacket({ rule: w.rule, request: req, entries: goodEntries({ word: [] }), iatUnix: T0 });
    const vp = { ...packet.vp_token, availability_word: foreign.vp_token.availability_word! };
    const check = await checkPacket({ rule: w.rule, request: req, vp_token: vp, ctx: ctx(), asOf: AS_OF });
    expect((await route(w.rule, check, { asOf: AS_OF })).missing.map((m) => m.criterion)).toEqual(["availability"]);
  });

  test("a predicate under another version of the rule does not answer this one", async () => {
    const copy = await party();
    const pred = await criterionPredicate(w.oreoasis, copy, w.rule, "projects", { version: "2" });
    const react: PacketEntry = { kind: "artifact", queryId: "react", artifact: w.projects[0] as unknown as Record<string, unknown>, signer: w.doer };
    const { routed } = await desk(goodEntries({ projects: [{ kind: "sd-jwt", queryId: "projects_predicate", held: pred, signer: copy }, react] }));
    expect(routed.missing.map((m) => m.criterion)).toEqual(["projects"]);
  });

  test("the person asking for a person always reaches one", async () => {
    const req = request();
    const packet = await buildPacket({ rule: w.rule, request: req, entries: goodEntries(), iatUnix: T0 });
    const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: ctx(), asOf: AS_OF });
    expect((await route(w.rule, check, { asOf: AS_OF, askedForPerson: true })).route).toBe("to-a-person");
  });
});

describe("a private rule — the queries are public, the thresholds sealed", () => {
  test("the checklist marks the rows it cannot read as sealed; the desk opens them and decides", async () => {
    const salt = { minProjects: "s1-practice-salt", window: "s2-practice-salt", startWithin: "s3-practice-salt" };
    const values = { minProjects: 3, window: "P24M", startWithin: "P28D" } as const;
    const sealed: Record<string, string> = {};
    for (const [n, v] of Object.entries(values)) sealed[n] = await sealParameter(n, v, salt[n as keyof typeof salt]);
    const priv = await readRule(await signRule(privateHiringRule(w.parties, sealed), w.door));
    const held = w.projects.map((v, i) => ({ ref: `p${i}`, value: v }));
    const list = await checklist(priv, held, { asOf: AS_OF });
    expect(list.rows.find((r) => r.criterion === "projects")!.state).toBe("sealed");

    const req = ruleRequest(priv, { nonce: "private-nonce-123456", responseUri: "https://door.practice.invalid/answer" });
    const packet = await buildPacket({ rule: priv, request: req, entries: goodEntries(), iatUnix: T0 });
    const check = await checkPacket({ rule: priv, request: req, vp_token: packet.vp_token, ctx: ctx(), asOf: AS_OF });
    const openings = Object.fromEntries(Object.entries(values).map(([n, v]) => [n, { value: v, salt: salt[n as keyof typeof salt] }]));
    expect((await route(priv, check, { asOf: AS_OF, openings })).route).toBe("automatic-yes");
    expect((await route(priv, check, { asOf: AS_OF, openings: { ...openings, minProjects: { value: 1, salt: salt.minProjects } } })).route).toBe("to-a-person");
    expect((await route(priv, check, { asOf: AS_OF })).route).toBe("to-a-person");
  });
});

describe("the decision comes back as a receipt the person keeps", () => {
  test("issued by the door to the person's key, it shows the rule, the outcome and automatic — the rest only if the person discloses it", async () => {
    const { routed } = await desk(goodEntries());
    const body = decisionFromRoute(routed, w.rule, { decidedAt: AS_OF });
    const personKey = await party();
    const held = await issueDecision({ body, rule: w.rule, issuer: w.door, holderPublicKey: personKey.publicKey, iatUnix: T0, expUnix: T0 + 365 * DAY });
    const read = await readDecision(held, { nowSec: T0 });
    expect(read!.ok).toBe(true);
    expect(read!.issuer).toBe(w.door.did);
    expect(read!.decision.outcome).toBe("yes");
    expect(read!.decision.rule).toEqual({ id: w.rule.body.id, version: 1, hash: w.rule.hash });
    expect(read!.decision.reasons).toEqual(["meets-all"]); // a held copy carries every disclosure
    await expect(issueDecision({ body, rule: w.rule, issuer: w.stranger, holderPublicKey: personKey.publicKey, iatUnix: T0, expUnix: T0 + DAY })).rejects.toThrow("whose rule it applies");
  });
});
