/**
 * Signed down the chain, rule version 1 (KS-Q9; ECOSYSTEM d94(c)) — the rulebook in
 * `docs/rulebooks/signed-down-the-chain/v1/`, read here as content, never exported: it
 * passes the floor, compiles to one DCQL query that a wider request cannot pass for, and
 * says yes or not yet on a practice hop the way rule.md says it does.
 *
 * The practice hop: a client, the prime that client contracted with, the house the prime
 * passes one piece to, and a stranger. Every record rides on Oreoasis's registered work
 * record (a profile, never a new tag) in the shapes OA-Q8 writes.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CountersignBundle } from "@kashscript/attest/countersign";
import { isRegisteredDst } from "@kashscript/attest/dst";
import { signEnvelope } from "@kashscript/attest/dsse";
import type { RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { checklist } from "../src/checklist";
import { DECISION_VCT } from "../src/constants";
import { ruleToDcql } from "../src/dcql";
import { decisionFromRoute, validateDecision } from "../src/decision";
import { WORK_RECORD_TYPE } from "../src/fixtures";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { route } from "../src/route";
import { openRuleRequest, readRule, ruleHash, ruleRequest, signRule, validateRule, type ReadRule } from "../src/rule";
import { countersigned, DAY, iso, party, type Party } from "./world";

const RULEBOOK = join(import.meta.dir, "..", "..", "..", "docs", "rulebooks", "signed-down-the-chain", "v1");
const rule = JSON.parse(readFileSync(join(RULEBOOK, "rule.json"), "utf8")) as RuleBody;
const plain = readFileSync(join(RULEBOOK, "rule.md"), "utf8");

const CONSENT = "engagement.subcontract-consent/1";
const ALL = ["c1-consent", "c2-house-signs", "c3-cites-scope", "c4-built-with", "c5-data-scope"];
/** Inside the rule's life (published 2026-11-07, ends 2027-11-07). */
const AS_OF = "2026-11-20T09:00:00Z";
const T = Date.parse(AS_OF) / 1000;
const UPSTREAM_SCOPE = "a1".repeat(32);
const PIECE_SCOPE = "b2".repeat(32);

let hash: string;
let client: Party;
let prime: Party;
let house: Party;
let stranger: Party;

beforeAll(async () => {
  hash = await ruleHash(rule);
  [client, prime, house, stranger] = await Promise.all([party(), party(), party(), party()]);
});

/** The rule re-authored under a practice key so it can be signed here. KashScript signs the real one. */
async function practiceRule(author: Party): Promise<ReadRule> {
  return readRule(await signRule({ ...rule, id: `${author.did}/rule/signed-down-the-chain`, author: author.did }, author));
}

/** `engagement.subcontract-consent/1`: the prime's record of the five fields, which the client accepts. */
function consentPayload(houseDid: string, monitoring = "none"): Record<string, unknown> {
  return {
    spec: "oreoasis.work-record/1",
    receiptId: `rcpt_consent_${houseDid.slice(-8)}_${monitoring}`,
    actor: { class: "organisation", id: prime.did },
    action: { type: "engagement.subcontract-consent", summary: "Consent to pass one bounded piece to another organisation." },
    inputs: [],
    outputs: [],
    status: "completed",
    timestamp: iso(T - 3 * DAY),
    meta: {
      profile: CONSENT,
      upstreamScopeHash: UPSTREAM_SCOPE,
      houseDid,
      pieceTitle: "The payments module's test suite",
      doneMeans: "Every test on the agreed list passes in the client's pipeline",
      dataScope: { receives: ["The payments module's repository", "Synthetic test data"], monitoring },
      practice: true,
    },
  };
}

const consent = (houseDid: string, monitoring = "none"): Promise<CountersignBundle> => countersigned(prime, client, consentPayload(houseDid, monitoring), T - 3 * DAY);

/** The house's delivery for its piece, accepted by the prime: its own scope version, the citation upward, Built with. */
function delivery(signer: Party, over: { readonly actor?: string; readonly upstream?: string; readonly stack?: readonly string[] | null } = {}): Promise<CountersignBundle> {
  const meta: Record<string, unknown> = { profile: "oreoasis-milestone/2", upstream: { ref: over.upstream ?? UPSTREAM_SCOPE, consentReceiptNo: "R-0001" }, practice: true };
  if (over.stack !== null) meta.stack = [...(over.stack ?? ["TypeScript", "Vitest"])];
  return countersigned(
    signer,
    prime,
    {
      spec: "oreoasis.work-record/1",
      receiptId: `rcpt_delivery_${signer.did.slice(-8)}`,
      actor: { class: "organisation", id: over.actor ?? signer.did },
      shape: "accepted",
      rule: { id: "piece-scope", version: 1, hash: PIECE_SCOPE },
      action: { type: "milestone.accept", summary: "The payments module's test suite, delivered." },
      inputs: [],
      outputs: [],
      status: "completed",
      timestamp: iso(T - DAY),
      meta,
    },
    T - DAY,
  );
}

async function rows(held: readonly unknown[]): Promise<Record<string, string>> {
  const list = await checklist({ body: rule, hash }, held.map((value, i) => ({ ref: `r${i}`, value })), { asOf: AS_OF });
  return Object.fromEntries(list.rows.map((r) => [r.criterion, r.state]));
}

const answeredBut = (missing: readonly string[] = []): Record<string, string> => Object.fromEntries(ALL.map((c) => [c, missing.includes(c) ? "missing" : "answered"]));

describe("Signed down the chain v1 — the floor", () => {
  test("it validates: no refusal, no warning to answer, every given answered", () => {
    const v = validateRule(rule);
    expect(v.refusals).toEqual([]);
    expect(v.warnings).toEqual([]);
    expect(v.ok).toBe(true);
    expect(v.completeness).toEqual({ addressed: true, complete: true, missing: [] });
  });

  test("no criterion asks about a person, a refusal, a time or a count", () => {
    expect(rule.criteria.map((c) => c.id)).toEqual(ALL);
    for (const c of rule.criteria) {
      expect(c.subject).toBe("organisation");
      expect(c.condition?.feel).not.toMatch(/\basOf\b|count\(/);
      if (c.answer.by !== "receipts") throw new Error(`${c.id} is answered by receipts`);
      for (const q of c.answer.query) {
        expect(q.meta?.vct_values ?? []).not.toContain(DECISION_VCT);
        for (const cl of q.claims ?? []) expect(cl.path).not.toContain("timestamp");
      }
    }
  });

  test("a yes only grants, and a no is kept for a named person", () => {
    expect(rule.outcome).toMatchObject({ binds: false, sensitive: false, automaticYes: true });
    expect(rule.reasons.map((r) => r.outcome)).toEqual(["yes", "not-yet", "no"]);
  });

  test("rule.md quotes this rule's hash, so the two cannot drift", () => {
    expect(plain).toContain(hash);
  });
});

describe("its DCQL query", () => {
  test("one required credential set per criterion, each asking for the registered work record, countersigned — a profile, never a new tag", () => {
    const dcql = ruleToDcql(rule, hash);
    expect(dcql.credential_sets.map((s) => s.required)).toEqual([true, true, true, true, true]);
    expect(isRegisteredDst(WORK_RECORD_TYPE)).toBe(true);
    for (const q of dcql.credentials) {
      expect(q.format).toBe("kash-artifact");
      expect(q.meta?.dst_values).toEqual([WORK_RECORD_TYPE]);
      expect(q.meta?.attestation).toBe("countersigned");
    }
    // C2 and C3 read the consent and a delivery together, so a third party can recompute the yes from the packet.
    expect(dcql.credential_sets[1]!.options).toEqual([["c2-house-signs_consent", "c2-house-signs_delivery"]]);
    expect(dcql.credential_sets[2]!.options).toEqual([["c3-cites-scope_consent", "c3-cites-scope_delivery"]]);
  });

  test("the request opens on the other side, and one asking for more than the rule says is refused", async () => {
    const door = await party();
    const practice = await practiceRule(door);
    const req = ruleRequest(practice, { nonce: "n-0123456789abcdef", responseUri: "https://prime.practice.invalid/hop" });
    expect((await openRuleRequest(JSON.stringify(req), T)).rule.hash).toBe(practice.hash);

    const oneClaimMore = {
      ...req.dcql_query,
      credentials: req.dcql_query.credentials.map((q, i) => (i === 0 ? { ...q, claims: [...(q.claims ?? []), { id: "timestamp", path: ["timestamp"] }] } : q)),
    };
    await expect(openRuleRequest({ ...req, dcql_query: oneClaimMore }, T)).rejects.toThrow("asks for more than the rule says");

    const oneRecordMore = { ...req.dcql_query, credentials: [...req.dcql_query.credentials, { id: "c1-consent_more", format: "kash-artifact", meta: { dst_values: [WORK_RECORD_TYPE] } }] };
    await expect(openRuleRequest({ ...req, dcql_query: oneRecordMore }, T)).rejects.toThrow("asks for more than the rule says");
  });
});

describe("a practice hop, checked on the prime's side", () => {
  test("a well-formed hop answers every row", async () => {
    expect(await rows([await consent(house.did), await delivery(house)])).toEqual(answeredBut());
  });

  test("C1: a consent the client never accepted counts for nothing", async () => {
    const unaccepted = await signEnvelope(consentPayload(house.did), WORK_RECORD_TYPE, prime, { canonical: true });
    expect(await rows([unaccepted, await delivery(house)])).toEqual(answeredBut(["c1-consent", "c2-house-signs", "c3-cites-scope", "c5-data-scope"]));
  });

  test("C2: a delivery by an organisation the client did not consent to", async () => {
    expect(await rows([await consent(house.did), await delivery(stranger)])).toEqual(answeredBut(["c2-house-signs"]));
  });

  test("C2: a delivery naming the house but signed with another organisation's key", async () => {
    expect(await rows([await consent(house.did), await delivery(stranger, { actor: house.did })])).toEqual(answeredBut(["c2-house-signs"]));
  });

  test("C3: a delivery citing another scope than the one the client consented within", async () => {
    expect(await rows([await consent(house.did), await delivery(house, { upstream: "c3".repeat(32) })])).toEqual(answeredBut(["c3-cites-scope"]));
  });

  test("C4: an empty Built with is an answer; a missing one is not", async () => {
    expect(await rows([await consent(house.did), await delivery(house, { stack: [] })])).toEqual(answeredBut());
    expect(await rows([await consent(house.did), await delivery(house, { stack: null })])).toEqual(answeredBut(["c4-built-with"]));
  });

  test("C5: a consent that lets the house monitor activity", async () => {
    expect(await rows([await consent(house.did, "screenshots"), await delivery(house)])).toEqual(answeredBut(["c5-data-scope"]));
  });

  test("no consent: not yet on every row that reads one", async () => {
    expect(await rows([await delivery(house)])).toEqual(answeredBut(["c1-consent", "c2-house-signs", "c3-cites-scope", "c5-data-scope"]));
  });
});

describe("the prime's desk", () => {
  async function desk(signer: Party, held: { readonly consent: CountersignBundle; readonly delivery: CountersignBundle }) {
    const practice = await practiceRule(prime);
    const request = ruleRequest(practice, { nonce: "n-fedcba9876543210", responseUri: "https://prime.practice.invalid/hop" });
    // Each record is sent once; the desk matches it against every criterion's queries.
    const entries: PacketEntry[] = [
      { kind: "artifact", queryId: "c1-consent", artifact: held.consent as unknown as Record<string, unknown>, signer: prime },
      { kind: "artifact", queryId: "c4-built-with", artifact: held.delivery as unknown as Record<string, unknown>, signer },
    ];
    const packet = await buildPacket({ rule: practice, request, entries, iatUnix: T });
    const check = await checkPacket({ rule: practice, request, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
    return { practice, check, routed: await route(practice, check, { asOf: AS_OF }) };
  }

  test("a well-formed hop: an automatic yes, naming the rule's version and its reason (node rule 11)", async () => {
    const { practice, check, routed } = await desk(house, { consent: await consent(house.did), delivery: await delivery(house) });
    expect(check.problems).toEqual([]);
    expect(routed.route).toBe("automatic-yes");
    expect([...routed.fired].sort()).toEqual(ALL);
    expect(routed.reasons).toEqual(["well-formed"]);
    const decision = decisionFromRoute(routed, practice, { decidedAt: AS_OF });
    expect(decision.rule).toEqual({ id: practice.body.id, version: 1, hash: practice.hash });
    expect((await validateDecision(decision, practice)).ok).toBe(true);
  });

  test("a delivery by another organisation: not yet, naming C2 — the machine never refuses", async () => {
    const { routed } = await desk(stranger, { consent: await consent(house.did), delivery: await delivery(stranger) });
    expect(routed.route).toBe("not-yet");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["c2-house-signs"]);
    expect(routed.reasons).toEqual(["criterion-missing"]);
  });
});
