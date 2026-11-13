/**
 * KS-Q11 — the countersigner presents. A `kash-artifact` query may name its holder
 * as the countersigner (`kash.rule@1.2.0`): the one key whose acceptance in the
 * bundle verifies. The guest who accepted a host's delivered-booking receipt signs
 * the presentation's binding with that key; the desk checks it against that key,
 * and issues its decision to it. Nothing else changes what a record binds to.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { resolveVerificationKey } from "@kashscript/attest/signing";
import { checklist } from "../src/checklist";
import { readDecision, decisionFromRoute, issueDecision } from "../src/decision";
import { artifactHolderOf, buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { readReceipt } from "../src/receipts";
import { route } from "../src/route";
import { readRule, ruleRequest, signRule, validateRule, type ReadRule, type RuleBody } from "../src/rule";
import { bookingReviewRule, WORK_RECORD_TYPE } from "../src/fixtures";
import { criterionQueries } from "../src/dcql";
import { AS_OF, bookingDelivered, DAY, hiringWorld, party, T0, withAcceptance, type HiringWorld, type Party } from "./world";
import type { CountersignBundle } from "@kashscript/attest/countersign";

type Artifact = Record<string, unknown>;
const asArtifact = (b: CountersignBundle): Artifact => b as unknown as Artifact;

let desk: Party, host: Party, guest: Party, stranger: Party, rule: ReadRule, booking: CountersignBundle;

beforeAll(async () => {
  [desk, host, guest, stranger] = await Promise.all([party(), party(), party(), party()]);
  rule = await readRule(await signRule(bookingReviewRule({ author: desk.did }), desk));
  booking = await bookingDelivered(host, guest, { start: T0 - 5 * DAY, end: T0 - 2 * DAY });
});

const request = () => ruleRequest(rule, { nonce: "door-nonce-ks-q11-0001", responseUri: "https://desk.practice.invalid/in" });

async function present(artifact: Artifact, signer: Party) {
  const req = request();
  const entries: PacketEntry[] = [{ kind: "artifact", queryId: "delivered", artifact, signer }];
  const packet = await buildPacket({ rule, request: req, entries, iatUnix: T0 });
  const check = await checkPacket({ rule, request: req, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
  return { req, packet, check };
}

const query = () => criterionQueries(rule.body, rule.hash, rule.body.criteria[0]!).queries.find((q) => q.id === "delivered")!;

describe("the countersigner as holder — a guest-held booking at a door", () => {
  test("the rule is a valid kash.rule@1.2.0 rule, and the person's side reads the booking as answered", async () => {
    expect(validateRule(rule.body).ok).toBe(true);
    const list = await checklist(rule, [{ ref: "b", value: booking }], { asOf: AS_OF });
    expect(list.rows[0]!.state).toBe("answered");
  });

  test("the view's countersigners are what attest verified, less the requester", async () => {
    const view = (await readReceipt({ ref: "b", value: booking }, { nowSec: T0 }))!;
    expect(view.countersigners).toEqual([guest.did]);
    expect(view.holder).toBeNull();
    expect(artifactHolderOf(query(), view, asArtifact(booking))).toBe(guest.did);
  });

  test("the guest signs the binding: it checks, the row is answered, and the holder is the guest", async () => {
    const { check } = await present(asArtifact(booking), guest);
    expect(check.problems).toEqual([]);
    expect(check.byCriterion.delivered!.receipts.length).toBe(1);
    const routed = await route(rule, check, { asOf: AS_OF });
    expect(routed.route).toBe("automatic-yes");
  });

  test("the host — who signed the record and asked for the acceptance — cannot sign the binding", async () => {
    const { check } = await present(asArtifact(booking), host);
    expect(check.byCriterion.delivered!.receipts.length).toBe(0);
    expect(check.problems.map((p) => p.why)).toContain("its binding is not signed by the record's holder");
  });

  test("a key that is in nothing cannot sign the binding", async () => {
    const { check } = await present(asArtifact(booking), stranger);
    expect(check.byCriterion.delivered!.receipts.length).toBe(0);
    expect(check.problems.map((p) => p.why)).toContain("its binding is not signed by the record's holder");
  });

  test("an acceptance that does not verify names no countersigner — its key cannot bind", async () => {
    const forged = structuredClone(booking);
    const acc = forged.acceptances[0]!;
    (acc.signature as { sig: string }).sig = "A".repeat((acc.signature as { sig: string }).sig.length);
    const v = (await readReceipt({ ref: "f", value: forged }, { nowSec: T0 }))!;
    expect(v.countersigners).toEqual([]);
    const { check } = await present(asArtifact(forged), guest);
    expect(check.byCriterion.delivered!.receipts.length).toBe(0);
    expect(check.problems.map((p) => p.why)).toContain("the record names no single countersigner to check its binding");
  });

  test("an acceptance bound to another request names no countersigner", async () => {
    const other = await bookingDelivered(host, guest, { start: T0 - 4 * DAY, end: T0 - 1 * DAY });
    const mixed = { ...booking, acceptances: other.acceptances };
    const { check } = await present(asArtifact(mixed), guest);
    expect(check.byCriterion.delivered!.receipts.length).toBe(0);
    expect(check.problems.map((p) => p.why)).toContain("the record names no single countersigner to check its binding");
  });

  test("two countersigners: neither is the holder — the binding is refused for both", async () => {
    const second = await party();
    const two = await withAcceptance(booking, second, T0 - 5 * DAY + 7200);
    const v = (await readReceipt({ ref: "2", value: two }, { nowSec: T0 }))!;
    expect([...v.countersigners].sort()).toEqual([guest.did, second.did].sort());
    for (const signer of [guest, second]) {
      const { check } = await present(asArtifact(two), signer);
      expect(check.byCriterion.delivered!.receipts.length).toBe(0);
      expect(check.problems.map((p) => p.why)).toContain("the record names no single countersigner to check its binding");
    }
  });

  test("the requester's own acceptance is never a countersigner", async () => {
    const withHost = await withAcceptance(booking, host, T0 - 5 * DAY + 7200);
    const v = (await readReceipt({ ref: "h", value: withHost }, { nowSec: T0 }))!;
    expect(v.countersigners).toEqual([guest.did]);
    expect((await present(asArtifact(withHost), guest)).check.problems).toEqual([]);
    expect((await present(asArtifact(withHost), host)).check.byCriterion.delivered!.receipts.length).toBe(0);
  });

  test("the desk side: the decision receipt is issued to the countersigner's key, and reads back as the guest's", async () => {
    const { check } = await present(asArtifact(booking), guest);
    const routed = await route(rule, check, { asOf: AS_OF });
    const m = check.byCriterion.delivered!.receipts[0]!;
    const holder = artifactHolderOf(query(), m.view, asArtifact(booking));
    expect(holder).toBe(guest.did);
    const body = decisionFromRoute(routed, rule, { decidedAt: AS_OF });
    const held = await issueDecision({ body, rule, issuer: desk, holderPublicKey: resolveVerificationKey(holder!)!, iatUnix: T0, expUnix: T0 + 365 * DAY });
    const read = (await readDecision(held, { nowSec: T0 }))!;
    expect(read.ok).toBe(true);
    expect(read.holder?.split("#")[0]).toBe(guest.did);
    expect(read.holder?.split("#")[0]).not.toBe(host.did);
  });
});

describe("nothing else binds differently", () => {
  let w: HiringWorld;
  beforeAll(async () => {
    w = await hiringWorld();
  });

  test("Client Sign-off (holder_path actor.id) still binds to the doer, and the client who countersigned cannot bind it", async () => {
    const run = async (signer: Party) => {
      const req = ruleRequest(w.rule, { nonce: "door-nonce-ks-q11-0002", responseUri: "https://desk.practice.invalid/in" });
      const entries: PacketEntry[] = [{ kind: "artifact", queryId: "react", artifact: w.projects[0] as unknown as Artifact, signer }];
      const packet = await buildPacket({ rule: w.rule, request: req, entries, iatUnix: T0 });
      return checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
    };
    const byDoer = await run(w.doer);
    expect(byDoer.problems).toEqual([]);
    const byClient = await run(w.clients[0]!);
    expect(byClient.problems.map((p) => p.why)).toContain("its binding is not signed by the record's holder");
  });

  const plainQueryRule = (meta: Record<string, unknown>): RuleBody => {
    const base = bookingReviewRule({ author: desk.did });
    const c = base.criteria[0]!;
    if (c.answer.by !== "receipts") throw new Error("receipts");
    return { ...base, criteria: [{ ...c, answer: { ...c.answer, query: [{ ...c.answer.query[0]!, meta: { dst_values: [WORK_RECORD_TYPE], attestation: "countersigned", ...meta } as never }] } }] };
  };

  test("a countersign query that names no holder still binds to the requester — the guest cannot bind it", async () => {
    const r = await readRule(await signRule(plainQueryRule({}), desk));
    const go = async (signer: Party) => {
      const req = ruleRequest(r, { nonce: "door-nonce-ks-q11-0003", responseUri: "https://desk.practice.invalid/in" });
      const packet = await buildPacket({ rule: r, request: req, entries: [{ kind: "artifact", queryId: "delivered", artifact: asArtifact(booking), signer }], iatUnix: T0 });
      return checkPacket({ rule: r, request: req, vp_token: packet.vp_token, ctx: {}, asOf: AS_OF });
    };
    expect((await go(host)).problems).toEqual([]);
    expect((await go(guest)).problems.map((p) => p.why)).toContain("its binding is not signed by the record's holder");
  });

  test("validation: holder only on kash-artifact, never beside holder_path, and only on a countersigned record", () => {
    const malformed = (b: RuleBody) => validateRule(b).refusals.filter((x) => x.code === "DCQL_MALFORMED").map((x) => x.message);
    expect(malformed(plainQueryRule({ holder: "countersigner", holder_path: ["actor", "id"] }))).toContain("a query names its holder one way — holder or holder_path, not both");
    const noAttestation = plainQueryRule({ holder: "countersigner" });
    const c = noAttestation.criteria[0]!;
    if (c.answer.by !== "receipts") throw new Error("receipts");
    const { attestation: _a, ...meta } = c.answer.query[0]!.meta!;
    const bare = { ...noAttestation, criteria: [{ ...c, answer: { ...c.answer, query: [{ ...c.answer.query[0]!, meta }] } }] };
    expect(malformed(bare)).toContain("holder: countersigner reads a countersigned record — say attestation: countersigned");
    const sd = { ...noAttestation, criteria: [{ ...c, answer: { ...c.answer, query: [{ id: "delivered", format: "dc+sd-jwt", meta: { vct_values: ["https://practice.invalid/vct/x/1"], holder: "countersigner" as const }, claims: c.answer.query[0]!.claims! }] } }] };
    expect(malformed(sd)).toContain("dst_values, attestation, holder_path and holder belong to kash-artifact");
    expect(validateRule(plainQueryRule({ holder: "requester" })).ok).toBe(false);
  });

  test("a countersigner query reads only a countersign bundle: a plain signed record has no countersigner", async () => {
    const view = (await readReceipt({ ref: "b", value: booking.subject }, { nowSec: T0 }))!;
    expect(view.kind).toBe("dsse");
    expect(view.countersigners).toEqual([]);
    expect(artifactHolderOf(query(), view, booking.subject as unknown as Artifact)).toBeNull();
  });
});
