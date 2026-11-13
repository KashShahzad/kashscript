/**
 * AU-3 (AUDIT-2026-11-11) at the desk: the packet check counts only what it
 * verified. A predicate or a decision signed by a stranger in Oreoasis's name
 * (A7-01); one accepted record re-wrapped three ways (A7-03); a packet with one
 * item that does not read beside items that do (A7-04); a countersigner named by
 * key, not by spelling (A7-02); and a key binding older than the window (A7-08).
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { PREDICATE_VCT } from "@kashscript/attest/exchange";
import { recordIdOf } from "@kashscript/attest/holder";
import { issueSdJwt, jwkOf, signJws } from "@kashscript/attest/sd-jwt";
import type { CountersignBundle } from "@kashscript/attest/countersign";
import { buildPacket, checkPacket, type PacketEntry } from "../src/packet";
import { readDecision } from "../src/decision";
import { readReceipt } from "../src/receipts";
import { route } from "../src/route";
import { ruleRequest } from "../src/rule";
import { ARTIFACT_KB_TYP, DECISION_VCT } from "../src/constants";
import { AS_OF, DAY, englishCert, hiringWorld, iso, party, T0, withAcceptance, type HiringWorld, type Party } from "./world";

let w: HiringWorld;
let copyA: Party;
let wordKey: Party;
let certA: string;

beforeAll(async () => {
  w = await hiringWorld();
  [copyA, wordKey] = await Promise.all([party(), party()]);
  certA = await englishCert(w.assessor, copyA);
});

const ctx = () => ({ trustLists: [w.list] });
const request = (nonce = "n-au3-0123456789abcdef") => ruleRequest(w.rule, { nonce, responseUri: "https://door.practice.invalid/answer" });
type Artifact = Record<string, unknown>;

function entries(over: Partial<Record<"projects" | "english" | "word", PacketEntry[]>> = {}): PacketEntry[] {
  return [
    ...(over.projects ?? w.projects.map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Artifact, signer: w.doer }))),
    ...(over.english ?? [{ kind: "sd-jwt", queryId: "english", held: certA, signer: copyA } as PacketEntry]),
    ...(over.word ?? [{ kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: wordKey } as PacketEntry]),
  ];
}

async function desk(list: PacketEntry[], opts: { readonly iatUnix?: number; readonly freshness?: { readonly maxKbAgeSec?: number } } = {}) {
  const req = request();
  const packet = await buildPacket({ rule: w.rule, request: req, entries: list, iatUnix: opts.iatUnix ?? T0 });
  const check = await checkPacket({ rule: w.rule, request: req, vp_token: packet.vp_token, ctx: ctx(), asOf: AS_OF, ...(opts.freshness !== undefined ? { freshness: opts.freshness } : {}) });
  return { packet, check, routed: await route(w.rule, check, { asOf: AS_OF }) };
}

describe("A7-01 — a stranger's key behind an organisation's name", () => {
  test("a predicate signed by a stranger, with Oreoasis's DID in iss and the stranger's key in kid, never answers the criterion", async () => {
    const attacker = await party();
    const copy = await party();
    const to = T0 - DAY;
    const forged = await issueSdJwt({
      header: { kid: attacker.did },
      claims: {
        iss: w.oreoasis.did,
        iat: T0 - DAY - ((T0 - DAY) % DAY),
        exp: T0 + 90 * DAY,
        vct: PREDICATE_VCT,
        cnf: { jwk: jwkOf(copy.publicKey) },
        predicate: { kind: "projects", answer: true, rule: { id: w.rule.body.id, version: String(w.rule.body.version), hash: w.rule.hash }, window: { from: iso(to - 730 * DAY), to: iso(to) } },
      },
      sdArrays: { restsOn: ["a".repeat(64)] },
      signer: attacker,
    });
    const react: PacketEntry = { kind: "artifact", queryId: "react", artifact: w.projects[0] as unknown as Artifact, signer: w.doer };
    const { check, routed } = await desk(entries({ projects: [{ kind: "sd-jwt", queryId: "projects_predicate", held: forged, signer: copy }, react] }));
    expect(check.byCriterion.projects!.predicates).toHaveLength(0);
    expect(check.problems.some((p) => p.queryId === "projects_predicate" && p.why.includes("KID_NOT_ISSUER"))).toBe(true);
    expect(routed.route).not.toBe("automatic-yes");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["projects"]);
  });

  test("a decision receipt signed by a stranger in the door's name does not read as a decision", async () => {
    const attacker = await party();
    const person = await party();
    const forged = await issueSdJwt({
      header: { kid: attacker.did },
      claims: {
        iss: w.door.did,
        iat: T0 - (T0 % DAY),
        exp: T0 + 365 * DAY,
        vct: DECISION_VCT,
        cnf: { jwk: jwkOf(person.publicKey) },
        decision: { rule: { id: w.rule.body.id, version: w.rule.body.version, hash: w.rule.hash }, outcome: "yes", automatic: true },
      },
      signer: attacker,
    });
    expect(await readDecision(forged, { nowSec: T0 })).toBeNull();
  });
});

describe("A7-03 — one record, one count", () => {
  test("one accepted project presented as issued, with an extra field, and with a junk signature entry counts once", async () => {
    const p = w.projects[0] as unknown as Artifact;
    const subject = p.subject as { signatures: unknown[] };
    const variants: Artifact[] = [p, { ...p, _: 1 }, { ...p, subject: { ...subject, signatures: [...subject.signatures, { keyid: "did:kash:Z", sig: "AAAA" }] } }];
    const { check, routed } = await desk(entries({ projects: variants.map((artifact): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact, signer: w.doer })) }));
    expect(check.byCriterion.projects!.receipts).toHaveLength(1);
    expect(check.problems.filter((x) => x.why.includes("counted once"))).toHaveLength(2);
    expect(routed.route).not.toBe("automatic-yes");
    expect(routed.missing.map((m) => m.criterion)).toEqual(["projects"]);
  });

  test("the same record once as a bare envelope and once countersigned is one record", async () => {
    const bundle = w.projects[1] as unknown as CountersignBundle;
    const bare = await readReceipt({ ref: "bare", value: bundle.subject }, { nowSec: T0 });
    const whole = await readReceipt({ ref: "whole", value: bundle }, { nowSec: T0 });
    expect(whole!.contentId).toMatch(/^[0-9a-f]{64}$/);
    expect(bare!.contentId).toBe(whole!.contentId);
    expect(bare!.id).not.toBe(whole!.id);
  });
});

describe("A7-04 — one item that does not read never stops the rest from being judged", () => {
  test("a kash-artifact whose subject payload is not JSON is a problem line; the other items count", async () => {
    const bundle = w.projects[2] as unknown as CountersignBundle;
    const bad = { ...bundle, subject: { ...bundle.subject, payload: Buffer.from("not json").toString("base64") } };
    const list = entries();
    list[2] = { kind: "artifact", queryId: "projects", artifact: bad as unknown as Artifact, signer: w.doer };
    const { check } = await desk(list);
    expect(check.byCriterion.projects!.receipts).toHaveLength(2);
    expect(check.problems.filter((x) => x.queryId === "projects")).toHaveLength(1);
  });

  test("a kash-artifact with a junk sibling signature anyone could append still reads, and still counts once", async () => {
    const bundle = w.projects[2] as unknown as CountersignBundle;
    const junk = { ...bundle, subject: { ...bundle.subject, signatures: [...bundle.subject.signatures, { keyid: "x", sig: "%%%" }] } };
    const list = entries();
    list[2] = { kind: "artifact", queryId: "projects", artifact: junk as unknown as Artifact, signer: w.doer };
    const { check, routed } = await desk(list);
    expect(check.byCriterion.projects!.receipts).toHaveLength(3);
    expect(routed.route).toBe("automatic-yes");
  });
});

describe("A7-02 — a countersigner is named by key", () => {
  test("an acceptance signed under an alias of the requester's own key is never a countersigner, and an alias of the client's key is the client", async () => {
    const bundle = w.projects[0] as unknown as CountersignBundle;
    const client = w.clients[0]!;
    const aliased = await withAcceptance(bundle, { ...client, did: `${client.did}#c` }, T0 - 300 * DAY + 7200);
    const v = (await readReceipt({ ref: "a", value: aliased }, { nowSec: T0 }))!;
    expect(v.countersigners).toEqual([client.did]);
    const selfAliased = await withAcceptance(bundle, { ...w.doer, did: `${w.doer.did}#c` }, T0 - 300 * DAY + 7200);
    const s = (await readReceipt({ ref: "s", value: selfAliased }, { nowSec: T0 }))!;
    expect(s.countersigners).toEqual([client.did]);
  });
});

describe("A7-08 — a key binding's age is bounded", () => {
  test("a packet built more than ten minutes before it is checked is stale; one built five minutes before is fresh; the window can be widened on purpose", async () => {
    const stale = await desk(entries(), { iatUnix: T0 - 601 });
    expect(stale.check.problems.some((p) => /stale/i.test(p.why))).toBe(true);
    expect(stale.routed.route).not.toBe("automatic-yes");
    const fresh = await desk(entries(), { iatUnix: T0 - 300 });
    expect(fresh.routed.route).toBe("automatic-yes");
    const widened = await desk(entries(), { iatUnix: T0 - 601, freshness: { maxKbAgeSec: Number.POSITIVE_INFINITY } });
    expect(widened.routed.route).toBe("automatic-yes");
  });

  test("an artifact binding the holder signed without a time is refused", async () => {
    const req = request();
    const packet = await buildPacket({ rule: w.rule, request: req, entries: entries(), iatUnix: T0 });
    const items = packet.vp_token.projects as { artifact: Artifact; kb: string }[];
    // The holder's own key signs a binding with no `iat` — well-formed, correctly signed, and timeless.
    const sha = await recordIdOf({ kind: "countersign-bundle", value: items[0]!.artifact });
    const timeless = { ...items[0]!, kb: await signJws({ typ: ARTIFACT_KB_TYP }, { aud: req.client_id, nonce: req.nonce, artifact_sha256: sha }, w.doer) };
    const check = await checkPacket({ rule: w.rule, request: req, vp_token: { ...packet.vp_token, projects: [timeless, ...items.slice(1)] }, ctx: ctx(), asOf: AS_OF });
    expect(check.problems.some((x) => x.queryId === "projects" && /no time/.test(x.why))).toBe(true);
    expect(check.byCriterion.projects!.receipts).toHaveLength(2);
  });
});
