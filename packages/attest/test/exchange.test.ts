/**
 * PL-3 — the ask, the predicate presentation, the presentation log, the
 * session receipt and the thank-you. Vectors in ./vectors/exchange were
 * generated once and are never regenerated.
 */

import { describe, it, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import type { DsseEnvelope } from "../src/dsse";
import {
  TRUST_LIST_FORMAT,
  makeKeyResolver,
  recordIdOf,
  signTrustList,
  verifyHolderExport,
  verifyStatusList,
  verifyTrustList,
  type HolderExport,
  type StatusListReport,
} from "../src/holder";
import { issueSdJwt, jwkOf, linkabilityBetween, presentSdJwt } from "../src/sd-jwt";
import {
  ASK_FORMAT,
  ASK_KEY_PATTERN,
  ASK_MAX_LIFETIME_SEC,
  ASK_NEED_KEYS,
  ASK_STATES,
  ASK_TOP_LEVEL_KEYS,
  DECLINING_CONST,
  FORBIDDEN_NEED_PATTERN,
  IMPROVEMENT_PATTERN,
  LINKING_CONST,
  PREDICATE_KIND_PATTERN,
  PREDICATE_VCT,
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  THANK_YOU_VCT,
  askRequest,
  askToDcql,
  cosignSessionEvent,
  credentialCopySha256,
  issuePredicateCredential,
  issueThankYou,
  lineItemCommitment,
  openLineItem,
  sessionEventSha256,
  sessionGenesisSha256,
  signSessionEvent,
  validateAsk,
  validatePresentationLog,
  verifyPredicatePresentation,
  verifyRedemption,
  verifySessionReceipt,
  verifyThankYou,
  type Ask,
  type SessionEventPayload,
  type SessionProfile,
} from "../src/exchange";

const V = join(import.meta.dir, "vectors", "exchange");
const txt = (f: string): string => readFileSync(join(V, f), "utf8").trim();
const json = <T = any>(f: string): T => JSON.parse(readFileSync(join(V, f), "utf8")) as T;
const ctx = json("context.v1.json");
const NOW = ctx.nowUnix as number;
const resolveKey = makeKeyResolver(new Map(), new Map());
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });
async function carried(f: string): Promise<StatusListReport> {
  return verifyStatusList(json<DsseEnvelope>(f), { resolveKey });
}

/* ── the ask ───────────────────────────────────────────────────────────── */

describe("ask — the eight rules and the forbidden needs, as validation", () => {
  it("accepts a valid ask", () => {
    expect(validateAsk(json("asks/valid.json"))).toEqual({ ok: true, violations: [] });
  });

  it("word boundaries: 'original' is not 'origin'", () => {
    expect(validateAsk(json("asks/valid-word-boundary.json")).ok).toBe(true);
  });

  const expected = json<Record<string, string>>("asks/expected.json");
  for (const [file, rule] of Object.entries(expected)) {
    it(`${file} fails ${rule}`, () => {
      const r = validateAsk(json(`asks/${file}`));
      expect(r.ok).toBe(false);
      expect(r.violations.map((v) => v.rule)).toContain(rule as never);
    });
  }

  it("every invalid vector is listed with the rule it breaks", () => {
    const files = readdirSync(join(V, "asks")).filter((f) => f.startsWith("invalid-"));
    expect(files.sort()).toEqual(Object.keys(expected).sort());
    const rules = new Set(Object.values(expected));
    for (const r of ["R1-predicates-only", "R2-says-why", "R3-no-is-answerable", "R4-expires", "R5-public", "R6-no-joining", "R7-excessive-recordable", "R8-no-improvement-item", "FORBIDDEN-NEED"]) {
      expect(rules.has(r)).toBe(true);
    }
  });

  it("a smuggled demand outside the shape is a rule-1 fault", () => {
    const r = validateAsk({ ...json<Record<string, unknown>>("asks/valid.json"), recordsWanted: ["receipts"] });
    expect(r.violations.map((v) => v.rule)).toContain("R1-predicates-only");
  });

  it("the published JSON Schema and the reference validator agree on every shared constant", () => {
    const schema = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "schemas", "ask.schema.json"), "utf8"));
    expect(schema.properties.format.const).toBe(ASK_FORMAT);
    expect(schema.properties.key.pattern).toBe(ASK_KEY_PATTERN);
    expect(schema.properties.declining.const).toBe(DECLINING_CONST);
    expect(schema.properties.linking.const).toBe(LINKING_CONST);
    expect(schema.properties.state.enum).toEqual([...ASK_STATES]);
    expect([...schema.required].sort()).toEqual([...ASK_TOP_LEVEL_KEYS].sort());
    expect(schema.additionalProperties).toBe(false);
    expect(schema["x-kash-maxLifetimeSec"]).toBe(ASK_MAX_LIFETIME_SEC);
    const need = schema.$defs.need;
    expect(Object.keys(need.properties).sort()).toEqual([...ASK_NEED_KEYS].sort());
    expect(need.properties.predicate.pattern).toBe(PREDICATE_KIND_PATTERN);
    expect(need.properties.predicate.allOf[0].not.pattern).toBe(IMPROVEMENT_PATTERN);
    expect(need.properties.predicate.allOf[1].not.pattern).toBe(FORBIDDEN_NEED_PATTERN);
  });

  it("becomes an OpenID4VP request: a DCQL query for predicate credentials, the ask by value, its digest", async () => {
    const ask = json<Ask>("asks/valid.json");
    const dcql = askToDcql(ask);
    expect(dcql.credentials).toHaveLength(1);
    expect(dcql.credentials[0]).toMatchObject({ id: "n1", format: "dc+sd-jwt", meta: { vct_values: [PREDICATE_VCT] } });
    const req = await askRequest(ask, { nonce: "n", responseUri: "https://verifier.example.org/cb" });
    expect(req.client_id).toBe(ask.who.id);
    expect(req.kash_ask).toEqual(ask);
    expect(req.kash_ask_sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

/* ── the predicate credential and its presentation ─────────────────────── */

describe("predicate — a yes, bound to the holder, offline except for status", () => {
  const A = ctx.verifiers.a;
  const B = ctx.verifiers.b;
  const C = ctx.verifiers.c;

  it("verifies presentation A against the audience and nonce A sent, with status carried", async () => {
    const r = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), {
      resolveKey, audience: A.did, nonce: A.nonce, nowSec: NOW, statusLists: [await carried("predicate-status-list.v1.json")],
    });
    expect(r.ok).toBe(true);
    expect(r.predicate?.rule.version).toBe("3");
    expect(r.disclosedRecordHashes).toEqual([]); // hidden unless the holder shows them
    expect(r.status.state).toBe("not-revoked");
    expect(r.status.text).toStartWith("valid unless revoked, as of ");
    expect(r.issuer).toBe(ctx.predicateIssuer);
  });

  it("A and B — two copies to two verifiers — share nothing that links them (rule 6)", async () => {
    expect(await linkabilityBetween(txt("predicate-presentation-a.v1.txt"), txt("predicate-presentation-b.v1.txt"))).toEqual([]);
    const b = await verifyPredicatePresentation(txt("predicate-presentation-b.v1.txt"), { resolveKey, audience: B.did, nonce: B.nonce, nowSec: NOW });
    expect(b.ok).toBe(true);
    expect(b.holder).not.toBe((await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { resolveKey, nowSec: NOW })).holder);
  });

  it("a presentation for A is refused by B", async () => {
    const r = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { resolveKey, audience: B.did, nonce: A.nonce, nowSec: NOW });
    expect(r.ok).toBe(false);
    expect(r.sdJwt.reason).toBe("AUDIENCE_MISMATCH");
  });

  it("record hashes appear only because the holder disclosed them, and an attached record binds to one", async () => {
    const work = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "holder", "source", "oreoasis-work-record.json"), "utf8")).envelope;
    const r = await verifyPredicatePresentation(txt("predicate-presentation-c-records.v1.txt"), {
      resolveKey, audience: C.did, nonce: C.nonce, nowSec: NOW, attachedRecords: [{ kind: "dsse", value: work }],
    });
    expect(r.ok).toBe(true);
    expect([...r.disclosedRecordHashes].sort()).toEqual([...ctx.restsOn].sort());
    expect(r.attachments).toEqual([{ recordId: ctx.restsOn[0], bound: true }]);
    expect(r.notes.join(" ")).toContain("link the presentations");
    const stray = await verifyPredicatePresentation(txt("predicate-presentation-c-records.v1.txt"), {
      resolveKey, audience: C.did, nonce: C.nonce, nowSec: NOW, attachedRecords: [{ kind: "dsse", value: { not: "a record it rests on" } }],
    });
    expect(stray.reason).toBe("ATTACHMENT_NOT_BOUND");
  });

  it("a revoked copy says revoked, with its time", async () => {
    const r = await verifyPredicatePresentation(txt("predicate-presentation-revoked.v1.txt"), {
      resolveKey, audience: ctx.verifiers.revoked.did, nonce: ctx.verifiers.revoked.nonce, nowSec: NOW, statusLists: [await carried("predicate-status-list.v1.json")],
    });
    expect(r.status.state).toBe("revoked");
    expect(r.status.text).toStartWith("revoked as of ");
  });

  it("without the list, status says it was not checked — it never guesses", async () => {
    const r = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { resolveKey, audience: A.did, nonce: A.nonce, nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(r.status.state).toBe("unknown");
    expect(r.status.text).toContain("networked check");
  });

  it("answers the ask it was made for, and nothing else", async () => {
    const ask = json<Ask>("asks/valid.json");
    const ok = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { resolveKey, audience: A.did, nonce: A.nonce, nowSec: NOW, ask, needId: "n1" });
    expect(ok.ok).toBe(true);
    const other: Ask = { ...ask, needs: [{ id: "n1", predicate: "within-mandate", withinDays: 30 }] };
    const bad = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { resolveKey, audience: A.did, nonce: A.nonce, nowSec: NOW, ask: other, needId: "n1" });
    expect(bad.reason).toBe("ASK_MISMATCH");
  });

  it("names its rule version (d43): issuing without one throws, and a credential without one fails", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const issuer = { did: deriveDid(iss.publicKey), ...kjs(iss) };
    const base = { kind: "k", answer: true, rule: { id: "r", version: "", hash: "h" }, window: { from: "2026-01-01", to: "2026-09-01" } };
    await expect(issuePredicateCredential({ issuer, holderPublicKey: h.publicKey, predicate: base, restsOn: [], credentialStatus: null, iatUnix: NOW, expUnix: NOW + 86_400 })).rejects.toThrow();
    const raw = await issueSdJwt({ claims: { iss: issuer.did, vct: PREDICATE_VCT, exp: NOW + 86_400, cnf: { jwk: jwkOf(h.publicKey) }, predicate: base }, signer: kjs(iss) });
    const p = await presentSdJwt(raw, () => true, kjs(h), { aud: "v", nonce: "n", iatUnix: NOW });
    expect((await verifyPredicatePresentation(p, { resolveKey, nowSec: NOW })).reason).toBe("RULE_VERSION_MISSING");
  });

  it("an issuer is listed only by a pinned trust list naming its vct", async () => {
    const pub = await generateKeyPair();
    const pubDid = deriveDid(pub.publicKey);
    const list = await signTrustList(
      { format: TRUST_LIST_FORMAT, listId: "l", version: 1, publisher: pubDid, issuedAtUnix: NOW - 10, validFromUnix: NOW - 10, validUntilUnix: NOW + 86_400, issuers: [{ issuerId: ctx.predicateIssuer, label: "A workshop (sample)", keys: [], dsts: [PREDICATE_VCT], validFromUnix: NOW - 10, validUntilUnix: NOW + 86_400 }] },
      { keyid: pubDid, ...kjs(pub) },
    );
    const opts = { resolveKey, audience: A.did, nonce: A.nonce, nowSec: NOW };
    const unpinned = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { ...opts, trustLists: [await verifyTrustList(list, { nowSec: NOW })] });
    expect(unpinned.trusted).toBe(false);
    const pinned = await verifyPredicatePresentation(txt("predicate-presentation-a.v1.txt"), { ...opts, trustLists: [await verifyTrustList(list, { nowSec: NOW, pinnedPublishers: [pubDid] })] });
    expect(pinned.trusted).toBe(true);
  });
});

/* ── the presentation log ──────────────────────────────────────────────── */

describe("presentation log — the holder's own, and a decline has no format", () => {
  const ref = { key: "ask:workshop-safety-check", version: 1, sha256: "e".repeat(64) };
  const pres = (verifier: string, relationship: string, copy: string, linkedByHolder = false) => ({
    kind: "presentation", atUnix: NOW, verifier, relationship, ask: ref, credentials: [{ vct: PREDICATE_VCT, copySha256: copy }], disclosed: [], attachedRecordIds: [], linkedByHolder,
  });

  it("accepts presentations to two verifiers from two copies, and an excessive-ask note", () => {
    const log = [pres("va", "ra", "c1"), pres("vb", "rb", "c2"), { kind: "excessive-ask", atUnix: NOW, ask: ref, rules: ["R1-predicates-only"], note: null }];
    expect(validatePresentationLog(log)).toEqual({ ok: true, violations: [] });
  });

  it("has no entry for a decline", () => {
    const r = validatePresentationLog([{ kind: "declined", atUnix: NOW, ask: ref }]);
    expect(r.violations.map((v) => v.code)).toEqual(["DECLINE_HAS_NO_FORMAT"]);
  });

  it("flags a copy or a relationship key shown to a second verifier, unless the holder linked them", () => {
    expect(validatePresentationLog([pres("va", "ra", "c1"), pres("vb", "rb", "c1")]).violations.map((v) => v.code)).toContain("COPY_REUSED_ACROSS_VERIFIERS");
    expect(validatePresentationLog([pres("va", "ra", "c1"), pres("vb", "ra", "c2")]).violations.map((v) => v.code)).toContain("RELATIONSHIP_REUSED_ACROSS_VERIFIERS");
    expect(validatePresentationLog([pres("va", "ra", "c1"), pres("vb", "ra", "c1", true)]).ok).toBe(true);
  });

  it("carries no record content", () => {
    const r = validatePresentationLog([{ ...pres("va", "ra", "c1"), rawRecord: { secret: 1 } }]);
    expect(r.violations.map((v) => v.code)).toContain("UNKNOWN_FIELD");
  });

  it("names a copy by the digest of its issuer JWT — the same for the held copy and its presentation", async () => {
    expect(await credentialCopySha256(txt("predicate-held-a.v1.txt"))).toBe(await credentialCopySha256(txt("predicate-presentation-a.v1.txt")));
  });

  it("travels in the holder export, and a bad log fails it", async () => {
    const e = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "holder", "holder-export.v1.json"), "utf8")) as HolderExport;
    expect((await verifyHolderExport({ ...e, presentationLog: [pres("va", "ra", "c1")] } as never)).ok).toBe(true);
    const bad = await verifyHolderExport({ ...e, presentationLog: [{ kind: "declined" }] } as never);
    expect(bad.reasons).toContain("PRESENTATION_LOG_INVALID");
  });
});

/* ── the session receipt ───────────────────────────────────────────────── */

type Line = { kind: SessionEventPayload["kind"]; by: "establishment" | "person"; body: Record<string, unknown>; cosign: boolean };
async function buildSession(profile: SessionProfile, lines: Line[], parties?: { est: KashKeyPair; per: KashKeyPair }) {
  const est = parties?.est ?? (await generateKeyPair());
  const per = parties?.per ?? (await generateKeyPair());
  const sessionId = "ses_test";
  const events: DsseEnvelope[] = [];
  let prev = await sessionGenesisSha256(sessionId);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    const [a, o] = l.by === "establishment" ? [est, per] : [per, est];
    const payload: SessionEventPayload = { spec: SESSION_EVENT_SPEC, sessionId, seq: i, prevSha256: prev, kind: l.kind, atUnix: NOW + i, by: l.by, body: l.body };
    let env = await signSessionEvent(payload, { keyid: deriveDid(a.publicKey), ...kjs(a) });
    if (l.cosign) env = await cosignSessionEvent(env, { keyid: deriveDid(o.publicKey), ...kjs(o) });
    events.push(env);
    prev = await sessionEventSha256(env);
  }
  return { receipt: { formatVersion: SESSION_RECEIPT_FORMAT, sessionId, profile, parties: { establishment: deriveDid(est.publicKey), person: deriveDid(per.publicKey) }, events, anchor: null }, est, per };
}
const openBody = (profile: SessionProfile, est: KashKeyPair, per: KashKeyPair, place: string | null) => ({
  profile, parties: { establishment: deriveDid(est.publicKey), person: deriveDid(per.publicKey) }, consent: { records: [], asks: [] }, place,
});

describe("session receipt — two parties, both signatures, pending is never proof", () => {
  it("the complete vector is proof: every line signed by both, closed, anchored, total shared", async () => {
    const r = await verifySessionReceipt(json("session-receipt-complete.v1.json"), { nowSec: NOW });
    expect(r.faults).toEqual([]);
    expect(r.state).toBe("complete");
    expect(r.proof).toBe(true);
    expect(r.total).toEqual({ amount: "4500.00", currency: "PKR" });
    expect(r.lineItemCount).toBe(2);
    expect(r.anchor?.matches).toBe(true);
    expect(r.events.find((e) => e.kind === "disagreement")?.bothSigned).toBe(true);
  });

  it("the pending vector verifies but is not proof — one signature is pending (d41)", async () => {
    const r = await verifySessionReceipt(json("session-receipt-pending.v1.json"), { nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(r.state).toBe("pending");
    expect(r.proof).toBe(false);
    expect(r.events.at(-1)?.signers).toEqual(["establishment"]);
  });

  it("line items are commitments: each opens only with its salt and its item", async () => {
    for (const li of json<{ commitment: string; saltHex: string; item: unknown }[]>("session-line-items.v1.json")) {
      expect(await openLineItem(li.commitment, li.saltHex, li.item)).toBe(true);
      expect(await openLineItem(li.commitment, li.saltHex, { ...(li.item as object), amount: "1.00" })).toBe(false);
      expect(await openLineItem(li.commitment, "00".repeat(16), li.item)).toBe(false);
    }
  });

  it("Indorania — or anyone else — signing a line as a third key fails the receipt", async () => {
    const r = json<any>("session-receipt-complete.v1.json");
    const platform = await generateKeyPair();
    r.events[2] = await cosignSessionEvent(r.events[2], { keyid: deriveDid(platform.publicKey), ...kjs(platform) });
    const v = await verifySessionReceipt(r, { nowSec: NOW });
    expect(v.ok).toBe(false);
    expect(v.faults.map((f) => f.fault)).toContain("FOREIGN_SIGNER");
  });

  it("a changed line breaks its signatures and the chain; a deleted line breaks the chain", async () => {
    const r = json<any>("session-receipt-complete.v1.json");
    const p = JSON.parse(new TextDecoder().decode(base64ToBytes(r.events[3].payload)));
    p.body.lineItems = [p.body.lineItems[0]];
    r.events[3] = { ...r.events[3], payload: bytesToBase64(new TextEncoder().encode(JSON.stringify(p))) };
    const faults = (await verifySessionReceipt(r, { nowSec: NOW })).faults.map((f) => f.fault);
    expect(faults).toContain("BAD_SIGNATURE");
    expect(faults).toContain("CHAIN_BROKEN");
    const d = json<any>("session-receipt-complete.v1.json");
    d.events.splice(2, 1);
    expect((await verifySessionReceipt(d, { nowSec: NOW })).faults.map((f) => f.fault)).toContain("CHAIN_BROKEN");
  });

  it("a profile records only what it allows: no process line in a coffee, no place in a grant tranche", async () => {
    const r = json<any>("session-receipt-complete.v1.json");
    r.profile = "presence+flow";
    const faults = (await verifySessionReceipt(r, { nowSec: NOW })).faults.map((f) => f.fault);
    expect(faults).toContain("PROFILE_VIOLATION");
    const est = await generateKeyPair();
    const per = await generateKeyPair();
    const s = await buildSession("flow+process", [{ kind: "open", by: "establishment", cosign: true, body: openBody("flow+process", est, per, "a desk") }], { est, per });
    expect((await verifySessionReceipt(s.receipt, { nowSec: NOW })).faults.map((f) => f.fault)).toContain("PLACE_NOT_ALLOWED");
  });

  it("the close must count every hashed line item", async () => {
    const est = await generateKeyPair();
    const per = await generateKeyPair();
    const c = await lineItemCommitment("aa".repeat(16), { label: "x" });
    const s = await buildSession("presence+flow", [
      { kind: "open", by: "establishment", cosign: true, body: openBody("presence+flow", est, per, "a café") },
      { kind: "flow", by: "establishment", cosign: true, body: { lineItems: [c, c] } },
      { kind: "close", by: "establishment", cosign: true, body: { total: { amount: "10", currency: "PKR" }, lineItemCount: 1, expiresAtUnix: NOW + 1000 } },
    ], { est, per });
    expect((await verifySessionReceipt(s.receipt, { nowSec: NOW })).faults.map((f) => f.fault)).toContain("LINE_COUNT_MISMATCH");
  });

  it("the author signs its own line; a line signed only by the other party fails", async () => {
    const est = await generateKeyPair();
    const per = await generateKeyPair();
    const s = await buildSession("presence+flow", [{ kind: "open", by: "establishment", cosign: false, body: openBody("presence+flow", est, per, null) }], { est, per });
    // Re-sign line 0 with the person's key alone.
    const payload = JSON.parse(new TextDecoder().decode(base64ToBytes(s.receipt.events[0]!.payload)));
    s.receipt.events[0] = await signSessionEvent(payload, { keyid: deriveDid(per.publicKey), ...kjs(per) });
    expect((await verifySessionReceipt(s.receipt, { nowSec: NOW })).faults.map((f) => f.fault)).toContain("AUTHOR_NOT_SIGNED");
  });

  it("a moved anchor fails", async () => {
    const r = json<any>("session-receipt-complete.v1.json");
    r.anchor.headSha256 = "0".repeat(64);
    expect((await verifySessionReceipt(r, { nowSec: NOW })).faults.map((f) => f.fault)).toContain("ANCHOR_MISMATCH");
  });

  it("travels in the holder export: complete as countersigned, pending never", async () => {
    const e = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "holder", "holder-export.v1.json"), "utf8")) as HolderExport;
    const mk = async (f: string, attestation: string, expiresAtUnix: number | null) => {
      const r = json<any>(f);
      const artifact = { kind: "session-receipt" as const, value: r };
      return {
        artifact,
        manifest: {
          recordId: await recordIdOf(artifact), issuer: r.parties.establishment, relationship: r.parties.person,
          type: { tag: "application/vnd.indorania.session-event+json", family: "dsse-type", attestation }, receivedAtUnix: NOW,
          expiresAtUnix, retentionSource: expiresAtUnix === null ? "none-declared" : "record", status: null, listing: "unlisted", keptUnlistedAtUnix: NOW,
        },
      };
    };
    const closeExpiry = (await verifySessionReceipt(json("session-receipt-complete.v1.json"))).expiresAtUnix;
    const complete = await mk("session-receipt-complete.v1.json", "countersigned", closeExpiry);
    const pending = await mk("session-receipt-pending.v1.json", "issuer-signed", null);
    const ok = await verifyHolderExport({ ...e, records: [...e.records, complete, pending] } as never, { nowSec: NOW });
    expect(ok.reasons).toEqual([]);
    const forged = await mk("session-receipt-pending.v1.json", "countersigned", null);
    const bad = await verifyHolderExport({ ...e, records: [...e.records, forged] } as never, { nowSec: NOW });
    expect(bad.records.at(-1)?.reasons).toContain("MANIFEST_CLASS_MISMATCH");
  });
});

/* ── the thank-you ─────────────────────────────────────────────────────── */

describe("thank-you — a promise, never a balance; it cannot move", () => {
  const REDEEM_NOW = ctx.redemptionNowUnix as number;

  it("the vector verifies: value as text, for the answering, bound to the holder", async () => {
    const r = await verifyThankYou(txt("thank-you.v1.txt"), { resolveKey, nowSec: NOW });
    expect(r.ok).toBe(true);
    expect(typeof r.value).toBe("string");
    expect(r.for).toEqual({ act: "confirmed-session", session: "ses_01JB7COFFEEDEMO000000000" });
    expect(r.holder).toMatch(/^did:kash:/);
  });

  it("redeems once with its own issuer; after the issuer marks it used, it is refused", async () => {
    const before = await verifyRedemption(txt("thank-you-redemption.v1.txt"), {
      resolveKey, nonce: ctx.redemptionNonce, nowSec: REDEEM_NOW, statusLists: [await carried("thank-you-status-before.v1.json")],
    });
    expect(before.ok).toBe(true);
    expect(before.status.text).toStartWith("not yet used");
    const after = await verifyRedemption(txt("thank-you-redemption.v1.txt"), {
      resolveKey, nonce: ctx.redemptionNonce, nowSec: REDEEM_NOW, statusLists: [await carried("thank-you-status-after.v1.json")],
    });
    expect(after.reason).toBe("USED_OR_WITHDRAWN");
    expect(after.status.text).toStartWith("used or withdrawn");
  });

  async function fresh(extra: Record<string, unknown> = {}, withCnf = true) {
    const [giver, holder, other] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const giverDid = deriveDid(giver.publicKey);
    const v = await issueSdJwt({
      claims: { iss: giverDid, iat: NOW - (NOW % 86_400), exp: NOW + 86_400, vct: THANK_YOU_VCT, ...(withCnf ? { cnf: { jwk: jwkOf(holder.publicKey) } } : {}), for: { act: "answered-ask", ask: "ask:x" }, value: "a free tea", redeemAt: "the counter", ...extra },
      signer: kjs(giver),
    });
    return { v, giver, giverDid, holder, other };
  }

  it("cannot be passed on: shown by any key but its holder's, it fails", async () => {
    const { v, giverDid, other } = await fresh();
    const p = await presentSdJwt(v, () => true, kjs(other), { aud: giverDid, nonce: "n", iatUnix: NOW });
    expect((await verifyRedemption(p, { resolveKey, nowSec: NOW })).reason).toBe("SD_JWT_INVALID");
  });

  it("is redeemed only with its own issuer", async () => {
    const { v, holder } = await fresh();
    const p = await presentSdJwt(v, () => true, kjs(holder), { aud: "did:kash:someone-else", nonce: "n", iatUnix: NOW });
    expect((await verifyRedemption(p, { resolveKey, nowSec: NOW })).reason).toBe("REDEEMED_ELSEWHERE");
  });

  it("refuses any field that could sum it — amount, balance, points, nested or not", async () => {
    for (const extra of [{ amount: 5 }, { balance: "5" }, { meta: { points: 3 } }, { transferable: true }]) {
      const { v } = await fresh(extra);
      expect((await verifyThankYou(v, { resolveKey, nowSec: NOW })).reason).toBe("BALANCE_FIELD");
    }
  });

  it("rewards the answering, never the answer", async () => {
    const { v } = await fresh({ for: { act: "answered-ask", ask: "ask:x", answer: "yes" } });
    expect((await verifyThankYou(v, { resolveKey, nowSec: NOW })).reason).toBe("ANSWER_CARRIED");
  });

  it("must be bound to a holder", async () => {
    const { v } = await fresh({}, false);
    expect((await verifyThankYou(v, { resolveKey, nowSec: NOW })).reason).toBe("NOT_HOLDER_BOUND");
  });

  it("issuing refuses a value that is not text", async () => {
    const [giver, holder] = [await generateKeyPair(), await generateKeyPair()];
    await expect(
      issueThankYou({ issuer: { did: deriveDid(giver.publicKey), ...kjs(giver) }, holderPublicKey: holder.publicKey, for: { act: "answered-ask", ask: "ask:x" }, value: "", redeemAt: "x", iatUnix: NOW, expUnix: NOW + 1, credentialStatus: null }),
    ).rejects.toThrow();
  });
});
