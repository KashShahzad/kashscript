/**
 * PL-3 conformance vectors — generated ONCE and committed.
 *
 *   bun packages/attest/test/vectors/exchange/gen-exchange-vectors.ts
 *
 * Never regenerate: every signature uses a fresh key, so a second run changes
 * every byte. Everything here is a simulation (d11) — no real person, venue or
 * organisation. See README.md beside this file.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "../../../src/chain";
import {
  STATUS_LIST_FORMAT,
  createStatusBitstring,
  encodeStatusList,
  setStatusBit,
  signStatusList,
  type StatusListEntry,
} from "../../../src/holder";
import { presentSdJwt } from "../../../src/sd-jwt";
import {
  ASK_FORMAT,
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  cosignSessionEvent,
  issuePredicateCredential,
  issueThankYou,
  lineItemCommitment,
  sessionEventSha256,
  sessionGenesisSha256,
  signSessionEvent,
  type Ask,
  type SessionEventPayload,
  type SessionProfile,
} from "../../../src/exchange";
import type { DsseEnvelope } from "../../../src/dsse";

const DIR = import.meta.dir;
const enc = new TextEncoder();
const T = 1_790_294_400; // 2026-09-25T00:00:00Z
const DAY = 86_400;

const did = (k: KashKeyPair): string => deriveDid(k.publicKey);
const signer = (k: KashKeyPair) => ({ keyid: did(k), did: did(k), privateKey: k.privateKey, publicKey: k.publicKey });
const randomIndex = (): number => crypto.getRandomValues(new Uint32Array(1))[0]! % 131_072;

/* ── keys ──────────────────────────────────────────────────────────────── */
const org = await generateKeyPair(); // an establishment issuing predicates
const verifierA = await generateKeyPair();
const verifierB = await generateKeyPair();
const verifierC = await generateKeyPair();
// One relationship key per verifier — never the same key twice.
const relA = await generateKeyPair();
const relB = await generateKeyPair();
const relC = await generateKeyPair();
const relD = await generateKeyPair();
const cafe = await generateKeyPair(); // a café that gives thank-yous
const relCafe = await generateKeyPair();
const workshopRel = await generateKeyPair(); // the establishment's relationship key in a session
const personRel = await generateKeyPair(); // the person's
const cafeRel = await generateKeyPair();
const visitorRel = await generateKeyPair();

/* ── the predicate issuer's status list: one copy per verifier, random indexes ── */
const PRED_STATUS_URL = "https://status.example.org/workshop-demo/predicates/2026-q3";
const idx = { a: randomIndex(), b: randomIndex(), c: randomIndex(), d: randomIndex() };
const predBits = createStatusBitstring();
setStatusBit(predBits, idx.d, true); // copy D is revoked
const predStatus = await signStatusList(
  { format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: PRED_STATUS_URL, issuer: did(org), statusPurpose: "revocation", encodedList: await encodeStatusList(predBits), issuedAtUnix: T - DAY, validUntilUnix: null, ttl: 86_400_000 },
  signer(org),
);
const entry = (url: string, index: number): StatusListEntry => ({ type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: String(index), statusListCredential: url });

/* ── the predicate: one issued copy per verifier ───────────────────────── */
const workRecord = JSON.parse(readFileSync(join(DIR, "..", "holder", "source", "oreoasis-work-record.json"), "utf8")) as { envelope: unknown };
const agentReceipt = JSON.parse(readFileSync(join(DIR, "..", "holder", "source", "oreoasis-agent-receipt.json"), "utf8")) as { envelope: unknown };
const { canonicalizeBytes } = await import("@kashscript/identity-core");
const restsOn = [await sha256Hex(canonicalizeBytes(workRecord.envelope)), await sha256Hex(canonicalizeBytes(agentReceipt.envelope))];
const predicate = {
  kind: "cited-rule-in-force",
  answer: true,
  rule: { id: "rule-demo-1", version: "3", hash: "a".repeat(64) },
  window: { from: "2026-07-01T00:00:00.000Z", to: "2026-09-01T00:00:00.000Z" },
};
const copy = (rel: KashKeyPair, index: number) =>
  issuePredicateCredential({
    issuer: signer(org),
    holderPublicKey: rel.publicKey,
    predicate,
    restsOn,
    credentialStatus: entry(PRED_STATUS_URL, index),
    iatUnix: T - 3 * DAY + 4321, // rounded to the day inside
    expUnix: T + 365 * DAY,
  });
const heldA = await copy(relA, idx.a);
const heldB = await copy(relB, idx.b);
const heldC = await copy(relC, idx.c);
const heldD = await copy(relD, idx.d);
const nonces = { a: "nonce-a-7f3c9e", b: "nonce-b-12d4a0", c: "nonce-c-9e1b77", d: "nonce-d-40aa19" };
const kbIat = T + 3600;
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });
const presA = await presentSdJwt(heldA, () => false, kjs(relA), { aud: did(verifierA), nonce: nonces.a, iatUnix: kbIat });
const presB = await presentSdJwt(heldB, () => false, kjs(relB), { aud: did(verifierB), nonce: nonces.b, iatUnix: kbIat });
const presC = await presentSdJwt(heldC, () => true, kjs(relC), { aud: did(verifierC), nonce: nonces.c, iatUnix: kbIat });
const presD = await presentSdJwt(heldD, () => false, kjs(relD), { aud: did(verifierA), nonce: nonces.d, iatUnix: kbIat });

/* ── asks: one valid, one failing per rule, and the forbidden needs ────── */
const validAsk: Ask = {
  format: ASK_FORMAT,
  key: "ask:workshop-safety-check",
  version: 1,
  title: "Show the workshop followed its safety rule",
  who: { name: "A repair co-op (sample)", id: did(verifierA) },
  needs: [{ id: "n1", predicate: "cited-rule-in-force", withinDays: 120 }],
  why: "We insure repairs and only cover work done under the safety rule in force at the time.",
  answer: { form: "yes", restsOn: "issuers" },
  goodFor: "The repair is covered by the co-op's insurance.",
  declining: "costs-only-goodFor",
  linking: "separate",
  published: { library: "https://asks.example.org/library", atUnix: T - 10 * DAY },
  expiresAtUnix: T + 170 * DAY,
  state: "published",
};
const bad: Record<string, { rule: string; ask: unknown }> = {
  "r1-record-demanded": { rule: "R1-predicates-only", ask: { ...validAsk, needs: [{ id: "n1", predicate: "cited-rule-in-force", withinDays: 120, records: ["work-record"] }] } },
  "r1-answer-rests-on-records": { rule: "R1-predicates-only", ask: { ...validAsk, answer: { form: "yes", restsOn: "records" } } },
  "r2-no-why": { rule: "R2-says-why", ask: { ...validAsk, why: "" } },
  "r3-declining-costs-more": { rule: "R3-no-is-answerable", ask: { ...validAsk, declining: "service-refused" } },
  "r4-never-expires": { rule: "R4-expires", ask: { ...validAsk, expiresAtUnix: null } },
  "r4-lives-too-long": { rule: "R4-expires", ask: { ...validAsk, expiresAtUnix: T + 400 * DAY } },
  "r5-not-published": { rule: "R5-public", ask: { ...validAsk, published: null } },
  "r6-joined": { rule: "R6-no-joining", ask: { ...validAsk, linking: "joined" } },
  "r6-same-kind-twice": { rule: "R6-no-joining", ask: { ...validAsk, needs: [validAsk.needs[0], { id: "n2", predicate: "cited-rule-in-force", withinDays: 30 }] } },
  "r7-no-stable-key": { rule: "R7-excessive-recordable", ask: { ...validAsk, key: "Workshop Check" } },
  "r8-improvement-item": { rule: "R8-no-improvement-item", ask: { ...validAsk, needs: [{ id: "n1", predicate: "improved-the-way-this-work-is-done", withinDays: 365 }] } },
  "forbidden-origin": { rule: "FORBIDDEN-NEED", ask: { ...validAsk, needs: [{ id: "n1", predicate: "place-of-origin", withinDays: 30 }] } },
  "forbidden-ethnicity": { rule: "FORBIDDEN-NEED", ask: { ...validAsk, needs: [{ id: "n1", predicate: "ethnicity-declared", withinDays: 30 }] } },
  "forbidden-sect": { rule: "FORBIDDEN-NEED", ask: { ...validAsk, needs: [{ id: "n1", predicate: "sect-membership", withinDays: 30 }] } },
  "forbidden-caste": { rule: "FORBIDDEN-NEED", ask: { ...validAsk, needs: [{ id: "n1", predicate: "caste-verified", withinDays: 30 }] } },
  "forbidden-ancestry": { rule: "FORBIDDEN-NEED", ask: { ...validAsk, needs: [{ id: "n1", predicate: "ancestry-check", withinDays: 30 }] } },
};
const passesWordBoundary: Ask = { ...validAsk, key: "ask:original-receipt", needs: [{ id: "n1", predicate: "original-receipt-held", withinDays: 30 }] };

/* ── session receipts ──────────────────────────────────────────────────── */
async function session(
  sessionId: string,
  profile: SessionProfile,
  est: KashKeyPair,
  per: KashKeyPair,
  lines: { kind: SessionEventPayload["kind"]; by: "establishment" | "person"; body: Record<string, unknown>; atUnix: number; cosign: boolean }[],
  anchorLast: boolean,
) {
  const events: DsseEnvelope[] = [];
  let prev = await sessionGenesisSha256(sessionId);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    const author = l.by === "establishment" ? est : per;
    const other = l.by === "establishment" ? per : est;
    const payload: SessionEventPayload = { spec: SESSION_EVENT_SPEC, sessionId, seq: i, prevSha256: prev, kind: l.kind, atUnix: l.atUnix, by: l.by, body: l.body };
    let env = await signSessionEvent(payload, { keyid: did(author), privateKey: author.privateKey, publicKey: author.publicKey });
    if (l.cosign) env = await cosignSessionEvent(env, { keyid: did(other), privateKey: other.privateKey, publicKey: other.publicKey });
    events.push(env);
    prev = await sessionEventSha256(env);
  }
  return {
    formatVersion: SESSION_RECEIPT_FORMAT,
    sessionId,
    profile,
    parties: { establishment: did(est), person: did(per) },
    events,
    anchor: anchorLast ? { headSha256: prev, coversSeq: lines.length - 1, witness: { backend: "none", receipt: {}, witnessedAt: null } } : null,
  };
}
const items = [
  { saltHex: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", item: { label: "replacement part", amount: "4000.00" } },
  { saltHex: "a1b2c3d4e5f60718293a4b5c6d7e8f90", item: { label: "labour", amount: "500.00" } },
];
const commitments = await Promise.all(items.map((x) => lineItemCommitment(x.saltHex, x.item)));
const REPAIR_ID = "ses_01JB7REPAIRDEMO000000000";
const repair = await session(REPAIR_ID, "process+flow", workshopRel, personRel, [
  { kind: "open", by: "establishment", atUnix: T + 600, cosign: true, body: { profile: "process+flow", parties: { establishment: did(workshopRel), person: did(personRel) }, consent: { records: ["process", "flow"], asks: [] }, place: "A repair workshop (sample)" } },
  { kind: "process", by: "establishment", atUnix: T + 1200, cosign: true, body: { step: "diagnosed", rule: { id: "rule-demo-1", version: "3" } } },
  { kind: "process", by: "establishment", atUnix: T + 5400, cosign: true, body: { step: "replaced the part", rule: { id: "rule-demo-1", version: "3" } } },
  { kind: "flow", by: "establishment", atUnix: T + 5500, cosign: true, body: { lineItems: commitments } },
  { kind: "disagreement", by: "person", atUnix: T + 5600, cosign: true, body: { about: 2, statementSha256: await sha256Hex(enc.encode("the part fitted was not the one agreed")) } },
  { kind: "close", by: "establishment", atUnix: T + 5700, cosign: true, body: { total: { amount: "4500.00", currency: "PKR" }, lineItemCount: 2, expiresAtUnix: T + 730 * DAY } },
], true);
const coffeeCommit = await lineItemCommitment("11223344556677889900aabbccddeeff", { label: "flat white", amount: "650.00" });
const coffee = await session("ses_01JB7COFFEEDEMO000000000", "presence+flow", cafeRel, visitorRel, [
  { kind: "open", by: "establishment", atUnix: T + 900, cosign: true, body: { profile: "presence+flow", parties: { establishment: did(cafeRel), person: did(visitorRel) }, consent: { records: ["presence", "flow"], asks: [] }, place: "A café (sample)" } },
  { kind: "presence", by: "person", atUnix: T + 910, cosign: true, body: {} },
  // The café has signed the line; the visitor has not yet — pending, never proof.
  { kind: "flow", by: "establishment", atUnix: T + 1500, cosign: false, body: { lineItems: [coffeeCommit] } },
], false);

/* ── the thank-you and its redemption ──────────────────────────────────── */
const TY_STATUS_URL = "https://status.example.org/cafe-demo/thank-yous/2026-09";
const tyIndex = randomIndex();
const tyList = async (redeemed: boolean, at: number) => {
  const bits = createStatusBitstring();
  if (redeemed) setStatusBit(bits, tyIndex, true);
  return signStatusList({ format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: TY_STATUS_URL, issuer: did(cafe), statusPurpose: "revocation", encodedList: await encodeStatusList(bits), issuedAtUnix: at, validUntilUnix: null }, signer(cafe));
};
const thankYou = await issueThankYou({
  issuer: signer(cafe),
  holderPublicKey: relCafe.publicKey,
  for: { act: "confirmed-session", session: "ses_01JB7COFFEEDEMO000000000" },
  value: "a free cup of tea on your next visit",
  redeemAt: "at the counter of the café that gave it",
  iatUnix: T,
  expUnix: T + 90 * DAY,
  credentialStatus: entry(TY_STATUS_URL, tyIndex),
});
const REDEEM_NONCE = "redeem-nonce-5c2e";
const redemption = await presentSdJwt(thankYou, () => true, kjs(relCafe), { aud: did(cafe), nonce: REDEEM_NONCE, iatUnix: T + 7 * DAY });

/* ── write ─────────────────────────────────────────────────────────────── */
const w = (name: string, content: string): void => writeFileSync(join(DIR, name), content.endsWith("\n") ? content : content + "\n");
const j = (v: unknown): string => JSON.stringify(v, null, 2) + "\n";
w("predicate-held-a.v1.txt", heldA);
w("predicate-presentation-a.v1.txt", presA);
w("predicate-presentation-b.v1.txt", presB);
w("predicate-presentation-c-records.v1.txt", presC);
w("predicate-presentation-revoked.v1.txt", presD);
w("predicate-status-list.v1.json", j(predStatus));
w("session-receipt-complete.v1.json", j(repair));
w("session-receipt-pending.v1.json", j(coffee));
w("session-line-items.v1.json", j(items.map((x, i) => ({ commitment: commitments[i], ...x }))));
w("thank-you.v1.txt", thankYou);
w("thank-you-redemption.v1.txt", redemption);
w("thank-you-status-before.v1.json", j(await tyList(false, T)));
w("thank-you-status-after.v1.json", j(await tyList(true, T + 7 * DAY + 60)));
mkdirSync(join(DIR, "asks"), { recursive: true });
w("asks/valid.json", j(validAsk));
w("asks/valid-word-boundary.json", j(passesWordBoundary));
for (const [name, b] of Object.entries(bad)) w(`asks/invalid-${name}.json`, j(b.ask));
w("asks/expected.json", j(Object.fromEntries(Object.entries(bad).map(([name, b]) => [`invalid-${name}.json`, b.rule]))));
w(
  "context.v1.json",
  j({
    note: "Public facts a verifier would already know. Simulation only.",
    nowUnix: T + 7200,
    predicateIssuer: did(org),
    verifiers: {
      a: { did: did(verifierA), nonce: nonces.a },
      b: { did: did(verifierB), nonce: nonces.b },
      c: { did: did(verifierC), nonce: nonces.c },
      revoked: { did: did(verifierA), nonce: nonces.d },
    },
    restsOn,
    cafe: did(cafe),
    redemptionNonce: REDEEM_NONCE,
    redemptionNowUnix: T + 7 * DAY + 120,
  }),
);
console.log(`predicate issuer ${did(org)}; copies at ${JSON.stringify(idx)}; thank-you index ${tyIndex}`);
