/**
 * GP-6 vectors — the session anchor's second version — generated ONCE and committed.
 *
 *   bun packages/attest/test/vectors/anchor/gen-anchor-vectors.ts
 *
 * Never regenerate: four of the five sessions are signed with fresh keys, so a
 * second run changes every byte. The fifth is PL-3's repair receipt, READ from
 * ../exchange and never written there: its six signed lines are copied as they
 * are, and only its anchor is new. Everything here is a simulation (d11) — no
 * real person, venue or organisation, and no public log. See README.md.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import type { DsseEnvelope } from "../../../src/dsse";
import {
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  cosignSessionEvent,
  lineItemCommitment,
  sessionAnchorBatch,
  sessionEventSha256,
  sessionGenesisSha256,
  signSessionEvent,
  verifySessionReceipt,
  type SessionEventPayload,
  type SessionProfile,
  type SessionReceipt,
} from "../../../src/exchange";
import type { AnchorWitness } from "../../../src/witness";

const DIR = import.meta.dir;
const T = 1_790_294_400; // 2026-09-25T00:00:00Z — the day PL-3's sessions ran
const DAY = 86_400;
const NOW = T + 2 * DAY;
const did = (k: KashKeyPair): string => deriveDid(k.publicKey);

type Line = { kind: SessionEventPayload["kind"]; by: "establishment" | "person"; body: Record<string, unknown>; atUnix: number };

/** A closed session, every line signed by its author and countersigned by the other party. */
async function session(sessionId: string, profile: SessionProfile, est: KashKeyPair, per: KashKeyPair, lines: Line[]): Promise<SessionReceipt> {
  const events: DsseEnvelope[] = [];
  let prev = await sessionGenesisSha256(sessionId);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    const [author, other] = l.by === "establishment" ? [est, per] : [per, est];
    const payload: SessionEventPayload = { spec: SESSION_EVENT_SPEC, sessionId, seq: i, prevSha256: prev, kind: l.kind, atUnix: l.atUnix, by: l.by, body: l.body };
    const env = await signSessionEvent(payload, { keyid: did(author), privateKey: author.privateKey, publicKey: author.publicKey });
    events.push(await cosignSessionEvent(env, { keyid: did(other), privateKey: other.privateKey, publicKey: other.publicKey }));
    prev = await sessionEventSha256(events[i]!);
  }
  return { formatVersion: SESSION_RECEIPT_FORMAT, sessionId, profile, parties: { establishment: did(est), person: did(per) }, events, anchor: null };
}

const open = (profile: SessionProfile, est: KashKeyPair, per: KashKeyPair, records: string[], place: string | null, atUnix: number): Line => ({
  kind: "open", by: "establishment", atUnix, body: { profile, parties: { establishment: did(est), person: did(per) }, consent: { records, asks: [] }, place },
});
const close = (amount: string, lineItemCount: number, atUnix: number): Line => ({
  kind: "close", by: "establishment", atUnix, body: { total: { amount, currency: "PKR" }, lineItemCount, expiresAtUnix: T + 365 * DAY },
});

/* ── four fresh sessions, one per profile ──────────────────────────────── */
const [cafe, visitor, guide, walker, fund, grantee, tailor, customer] = await Promise.all(Array.from({ length: 8 }, () => generateKeyPair()));

const coffee = await session("ses_01JB8ANCHORCOFFEE000000", "presence+flow", cafe!, visitor!, [
  open("presence+flow", cafe!, visitor!, ["presence", "flow"], "A café (sample)", T + 3600),
  { kind: "presence", by: "person", atUnix: T + 3610, body: {} },
  { kind: "flow", by: "establishment", atUnix: T + 4200, body: { lineItems: [await lineItemCommitment("5e1f0a2b3c4d5e6f708192a3b4c5d6e7", { label: "flat white", amount: "650.00" })] } },
  close("650.00", 1, T + 4210),
]);

const guidedDay = await session("ses_01JB8ANCHORGUIDEDDAY000", "presence+process+flow", guide!, walker!, [
  open("presence+process+flow", guide!, walker!, ["presence", "process", "flow"], "A guided walk (sample)", T + 7200),
  { kind: "presence", by: "person", atUnix: T + 7260, body: {} },
  { kind: "process", by: "establishment", atUnix: T + 7300, body: { step: "the walk began", rule: null } },
  { kind: "process", by: "establishment", atUnix: T + 21600, body: { step: "the walk ended", rule: null } },
  {
    kind: "flow", by: "establishment", atUnix: T + 21700, body: {
      lineItems: [
        await lineItemCommitment("0123456789abcdef0123456789abcdef", { label: "the walk", amount: "3000.00" }),
        await lineItemCommitment("fedcba9876543210fedcba9876543210", { label: "lunch", amount: "1200.00" }),
      ],
    },
  },
  close("4200.00", 2, T + 21710),
]);

const tranche = await session("ses_01JB8ANCHORTRANCHE00000", "flow+process", fund!, grantee!, [
  open("flow+process", fund!, grantee!, ["flow", "process"], null, T + 36000),
  { kind: "flow", by: "establishment", atUnix: T + 36100, body: { lineItems: [await lineItemCommitment("00112233445566778899aabbccddeeff", { label: "second tranche", amount: "50000.00" })] } },
  { kind: "process", by: "establishment", atUnix: T + 36200, body: { step: "the tranche was released", rule: { id: "rule-demo-grant", version: "1" } } },
  close("50000.00", 1, T + 36210),
]);

const alteration = await session("ses_01JB8ANCHORTAILOR000000", "process+flow", tailor!, customer!, [
  open("process+flow", tailor!, customer!, ["process", "flow"], "A tailor's shop (sample)", T + 43200),
  { kind: "process", by: "establishment", atUnix: T + 43300, body: { step: "measured", rule: null } },
  { kind: "flow", by: "establishment", atUnix: T + 50400, body: { lineItems: [await lineItemCommitment("9f8e7d6c5b4a39281706f5e4d3c2b1a0", { label: "alteration", amount: "800.00" })] } },
  close("800.00", 1, T + 50410),
]);

/* ── PL-3's repair, read and never written ─────────────────────────────── */
const repair = JSON.parse(readFileSync(join(DIR, "..", "exchange", "session-receipt-complete.v1.json"), "utf8")) as SessionReceipt;

/* ── the batch: one tree, one witness, each receipt its own path ───────── */
const receipts = [coffee, guidedDay, repair, tranche, alteration];
const entries = await Promise.all(receipts.map(async (r) => ({ headSha256: await sessionEventSha256(r.events.at(-1)!), coversSeq: r.events.length - 1 })));
const batch = await sessionAnchorBatch(entries);
const witness: AnchorWitness = {
  backend: "none",
  receipt: { witnessed: false, reason: "practice — not witnessed by any public log", merkleRoot: batch.root },
  witnessedAt: null,
};
const anchored = receipts.map((r, i) => ({ ...r, anchor: batch.anchorFor(i, witness) }));

for (const [i, r] of anchored.entries()) {
  const report = await verifySessionReceipt(r, { nowSec: NOW });
  if (!report.ok || !report.proof || report.anchor?.inclusion?.included !== true || report.anchor.inclusion.witnessNamesRoot !== true) {
    throw new Error(`receipt ${i} does not verify: ${JSON.stringify(report.faults)}`);
  }
}

/* ── write ─────────────────────────────────────────────────────────────── */
const j = (v: unknown): string => JSON.stringify(v, null, 2) + "\n";
const w = (name: string, v: unknown): void => writeFileSync(join(DIR, name), j(v));
for (const [i, r] of anchored.entries()) w(`session-anchored-${i}.v2.json`, r);
w("batch.v2.json", {
  note: "The anchoring host's own view of the batch. It is never shipped with a receipt; it is here only so the tests can show that no receipt carries any of it.",
  root: batch.root,
  treeSize: batch.treeSize,
  sessions: receipts.map((r, i) => ({ sessionId: r.sessionId, parties: r.parties, headSha256: entries[i]!.headSha256, coversSeq: entries[i]!.coversSeq })),
});
w("context.v2.json", { note: "Public facts a verifier would already know. Simulation only.", nowUnix: NOW });
console.log(`wrote 5 anchored receipts, a batch of ${batch.treeSize}, root ${batch.root}`);
