#!/usr/bin/env bun
/**
 * Writes PY-5's conformance files into `specs/attestation/tck/` — `batch-chance@1`, `batch-draw@1`,
 * `batch-items@1` and `kash.attestation@1.1.0`. **Run once; never regenerated** (it refuses to overwrite).
 *
 * Every case states what its author meant — the faults a body should raise, the counts and the bound — and the
 * script refuses to write when the reference implementation disagrees, so the files record intent, not an echo.
 * Nothing in them is signed or a key; every salt, seed and item is written in, so a stranger recomputes each one.
 *
 *   bun scripts/batch-vectors.ts                          # all four, once
 *   bun scripts/batch-vectors.ts kash.attestation@1.1.0   # only the files named — each still refused if it exists
 *
 * **Recorded regenerations (PY-5r, 2026-11-26), before anything was exported or published:** the fresh-session
 * review wrote `kash.attestation@1.1.0` again for two of its fixes — a sampled batch carries the draw block's coinbase
 * (BIP34; a header carries no height), and a not yet within the plan does not give the over-the-plan reason. The
 * other three files are unchanged.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkAttestation, type AttestationBody } from "../src/attestation";
import {
  OVER_PLAN_REASON,
  SEAL_FORMAT,
  boundOf,
  chanceAtMost,
  drawPositions,
  drawSeed,
  heightPush,
  itemDigestOf,
  itemTree,
  limitOf,
  type Alpha,
  type Batch,
  type BatchSeal,
  type DrawCoinbase,
} from "../src/batch";

const TCK = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck");
const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const enc = new TextEncoder();

function write(dir: string, value: unknown): void {
  const d = join(TCK, dir);
  if (existsSync(join(d, "cases.json"))) throw new Error(`${d}/cases.json exists — the conformance files are written once`);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "cases.json"), json(value));
}

/* ── batch-chance@1 ─────────────────────────────────────────────────── */

async function chance(): Promise<void> {
  const a20: Alpha = { num: 1, den: 20 };
  const rows: [string, number, number, number, Alpha, number][] = [
    ["ten items, three drawn, two short, none found", 10, 3, 0, a20, 2],
    ["the worked example's plan: 140 of 2,000, 41 short — the plan's limit is 40", 2000, 140, 0, a20, 41],
    ["the same plan with exactly the limit short", 2000, 140, 0, a20, 40],
    ["a census of 40: every item seen, one found", 40, 40, 1, a20, 1],
    ["the plan's example: 300 of 10,000, none found", 10_000, 300, 0, a20, 98],
    ["300 of 10,000, two found, 200 short", 10_000, 300, 2, a20, 200],
    ["50 of 500, three found, at 3 in 100", 500, 50, 3, { num: 3, den: 100 }, 30],
    ["all but one drawn, none found, one short", 100, 99, 0, a20, 1],
    ["one item, drawn", 1, 1, 0, a20, 0],
    ["every drawn item short", 60, 30, 30, a20, 60],
    ["one of 1,000 drawn, at 1 in 2", 1000, 1, 0, { num: 1, den: 2 }, 500],
    ["77 of 777, seven found, at 1 in 1,000", 777, 77, 7, { num: 1, den: 1000 }, 77],
  ];
  const cases = rows.map(([name, size, sample, found, alpha, short]) => {
    const c = chanceAtMost(size, short, sample, found);
    return { name, size, sample, found, alpha, short, drawsWithAtMost: c.num.toString(), draws: c.den.toString(), bound: boundOf({ size, sample, found, alpha }) };
  });
  // Intent, checked: the worked example's plan has limit 40; a census's bound is the count found.
  if (cases[1]!.bound !== 40 || cases[3]!.bound !== 1) throw new Error("the plan's figures moved");
  write("batch-chance@1", {
    format: "batch-chance@1",
    about:
      "The arithmetic of a batch accepted on a sample (specs/attestation/batch.md §4), exactly. For each case: drawsWithAtMost is how many of the C(size, sample) equally likely draws hold at most `found` short items when `short` of the `size` are; draws is C(size, sample); bound is the largest number of short items for which a draw holding `found` or fewer short comes up more often than alpha — it depends on size, sample, found and alpha, not on `short`. Big numbers are decimal strings. Reference: @kashscript/attest/batch's chanceAtMost and boundOf.",
    cases,
  });
}

/* ── batch-draw@1 ───────────────────────────────────────────────────── */

async function draw(): Promise<void> {
  const rows: [string, string, string, number, number][] = [
    ["ten items, three drawn", "00".repeat(32), "00".repeat(32), 10, 3],
    ["one item", "11".repeat(32), "22".repeat(32), 1, 1],
    ["every one of five", "33".repeat(32), "44".repeat(32), 5, 5],
    [
      "the worked example's seal over block 974281's hash — a stand-in block, not that seal's draw block",
      "5c31544c631301fa835e7986dce0b689a460617c6d1ca92df5d2262a23dd4125",
      "000000000000000000008c599e68c2875ef9fd915b1bb5077e67a859cedd3223",
      2000,
      140,
    ],
    ["25 of a million", "ab".repeat(32), "cd".repeat(32), 1_000_000, 25],
    ["a thousand of ten thousand", "ef".repeat(32), "01".repeat(32), 10_000, 1000],
  ];
  const cases = [];
  for (const [name, sealDigest, blockHash, size, sample] of rows) {
    const seed = await drawSeed(sealDigest, blockHash);
    cases.push({ name, sealDigest, blockHash, seed, size, sample, positions: await drawPositions(seed, size, sample) });
  }
  if (JSON.stringify(cases[2]!.positions) !== JSON.stringify([0, 1, 2, 3, 4])) throw new Error("drawing every item must give every position");
  write("batch-draw@1", {
    format: "batch-draw@1",
    about:
      "The draw of a batch accepted on a sample (specs/attestation/batch.md §3). seed = SHA-256(\"kash-batch-draw-v1\\n\" ‖ seal digest ‖ block hash), the hash as Bitcoin displays it. The stream is SHA-256(seed ‖ n) for n = 0, 1, 2, … as four big-endian bytes, each block read as four big-endian 64-bit words. A number below m takes the next word w and gives w mod m when w is below 2^64 − (2^64 mod m), else takes the next word. The positions: for i = 0 … sample−1, j = i + (a number below size − i), swap entries i and j of 0 … size−1; the first `sample` entries, ascending. Reference: @kashscript/attest/batch's drawSeed and drawPositions.",
    cases,
  });
}

/* ── batch-items@1 ──────────────────────────────────────────────────── */

async function items(): Promise<void> {
  const salt = "5a".repeat(32);
  const sets: [string, string[]][] = [
    ["one item", ["SAMPLE item one"]],
    ["two items", ["SAMPLE item one", "SAMPLE item two"]],
    ["seven items", Array.from({ length: 7 }, (_, i) => `SAMPLE line ${i + 1} of 7`)],
  ];
  const cases = [];
  for (const [name, texts] of sets) {
    const digests = await Promise.all(texts.map((t) => itemDigestOf(enc.encode(t))));
    const tree = await itemTree(salt, digests);
    cases.push({ name, salt, items: texts, digests, leaves: tree.leaves, root: tree.root, paths: texts.map((_, p) => ({ position: p, path: tree.path(p) })) });
  }
  write("batch-items@1", {
    format: "batch-items@1",
    about:
      "One root over many items, kash-items/1 (specs/attestation/batch.md §1). Each item's digest is SHA-256 of its UTF-8 bytes. Its leaf is SHA-256(0x00 ‖ \"kash-batch-item-v1\\n\" ‖ size as 8 bytes big-endian ‖ salt ‖ digest). Leaves are sorted ascending; the root is RFC 6962's Merkle tree hash over them in that order; a position's path is its RFC 6962 audit path, nearest sibling first. leaves lists the leaves in order. Reference: @kashscript/attest/batch's itemTree.",
    cases,
  });
}

/* ── kash.attestation@1.1.0 ─────────────────────────────────────────── */

async function attestation(): Promise<void> {
  const ISSUER = "did:kash:AgencyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const APPROVER = "did:kash:CounterpartyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  const SEAL_DIGEST = "3f1c9a52e6b07d48a1e2c5f9b8d4a6017e3c2b9f5d8a1e4c7b0f3a6d9e2c5b81";
  const a20: Alpha = { num: 1, den: 20 };
  const header = "00".repeat(80);
  // A block's first transaction naming block 977,713 (BIP34): one input spending nothing, its script the height's
  // push and a SAMPLE tag, one output. Like the stamp and the headers, a placeholder for these rules — the checks that
  // hash it are in the worked examples. Its path is empty: a block of one transaction.
  const tag = Array.from(enc.encode("SAMPLE pool"));
  const script = [...heightPush(977_713), ...tag];
  const coinbase: DrawCoinbase = {
    tx: Buffer.from([2, 0, 0, 0, 1, ...new Array<number>(32).fill(0), 0xff, 0xff, 0xff, 0xff, script.length, ...script, 0xff, 0xff, 0xff, 0xff, 1, 0, 0xf2, 0x05, 0x2a, 1, 0, 0, 0, 1, 0x6a, 0, 0, 0, 0]).toString("hex"),
    path: [],
  };
  const sampled = (over: Partial<BatchSeal> = {}): BatchSeal => ({
    format: SEAL_FORMAT,
    root: "7e348acf79b2b03b".repeat(4),
    size: 2000,
    plan: { sample: 140, accept: 0, alpha: a20, limit: limitOf({ size: 2000, sample: 140, accept: 0, alpha: a20 }) },
    draw: { source: "bitcoin/1", height: 977713 },
    ...over,
  });
  // A case with a chance this format refuses has no bound to compute; it stays 0, and the rules stop before it.
  const boundFor = (seal: BatchSeal, found: number): number => {
    try {
      return boundOf({ size: seal.size, sample: seal.plan.sample, found, alpha: seal.plan.alpha });
    } catch {
      return 0;
    }
  };
  const batch = (found: number[], over: Partial<Batch> = {}, seal = sampled()): Batch => ({
    seal,
    stamp: "AA==",
    blocks: [header, header],
    coinbase,
    found,
    bound: boundFor(seal, found.length),
    ...over,
  });
  const body = (b: Batch, over: Partial<AttestationBody> = {}): AttestationBody => ({
    issuer: ISSUER,
    kind: "receipt",
    outcome: "accepted",
    reference: { kind: "artefact", sha256: SEAL_DIGEST },
    statement: "Batch 14: product descriptions translated into Urdu.",
    profile: "client-signoff/1",
    counterparty: APPROVER,
    grade: 1,
    claimedAt: "2026-11-26T12:00:00Z",
    expiresAt: "2027-11-26T12:00:00Z",
    batch: b,
    ...over,
  });
  const censusSeal: BatchSeal = { format: SEAL_FORMAT, root: "d9aa9702772ea57d".repeat(4), size: 40, plan: { sample: 40, accept: 1, alpha: a20, limit: 1 } };
  const notYet = { outcome: "not-yet" as const, reasons: [OVER_PLAN_REASON] };
  const rows: [string, unknown, string[]][] = [
    ["a batch accepted on a sample: 140 of 2,000 drawn, none found short", body(batch([])), []],
    ["a census of 40: one found short within the plan, accepted — the acceptance does not cover it", body({ seal: censusSeal, found: [17], bound: 1 }), []],
    ["a not yet over the plan, saying so", body(batch([12, 400]), notYet), []],
    ["a 1.0.0 body, with no batch, still reads", (({ batch: _b, ...rest }) => rest)(body(batch([]))), []],
    ["a batch on an assurance", body(batch([]), { kind: "assurance" }), ["BATCH_KIND"]],
    ["a batch made against an agreement, not the seal", body(batch([]), { reference: { kind: "agreement", sha256: SEAL_DIGEST } }), ["BATCH_REFERENCE"]],
    ["answered by an organisation's own key, at grade 3", body(batch([]), { counterparty: "did:web:client.example", grade: 3 }), ["BATCH_BY_A_PERSON"]],
    ["answered at grade 3 with a key", body(batch([]), { grade: 3 }), ["BATCH_BY_A_PERSON"]],
    ["a plan that accepts as many as it draws", body(batch([], {}, sampled({ plan: { sample: 140, accept: 140, alpha: a20, limit: 2000 } }))), ["BATCH_LIMITS"]],
    ["a chance above 1 in 2", body(batch([], {}, sampled({ plan: { sample: 140, accept: 0, alpha: { num: 3, den: 4 }, limit: 40 } }))), ["BATCH_LIMITS"]],
    ["a census carrying a draw", body({ seal: { ...censusSeal, draw: { source: "bitcoin/1", height: 977713 } }, found: [17], bound: 1 }), ["BATCH_CENSUS"]],
    ["a census carrying a coinbase", body({ seal: censusSeal, coinbase, found: [17], bound: 1 }), ["BATCH_CENSUS"]],
    ["a sampled batch without its stamp", body((({ stamp: _s, ...rest }) => rest)(batch([]))), ["BATCH_CENSUS"]],
    ["a sampled batch without the draw block's coinbase, which names its height", body((({ coinbase: _c, ...rest }) => rest)(batch([]))), ["BATCH_CENSUS"]],
    ["positions found short out of order", body(batch([400, 12]), notYet), ["BATCH_FOUND"]],
    ["a position found short outside the batch", body(batch([2000]), notYet), ["BATCH_FOUND"]],
    ["accepted with more found short than the plan accepts", body(batch([12])), ["BATCH_OVER_PLAN"]],
    ["a not yet over the plan that does not say so", body(batch([12]), { outcome: "not-yet", reasons: ["wrong-dialect"] }), ["BATCH_OVER_PLAN"]],
    ["a not yet within the plan that gives the over-the-plan reason", body(batch([]), notYet), ["BATCH_OVER_PLAN"]],
    ["a plan's limit one too low", body(batch([], {}, sampled({ plan: { sample: 140, accept: 0, alpha: a20, limit: 39 } }))), ["BATCH_PLAN"]],
    ["a bound one too high", body(batch([], { bound: 41 })), ["BATCH_BOUND"]],
    ["one header is no draw", body(batch([], { blocks: [header] })), ["SHAPE"]],
  ];
  const cases = rows.map(([name, b, faults]) => {
    const r = checkAttestation(b);
    const got = [...new Set(r.faults.map((f) => f.code))].sort();
    if (JSON.stringify(got) !== JSON.stringify([...faults].sort())) throw new Error(`${name}: meant ${faults.join(", ") || "valid"}, the reference gives ${got.join(", ") || "valid"}`);
    return { name, valid: faults.length === 0, body: b, ...(faults.length > 0 ? { faults } : {}) };
  });
  write("kash.attestation@1.1.0", {
    lexicon: "kash.attestation@1.1.0",
    about:
      "Conformance cases for the attestation record with a batch accepted on a sample (specs/attestation/batch.md §5). Each case is a body; a reader runs the shape (KASH_ATTESTATION_1_1_BODY_SCHEMA, or specs/schemas/attestation.schema.json) and then the cross-field rules, and must reach `valid` with exactly the listed fault codes. These are the rules that need no hashing; the stamp, the block headers and the draw block's coinbase here are placeholders, and the checks of the seal's digest, the stamp, the headers, the coinbase and the draw are in the worked examples. The DIDs are SAMPLE strings that match the patterns; nothing here is signed. Reference implementation: @kashscript/attest/attestation's checkAttestation. Written again by the fresh-session review (PY-5r, 2026-11-26), before anything was exported: a sampled batch carries the draw block's coinbase, which names its height (BIP34); a not yet within the plan does not give the over-the-plan reason.",
    cases,
  });
}

const FILES: Record<string, () => Promise<void>> = { "batch-chance@1": chance, "batch-draw@1": draw, "batch-items@1": items, "kash.attestation@1.1.0": attestation };
const named = process.argv.slice(2);
const unknown = named.filter((n) => !(n in FILES));
if (unknown.length > 0) throw new Error(`no conformance file named ${unknown.join(", ")} — the files are ${Object.keys(FILES).join(", ")}`);
const chosen = named.length > 0 ? named : Object.keys(FILES);
for (const n of chosen) await FILES[n]!();
console.log(`written: ${chosen.join(", ")}`);
