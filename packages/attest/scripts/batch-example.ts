#!/usr/bin/env bun
/**
 * Writes the worked examples of a batch accepted on a sample into `specs/attestation/examples/` (PY-5).
 *
 *   bun scripts/batch-example.ts stamp      # the sampled batch: seal it, name a block ahead, stamp the seal (online)
 *   bun scripts/batch-example.ts finish     # once that block is mined: upgrade the stamp, fetch the headers and the draw block's coinbase, draw, sign (online)
 *   bun scripts/batch-example.ts census     # the census: every item checked, no draw (offline)
 *
 * **Run once each; never regenerated.** Keys are made fresh and thrown away: only public keys, DIDs and signed
 * bytes are written. Every party is SAMPLE and every record `practice: true`. Going online sends a 32-byte hash
 * to OpenTimestamps' calendars and asks a public block source for block heights, headers, the draw block's
 * transaction ids and its first transaction — nothing else. (PY-5r added the coinbase: the draw block's own word
 * for its height, BIP34, which the record now carries; the seal and the stamp are unchanged.)
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../src/dsse";
import { signBytes } from "../src/signing";
import { checkBitcoinHeader, otsLeaves, parseOts, stampOpenTimestamps, upgradeOpenTimestamps, type FetchBytes } from "../src/witness/ots";
import { ATTESTATION_DST, checkAttestation, verifyAttestationRecord, type AttestationBody } from "../src/attestation";
import { checkDrawBlocks, fetchBitcoinHeaders, fetchBitcoinTip, fetchDrawCoinbase, type FetchText } from "../src/batch/beacon";
import { boundOf, limitOf, planFor } from "../src/batch/chance";
import { drawPositions, drawSeed } from "../src/batch/draw";
import { itemDigestOf, itemTree, BATCH_ITEMS_FORMAT, type BatchItemsFile } from "../src/batch/items";
import { DRAW_SOURCE_BITCOIN, SEAL_FORMAT, sealDigestOf, type Batch, type BatchSeal } from "../src/batch/seal";
import { batchWords } from "../src/batch/words";

const OUT = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "examples");
const SAMPLED = join(OUT, "receipt-batch-sampled");
const CENSUS = join(OUT, "receipt-batch-all");
const NOTE = "SAMPLE parties, practice only. Public identifiers; no key material.";

type Party = KashKeyPair & { readonly did: string; readonly keyid: string };
async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

/** The record of truth in the spec's order (§2.3): the approver signs the final bytes first, then the asker's book. */
async function recordOf(body: AttestationBody, asker: Party, approver: Party): Promise<DsseEnvelope> {
  const checked = checkAttestation(body);
  if (!checked.ok) throw new Error(`the body does not check: ${checked.faults.map((f) => `${f.code} ${f.message}`).join("; ")}`);
  const env = await signEnvelope(body, ATTESTATION_DST, approver, { canonical: true });
  const sig = await signBytes(asker, pae(env.payloadType, base64ToBytes(env.payload)), "der");
  return { ...env, signatures: [...env.signatures, { keyid: asker.keyid, sig: bytesToBase64(sig) }] };
}

function receipt(asker: Party, approver: Party, batch: Batch, sealDigest: string, statement: string, now: Date): AttestationBody {
  const year = new Date(now.getTime() + 365 * 86_400_000);
  return {
    issuer: asker.did,
    kind: "receipt",
    outcome: "accepted",
    reference: { kind: "artefact", sha256: sealDigest },
    statement,
    profile: "client-signoff/1",
    counterparty: approver.did,
    grade: 1,
    claimedAt: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    expiresAt: year.toISOString().replace(/\.\d{3}Z$/, "Z"),
    practice: true,
    batch,
  };
}
const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
const enc = new TextEncoder();

const fetchBytes: FetchBytes = async (url, init) => {
  const res = await fetch(url, { method: init.method, headers: init.headers, ...(init.body !== undefined ? { body: init.body as unknown as BodyInit } : {}) });
  return { ok: res.ok, status: res.status, bytes: async () => new Uint8Array(await res.arrayBuffer()) };
};
const fetchText: FetchText = async (url) => {
  const res = await fetch(url);
  return { ok: res.ok, status: res.status, text: () => res.text() };
};

/** The SAMPLE items: 2,000 lines of practice text, each its own item. */
async function sampleItems(size: number, label: string): Promise<{ texts: string[]; digests: string[] }> {
  const texts: string[] = [];
  const digests: string[] = [];
  for (let i = 1; i <= size; i++) {
    const t = `SAMPLE ${label} item ${String(i).padStart(4, "0")} of ${size} — practice only`;
    texts.push(t);
    digests.push(await itemDigestOf(enc.encode(t)));
  }
  return { texts, digests };
}

async function stamp(): Promise<void> {
  if (existsSync(join(SAMPLED, "seal.json"))) throw new Error(`${SAMPLED} already holds a seal — the example is sealed once`);
  const size = 2000;
  const { digests } = await sampleItems(size, "translation");
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
  const tree = await itemTree(salt, digests);
  const alpha = { num: 1, den: 20 };
  const plan = planFor({ size, limit: 40, accept: 0, alpha });
  const ahead = Number(process.env.DRAW_AHEAD ?? "24");
  const tip = await fetchBitcoinTip({ fetch: fetchText });
  const seal: BatchSeal = {
    format: SEAL_FORMAT,
    root: tree.root,
    size,
    plan: { sample: plan.sample, accept: 0, alpha, limit: plan.limit },
    draw: { source: DRAW_SOURCE_BITCOIN, height: tip + ahead },
  };
  const digest = await sealDigestOf(seal);
  const stamped = await stampOpenTimestamps(digest, { fetch: fetchBytes });
  mkdirSync(SAMPLED, { recursive: true });
  const items: BatchItemsFile = { format: BATCH_ITEMS_FORMAT, salt, digests };
  writeFileSync(join(SAMPLED, "items.json"), json(items));
  writeFileSync(join(SAMPLED, "seal.json"), json(seal));
  writeFileSync(join(SAMPLED, "stamp.ots.b64"), `${bytesToBase64(stamped.ots)}\n`);
  writeFileSync(
    join(SAMPLED, "pending.json"),
    json({
      note: "The seal is stamped and waiting: run `bun scripts/batch-example.ts finish` once the draw block is mined and the stamp has reached a block below it.",
      sealDigest: digest,
      tipWhenSealed: tip,
      drawHeight: seal.draw!.height,
      calendars: stamped.accepted,
      sealedAtUtc: new Date().toISOString(),
    }),
  );
  console.log(`sealed ${size} SAMPLE items: root ${tree.root.slice(0, 16)}…, plan ${plan.sample} drawn, accept 0, limit ${plan.limit} at 1 in 20`);
  console.log(`seal digest ${digest}; stamped at ${stamped.accepted.length} calendars; the draw block is ${seal.draw!.height} (tip ${tip} + ${ahead})`);
}

/** Once the draw block is mined: upgrade the stamp, fetch the headers, draw, have the SAMPLE approver answer, sign. */
async function finish(): Promise<void> {
  if (existsSync(join(SAMPLED, "record.dsse.json"))) throw new Error(`${SAMPLED} already holds its record — the example is finished once`);
  const seal = JSON.parse(readFileSync(join(SAMPLED, "seal.json"), "utf8")) as BatchSeal;
  const sealDigest = await sealDigestOf(seal);
  const drawHeight = seal.draw!.height;
  const up = await upgradeOpenTimestamps(base64ToBytes(readFileSync(join(SAMPLED, "stamp.ots.b64"), "utf8").trim()), { fetch: fetchBytes });
  for (const n of up.notes) console.log(`  calendar: ${n}`);
  const stamp = bytesToBase64(up.ots);
  if (up.changed) writeFileSync(join(SAMPLED, "stamp.ots.b64"), `${stamp}\n`);
  const heights = [...new Set(otsLeaves((await parseOts(up.ots)).timestamp).flatMap((l) => (l.attestation.kind === "bitcoin" ? [l.attestation.height] : [])))].sort((a, b) => a - b);
  if (heights.length === 0) {
    console.log(`the stamp is not in a Bitcoin block yet; run finish again later (the draw block is ${drawHeight})`);
    process.exit(3);
  }
  const below = heights.filter((h) => h < drawHeight);
  if (below.length === 0) throw new Error(`the stamp reached block ${heights[0]}, not below the draw block ${drawHeight}: this seal cannot draw — seal a new batch`);
  const tip = await fetchBitcoinTip({ fetch: fetchText });
  if (tip < drawHeight) {
    console.log(`the stamp reached block ${below[0]}; the draw block ${drawHeight} is not mined yet (tip ${tip}); run finish again later`);
    process.exit(3);
  }
  // The draw block's first transaction and its path name its height (BIP34; PY-5r): a header carries none.
  const [drawHeader] = await fetchBitcoinHeaders(drawHeight, drawHeight, { fetch: fetchText });
  const coinbase = await fetchDrawCoinbase((await checkBitcoinHeader(drawHeader!)).hashHex, { fetch: fetchText });
  // The stamp may reach several blocks; any one below the draw block will do, and none changes the draw.
  let blocks: string[] | null = null;
  let drawBlockHash: string | null = null;
  for (const h of below) {
    const headers = await fetchBitcoinHeaders(h, drawHeight, { fetch: fetchText });
    const check = await checkDrawBlocks({ stamp, sealDigest, blocks: headers, coinbase, drawHeight });
    if (check.ok) {
      blocks = headers;
      drawBlockHash = check.drawBlockHash;
      break;
    }
    console.log(`  from block ${h}: ${check.problems.join("; ")}`);
  }
  if (blocks === null || drawBlockHash === null) throw new Error("no block the stamp reached gives headers that stand");
  const drawn = await drawPositions(await drawSeed(sealDigest, drawBlockHash), seal.size, seal.plan.sample);
  // The SAMPLE approver checks the drawn items and finds all of them meet the agreed words.
  const found: number[] = [];
  const batch: Batch = { seal, stamp, blocks, coinbase, found, bound: boundOf({ size: seal.size, sample: seal.plan.sample, found: found.length, alpha: seal.plan.alpha }) };
  const asker = await party();
  const approver = await party();
  const body = receipt(asker, approver, batch, sealDigest, "SAMPLE batch 14: 2,000 product descriptions translated into Urdu", new Date());
  const record = await recordOf(body, asker, approver);
  const r = await verifyAttestationRecord(record);
  if (!r.ok) throw new Error(`the record does not check: ${r.problems.map((p) => `${p.code} ${p.message}`).join("; ")}`);
  const words = batchWords(body);
  writeFileSync(join(SAMPLED, "body.json"), json(body));
  writeFileSync(join(SAMPLED, "record.dsse.json"), json(record));
  writeFileSync(
    join(SAMPLED, "context.json"),
    json({ note: NOTE, sealDigest, drawHeight, drawBlockHash, stampHeight: drawHeight - (blocks.length - 1), drawn, found, words: [...words.lines, ...words.doesNotProve] }),
  );
  rmSync(join(SAMPLED, "pending.json"), { force: true });
  console.log(`finished: drew ${drawn.length} of ${seal.size} with block ${drawHeight} (${drawBlockHash}); record ${r.contentId}`);
}

/** The census: 40 SAMPLE items, every one checked — no draw, no stamp, offline. */
async function census(): Promise<void> {
  if (existsSync(CENSUS)) throw new Error(`${CENSUS} exists — the example is generated once`);
  const size = 40;
  const { digests } = await sampleItems(size, "milestone");
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
  const tree = await itemTree(salt, digests);
  const alpha = { num: 1, den: 20 };
  const seal: BatchSeal = { format: SEAL_FORMAT, root: tree.root, size, plan: { sample: size, accept: 1, alpha, limit: limitOf({ size, sample: size, accept: 1, alpha }) } };
  const sealDigest = await sealDigestOf(seal);
  // The SAMPLE approver checks all 40 and finds one short, which the plan allows; the acceptance does not cover it.
  const found = [17];
  const batch: Batch = { seal, found, bound: boundOf({ size, sample: size, found: found.length, alpha }) };
  const asker = await party();
  const approver = await party();
  const body = receipt(asker, approver, batch, sealDigest, "SAMPLE: 40 labelled photographs for the catalogue, delivery 3", new Date("2026-11-26T09:00:00Z"));
  const record = await recordOf(body, asker, approver);
  const r = await verifyAttestationRecord(record);
  if (!r.ok) throw new Error(`the record does not check: ${r.problems.map((p) => `${p.code} ${p.message}`).join("; ")}`);
  const words = batchWords(body);
  mkdirSync(CENSUS, { recursive: true });
  writeFileSync(join(CENSUS, "items.json"), json({ format: BATCH_ITEMS_FORMAT, salt, digests } satisfies BatchItemsFile));
  writeFileSync(join(CENSUS, "body.json"), json(body));
  writeFileSync(join(CENSUS, "record.dsse.json"), json(record));
  writeFileSync(join(CENSUS, "context.json"), json({ note: NOTE, sealDigest, found, words: [...words.lines, ...words.doesNotProve] }));
  console.log(`census: ${size} items, one found short, bound ${batch.bound}; record ${r.contentId}`);
}

const step = process.argv[2];
if (step === "stamp") await stamp();
else if (step === "finish") await finish();
else if (step === "census") await census();
else {
  console.error("usage: bun scripts/batch-example.ts stamp | finish | census");
  process.exit(2);
}
