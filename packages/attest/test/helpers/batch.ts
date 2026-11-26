/**
 * PY-5's test helpers: a seeded generator for property tests (nothing installed), a synthetic Bitcoin chain mined
 * at low difficulty with an OpenTimestamps proof that reaches it, and a batch receipt signed by throwaway keys.
 *
 * The synthetic chain claims about 8 bits of work per header, so a checker run at the default floor refuses it —
 * tests that need it to stand pass their own floor, and the report says so.
 */

import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { bytesToHex, hexToBytes } from "../../src/chain";
import { base64ToBytes, bytesToBase64 } from "../../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../../src/dsse";
import { signBytes } from "../../src/signing";
import { serializeOts, type OtsFile } from "../../src/witness/ots";
import { ATTESTATION_DST, type AttestationBody } from "../../src/attestation";
import { DRAW_SOURCE_BITCOIN, SEAL_FORMAT, boundOf, drawPositions, drawSeed, itemTree, limitOf, sealDigestOf, type Alpha, type Batch, type BatchSeal, type DrawCoinbase } from "../../src/batch";

/** mulberry32: a small, fixed generator — the same cases every run. Returns a float in [0, 1). */
export function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const intIn = (rand: () => number, lo: number, hi: number): number => lo + Math.floor(rand() * (hi - lo + 1));

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource));
}
const sha256d = async (bytes: Uint8Array): Promise<Uint8Array> => sha256(await sha256(bytes));

/** Low difficulty: exponent 0x20, mantissa 0x00ffff — a target near 2^248, about 8 bits of work. */
export const SYNTHETIC_BITS = 0x2000ffff;
/** A floor the synthetic chain meets. */
export const TEST_FLOOR = 4;

/** Mine an 80-byte header over `prev` and `merkleRoot` (both internal byte order) at `bits`. */
export async function mineHeader(prev: Uint8Array, merkleRoot: Uint8Array, time: number, bits = SYNTHETIC_BITS): Promise<string> {
  const h = new Uint8Array(80);
  const v = new DataView(h.buffer);
  v.setUint32(0, 0x20000000, true);
  h.set(prev, 4);
  h.set(merkleRoot, 36);
  v.setUint32(68, time, true);
  v.setUint32(72, bits, true);
  const exp = bits >>> 24;
  const target = BigInt(bits & 0x7fffff) << BigInt(8 * (exp - 3));
  for (let nonce = 0; ; nonce++) {
    v.setUint32(76, nonce, true);
    const hash = await sha256d(h);
    if (BigInt("0x" + bytesToHex(hash.slice().reverse())) <= target) return bytesToHex(h);
  }
}

/**
 * BIP34's push of a height, written here apart from the code under test: three bytes, little-endian, for the heights
 * the tests use (from 32,768 to 8,388,607, where the top byte never reaches 0x80).
 */
export function testHeightPush(height: number): number[] {
  if (height < 0x8000 || height > 0x7fffff) throw new Error("the test encoder writes three-byte heights only");
  return [3, height & 0xff, (height >>> 8) & 0xff, (height >>> 16) & 0xff];
}

/**
 * A block's first transaction naming `height`: one input that spends nothing, its script the height's push and a
 * SAMPLE tag; one output; in witness form (as blocks since SegWit carry it) unless `witness` is false. Its id is over
 * the bytes without the witness.
 */
export async function coinbaseOf(height: number, opts: { readonly witness?: boolean; readonly push?: readonly number[]; readonly tag?: string } = {}): Promise<{ hex: string; txid: Uint8Array }> {
  const script = [...(opts.push ?? testHeightPush(height)), ...new TextEncoder().encode(opts.tag ?? "SAMPLE pool")];
  const input = [1, ...new Array<number>(32).fill(0), 0xff, 0xff, 0xff, 0xff, script.length, ...script, 0xff, 0xff, 0xff, 0xff];
  const output = [1, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 1, 0x6a];
  const version = [2, 0, 0, 0];
  const lock = [0, 0, 0, 0];
  const stripped = Uint8Array.from([...version, ...input, ...output, ...lock]);
  const full = opts.witness === false ? stripped : Uint8Array.from([...version, 0x00, 0x01, ...input, ...output, 1, 32, ...new Array<number>(32).fill(0), ...lock]);
  return { hex: bytesToHex(full), txid: await sha256d(stripped) };
}

/** A block of three transactions — the coinbase and two others — with its Merkle root and the coinbase's path. */
export async function blockOf(coinbase: { hex: string; txid: Uint8Array }): Promise<{ root: Uint8Array; coinbase: DrawCoinbase }> {
  const t1 = await sha256(Uint8Array.of(0xa1));
  const t2 = await sha256(Uint8Array.of(0xa2));
  const join = (a: Uint8Array, b: Uint8Array): Uint8Array => Uint8Array.from([...a, ...b]);
  const left = await sha256d(join(coinbase.txid, t1));
  const right = await sha256d(join(t2, t2)); // a level of odd length pairs its last node with itself
  return { root: await sha256d(join(left, right)), coinbase: { tx: coinbase.hex, path: [bytesToHex(t1), bytesToHex(right)] } };
}

export interface SyntheticDraw {
  readonly stamp: string;
  readonly blocks: readonly string[];
  /** The draw block's first transaction and path, naming its height. */
  readonly coinbase: DrawCoinbase;
  /** Each block's, by position; null for the stamp's block, whose Merkle root is the stamp's message. */
  readonly coinbases: readonly (DrawCoinbase | null)[];
  readonly stampHeight: number;
  readonly drawHeight: number;
}

/**
 * An OpenTimestamps proof over `digestHex` — the digest, a 16-byte nonce appended, SHA-256 — with a Bitcoin
 * attestation at `stampHeight` over that message, and headers from that block to `stampHeight + gap`, the first
 * carrying the message as its Merkle root, each later one a block whose first transaction names its own height.
 * Two calls with the same stamp height and different gaps make the same chain, one longer than the other.
 */
export async function syntheticDraw(digestHex: string, opts: { readonly stampHeight?: number; readonly gap?: number; readonly attestAt?: number; readonly bits?: number } = {}): Promise<SyntheticDraw> {
  const stampHeight = opts.stampHeight ?? 900_000;
  const gap = opts.gap ?? 3;
  const digest = hexToBytes(digestHex);
  const nonce = new Uint8Array(16).fill(7);
  const appended = new Uint8Array(48);
  appended.set(digest, 0);
  appended.set(nonce, 32);
  const msg = await sha256(appended);
  const file: OtsFile = {
    hashOp: "sha256",
    digest,
    timestamp: {
      msg: digest,
      attestations: [],
      ops: [{ op: { op: "append", arg: nonce }, next: { msg: appended, attestations: [], ops: [{ op: { op: "sha256" }, next: { msg, attestations: [{ kind: "bitcoin", height: opts.attestAt ?? stampHeight }], ops: [] } }] } }],
    },
  };
  const blocks: string[] = [];
  const coinbases: (DrawCoinbase | null)[] = [];
  let prev: Uint8Array = new Uint8Array(32).fill(1);
  for (let k = 0; k <= gap; k++) {
    let root = msg;
    if (k === 0) coinbases.push(null);
    else {
      const b = await blockOf(await coinbaseOf(stampHeight + k));
      root = b.root;
      coinbases.push(b.coinbase);
    }
    const header = await mineHeader(prev, root, 1_790_000_000 + 600 * k, opts.bits);
    blocks.push(header);
    prev = await sha256d(hexToBytes(header));
  }
  return { stamp: bytesToBase64(serializeOts(file)), blocks, coinbase: coinbases[gap]!, coinbases, stampHeight, drawHeight: stampHeight + gap };
}

export type Party = KashKeyPair & { readonly did: string; readonly keyid: string };
export async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

/** The record of truth in the spec's order: the counterparty signs the final bytes first, then the issuer. */
export async function signRecord(body: AttestationBody, issuer: Party, counterparty?: Party): Promise<DsseEnvelope> {
  const first = counterparty ?? issuer;
  let env = await signEnvelope(body, ATTESTATION_DST, first, { canonical: true });
  if (counterparty !== undefined) {
    const sig = await signBytes(issuer, pae(env.payloadType, base64ToBytes(env.payload)), "der");
    env = { ...env, signatures: [...env.signatures, { keyid: issuer.keyid, sig: bytesToBase64(sig) }] };
  }
  return env;
}

export interface SampledBatch {
  readonly salt: string;
  readonly digests: readonly string[];
  readonly seal: BatchSeal;
  readonly sealDigest: string;
  readonly draw: SyntheticDraw;
  readonly drawn: readonly number[];
}

/** A sealed, stamped and drawn batch of `size` items, on the synthetic chain. */
export async function sampledBatch(opts: { readonly size?: number; readonly sample?: number; readonly accept?: number; readonly alpha?: Alpha; readonly gap?: number; readonly previous?: string } = {}): Promise<SampledBatch> {
  const size = opts.size ?? 200;
  const sample = opts.sample ?? 30;
  const accept = opts.accept ?? 0;
  const alpha = opts.alpha ?? { num: 1, den: 20 };
  const salt = "5a".repeat(32);
  const digests: string[] = [];
  for (let i = 0; i < size; i++) digests.push(bytesToHex(await sha256(new TextEncoder().encode(`SAMPLE item ${i}`))));
  const tree = await itemTree(salt, digests);
  const stampHeight = 900_000;
  const gap = opts.gap ?? 3;
  const seal: BatchSeal = {
    format: SEAL_FORMAT,
    root: tree.root,
    size,
    plan: { sample, accept, alpha, limit: limitOf({ size, sample, accept, alpha }) },
    draw: { source: DRAW_SOURCE_BITCOIN, height: stampHeight + gap },
    ...(opts.previous !== undefined ? { previous: opts.previous } : {}),
  };
  const sealDigest = await sealDigestOf(seal);
  const draw = await syntheticDraw(sealDigest, { stampHeight, gap });
  const last = draw.blocks[draw.blocks.length - 1]!;
  const blockHash = bytesToHex((await sha256d(hexToBytes(last))).reverse());
  const drawn = await drawPositions(await drawSeed(sealDigest, blockHash), size, sample);
  return { salt, digests, seal, sealDigest, draw, drawn };
}

/** The batch object for a sealed batch, with `found` drawn positions found short and the exact bound. */
export function batchOf(b: SampledBatch, found: readonly number[]): Batch {
  const plan = b.seal.plan;
  return {
    seal: b.seal,
    stamp: b.draw.stamp,
    blocks: b.draw.blocks,
    coinbase: b.draw.coinbase,
    found,
    bound: boundOf({ size: b.seal.size, sample: plan.sample, found: found.length, alpha: plan.alpha }),
  };
}

/** A batch receipt's body: the asker's book as issuer, the approver's key as counterparty, grade 1, practice. */
export function receiptOf(issuer: Party, counterparty: Party, batch: Batch, sealDigest: string, over: Partial<AttestationBody> = {}): AttestationBody {
  return {
    issuer: issuer.did,
    kind: "receipt",
    outcome: "accepted",
    reference: { kind: "artefact", sha256: sealDigest },
    statement: "SAMPLE batch 14: product descriptions translated into Urdu",
    profile: "client-signoff/1",
    counterparty: counterparty.did,
    grade: 1,
    claimedAt: "2026-11-26T12:00:00Z",
    expiresAt: "2027-11-26T12:00:00Z",
    practice: true,
    batch,
    ...over,
  };
}
