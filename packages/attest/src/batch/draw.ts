/**
 * The draw (PY-5; `specs/attestation/batch.md` §3) — which positions of a sealed batch a person checks,
 * fixed by a seed neither side can choose.
 *
 * **The seed** is `SHA-256("kash-batch-draw-v1\n" ‖ seal digest ‖ the draw block's hash)`: 32 bytes of the
 * seal's digest and 32 bytes of the hash of the Bitcoin block the seal named, as Bitcoin displays it (the
 * double SHA-256 of the header, byte-reversed). The block is mined after the seal was stamped, so nobody knew
 * the seed when the batch was fixed (`./beacon`).
 *
 * **The stream** is `SHA-256(seed ‖ n)` for n = 0, 1, 2, … as four big-endian bytes, each 32-byte block read
 * as four big-endian 64-bit words, in order.
 *
 * **A number below m** takes the next word `w`; when `w` is below the largest multiple of `m` that fits under
 * 2^64 it gives `w mod m`, and otherwise it takes the next word — so every number below `m` is equally likely.
 *
 * **The positions** come from a partial Fisher–Yates shuffle of 0 … size−1: for i = 0, 1, …, sample−1, pick
 * `j = i + (a number below size − i)` and swap positions i and j; the first `sample` entries are the draw,
 * returned in ascending order. Written so that a stranger can reimplement it; `batch-draw@1` fixes it with
 * vectors.
 */

import { bytesToHex, hexToBytes } from "../chain";
import { AttestError } from "../errors";

export const DRAW_DOMAIN = "kash-batch-draw-v1\n";

const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource));
}

/** The seed of a batch's draw, as 64 hex characters. */
export async function drawSeed(sealDigestHex: string, blockHashHex: string): Promise<string> {
  if (!HEX64.test(sealDigestHex) || !HEX64.test(blockHashHex)) throw new AttestError("INVALID_INPUT", "a seal digest and a block hash are each 64 lowercase hex characters");
  const tag = enc.encode(DRAW_DOMAIN);
  const msg = new Uint8Array(tag.length + 64);
  msg.set(tag, 0);
  msg.set(hexToBytes(sealDigestHex), tag.length);
  msg.set(hexToBytes(blockHashHex), tag.length + 32);
  return bytesToHex(await sha256(msg));
}

/** The seed's stream of 64-bit words. */
export class DrawStream {
  private block: Uint8Array = new Uint8Array(0);
  private counter = 0;
  private offset = 32;

  constructor(private readonly seed: Uint8Array) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new AttestError("INVALID_INPUT", "a seed is 32 bytes");
  }

  async next(): Promise<bigint> {
    if (this.offset === 32) {
      if (this.counter > 0xffffffff) throw new AttestError("INVALID_INPUT", "the stream ran out of counters");
      const msg = new Uint8Array(36);
      msg.set(this.seed, 0);
      new DataView(msg.buffer).setUint32(32, this.counter, false);
      this.block = await sha256(msg);
      this.counter++;
      this.offset = 0;
    }
    let w = 0n;
    for (let i = 0; i < 8; i++) w = (w << 8n) | BigInt(this.block[this.offset + i]!);
    this.offset += 8;
    return w;
  }
}

const TWO_64 = 1n << 64n;

/** Anything that gives 64-bit words in order — the seed's stream, or a test's chosen words. */
export interface WordSource {
  next(): Promise<bigint>;
}

/** A whole number below `m` (1 ≤ m ≤ 2^53), every one equally likely. */
export async function uniformBelow(stream: WordSource, m: number): Promise<number> {
  if (!Number.isSafeInteger(m) || m < 1) throw new AttestError("INVALID_INPUT", "a range is a whole number of at least 1");
  const range = BigInt(m);
  const limit = TWO_64 - (TWO_64 % range);
  for (;;) {
    const w = await stream.next();
    if (w < limit) return Number(w % range);
  }
}

/** The `sample` distinct positions of `size` the seed draws, ascending. */
export async function drawPositions(seedHex: string, size: number, sample: number): Promise<number[]> {
  if (!HEX64.test(seedHex)) throw new AttestError("INVALID_INPUT", "a seed is 64 lowercase hex characters");
  if (!Number.isSafeInteger(size) || size < 1) throw new AttestError("INVALID_INPUT", "a batch holds at least one item");
  if (!Number.isSafeInteger(sample) || sample < 1 || sample > size) throw new AttestError("INVALID_INPUT", "a draw takes from 1 to size items");
  const stream = new DrawStream(hexToBytes(seedHex));
  const moved = new Map<number, number>();
  const at = (i: number): number => moved.get(i) ?? i;
  const out: number[] = [];
  for (let i = 0; i < sample; i++) {
    const j = i + (await uniformBelow(stream, size - i));
    const vi = at(i);
    const vj = at(j);
    moved.set(i, vj);
    moved.set(j, vi);
    out.push(vj);
  }
  return out.sort((a, b) => a - b);
}
