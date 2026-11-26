/**
 * The Merkle tree of RFC 6962 §2.1 (RFC 9162 §2.1), over SHA-256: a leaf is
 * SHA-256(0x00 ‖ data), an inner node SHA-256(0x01 ‖ left ‖ right).
 *
 * A batch anchored on it lets each member prove it is in the batch with its own
 * audit path — at most ⌈log₂ n⌉ sibling hashes — and nothing of any other
 * member. `computeAnchorMerkleRoot` beside it is a flat digest: checking one
 * tip against it needs every tip in the batch.
 *
 * The tree is built bottom-up, an unpaired last node promoted unchanged, which
 * gives exactly RFC 6962's root and audit paths in O(n) hashes. Web Crypto only,
 * so a browser verifies as Node and Bun do.
 */

import { AttestError } from "../errors";

/** No real path is longer: a tree of 2^53 leaves has 53 levels. Anything longer is refused unread. */
const MAX_PATH = 64;
/** How many hashes of one level are in flight at once. */
const HASH_CHUNK = 4096;

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  let length = 0;
  for (const p of parts) length += p.length;
  const buf = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf as unknown as BufferSource));
}

const LEAF = Uint8Array.of(0x00);
const NODE = Uint8Array.of(0x01);

/** RFC 6962 §2.1: the hash of one leaf, SHA-256(0x00 ‖ data). */
export function rfc6962LeafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(LEAF, data);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(NODE, left, right);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export interface Rfc6962Tree {
  /** How many leaves. */
  readonly size: number;
  /** The Merkle Tree Hash of the leaves, in their order. */
  readonly root: Uint8Array;
  /** One leaf's audit path, nearest sibling first (RFC 6962 §2.1.1). */
  path(index: number): Uint8Array[];
}

/** Build the tree over these leaf hashes, in this order. A batch has at least one leaf. */
export async function rfc6962Tree(leafHashes: readonly Uint8Array[]): Promise<Rfc6962Tree> {
  if (leafHashes.length === 0) throw new AttestError("INVALID_INPUT", "an RFC 6962 batch has at least one leaf");
  for (const h of leafHashes) {
    if (!(h instanceof Uint8Array) || h.length !== 32) throw new AttestError("INVALID_INPUT", "a leaf hash is 32 bytes");
  }
  const levels: Uint8Array[][] = [[...leafHashes]];
  for (let below = levels[0]!; below.length > 1; below = levels[levels.length - 1]!) {
    // Each level's pairs are hashed concurrently, in chunks: Web Crypto's per-call cost dominates one at a time
    // (PY-5 measured about five times faster). The order of the results, and so the tree, is unchanged.
    const above: Uint8Array[] = new Array(Math.ceil(below.length / 2));
    for (let start = 0; start < above.length; start += HASH_CHUNK) {
      const end = Math.min(above.length, start + HASH_CHUNK);
      const chunk: Promise<Uint8Array>[] = [];
      for (let j = start; j < end; j++) {
        const i = 2 * j;
        chunk.push(i + 1 < below.length ? nodeHash(below[i]!, below[i + 1]!) : Promise.resolve(below[i]!));
      }
      const done = await Promise.all(chunk);
      for (let j = start; j < end; j++) above[j] = done[j - start]!;
    }
    levels.push(above);
  }
  const size = leafHashes.length;
  return {
    size,
    root: levels[levels.length - 1]![0]!,
    path(index: number): Uint8Array[] {
      if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
        throw new AttestError("INVALID_INPUT", `no leaf ${String(index)} in a tree of ${size}`);
      }
      const out: Uint8Array[] = [];
      let i = index;
      for (let l = 0; l < levels.length - 1; l++) {
        const sibling = i % 2 === 0 ? i + 1 : i - 1;
        if (sibling < levels[l]!.length) out.push(levels[l]![sibling]!);
        i = Math.floor(i / 2);
      }
      return out;
    },
  };
}

/**
 * RFC 9162 §2.1.3.2: does this leaf hash sit at `index` of a tree of `size`
 * leaves whose root is `root`, by this audit path? False for anything that
 * does not prove it, malformed input included. Never throws.
 */
export async function rfc6962VerifyInclusion(
  leafHash: Uint8Array,
  index: number,
  size: number,
  path: readonly Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  if (!(leafHash instanceof Uint8Array) || leafHash.length !== 32) return false;
  if (!(root instanceof Uint8Array) || root.length !== 32) return false;
  if (!Array.isArray(path) || path.length > MAX_PATH) return false;
  // Halving, not `>>`: the bit operators are 32-bit, and a size may be any safe integer.
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  for (const p of path) {
    if (!(p instanceof Uint8Array) || p.length !== 32) return false;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && sameBytes(r, root);
}

/* ── consistency between two tree heads (KS-Q4, the trust log) ─────────── */

/** The largest power of two strictly below `n` (RFC 9162 §2.1: `k`). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n: number): boolean {
  if (!Number.isSafeInteger(n) || n < 1) return false;
  let k = 1;
  while (k < n) k *= 2;
  return k === n;
}

/**
 * RFC 9162 §2.1.4.1: the consistency proof between the tree over the first
 * `first` leaf hashes and the tree over the first `second` of them,
 * `PROOF(m, D_n) = SUBPROOF(m, D_n, true)`. Empty when the two heads are one.
 * The leaves are leaf HASHES (`rfc6962LeafHash`), in the log's order.
 */
export async function rfc6962ConsistencyProof(
  leafHashes: readonly Uint8Array[],
  first: number,
  second: number,
): Promise<Uint8Array[]> {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || first > second || second > leafHashes.length) {
    throw new AttestError("INVALID_INPUT", `a consistency proof needs 1 <= first (${String(first)}) <= second (${String(second)}) <= leaves (${leafHashes.length})`);
  }
  for (const h of leafHashes) {
    if (!(h instanceof Uint8Array) || h.length !== 32) throw new AttestError("INVALID_INPUT", "a leaf hash is 32 bytes");
  }
  // MTH over the half-open range [lo, hi), from the RFC's recursive definition; memoised by range.
  const memo = new Map<string, Uint8Array>();
  const mth = async (lo: number, hi: number): Promise<Uint8Array> => {
    if (hi - lo === 1) return leafHashes[lo]!;
    const key = `${lo}:${hi}`;
    const seen = memo.get(key);
    if (seen !== undefined) return seen;
    const k = split(hi - lo);
    const h = await nodeHash(await mth(lo, lo + k), await mth(lo + k, hi));
    memo.set(key, h);
    return h;
  };
  // SUBPROOF(m, D[lo:hi], b), with m counted from lo.
  const subproof = async (m: number, lo: number, hi: number, b: boolean): Promise<Uint8Array[]> => {
    const n = hi - lo;
    if (m === n) return b ? [] : [await mth(lo, hi)];
    const k = split(n);
    if (m <= k) return [...(await subproof(m, lo, lo + k, b)), await mth(lo + k, hi)];
    return [...(await subproof(m - k, lo + k, hi, false)), await mth(lo, lo + k)];
  };
  return subproof(first, 0, second, true);
}

/**
 * RFC 9162 §2.1.4.2: are these two tree heads consistent — is the tree of
 * `second` leaves an append-only extension of the tree of `first` — by this
 * proof? False for anything that does not prove it, malformed input included.
 * Two equal heads are consistent by an empty proof. Never throws.
 */
export async function rfc6962VerifyConsistency(
  first: number,
  second: number,
  path: readonly Uint8Array[],
  firstHash: Uint8Array,
  secondHash: Uint8Array,
): Promise<boolean> {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || first > second) return false;
  if (!(firstHash instanceof Uint8Array) || firstHash.length !== 32) return false;
  if (!(secondHash instanceof Uint8Array) || secondHash.length !== 32) return false;
  if (!Array.isArray(path) || path.length > MAX_PATH) return false;
  for (const p of path) if (!(p instanceof Uint8Array) || p.length !== 32) return false;
  if (first === second) return path.length === 0 && sameBytes(firstHash, secondHash);
  if (path.length === 0) return false;
  const steps = isPowerOfTwo(first) ? [firstHash, ...path] : [...path];
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = steps[0]!;
  let sr = steps[0]!;
  for (let i = 1; i < steps.length; i++) {
    const c = steps[i]!;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && sameBytes(fr, firstHash) && sameBytes(sr, secondHash);
}
