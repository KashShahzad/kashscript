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
    const above: Uint8Array[] = [];
    for (let i = 0; i < below.length; i += 2) {
      above.push(i + 1 < below.length ? await nodeHash(below[i]!, below[i + 1]!) : below[i]!);
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
