/**
 * Binary Merkle tree primitives — SHA-256 leaf hashing, positional sibling
 * concatenation, odd-leaf duplication. Pure deterministic logic, no I/O.
 *
 * Leaves are sorted by an external key (alphabetical field name) BEFORE
 * being passed to `buildMerkleTree` so two builders working from the same
 * body always reproduce the same root.
 *
 * Algorithm choices and why:
 *   • SHA-256 (not Poseidon) — universal, hardware-accelerated, matches the
 *     hash family of the Identity Bible. Selective disclosure does not need
 *     a SNARK-friendly hash.
 *   • Positional concat (left || right) — verifier needs the sibling AND
 *     the position to reconstruct; we encode both in the proof.
 *   • Odd-leaf duplication — the last leaf is hashed against itself when
 *     the level has an odd cardinality. Matches Bitcoin/AT Protocol practice.
 *
 * **F5 — Length-prefixed leaf encoding (v2).** Leaves are encoded with explicit
 * `u32be` length prefixes on the data and salt segments so that two distinct
 * (data, salt) pairs cannot ever produce the same byte string under
 * concatenation. The string DST "kash-leaf-v2\n" is hashed in too, making
 * leaves from this package non-collidable with leaves from any other system
 * that happens to also SHA-256 a similar layout. Internal nodes get their
 * own "kash-merkle-internal-v2\n" DST for the same reason.
 *
 * **Wire-format version: 2.** v1 used `0x00 || JCS || salt` without length
 * prefixes; commitments under v1 are NOT interoperable with v2. Mixing
 * versions in the same tree is a build-time error.
 */

import { canonicalize } from "@kashscript/identity-core";
import { KashZkpError } from "./errors";

/** Leaf encoding format version. Bumped on any change to the byte-layout of {@link hashLeaf}. */
export const LEAF_ENCODING_VERSION = 2 as const;

/** DST string prepended (as UTF-8 bytes) before the length-prefixed leaf payload. */
const LEAF_DST     = "kash-leaf-v2\n";
/** DST string prepended (as UTF-8 bytes) before internal-node concatenation. */
const INTERNAL_DST = "kash-merkle-internal-v2\n";

const TEXT_ENCODER    = new TextEncoder();
const LEAF_DST_BYTES     = TEXT_ENCODER.encode(LEAF_DST);
const INTERNAL_DST_BYTES = TEXT_ENCODER.encode(INTERNAL_DST);

/** Compact inclusion proof for one leaf. */
export interface MerkleInclusionProof {
  /** Sibling hashes, level by level from leaf to root. */
  readonly siblings: readonly Uint8Array[];
  /** For each sibling, `0` if the sibling is the LEFT child, `1` if RIGHT. */
  readonly positions: readonly (0 | 1)[];
}

/* ── hashing primitives ──────────────────────────────────────────── */

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const out = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(out);
}

/**
 * Hash a single (key, value, salt) triple into a leaf commitment (v2).
 *
 *   leaf = SHA-256(
 *     "kash-leaf-v2\n"     ||      // DST
 *     u32be(len(JCS_data)) ||  JCS_data    ||
 *     u32be(len(salt))     ||  salt
 *   )
 *
 * The per-field salt prevents brute-force attacks on low-entropy fields
 * (e.g., a boolean leaf would otherwise have only two possible pre-images).
 *
 * F5 — the explicit `u32be` length prefixes make the data/salt boundary
 * unambiguous: there is no pair of distinct inputs `(d1, s1) ≠ (d2, s2)`
 * whose preimage byte string collides, even if `d1 || s1 == d2 || s2`
 * (which is possible under the v1 unprefixed encoding). Both segments are
 * capped at 2³² − 1 bytes; we additionally reject `len(salt) === 0` per the
 * existing salt-non-empty rule.
 */
export async function hashLeaf(
  key: string,
  value: unknown,
  salt: Uint8Array,
): Promise<Uint8Array> {
  if (typeof key !== "string" || key.length === 0) {
    throw new KashZkpError("hashLeaf: key must be a non-empty string.", "INVALID_INPUT");
  }
  if (!(salt instanceof Uint8Array) || salt.length === 0) {
    throw new KashZkpError("hashLeaf: salt must be a non-empty Uint8Array.", "INVALID_INPUT");
  }
  const canonicalBytes = TEXT_ENCODER.encode(canonicalize({ [key]: value }));
  if (canonicalBytes.length > 0xFFFFFFFF) {
    throw new KashZkpError("hashLeaf: canonical data exceeds 2^32-1 bytes.", "INVALID_INPUT");
  }
  if (salt.length > 0xFFFFFFFF) {
    throw new KashZkpError("hashLeaf: salt exceeds 2^32-1 bytes.", "INVALID_INPUT");
  }
  const buf = concat(
    LEAF_DST_BYTES,
    u32be(canonicalBytes.length), canonicalBytes,
    u32be(salt.length),           salt,
  );
  return sha256(buf);
}

/**
 * Hash a (left, right) internal pair (v2).
 *
 *   internal = SHA-256( "kash-merkle-internal-v2\n" || left || right )
 *
 * Length prefixes are omitted here — both operands are fixed 32-byte SHA-256
 * outputs, so there is no boundary ambiguity. The DST string suffices to
 * keep internal-node hashes non-collidable with any other use of SHA-256.
 */
export async function hashInternal(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  if (left.length !== 32 || right.length !== 32) {
    throw new KashZkpError("hashInternal: operands must be 32-byte SHA-256 outputs.", "INVALID_INPUT");
  }
  return sha256(concat(INTERNAL_DST_BYTES, left, right));
}

/* ── tree construction ──────────────────────────────────────────── */

/**
 * Build the Merkle root from an ordered leaf list. Returns the root only;
 * use `buildMerkleTreeWithPaths` when you also need inclusion proofs.
 */
export async function buildMerkleRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) {
    throw new KashZkpError("buildMerkleRoot: leaves array is empty.", "INVALID_INPUT");
  }
  let level: Uint8Array[] = [...leaves];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left  = level[i]!;
      const right = level[i + 1] ?? left; // duplicate odd
      next.push(await hashInternal(left, right));
    }
    level = next;
  }
  return level[0]!;
}

/**
 * Build the root AND produce per-leaf inclusion proofs in one pass.
 * Index by leaf position (0..n-1); the caller knows the position from
 * the sort-key order of the field names.
 */
export async function buildMerkleTreeWithPaths(
  leaves: readonly Uint8Array[],
): Promise<{ readonly root: Uint8Array; readonly proofs: readonly MerkleInclusionProof[] }> {
  if (leaves.length === 0) {
    throw new KashZkpError("buildMerkleTreeWithPaths: leaves array is empty.", "INVALID_INPUT");
  }

  // Cache every level so we can walk back down each leaf's path.
  const levels: Uint8Array[][] = [[...leaves]];
  while (levels[levels.length - 1]!.length > 1) {
    const current = levels[levels.length - 1]!;
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left  = current[i]!;
      const right = current[i + 1] ?? left;
      next.push(await hashInternal(left, right));
    }
    levels.push(next);
  }

  const proofs: MerkleInclusionProof[] = [];
  for (let leafIdx = 0; leafIdx < leaves.length; leafIdx++) {
    const siblings:  Uint8Array[] = [];
    const positions: (0 | 1)[]    = [];
    let idx = leafIdx;
    for (let depth = 0; depth < levels.length - 1; depth++) {
      const level = levels[depth]!;
      const isLeft = idx % 2 === 0;
      const siblingIdx = isLeft ? idx + 1 : idx - 1;
      const sibling = level[siblingIdx] ?? level[idx]!; // odd-duplication
      siblings.push(sibling);
      positions.push(isLeft ? 1 : 0); // sibling is on the RIGHT if we are LEFT
      idx = Math.floor(idx / 2);
    }
    proofs.push({ siblings, positions });
  }

  return { root: levels[levels.length - 1]![0]!, proofs };
}

/** Reconstruct a Merkle root from a leaf and its inclusion proof. */
export async function recoverRoot(
  leaf: Uint8Array,
  proof: MerkleInclusionProof,
): Promise<Uint8Array> {
  if (proof.siblings.length !== proof.positions.length) {
    throw new KashZkpError(
      `Inclusion proof is unbalanced (${proof.siblings.length} siblings vs ${proof.positions.length} positions).`,
      "INVALID_INPUT",
    );
  }
  let acc = leaf;
  for (let i = 0; i < proof.siblings.length; i++) {
    const sib = proof.siblings[i]!;
    const pos = proof.positions[i]!;
    acc = pos === 1 ? await hashInternal(acc, sib)   // we were left, sibling right
                    : await hashInternal(sib, acc);  // we were right, sibling left
  }
  return acc;
}

/** Constant-time byte-equality. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/* ── internal ────────────────────────────────────────────────────── */

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

/** 4-byte big-endian unsigned 32-bit length prefix. */
function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xFFFFFFFF) {
    throw new KashZkpError(`u32be: ${n} is not a valid uint32.`, "INVALID_INPUT");
  }
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xFF;
  out[1] = (n >>> 16) & 0xFF;
  out[2] = (n >>>  8) & 0xFF;
  out[3] =  n         & 0xFF;
  return out;
}
