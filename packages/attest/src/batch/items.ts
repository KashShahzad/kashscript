/**
 * One root over many items — `kash-items/1` (PY-5; `specs/attestation/batch.md` §1). A sampled batch fixes
 * its items with it before the draw; a page of many answers (CLIENT-WALKTHROUGH finding 7) fixes the records a
 * person is about to sign with it, so one passkey step covers them all.
 *
 * - **The item** is named by the SHA-256 of its bytes, as the asker delivers them (`itemDigestOf`).
 * - **The leaf** is RFC 6962's, `SHA-256(0x00 ‖ "kash-batch-item-v1\n" ‖ size ‖ salt ‖ item digest)`: the size as
 *   8 bytes, big-endian, so a tree of one size can never pass as one of another (the session anchor's rule); a
 *   32-byte salt the asker keeps with the batch and never puts in a record, so a root cannot be used to test a
 *   guess about an item.
 * - **The order is fixed by the leaves themselves**, sorted ascending, and two equal items are refused: the asker
 *   cannot move an item into or out of the positions a draw will pick.
 * - **The tree** is RFC 6962's (`../witness/rfc6962`); a position's path is its audit path, nearest sibling first.
 */

import { bytesToHex, hexToBytes, sha256Hex } from "../chain";
import { AttestError } from "../errors";
import { rfc6962LeafHash, rfc6962Tree, rfc6962VerifyInclusion } from "../witness/rfc6962";
import { BATCH_MAX_SIZE } from "./chance";

export const ITEMS_TREE = "kash-items/1";
/** Registered in attest's DST registry, family `merkle-leaf`. */
export const ITEM_LEAF_TAG = "kash-batch-item-v1\n";
/** The file that carries a batch's items to whoever checks them: the salt and every item's digest. */
export const BATCH_ITEMS_FORMAT = "kashscript-batch-items/1";

export interface BatchItemsFile {
  readonly format: typeof BATCH_ITEMS_FORMAT;
  /** 32 bytes, as 64 hex characters — never in a record. */
  readonly salt: string;
  /** Every item's SHA-256, in any order. */
  readonly digests: readonly string[];
}

const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

/** An item's name: the SHA-256 of its bytes, as 64 hex characters. */
export const itemDigestOf = (bytes: Uint8Array): Promise<string> => sha256Hex(bytes);

/** A 32-byte salt, fresh from the platform's random source. */
export function newItemSalt(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function checkSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 1 || size > BATCH_MAX_SIZE) throw new AttestError("INVALID_INPUT", `a batch holds from 1 to ${BATCH_MAX_SIZE} items`);
}

const TAG = enc.encode(ITEM_LEAF_TAG);

/** `tag ‖ size ‖ salt` — the part of a leaf every item in one batch shares. */
function leafPrefix(size: number, saltHex: string): Uint8Array {
  checkSize(size);
  if (!HEX64.test(saltHex)) throw new AttestError("INVALID_INPUT", "a salt is 64 lowercase hex characters");
  const prefix = new Uint8Array(TAG.length + 40);
  prefix.set(TAG, 0);
  new DataView(prefix.buffer).setBigUint64(TAG.length, BigInt(size), false);
  prefix.set(hexToBytes(saltHex), TAG.length + 8);
  return prefix;
}

function leafOf(prefix: Uint8Array, digestHex: string): Promise<Uint8Array> {
  const data = new Uint8Array(prefix.length + 32);
  data.set(prefix, 0);
  data.set(hexToBytes(digestHex), prefix.length);
  return rfc6962LeafHash(data);
}

/** The leaf of one item in a batch of `size`. */
export async function itemLeafHash(size: number, saltHex: string, digestHex: string): Promise<Uint8Array> {
  const prefix = leafPrefix(size, saltHex);
  if (!HEX64.test(digestHex)) throw new AttestError("INVALID_INPUT", "an item digest is 64 lowercase hex characters");
  return leafOf(prefix, digestHex);
}

export interface ItemTree {
  readonly size: number;
  readonly salt: string;
  /** The root, as 64 hex characters. */
  readonly root: string;
  /** The leaves in their fixed order, as hex. */
  readonly leaves: readonly string[];
  /** The position an item holds, or -1 when it is not in the batch. */
  positionOf(digestHex: string): number;
  /** The item digest at a position. */
  digestAt(position: number): string;
  /** A position's audit path, nearest sibling first, as hex. */
  path(position: number): string[];
}

/** The tree over these items. Refuses an empty batch, a malformed digest and two equal items. */
export async function itemTree(saltHex: string, digests: readonly string[]): Promise<ItemTree> {
  if (!Array.isArray(digests) || digests.length === 0) throw new AttestError("INVALID_INPUT", "a batch holds at least one item");
  const size = digests.length;
  checkSize(size);
  for (const d of digests) {
    if (typeof d !== "string" || !HEX64.test(d)) throw new AttestError("INVALID_INPUT", "an item digest is 64 lowercase hex characters");
  }
  // Hashed concurrently, in chunks — Web Crypto's per-call cost dominates one at a time.
  const prefix = leafPrefix(size, saltHex);
  const pairs: { leaf: string; digest: string }[] = [];
  for (let start = 0; start < size; start += 4096) {
    const chunk = digests.slice(start, start + 4096);
    const leaves = await Promise.all(chunk.map((d) => leafOf(prefix, d)));
    leaves.forEach((l, k) => pairs.push({ leaf: bytesToHex(l), digest: chunk[k]! }));
  }
  pairs.sort((a, b) => (a.leaf < b.leaf ? -1 : a.leaf > b.leaf ? 1 : 0));
  for (let i = 1; i < pairs.length; i++) {
    if (pairs[i]!.leaf === pairs[i - 1]!.leaf) throw new AttestError("INVALID_INPUT", "two items are the same bytes — give each its own id, so each is one item");
  }
  const tree = await rfc6962Tree(pairs.map((p) => hexToBytes(p.leaf)));
  const byDigest = new Map(pairs.map((p, i) => [p.digest, i] as const));
  return {
    size,
    salt: saltHex,
    root: bytesToHex(tree.root),
    leaves: pairs.map((p) => p.leaf),
    positionOf: (digestHex) => byDigest.get(digestHex) ?? -1,
    digestAt: (position) => {
      const p = pairs[position];
      if (p === undefined) throw new AttestError("INVALID_INPUT", `no position ${String(position)} in a batch of ${size}`);
      return p.digest;
    },
    path: (position) => tree.path(position).map(bytesToHex),
  };
}

export interface ItemPathInput {
  readonly size: number;
  readonly salt: string;
  readonly root: string;
  readonly position: number;
  readonly digest: string;
  readonly path: readonly string[];
}

/** Whether this item sits at this position of the batch with this root. False for anything that does not prove it. Never throws. */
export async function verifyItemPath(i: ItemPathInput): Promise<boolean> {
  try {
    if (!HEX64.test(i.root) || !Array.isArray(i.path) || !i.path.every((p) => typeof p === "string" && HEX64.test(p))) return false;
    const leaf = await itemLeafHash(i.size, i.salt, i.digest);
    return await rfc6962VerifyInclusion(leaf, i.position, i.size, i.path.map(hexToBytes), hexToBytes(i.root));
  } catch {
    return false;
  }
}

/** Read a batch's items file; throws for anything that is not one. */
export function readBatchItemsFile(value: unknown): BatchItemsFile {
  const v = value as Partial<BatchItemsFile> | null;
  if (v === null || typeof v !== "object" || v.format !== BATCH_ITEMS_FORMAT) throw new AttestError("INVALID_INPUT", `not a ${BATCH_ITEMS_FORMAT} file`);
  if (typeof v.salt !== "string" || !HEX64.test(v.salt)) throw new AttestError("INVALID_INPUT", "the items file's salt is 64 lowercase hex characters");
  if (!Array.isArray(v.digests) || v.digests.some((d) => typeof d !== "string" || !HEX64.test(d))) throw new AttestError("INVALID_INPUT", "the items file lists each item's SHA-256 as 64 lowercase hex characters");
  const keys = Object.keys(v).sort().join(",");
  if (keys !== "digests,format,salt") throw new AttestError("INVALID_INPUT", "the items file carries format, salt and digests, and nothing else");
  return { format: BATCH_ITEMS_FORMAT, salt: v.salt, digests: v.digests };
}
