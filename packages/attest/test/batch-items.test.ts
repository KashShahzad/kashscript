/**
 * PY-5 — one root over many items, `kash-items/1` (`specs/attestation/batch.md` §1): the leaf binds the size,
 * the salt and the item; the order is the leaves' own; two equal items are refused; every position's path
 * proves it and nothing else. And `rfc6962Tree`, now hashing each level concurrently, still builds RFC 6962's tree.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex, hexToBytes } from "../src/chain";
import { rfc6962LeafHash, rfc6962Tree, rfc6962VerifyInclusion } from "../src/witness/rfc6962";
import { lookupDst } from "../src/dst";
import { BATCH_ITEMS_FORMAT, ITEM_LEAF_TAG, itemDigestOf, itemLeafHash, itemTree, readBatchItemsFile, verifyBatchItems, verifyItemPath, type BatchSeal } from "../src/batch";
import { seeded } from "./helpers/batch";

const SALT = "5a".repeat(32);
const enc = new TextEncoder();
const digestsOf = async (n: number, label = "item"): Promise<string[]> => Promise.all(Array.from({ length: n }, (_, i) => itemDigestOf(enc.encode(`SAMPLE ${label} ${i}`))));

/** RFC 6962's tree hash, written plainly and recursively — the reference the concurrent builder must equal. */
async function mth(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 1) return leaves[0]!;
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  const l = await mth(leaves.slice(0, k));
  const r = await mth(leaves.slice(k));
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([0x01, ...l, ...r])));
}

describe("rfc6962Tree, hashing each level concurrently", () => {
  test("equals RFC 6962's recursive tree hash for every size from 1 to 300, and every path verifies", async () => {
    for (let n = 1; n <= 300; n++) {
      const leaves = await Promise.all(Array.from({ length: n }, (_, i) => rfc6962LeafHash(Uint8Array.of(i & 0xff, i >> 8))));
      const tree = await rfc6962Tree(leaves);
      expect(bytesToHex(tree.root)).toBe(bytesToHex(await mth(leaves)));
      if (n <= 40 || n % 37 === 0) for (let i = 0; i < n; i++) expect(await rfc6962VerifyInclusion(leaves[i]!, i, n, tree.path(i), tree.root)).toBe(true);
    }
  }, 60_000);
});

describe("the leaf", () => {
  test("is SHA-256(0x00 ‖ tag ‖ size, 8 bytes big-endian ‖ salt ‖ item digest), and its tag is registered as a merkle leaf", async () => {
    const d = await itemDigestOf(enc.encode("SAMPLE"));
    const tag = enc.encode(ITEM_LEAF_TAG);
    const size = new Uint8Array(8);
    new DataView(size.buffer).setBigUint64(0, 2000n, false);
    const want = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([0x00, ...tag, ...size, ...hexToBytes(SALT), ...hexToBytes(d)])));
    expect(bytesToHex(await itemLeafHash(2000, SALT, d))).toBe(bytesToHex(want));
    expect(lookupDst(ITEM_LEAF_TAG)?.family).toBe("merkle-leaf");
  });

  test("binds the size and the salt: the same item makes another leaf in a batch of another size, or under another salt", async () => {
    const d = await itemDigestOf(enc.encode("SAMPLE"));
    const a = bytesToHex(await itemLeafHash(10, SALT, d));
    expect(bytesToHex(await itemLeafHash(11, SALT, d))).not.toBe(a);
    expect(bytesToHex(await itemLeafHash(10, "5b".repeat(32), d))).not.toBe(a);
  });
});

describe("the tree", () => {
  test("the order is the items' own: any order of the same items gives the same root", async () => {
    const ds = await digestsOf(57);
    const rand = seeded(3);
    const shuffled = [...ds].sort(() => rand() - 0.5);
    expect((await itemTree(SALT, shuffled)).root).toBe((await itemTree(SALT, ds)).root);
  });

  test("two equal items are refused — each item is one item", async () => {
    const ds = await digestsOf(5);
    await expect(itemTree(SALT, [...ds, ds[2]!])).rejects.toThrow(/same bytes/);
  });

  test("every position's path proves that item there, and fails for another position, size, salt, item or root", async () => {
    for (const n of [1, 2, 3, 10, 33]) {
      const ds = await digestsOf(n);
      const tree = await itemTree(SALT, ds);
      for (let p = 0; p < n; p++) {
        const base = { size: n, salt: SALT, root: tree.root, position: p, digest: tree.digestAt(p), path: tree.path(p) };
        expect(await verifyItemPath(base)).toBe(true);
        expect(tree.positionOf(tree.digestAt(p))).toBe(p);
        if (n > 1) expect(await verifyItemPath({ ...base, position: (p + 1) % n })).toBe(false);
        expect(await verifyItemPath({ ...base, size: n + 1 })).toBe(false);
        if (n > 1) expect(await verifyItemPath({ ...base, size: n - 1 })).toBe(false);
        expect(await verifyItemPath({ ...base, salt: "5b".repeat(32) })).toBe(false);
        expect(await verifyItemPath({ ...base, digest: "ab".repeat(32) })).toBe(false);
        expect(await verifyItemPath({ ...base, root: "00".repeat(32) })).toBe(false);
      }
    }
  });

  test("a malformed path or input is false, never thrown", async () => {
    expect(await verifyItemPath({ size: 3, salt: SALT, root: "zz", position: 0, digest: "ab".repeat(32), path: [] })).toBe(false);
    expect(await verifyItemPath({ size: -1, salt: SALT, root: "00".repeat(32), position: 0, digest: "ab".repeat(32), path: [] })).toBe(false);
  });
});

describe("the items file", () => {
  const sealOf = (root: string, size: number): BatchSeal => ({ format: "kash-batch-seal/1", root, size, plan: { sample: size, accept: 0, alpha: { num: 1, den: 20 }, limit: 0 } });

  test("holds exactly the sealed items: the same count, the same root — and fails for one item swapped, added or left out, or another salt", async () => {
    const ds = await digestsOf(40);
    const tree = await itemTree(SALT, ds);
    const batch = { seal: sealOf(tree.root, 40), found: [], bound: 0 };
    const file = (digests: string[], salt = SALT) => ({ format: BATCH_ITEMS_FORMAT, salt, digests }) as const;
    expect((await verifyBatchItems(batch, file(ds))).ok).toBe(true);
    const swapped = [...ds];
    swapped[7] = await itemDigestOf(enc.encode("SAMPLE a different item"));
    expect((await verifyBatchItems(batch, file(swapped))).problems[0]).toContain("do not make the seal's root");
    expect((await verifyBatchItems(batch, file([...ds, swapped[7]!]))).problems[0]).toContain("lists 41 items");
    expect((await verifyBatchItems(batch, file(ds.slice(1)))).problems[0]).toContain("lists 39 items");
    expect((await verifyBatchItems(batch, file(ds, "5b".repeat(32)))).ok).toBe(false);
  });

  test("carries format, salt and digests, and nothing else", () => {
    expect(() => readBatchItemsFile({ format: BATCH_ITEMS_FORMAT, salt: SALT, digests: [] })).not.toThrow();
    expect(() => readBatchItemsFile({ format: BATCH_ITEMS_FORMAT, salt: SALT, digests: [], names: [] })).toThrow();
    expect(() => readBatchItemsFile({ format: "other/1", salt: SALT, digests: [] })).toThrow();
    expect(() => readBatchItemsFile({ format: BATCH_ITEMS_FORMAT, salt: "short", digests: [] })).toThrow();
  });
});

describe("batch-items@1 — the conformance file", () => {
  interface Case {
    readonly name: string;
    readonly salt: string;
    readonly items: readonly string[];
    readonly digests: readonly string[];
    readonly leaves: readonly string[];
    readonly root: string;
    readonly paths: readonly { readonly position: number; readonly path: readonly string[] }[];
  }
  const file = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck", "batch-items@1", "cases.json"), "utf8")) as { cases: Case[] };

  test("every case reaches its stated digests, ordered leaves, root and paths", async () => {
    expect(file.cases.length).toBeGreaterThanOrEqual(3);
    for (const c of file.cases) {
      const ds = await Promise.all(c.items.map((t) => itemDigestOf(enc.encode(t))));
      expect(ds).toEqual([...c.digests]);
      const tree = await itemTree(c.salt, ds);
      expect([...tree.leaves]).toEqual([...c.leaves]);
      expect(tree.root).toBe(c.root);
      for (const p of c.paths) expect(tree.path(p.position)).toEqual([...p.path]);
    }
  });
});
