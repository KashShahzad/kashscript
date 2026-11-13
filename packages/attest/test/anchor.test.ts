/**
 * GP-6 — the session anchor's second version (specs/session-receipt.md §3,
 * v1.1). One RFC 6962 batch; each receipt carries its own audit path and
 * nothing of any other session; the batch's size rides in every leaf, because
 * a path alone does not fix it. A first-version anchor still verifies and says
 * what it does not prove. ./vectors/anchor was generated once and is never
 * regenerated; ./vectors/exchange is read here, never written.
 */

import { describe, it, expect } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { lookupDst } from "../src/dst";
import {
  SESSION_ANCHOR_FORMAT,
  SESSION_HEAD_LEAF_DST,
  sessionAnchorBatch,
  sessionEventSha256,
  sessionHeadLeafHash,
  verifySessionReceipt,
} from "../src/exchange";
import { recordIdOf, verifyHolderExport, type HolderExport } from "../src/holder";
import { rfc6962LeafHash, rfc6962Tree, rfc6962VerifyInclusion } from "../src/witness";

const A = join(import.meta.dir, "vectors", "anchor");
const X = join(import.meta.dir, "vectors", "exchange");
const H = join(import.meta.dir, "vectors", "holder");
const read = <T = any>(dir: string, f: string): T => JSON.parse(readFileSync(join(dir, f), "utf8")) as T;
const NOW = read(A, "context.v2.json").nowUnix as number;
const anchored = (i: number): any => read(A, `session-anchored-${i}.v2.json`);
const BATCH = read<{
  root: string;
  treeSize: number;
  sessions: { sessionId: string; parties: { establishment: string; person: string }; headSha256: string; coversSeq: number }[];
}>(A, "batch.v2.json");
const verify = (r: unknown) => verifySessionReceipt(r, { nowSec: NOW });
const faultsOf = async (r: unknown) => (await verify(r)).faults.map((f) => f.fault);

/* ── the test's own RFC 6962, written from the RFC's text; it shares no code with src/ ── */
const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const split = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
/** RFC 6962 §2.1: MTH. */
const refRoot = (d: readonly Uint8Array[]): Uint8Array =>
  d.length === 1 ? sha(Uint8Array.of(0), d[0]!) : sha(Uint8Array.of(1), refRoot(d.slice(0, split(d.length))), refRoot(d.slice(split(d.length))));
/** RFC 6962 §2.1.1: PATH. */
const refPath = (m: number, d: readonly Uint8Array[]): Uint8Array[] => {
  if (d.length <= 1) return [];
  const k = split(d.length);
  return m < k ? [...refPath(m, d.slice(0, k)), refRoot(d.slice(k))] : [...refPath(m - k, d.slice(k)), refRoot(d.slice(0, k))];
};
const leavesOf = (d: readonly Uint8Array[]) => Promise.all(d.map(rfc6962LeafHash));

/* ── Certificate Transparency's published vectors ─────────────────────── */
// transparency-dev/merkle, testonly/constants.go (Apache-2.0): LeafInputs() and RootHashes() for trees of 1 to 8.
const CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"].map(bytes);
const CT_ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
// Four audit paths over the same leaves, as RFC 6962 §2.1.1 defines them (and as refPath recomputes below).
const CT_PATHS: { index: number; size: number; path: string[] }[] = [
  { index: 0, size: 8, path: ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
  { index: 5, size: 8, path: ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
  { index: 2, size: 3, path: ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"] },
  { index: 1, size: 5, path: ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
];

describe("RFC 6962 — the tree under the session anchor", () => {
  it("matches Certificate Transparency's published roots for trees of 1 to 8", async () => {
    for (let n = 1; n <= 8; n++) {
      const tree = await rfc6962Tree(await leavesOf(CT_LEAVES.slice(0, n)));
      expect(hex(tree.root)).toBe(CT_ROOTS[n - 1]!);
    }
  });

  it("gives RFC 6962's audit paths, and each one verifies", async () => {
    for (const { index, size, path } of CT_PATHS) {
      const d = CT_LEAVES.slice(0, size);
      const tree = await rfc6962Tree(await leavesOf(d));
      expect(tree.path(index).map(hex)).toEqual(path);
      expect(refPath(index, d).map(hex)).toEqual(path);
      expect(await rfc6962VerifyInclusion(await rfc6962LeafHash(d[index]!), index, size, path.map(bytes), tree.root)).toBe(true);
    }
  });

  it("equals the RFC's recursive definition for every leaf of every tree of 1 to 64 leaves, and every path verifies", async () => {
    for (let n = 1; n <= 64; n++) {
      const d = Array.from({ length: n }, (_, i) => Uint8Array.of(i, n));
      const tree = await rfc6962Tree(await leavesOf(d));
      expect(hex(tree.root)).toBe(hex(refRoot(d)));
      for (let m = 0; m < n; m++) {
        const path = tree.path(m);
        expect(path.map(hex)).toEqual(refPath(m, d).map(hex));
        expect(await rfc6962VerifyInclusion(await rfc6962LeafHash(d[m]!), m, n, path, tree.root)).toBe(true);
      }
    }
    // 2,080 inclusion proofs: well past bun's 5 s default when another suite is building beside it.
  }, 60_000);

  it("refuses what does not prove inclusion, and never throws on junk", async () => {
    const d = Array.from({ length: 13 }, (_, i) => Uint8Array.of(i));
    const tree = await rfc6962Tree(await leavesOf(d));
    const leaf = await rfc6962LeafHash(d[6]!);
    const path = tree.path(6);
    const ok = (l: Uint8Array, i: number, s: number, p: readonly Uint8Array[], r: Uint8Array) => rfc6962VerifyInclusion(l, i, s, p, r);
    expect(await ok(leaf, 6, 13, path, tree.root)).toBe(true);
    expect(await ok(await rfc6962LeafHash(d[7]!), 6, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, 5, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, 7, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, 6, 13, path.slice(0, -1), tree.root)).toBe(false);
    expect(await ok(leaf, 6, 13, [...path, path[0]!], tree.root)).toBe(false);
    const flipped = path.map((p) => p.slice());
    const sibling = flipped[1]!;
    sibling[0] = sibling[0]! ^ 1;
    expect(await ok(leaf, 6, 13, flipped, tree.root)).toBe(false);
    expect(await ok(leaf, 6, 13, path, sha(tree.root))).toBe(false);
    expect(await ok(leaf, 13, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, -1, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, 1.5, 13, path, tree.root)).toBe(false);
    expect(await ok(leaf, 0, 0, [], tree.root)).toBe(false);
    expect(await ok(leaf, 6, 13, Array.from({ length: 65 }, () => path[0]!), tree.root)).toBe(false);
    expect(await ok(leaf, 6, 13, [path[0]!.slice(1), ...path.slice(1)], tree.root)).toBe(false);
    expect(await ok(leaf.slice(1), 6, 13, path, tree.root)).toBe(false);
  });

  it("a path alone does not fix the tree's size — which is why the session leaf carries it", async () => {
    const d = Array.from({ length: 5 }, (_, i) => Uint8Array.of(i));
    const tree = await rfc6962Tree(await leavesOf(d));
    // RFC 9162 §2.1.3.2 binds the size only through a signed tree head. Leaf 2 of 5 also "verifies" as leaf 2 of 6:
    expect(await rfc6962VerifyInclusion(await rfc6962LeafHash(d[2]!), 2, 6, tree.path(2), tree.root)).toBe(true);
    // The session anchor's witness signs only the root, so the size is in every leaf instead; see the misstated-size case below.
  });

  it("refuses an empty batch, a malformed leaf hash, and a leaf the tree does not have", async () => {
    await expect(rfc6962Tree([])).rejects.toThrow();
    await expect(rfc6962Tree([new Uint8Array(31)])).rejects.toThrow();
    const tree = await rfc6962Tree([new Uint8Array(32)]);
    expect(tree.path(0)).toEqual([]);
    expect(() => tree.path(1)).toThrow();
  });
});

describe("the session anchor, second version — each receipt proves its own place and shows no other session", () => {
  it("leaves with the registered tag and the batch's size: SHA-256(0x00 ‖ tag ‖ size ‖ head)", async () => {
    expect(SESSION_HEAD_LEAF_DST).toBe("kash-session-head-v1\n");
    expect(lookupDst(SESSION_HEAD_LEAF_DST)?.family).toBe("merkle-leaf");
    const head = BATCH.sessions[2]!.headSha256;
    const size = new Uint8Array(8);
    new DataView(size.buffer).setUint32(4, 5);
    const expected = sha(Uint8Array.of(0), new TextEncoder().encode(SESSION_HEAD_LEAF_DST), size, bytes(head));
    expect(hex(await sessionHeadLeafHash(head, 5))).toBe(hex(expected));
    expect(hex(await sessionHeadLeafHash(head, 6))).not.toBe(hex(expected));
  });

  it("every receipt in the batch is proof, each at its own leaf, all under one witnessed root", async () => {
    for (let i = 0; i < 5; i++) {
      const r = await verify(anchored(i));
      expect(r.faults).toEqual([]);
      expect(r.proof).toBe(true);
      expect(r.anchor?.matches).toBe(true);
      expect(r.anchor?.inclusion).toEqual({ treeSize: 5, leafIndex: i, root: BATCH.root, included: true, witnessNamesRoot: true });
      expect(r.notes.join(" ")).toContain(`its path leads from its head, as leaf index ${i} in a batch of 5, to the root this anchor names`);
      // Honest about what stands behind the root: nothing outside this file, in a practice batch.
      expect(r.notes.join(" ")).toContain("no public log witnessed it — nothing outside this file vouches for it");
      expect(anchored(i).anchor.formatVersion).toBe(SESSION_ANCHOR_FORMAT);
    }
  });

  it("a receipt holds no other session's id, keys, head or lines — only its own path", async () => {
    for (let i = 0; i < 5; i++) {
      const own = anchored(i);
      const text = JSON.stringify(own);
      for (let j = 0; j < 5; j++) {
        if (j === i) continue;
        const other = BATCH.sessions[j]!;
        expect(text).not.toContain(other.sessionId);
        expect(text).not.toContain(other.parties.establishment);
        expect(text).not.toContain(other.parties.person);
        expect(text).not.toContain(other.headSha256);
        for (const ev of anchored(j).events) {
          expect(text).not.toContain(ev.payload);
          for (const s of ev.signatures) expect(text).not.toContain(s.sig);
        }
      }
      // ⌈log₂ 5⌉ = 3: no path in this batch is longer.
      expect(own.anchor.inclusion.path.length).toBeLessThanOrEqual(3);
    }
  });

  it("the repair keeps PL-3's six signed lines byte for byte; only its anchor is new", () => {
    const v1 = read(X, "session-receipt-complete.v1.json");
    const v2 = anchored(2);
    expect(v2.events).toEqual(v1.events);
    expect({ ...v2, anchor: null }).toEqual({ ...v1, anchor: null });
    expect(v2.anchor.headSha256).toBe(v1.anchor.headSha256);
  });

  it("the host's helper rebuilds the same root and the same path for every receipt", async () => {
    const batch = await sessionAnchorBatch(BATCH.sessions.map((s) => ({ headSha256: s.headSha256, coversSeq: s.coversSeq })));
    expect(batch.root).toBe(BATCH.root);
    expect(batch.treeSize).toBe(5);
    for (let i = 0; i < 5; i++) {
      const a = batch.anchorFor(i, anchored(i).anchor.witness);
      expect(a).toEqual(anchored(i).anchor);
      expect(await sessionEventSha256(anchored(i).events.at(-1))).toBe(a.headSha256);
    }
    expect(() => batch.anchorFor(5, anchored(0).anchor.witness)).toThrow();
    await expect(sessionAnchorBatch([])).rejects.toThrow();
    await expect(sessionAnchorBatch([{ headSha256: "AB".repeat(32), coversSeq: 0 }])).rejects.toThrow();
    await expect(sessionAnchorBatch([{ headSha256: "ab".repeat(32), coversSeq: -1 }])).rejects.toThrow();
  });

  it("an anchor taken from one receipt fails on another", async () => {
    const r = anchored(0);
    r.anchor = anchored(1).anchor;
    expect(await faultsOf(r)).toContain("ANCHOR_MISMATCH");
  });

  it("a changed path, index, size, root, head or witness root fails the receipt", async () => {
    const cases: [string, (a: any) => void, Partial<{ included: boolean; witnessNamesRoot: boolean | null }>][] = [
      ["a flipped sibling", (a) => { a.inclusion.path[0] = a.inclusion.path[0].replace(/^./, (c: string) => (c === "0" ? "1" : "0")); }, { included: false }],
      ["another leaf index", (a) => { a.inclusion.leafIndex = 3; }, { included: false }],
      ["a bigger batch than it was", (a) => { a.inclusion.treeSize = 6; }, { included: false }],
      ["a smaller batch than it was", (a) => { a.inclusion.treeSize = 4; }, { included: false }],
      ["another root", (a) => { a.root = "ab".repeat(32); }, { included: false, witnessNamesRoot: false }],
      ["another root, named by the witness too", (a) => { a.root = "ab".repeat(32); a.witness.receipt.merkleRoot = a.root; }, { included: false, witnessNamesRoot: true }],
      ["a witness naming another root", (a) => { a.witness.receipt.merkleRoot = "cd".repeat(32); }, { included: true, witnessNamesRoot: false }],
      ["another head", (a) => { a.headSha256 = "ef".repeat(32); }, { included: false }],
    ];
    for (const [what, change, expected] of cases) {
      const r = anchored(2);
      change(r.anchor);
      const report = await verify(r);
      expect({ what, faults: report.faults.map((f) => f.fault) }).toEqual({ what, faults: ["ANCHOR_MISMATCH"] });
      expect(report.ok).toBe(false);
      // `matches` keeps its old meaning — false exactly when ANCHOR_MISMATCH is raised — so a consumer reading only it is not misled.
      expect({ what, matches: report.anchor?.matches }).toEqual({ what, matches: false });
      expect({ what, ...report.anchor?.inclusion }).toMatchObject({ what, ...expected });
    }
  });

  it("an inclusion proof that cannot be read proves nothing, and fails", async () => {
    for (const change of [
      (a: any) => { delete a.inclusion; },
      (a: any) => { a.inclusion.path = "not a path"; },
      (a: any) => { a.inclusion.treeSize = 0; },
      (a: any) => { a.root = a.root.toUpperCase(); },
      (a: any) => { a.inclusion.path = Array.from({ length: 65 }, () => "00".repeat(32)); },
    ]) {
      const r = anchored(2);
      change(r.anchor);
      const report = await verify(r);
      expect(report.faults.map((f) => f.fault)).toEqual(["ANCHOR_MISMATCH"]);
      expect(report.anchor?.inclusion?.included).toBe(false);
    }
    const r = anchored(2);
    delete r.anchor.inclusion;
    expect((await verify(r)).notes.join(" ")).toContain("cannot be read");
  });

  it("a witness that names no root is not held against the receipt, and the note says what is left unchecked", async () => {
    const r = anchored(2);
    r.anchor.witness = { backend: "rekor", receipt: { uuid: "test-only-shape" }, witnessedAt: null };
    const report = await verify(r);
    expect(report.faults).toEqual([]);
    expect(report.anchor?.inclusion?.witnessNamesRoot).toBeNull();
    expect(report.notes.join(" ")).toContain("names no root");
  });

  it("a file can name any root, so a self-made one-leaf anchor passes only as itself — and the output says nothing outside the file vouches for it", async () => {
    // A forger's anchor: a one-leaf tree is its own root, and no witness stands behind it.
    const r = anchored(2);
    const head = r.anchor.headSha256 as string;
    const root = hex(await sessionHeadLeafHash(head, 1));
    r.anchor = { ...r.anchor, root, inclusion: { treeSize: 1, leafIndex: 0, path: [] }, witness: { backend: "rekor", receipt: {}, witnessedAt: null } };
    const report = await verify(r);
    expect(report.faults).toEqual([]);
    expect(report.anchor?.inclusion).toMatchObject({ included: true, witnessNamesRoot: null });
    const said = report.notes.join(" ");
    expect(said).toContain("names no root — that a log witnessed this root is not checked");
    expect(said).not.toContain("proved by");
  });
});

describe("the anchoring host's helper refuses a batch it would get wrong", () => {
  const witness = { backend: "none", receipt: {}, witnessedAt: null } as const;
  const a = "ab".repeat(32);
  const b = "cd".repeat(32);

  it("names the entry with a bad head or a bad coversSeq, before any leaf is built", async () => {
    await expect(sessionAnchorBatch([{ headSha256: a, coversSeq: 0 }, { headSha256: "not-hex", coversSeq: 0 }])).rejects.toThrow("entry 1: a session head is 64 lowercase hex characters");
    await expect(sessionAnchorBatch([{ headSha256: a, coversSeq: 0 }, { headSha256: b, coversSeq: -1 }])).rejects.toThrow("entry 1: coversSeq is the index");
    await expect(sessionAnchorBatch([{ headSha256: a, coversSeq: 1.5 }])).rejects.toThrow("entry 0: coversSeq");
  });

  it("refuses the same head twice: a session is anchored once per batch, and a batch's size is not inflated", async () => {
    await expect(sessionAnchorBatch([{ headSha256: a, coversSeq: 3 }, { headSha256: b, coversSeq: 3 }, { headSha256: a, coversSeq: 3 }])).rejects.toThrow("entries 0 and 2 carry the same head");
    const ok = await sessionAnchorBatch([{ headSha256: a, coversSeq: 3 }, { headSha256: b, coversSeq: 3 }]);
    expect(ok.treeSize).toBe(2);
    expect(ok.anchorFor(1, witness).inclusion.leafIndex).toBe(1);
  });
});

describe("first-version anchors verify forever, and say what they do not prove", () => {
  it("PL-3's complete receipt (alpha.1) verifies as before, with the limit stated", async () => {
    const r = await verifySessionReceipt(read(X, "session-receipt-complete.v1.json"), { nowSec: read(X, "context.v1.json").nowUnix });
    expect(r.faults).toEqual([]);
    expect(r.proof).toBe(true);
    expect(r.anchor).toEqual({ coversSeq: 5, matches: true, backend: "none" });
    expect(r.notes).toContain("this anchor carries no inclusion proof — that its head is in a witnessed batch is not checked");
  });

  it("PL-3's pending receipt is still pending, and still not anchored", async () => {
    const r = await verifySessionReceipt(read(X, "session-receipt-pending.v1.json"), { nowSec: read(X, "context.v1.json").nowUnix });
    expect(r.ok).toBe(true);
    expect(r.proof).toBe(false);
    expect(r.anchor).toBeNull();
    expect(r.notes).toContain("not anchored");
  });

  it("an explicit first-version tag reads as the first version", async () => {
    const v1 = read(X, "session-receipt-complete.v1.json");
    v1.anchor.formatVersion = "kashscript-session-anchor/1";
    const r = await verify(v1);
    expect(r.faults).toEqual([]);
    expect(r.anchor?.inclusion).toBeUndefined();
  });

  it("an anchor that carries its own tree inside the witness receipt — Indorania's practice shape — is checked as a first version: its head, nothing more", async () => {
    const v1 = read(X, "session-receipt-complete.v1.json");
    v1.anchor.witness = { backend: "none", receipt: { tree: "rfc6962-sha256", root: "ab".repeat(32), treeSize: 2, leafIndex: 0, path: ["cd".repeat(32)] }, witnessedAt: null };
    const r = await verify(v1);
    expect(r.faults).toEqual([]);
    expect(r.anchor?.inclusion).toBeUndefined();
    expect(r.notes.join(" ")).toContain("carries no inclusion proof");
  });

  it("an anchor format this verifier does not know: its head is checked, no fault, and it says so", async () => {
    const r = anchored(2);
    r.anchor.formatVersion = "kashscript-session-anchor/9";
    const report = await verify(r);
    expect(report.faults).toEqual([]);
    expect(report.anchor?.inclusion).toBeUndefined();
    expect(report.notes.join(" ")).toContain("is not known to this verifier — only its head was checked");
  });
});

describe("the holder export reads the second version", () => {
  const XNOW = read(X, "context.v1.json").nowUnix as number;
  const record = async (receipt: any) => {
    const artifact = { kind: "session-receipt" as const, value: receipt };
    const expiresAtUnix = (await verifySessionReceipt(receipt, { nowSec: XNOW })).expiresAtUnix;
    return {
      artifact,
      manifest: {
        recordId: await recordIdOf(artifact), issuer: receipt.parties.establishment, relationship: receipt.parties.person,
        type: { tag: "application/vnd.indorania.session-event+json", family: "dsse-type", attestation: "countersigned" }, receivedAtUnix: XNOW,
        expiresAtUnix, retentionSource: "record", status: null, listing: "unlisted", keptUnlistedAtUnix: XNOW,
      },
    };
  };

  it("an anchored receipt is noted with its place in its batch; a broken path fails the record", async () => {
    const e = read<HolderExport>(H, "holder-export.v1.json");
    const ok = await verifyHolderExport({ ...e, records: [...e.records, await record(anchored(2))] } as never, { nowSec: XNOW });
    expect(ok.reasons).toEqual([]);
    expect(ok.records.at(-1)?.notes).toContain(
      "its anchor's own path leads from this record's head, as leaf index 2 in a batch of 5, to the root the anchor names — no public log witnessed that root",
    );
    const broken = anchored(2);
    broken.anchor.inclusion.leafIndex = 1;
    const bad = await verifyHolderExport({ ...e, records: [...e.records, await record(broken)] } as never, { nowSec: XNOW });
    expect(bad.records.at(-1)?.reasons).toContain("SIGNATURE_INVALID");
    expect(bad.records.at(-1)?.notes).toContain("its anchor does not prove its place in a batch (ANCHOR_MISMATCH)");
    const old = await verifyHolderExport({ ...e, records: [...e.records, await record(read(X, "session-receipt-complete.v1.json"))] } as never, { nowSec: XNOW });
    expect(old.reasons).toEqual([]);
    expect(old.records.at(-1)?.notes).toContain("anchored without an inclusion proof this verifier reads — its place in a batch is not checked");
  });
});
