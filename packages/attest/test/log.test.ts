/**
 * KS-Q4 — the trust log. The consistency proof against RFC 9162's own
 * definition and Certificate Transparency's published vectors; the entry guard;
 * the leaf and the salt; checkpoints; inclusion and consistency proofs from
 * ./vectors/log (generated once, never regenerated); the audit — a mirror
 * rebuilt from the log alone matches the original, every tamper is named, a
 * split view is seen when both views are held; and the planted backdated
 * attestation is caught by the witness.
 */

import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizeBytes, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { lookupDst } from "../src/dst";
import {
  DST_LOG_CHECKPOINT,
  InMemoryLogStore,
  LOG_ENTRY_LEAF_DST,
  LOG_SALT_DST,
  auditLog,
  claimedTimeOf,
  describeLog,
  logEntryFaults,
  logLeafHash,
  openTrustLog,
  rebuildFromEntries,
  saltedRecordHash,
  timeVerdict,
  verifyCheckpoint,
  verifyLogConsistency,
  verifyLogInclusion,
  type LogEntry,
  type LogFiles,
  type LogInclusionFailureReason,
} from "../src/log";
import { checkpointHash } from "../src/log";
import { readLogDirectory } from "../src/log/files";
import { opensslAvailable, opensslRfc3161Check } from "../src/bin/openssl";
import { bytesToBase64 } from "../src/ed25519";
import { fakeTimeStampResp } from "./witness/fake-tsa";
import { rfc6962ConsistencyProof, rfc6962LeafHash, rfc6962Tree, rfc6962VerifyConsistency } from "../src/witness";

const V = join(import.meta.dir, "vectors", "log");
const read = <T = any>(...p: string[]): T => JSON.parse(readFileSync(join(V, ...p), "utf8")) as T;
const CTX = read("context.json");
const files = (...p: string[]): LogFiles => readLogDirectory(join(V, ...p));
/** The test stands in for `openssl ts -verify`: the vectors' witnesses are the fake authority's unsigned tokens. */
const signed = async (): Promise<boolean> => true;

const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

/* ── the test's own RFC 9162, from the RFC's text; it shares no code with src/ ── */
const split = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
const refRoot = (d: readonly Uint8Array[]): Uint8Array =>
  d.length === 1 ? sha(Uint8Array.of(0), d[0]!) : sha(Uint8Array.of(1), refRoot(d.slice(0, split(d.length))), refRoot(d.slice(split(d.length))));
/** §2.1.4.1: SUBPROOF(m, D_n, b). */
const refSubproof = (m: number, d: readonly Uint8Array[], b: boolean): Uint8Array[] => {
  const n = d.length;
  if (m === n) return b ? [] : [refRoot(d)];
  const k = split(n);
  return m <= k ? [...refSubproof(m, d.slice(0, k), b), refRoot(d.slice(k))] : [...refSubproof(m - k, d.slice(k), false), refRoot(d.slice(0, k))];
};
const refProof = (m: number, d: readonly Uint8Array[]): Uint8Array[] => refSubproof(m, d, true);
const leavesOf = (d: readonly Uint8Array[]) => Promise.all(d.map(rfc6962LeafHash));

// transparency-dev/merkle, testonly/constants.go (Apache-2.0): the same eight leaves anchor.test.ts uses, and the published consistency proofs.
const CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"].map(bytes);
const CT_CONSISTENCY: { first: number; second: number; path: string[] }[] = [
  { first: 1, second: 1, path: [] },
  { first: 1, second: 8, path: ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
  { first: 6, second: 8, path: ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
  { first: 2, second: 5, path: ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
];

describe("RFC 9162 — consistency between two heads", () => {
  it("gives Certificate Transparency's published consistency proofs, and each verifies", async () => {
    for (const { first, second, path } of CT_CONSISTENCY) {
      const leaves = await leavesOf(CT_LEAVES.slice(0, second));
      const proof = await rfc6962ConsistencyProof(leaves, first, second);
      expect(proof.map(hex)).toEqual(path);
      expect(refProof(first, CT_LEAVES.slice(0, second)).map(hex)).toEqual(path);
      const firstRoot = (await rfc6962Tree(leaves.slice(0, first))).root;
      const secondRoot = (await rfc6962Tree(leaves)).root;
      expect(await rfc6962VerifyConsistency(first, second, proof, firstRoot, secondRoot)).toBe(true);
    }
  });

  it("equals the RFC's recursive definition for every pair m ≤ n ≤ 32, and every proof verifies", async () => {
    const d = Array.from({ length: 32 }, (_, i) => Uint8Array.of(i, 99));
    const leaves = await leavesOf(d);
    for (let n = 1; n <= 32; n++) {
      const secondRoot = (await rfc6962Tree(leaves.slice(0, n))).root;
      for (let m = 1; m <= n; m++) {
        const proof = await rfc6962ConsistencyProof(leaves.slice(0, n), m, n);
        expect(proof.map(hex)).toEqual(refProof(m, d.slice(0, n)).map(hex));
        const firstRoot = (await rfc6962Tree(leaves.slice(0, m))).root;
        expect(await rfc6962VerifyConsistency(m, n, proof, firstRoot, secondRoot)).toBe(true);
      }
    }
  }, 60_000);

  it("refuses what does not prove consistency, and never throws on junk", async () => {
    const d = Array.from({ length: 13 }, (_, i) => Uint8Array.of(i));
    const leaves = await leavesOf(d);
    const r6 = (await rfc6962Tree(leaves.slice(0, 6))).root;
    const r13 = (await rfc6962Tree(leaves)).root;
    const proof = await rfc6962ConsistencyProof(leaves, 6, 13);
    const ok = (f: number, s: number, p: readonly Uint8Array[], a: Uint8Array, b: Uint8Array) => rfc6962VerifyConsistency(f, s, p, a, b);
    expect(await ok(6, 13, proof, r6, r13)).toBe(true);
    expect(await ok(6, 13, proof, r13, r6)).toBe(false);
    expect(await ok(6, 13, proof.slice(1), r6, r13)).toBe(false);
    expect(await ok(6, 13, [...proof, proof[0]!], r6, r13)).toBe(false);
    expect(await ok(7, 13, proof, r6, r13)).toBe(false);
    // A proof alone does not fix the second size: this path takes the same turns for a tree of 12 as of 13 (as an
    // inclusion path does, anchor.test.ts). RFC 9162 binds sizes through signed tree heads, which is why a log
    // consistency proof is checked against the sizes its two checkpoints sign — see "consistency proofs" below.
    expect(await ok(6, 12, proof, r6, r13)).toBe(true);
    expect(await ok(6, 13, [], r6, r13)).toBe(false);
    expect(await ok(13, 6, proof, r13, r6)).toBe(false);
    expect(await ok(0, 13, proof, r6, r13)).toBe(false);
    expect(await ok(6, 13, proof, r6.slice(1), r13)).toBe(false);
    const flipped = proof.map((p) => p.slice());
    flipped[0]![0] = flipped[0]![0]! ^ 1;
    expect(await ok(6, 13, flipped, r6, r13)).toBe(false);
    // A tree that was rewritten, not extended: the first six leaves differ.
    const other = await leavesOf([Uint8Array.of(42), ...d.slice(1)]);
    const r13b = (await rfc6962Tree(other)).root;
    expect(await ok(6, 13, await rfc6962ConsistencyProof(other, 6, 13), r6, r13b)).toBe(false);
    // Equal heads: consistent by an empty proof, and only so.
    expect(await ok(13, 13, [], r13, r13)).toBe(true);
    expect(await ok(13, 13, [proof[0]!], r13, r13)).toBe(false);
    expect(await ok(13, 13, [], r13, r6)).toBe(false);
    await expect(rfc6962ConsistencyProof(leaves, 0, 13)).rejects.toThrow();
    await expect(rfc6962ConsistencyProof(leaves, 7, 6)).rejects.toThrow();
    await expect(rfc6962ConsistencyProof(leaves, 1, 14)).rejects.toThrow();
  });
});

describe("the entries — issuers and lists, and attestations by salted hash; never a person", () => {
  const good: LogEntry[] = readFileSync(join(V, "original", "entries", "000000.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l) as LogEntry);

  it("admits the four kinds as the vectors write them", () => {
    expect(good.length).toBe(9);
    for (const e of good) expect({ kind: e.kind, faults: logEntryFaults(e) }).toEqual({ kind: e.kind, faults: [] });
    expect(new Set(good.map((e) => e.kind))).toEqual(new Set(["trust-list", "status-list", "issuer-key", "attestation"]));
  });

  it("refuses an unknown kind, a missing or extra field, a bad value, and over-long text", () => {
    const att = good.find((e) => e.kind === "attestation")!;
    const codes = (e: unknown) => logEntryFaults(e).map((f) => f.code);
    expect(codes({ ...att, kind: "presentation" })).toEqual(["UNKNOWN_KIND"]);
    expect(codes({ ...att, extra: 1 })).toEqual(["EXTRA_FIELD"]);
    const { salted: _s, ...missing } = att as unknown as Record<string, unknown>;
    expect(codes(missing)).toEqual(["MISSING_FIELD"]);
    expect(codes({ ...att, salted: "not-hex" })).toEqual(["BAD_VALUE"]);
    expect(codes({ ...att, claimedAtUnix: -1 })).toEqual(["BAD_VALUE"]);
    expect(codes({ ...att, issuer: "x".repeat(257) })).toEqual(["TEXT_TOO_LONG"]);
    expect(codes({ ...att, issuer: "two\nlines" })).toEqual(["BAD_VALUE"]);
    expect(codes({ ...att, v: 2 })).toEqual(["BAD_VERSION"]);
    expect(codes({ ...att, backfilled: "yes" })).toEqual(["BAD_VALUE"]);
    expect(codes("a string")).toEqual(["NOT_AN_OBJECT"]);
    expect(codes(null)).toEqual(["NOT_AN_OBJECT"]);
  });

  it("refuses by name any field that would carry a person, a record, a presentation or a salt", () => {
    const att = good.find((e) => e.kind === "attestation")!;
    for (const name of ["holder", "name", "email", "phone", "payload", "content", "presentation", "vp_token", "salt", "amount", "relationship"]) {
      const faults = logEntryFaults({ ...att, [name]: "x" });
      expect({ name, codes: faults.map((f) => f.code) }).toEqual({ name, codes: ["FORBIDDEN_FIELD"] });
    }
    // A presentation log entry, a holder export record, a person's own record: none is a log entry.
    expect(logEntryFaults({ kind: "presentation", atUnix: 1, verifier: "x", relationship: "y" }).map((f) => f.code)).toEqual(["BAD_VERSION", "UNKNOWN_KIND"]);
    expect(logEntryFaults({ v: 1, kind: "attestation", issuer: "a", salted: "ab".repeat(32), claimedAtUnix: 1, holder: "did:kash:z" }).map((f) => f.code)).toEqual(["FORBIDDEN_FIELD"]);
  });

  it("the leaf is SHA-256(0x00 ‖ tag ‖ JCS(entry)), and the tag is registered as a merkle leaf", async () => {
    expect(LOG_ENTRY_LEAF_DST).toBe("kash-log-entry-v1\n");
    expect(lookupDst(LOG_ENTRY_LEAF_DST)?.family).toBe("merkle-leaf");
    expect(lookupDst(DST_LOG_CHECKPOINT)?.family).toBe("dsse-type");
    for (const e of good) {
      const expected = sha(Uint8Array.of(0), new TextEncoder().encode(LOG_ENTRY_LEAF_DST), canonicalizeBytes(e));
      expect(hex(await logLeafHash(e))).toBe(hex(expected));
    }
    // Key order never changes the leaf.
    const e = good[0]!;
    const reordered = Object.fromEntries(Object.entries(e).reverse()) as unknown as LogEntry;
    expect(hex(await logLeafHash(reordered))).toBe(hex(await logLeafHash(e)));
  });

  it("the salted hash is SHA-256(tag ‖ salt ‖ record hash): without the salt the log names no record; with it the holder proves which", async () => {
    for (const key of ["entry3", "entry6", "entry8"] as const) {
      const { salt, recordHash } = CTX.salts[key];
      const expected = sha(new TextEncoder().encode(LOG_SALT_DST), bytes(salt), bytes(recordHash));
      const salted = await saltedRecordHash(salt, recordHash);
      expect(salted).toBe(hex(expected));
      const index = Number(key.slice(5));
      expect((good[index] as { salted: string }).salted).toBe(salted);
      // The record hash alone, or another salt, reaches another value.
      expect(await saltedRecordHash("00".repeat(32), recordHash)).not.toBe(salted);
      expect(JSON.stringify(good)).not.toContain(recordHash);
      expect(JSON.stringify(good)).not.toContain(salt);
    }
    await expect(saltedRecordHash("short", "ab".repeat(32))).rejects.toThrow();
    await expect(saltedRecordHash("ab".repeat(32), "nothex")).rejects.toThrow();
  });

  it("names each entry's claimed time", () => {
    expect(good.map(claimedTimeOf)).toEqual(CTX.claimed);
  });
});

describe("checkpoints — the log's own key, and only it", () => {
  const original = files("original");

  it("every checkpoint in the vectors verifies, names the log and its previous head, and gives the hash a witness stamps", async () => {
    const sizes: number[] = [];
    let previous: { treeSize: number; rootHash: string } | null = null;
    for (const env of original.checkpoints) {
      const r = await verifyCheckpoint(env, { logId: CTX.logId });
      expect(r.reason).toBeNull();
      expect(r.ok).toBe(true);
      expect(r.key).toBe(CTX.publisherDid);
      expect(r.previous).toEqual(previous);
      expect(r.payloadSha256).toMatch(/^[0-9a-f]{64}$/);
      previous = { treeSize: r.treeSize!, rootHash: r.rootHash! };
      sizes.push(r.treeSize!);
    }
    expect(sizes).toEqual([4, 7, 9]);
  });

  it("a checkpoint signed by a stranger over the log's id, another log's checkpoint, and junk are refused", async () => {
    const stranger = files("tampered", "stranger").checkpoints.at(-1);
    expect((await verifyCheckpoint(stranger)).reason).toBe("CHECKPOINT_SIGNATURE_INVALID");
    expect((await verifyCheckpoint(original.checkpoints[0], { logId: `${CTX.strangerDid}/log/sample` })).reason).toBe("LOG_ID_MISMATCH");
    expect((await verifyCheckpoint({ payloadType: DST_LOG_CHECKPOINT, payload: "bm90IGpzb24", signatures: [] })).reason).toBe("MALFORMED_CHECKPOINT");
    expect((await verifyCheckpoint({ ...(original.checkpoints[0] as object), payloadType: "application/vnd.kash.trust-list+json" })).reason).toBe("CHECKPOINT_TYPE_MISMATCH");
    expect((await verifyCheckpoint("nope")).reason).toBe("MALFORMED_CHECKPOINT");
  });
});

describe("inclusion proofs — one entry, its own path, the signed head, the witnesses", () => {
  const opts = { logId: CTX.logId as string, maxBatchDelaySec: 86_400, verifyRfc3161Signature: signed };

  it("an attestation's proof verifies, and its time is the witness's, not the issuer's", async () => {
    const r = await verifyLogInclusion(read("inclusion-attestation-ok.json"), opts);
    expect(r.reason).toBeNull();
    expect(r.ok).toBe(true);
    expect(r.included).toBe(true);
    expect(r.leafIndex).toBe(3);
    expect(r.treeSize).toBe(4);
    expect(r.witnesses.map((w) => [w.kind, w.state, w.digestOk])).toEqual([["rfc3161", "final", true]]);
    expect(r.time?.state).toBe("attested");
    expect(r.time?.attestedAtUnix).toBe(CTX.heads[0].witnessedAt);
    expect(r.time?.claimedAtUnix).toBe(CTX.claimed[3]);
    expect(r.time?.logClaimedAtUnix).toBe(CTX.heads[0].at);
    expect(r.time?.fault).toBeNull();
    expect(r.time?.text).toContain("attested by");
  });

  it("the same entry proved against a later head still verifies; its witness is an upper bound, so the claimed time is not judged", async () => {
    const r = await verifyLogInclusion(read("inclusion-later-head.json"), opts);
    expect(r.ok).toBe(true);
    expect(r.treeSize).toBe(9);
    expect(r.time?.attestedAtUnix).toBe(CTX.heads[2].witnessedAt);
    expect(r.time?.firstHead).toBe(false);
    expect(r.time?.fault).toBeNull();
    expect(r.time?.text).toContain("the claimed time is not judged here");
  });

  it("a trust-list version's proof verifies, against a later head than its first", async () => {
    const r = await verifyLogInclusion(read("inclusion-trust-list.json"), opts);
    expect(r.ok).toBe(true);
    expect(r.entry?.kind).toBe("trust-list");
    expect(r.time?.firstHead).toBe(false);
  });

  it("THE PLANTED BACKDATED ATTESTATION IS CAUGHT: it claims ten days before its first witness, and the witness says so", async () => {
    const r = await verifyLogInclusion(read("inclusion-backdated.json"), opts);
    expect(r.included).toBe(true); // it IS in the log — what fails is its claim about time
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("TIME_NOT_SUPPORTED");
    expect(r.time?.firstHead).toBe(true); // the head of 9 is its first: the head before it held 7 entries, and this is entry 8
    expect(r.time?.fault).toBe("CLAIMED_BEFORE_WITNESS");
    expect(r.time?.attestedAtUnix).toBe(CTX.heads[2].witnessedAt);
    expect(r.time?.claimedAtUnix).toBe(CTX.claimed[8]);
    expect(CTX.heads[2].witnessedAt - CTX.claimed[8]).toBeGreaterThan(10 * 86_400 - 3600); // ten days and change before its first witness
    expect(r.time?.text).toContain("not supported");
    expect(r.time?.text).toContain("the attested time stands");
  });

  it("a backfilled attestation claims an earlier time too, says so, and is attested when anchored — never backdated, never faulted", async () => {
    const r = await verifyLogInclusion(read("inclusion-backfilled.json"), opts);
    expect(r.ok).toBe(true);
    expect(r.time?.backfilled).toBe(true);
    expect(r.time?.fault).toBeNull();
    expect(r.time?.attestedAtUnix).toBe(CTX.heads[1].witnessedAt);
    expect(r.time?.text).toContain("attested when anchored, never backdated");
  });

  it("without the signature check the token's time is read, never relied on: no attested time, and no fault either way", async () => {
    const r = await verifyLogInclusion(read("inclusion-backdated.json"), { logId: CTX.logId });
    expect(r.ok).toBe(true);
    expect(r.witnesses[0]?.state).toBe("unchecked");
    expect(r.witnesses[0]?.detail).toContain("openssl ts -verify");
    expect(r.time?.state).toBe("unwitnessed");
    expect(r.time?.attestedAtUnix).toBeNull();
    expect(r.time?.text).toContain("only the log's word");
  });

  it("a proof carries no other entry: not another salted hash, key or list", () => {
    const entries = readFileSync(join(V, "original", "entries", "000000.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const [file, index] of [["inclusion-attestation-ok.json", 3], ["inclusion-backdated.json", 8], ["inclusion-trust-list.json", 0]] as const) {
      const text = readFileSync(join(V, file), "utf8");
      for (const [i, e] of entries.entries()) {
        if (i === index) continue;
        for (const value of [e.salted, e.sha256, e.keyid, e.id]) if (typeof value === "string") expect({ file, i, value, held: text.includes(value) }).toEqual({ file, i, value, held: false });
      }
      // ⌈log₂ 9⌉ = 4: no path is longer.
      expect((JSON.parse(text) as { path: string[] }).path.length).toBeLessThanOrEqual(4);
    }
  });

  it("a changed path, index, size, head, entry or log id fails; a refused entry never reaches the tree", async () => {
    const base = read("inclusion-attestation-ok.json");
    const other = read("inclusion-trust-list.json");
    const cases: [string, (p: any) => void, LogInclusionFailureReason][] = [
      ["a flipped sibling", (p) => { p.path[0] = p.path[0].replace(/^./, (c: string) => (c === "0" ? "1" : "0")); }, "NOT_INCLUDED"],
      ["another index", (p) => { p.leafIndex = 2; }, "NOT_INCLUDED"],
      ["another size", (p) => { p.treeSize = 7; }, "NOT_INCLUDED"],
      ["another head", (p) => { p.checkpoint = other.checkpoint; }, "NOT_INCLUDED"],
      ["an altered entry", (p) => { p.entry.claimedAtUnix += 1; }, "NOT_INCLUDED"],
      ["another log's checkpoint", (p) => { p.checkpoint = files("tampered", "stranger").checkpoints.at(-1); }, "CHECKPOINT_INVALID"],
      ["a person in the entry", (p) => { p.entry.holder = "did:kash:z"; }, "ENTRY_REFUSED"],
      ["a presentation as the entry", (p) => { p.entry = { kind: "presentation", verifier: "x" }; }, "ENTRY_REFUSED"],
      ["no path at all", (p) => { p.path = "nope"; }, "MALFORMED_PROOF"],
      ["a log id that is not the checkpoint's", (p) => { p.logId = `${CTX.strangerDid}/log/sample`; }, "LOG_ID_MISMATCH"],
    ];
    for (const [what, change, reason] of cases) {
      const p = structuredClone(base);
      change(p);
      const r = await verifyLogInclusion(p, { maxBatchDelaySec: 86_400, verifyRfc3161Signature: signed });
      expect({ what, reason: r.reason, ok: r.ok }).toEqual({ what, reason, ok: false });
    }
    expect((await verifyLogInclusion("junk")).reason).toBe("MALFORMED_PROOF");
    expect((await verifyLogInclusion({ format: "kashscript-log-inclusion/9" })).reason).toBe("MALFORMED_PROOF");
  });

  it("a witness over another digest, or one that is not a proof, gives no attested time", async () => {
    const p = read("inclusion-attestation-ok.json");
    p.witnesses = [read("inclusion-trust-list.json").witnesses[0]];
    const r = await verifyLogInclusion(p, opts);
    expect(r.ok).toBe(true); // inclusion holds; the time does not
    expect(r.witnesses[0]?.digestOk).toBe(false);
    expect(r.time?.state).toBe("unwitnessed");
    p.witnesses = [{ kind: "rfc3161", proofBase64: "AAEC" }];
    expect((await verifyLogInclusion(p, opts)).witnesses[0]?.state).toBe("invalid");
    p.witnesses = [{ kind: "opentimestamps", proofBase64: "AAEC" }, "junk"];
    const r2 = await verifyLogInclusion(p, opts);
    expect(r2.witnesses.map((w) => w.state)).toEqual(["invalid", "invalid"]);
  });
});

describe("the witnesses through openssl — real RFC 3161 tokens from the vectors' SAMPLE authority", () => {
  const root = join(V, "sample-tsa-root.crt");
  const have = opensslAvailable();

  it("every head's token verifies against the SAMPLE root, and the backdated attestation is caught end to end", async () => {
    if (!have) {
      console.warn("openssl not found — the end-to-end witness check was skipped");
      return;
    }
    const { check, rootSha256 } = opensslRfc3161Check(root);
    expect(rootSha256).toMatch(/^[0-9a-f]{64}$/);
    const audit = await auditLog(files("original"), { verifyRfc3161Signature: check });
    expect(audit.ok).toBe(true);
    expect(audit.checkpoints.map((c) => [c.treeSize, c.witnesses.map((w) => w.state)])).toEqual([[4, ["final"]], [7, ["final"]], [9, ["final"]]]);
    expect(audit.timeFindings.map((f) => [f.index, f.fault])).toEqual([[8, "CLAIMED_BEFORE_WITNESS"]]);
    const caught = await verifyLogInclusion(read("inclusion-backdated.json"), { logId: CTX.logId, maxBatchDelaySec: CTX.maxBatchDelaySec, verifyRfc3161Signature: check });
    expect([caught.ok, caught.reason, caught.time?.fault]).toEqual([false, "TIME_NOT_SUPPORTED", "CLAIMED_BEFORE_WITNESS"]);
    expect(caught.witnesses[0]?.by).toBe("SAMPLE Time Authority (RFC 3161)");
    const fine = await verifyLogInclusion(read("inclusion-attestation-ok.json"), { logId: CTX.logId, maxBatchDelaySec: CTX.maxBatchDelaySec, verifyRfc3161Signature: check });
    expect([fine.ok, fine.time?.state]).toEqual([true, "attested"]);
  });

  it("against another root the same tokens give no attested time — the root is the caller's choice, and the only trust anchor", async () => {
    if (!have) return;
    const { check } = opensslRfc3161Check(join(import.meta.dir, "vectors", "witness", "digicert-trusted-root-g4.crt"));
    const r = await verifyLogInclusion(read("inclusion-backdated.json"), { logId: CTX.logId, verifyRfc3161Signature: check });
    expect(r.witnesses[0]?.state).toBe("unchecked");
    expect(r.time?.state).toBe("unwitnessed");
    expect(r.ok).toBe(true); // in the log, with no time to judge its claim by
  });
});

describe("consistency proofs — the later head extends the earlier", () => {
  it("the three vectors verify", async () => {
    for (const [file, first, second] of [["consistency-4-7.json", 4, 7], ["consistency-7-9.json", 7, 9], ["consistency-4-9.json", 4, 9]] as const) {
      const r = await verifyLogConsistency(read(file), { logId: CTX.logId });
      expect({ file, reason: r.reason, ok: r.ok, consistent: r.consistent }).toEqual({ file, reason: null, ok: true, consistent: true });
      expect([r.first?.treeSize, r.second?.treeSize]).toEqual([first, second]);
    }
    const skip = await verifyLogConsistency(read("consistency-4-9.json"));
    expect(skip.notes.join(" ")).toContain("not its direct successor");
  });

  it("a changed path, swapped heads or a stranger's head fails", async () => {
    const base = read("consistency-4-7.json");
    let p = structuredClone(base);
    p.path[0] = p.path[0].replace(/^./, (c: string) => (c === "0" ? "1" : "0"));
    expect((await verifyLogConsistency(p)).reason).toBe("NOT_CONSISTENT");
    p = structuredClone(base);
    p.checkpoints = { first: base.checkpoints.second, second: base.checkpoints.first };
    expect((await verifyLogConsistency(p)).reason).toBe("NOT_CONSISTENT");
    p = structuredClone(base);
    p.checkpoints.second = files("tampered", "stranger").checkpoints.at(-1);
    expect((await verifyLogConsistency(p)).reason).toBe("CHECKPOINT_INVALID");
    p = structuredClone(base);
    p.path = [];
    expect((await verifyLogConsistency(p)).reason).toBe("NOT_CONSISTENT");
    expect((await verifyLogConsistency({ format: "kashscript-log-consistency/1" })).reason).toBe("MALFORMED_PROOF");
  });
});

describe("the audit — a mirror rebuilt from the log alone matches the original; every tamper is named", () => {
  const original = files("original");

  it("the original is whole: every head's root is rebuilt from the entries, each extends the last, each witness stamps its head", async () => {
    const r = await auditLog(original, { verifyRfc3161Signature: signed });
    expect(r.faults).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.entries).toBe(9);
    expect(r.checkpoints.map((c) => [c.treeSize, c.rootMatches, c.previousOk, c.consistentWithPrevious])).toEqual([
      [4, true, true, null],
      [7, true, true, true],
      [9, true, true, true],
    ]);
    expect(r.checkpoints.map((c) => c.attestedAtUnix)).toEqual(CTX.heads.map((h: { witnessedAt: number }) => h.witnessedAt));
    expect(r.latest?.treeSize).toBe(9);
    expect(r.notes.join(" ")).toContain("without gossip");
    // The log is whole, and the audit still names the one entry whose claim its first head's witness does not support.
    expect(r.timeFindings.map((f) => [f.index, f.kind, f.fault, f.headSize])).toEqual([[8, "attestation", "CLAIMED_BEFORE_WITNESS", 9]]);
    expect(r.notes.join(" ")).toContain("the log is whole; those claims are not");
  });

  it("without the witnesses' signatures checked, the audit gives no attested time and judges no claim", async () => {
    const r = await auditLog(original);
    expect(r.ok).toBe(true);
    expect(r.checkpoints.every((c) => c.attestedAtUnix === null)).toBe(true);
    expect(r.timeFindings).toEqual([]);
    expect(r.notes.join(" ")).toContain("its time is the log's own claim");
  });

  it("the mirror, rebuilt from its entries alone, reaches every root the original signed", async () => {
    const r = await auditLog(original, { mirror: files("mirror") });
    expect(r.faults).toEqual([]);
    expect(r.ok).toBe(true);
    // And from the raw entries, without the audit: the same roots as the checkpoints.
    const rebuilt = await rebuildFromEntries(files("mirror").entries);
    expect(rebuilt.ok).toBe(true);
    for (const c of r.checkpoints) expect(await rebuilt.rootAt(c.treeSize)).toBe(c.rootHash);
  });

  it("an altered, a removed and a reordered entry are each caught — as a mirror, and on their own", async () => {
    for (const [name, size] of [["altered", 4], ["removed", 7], ["reordered", 4]] as const) {
      const asMirror = await auditLog(original, { mirror: files("tampered", name) });
      expect({ name, codes: asMirror.faults.map((f) => f.code) }).toEqual({ name, codes: expect.arrayContaining(["MIRROR_ROOT_MISMATCH"]) });
      expect(asMirror.faults.find((f) => f.code === "MIRROR_ROOT_MISMATCH")?.at).toBe(size);
      const alone = await auditLog(files("tampered", name));
      expect({ name, ok: alone.ok, codes: [...new Set(alone.faults.map((f) => f.code))] }).toEqual({ name, ok: false, codes: expect.arrayContaining([name === "removed" ? "SIZE_BEYOND_ENTRIES" : "ROOT_MISMATCH"]) });
    }
  });

  it("a head signed by a stranger over the log's id is refused, and the chain before it stands", async () => {
    const r = await auditLog(files("tampered", "stranger"));
    expect(r.ok).toBe(false);
    expect(r.faults.map((f) => [f.code, f.at])).toEqual([["CHECKPOINT_INVALID", 9]]);
    expect(r.checkpoints.map((c) => c.treeSize)).toEqual([4, 7]);
    // As a mirror it is named too: its entries rebuild every root, but it serves a head the log's key did not sign.
    const asMirror = await auditLog(original, { mirror: files("tampered", "stranger") });
    expect(asMirror.faults.map((f) => [f.code, f.at])).toEqual([["MIRROR_CHECKPOINT_INVALID", 9]]);
  });

  it("two heads of one size with different roots, both signed by the log's key, are a split view — seen only because both are held", async () => {
    const r = await auditLog(files("tampered", "split"));
    expect(r.ok).toBe(false);
    expect(r.faults.map((f) => f.code)).toEqual(expect.arrayContaining(["SPLIT_VIEW", "ROOT_MISMATCH"]));
    // Held as a mirror of the original, the other view is reported the same way.
    const viaMirror = await auditLog(original, { mirror: files("tampered", "split") });
    expect(viaMirror.faults.map((f) => f.code)).toEqual(["SPLIT_VIEW"]);
    expect(viaMirror.notes.join(" ")).toContain("split view shown to someone else is not caught here");
  });

  it("a mirror of another log, and a descriptor that does not read, are named", async () => {
    const other: LogFiles = { ...original, descriptor: { ...(original.descriptor as object), logId: `${CTX.strangerDid}/log/sample`, key: CTX.strangerDid } };
    const r = await auditLog(original, { mirror: other });
    expect(r.faults.map((f) => f.code)).toEqual(["MIRROR_DESCRIPTOR_DIFFERS"]);
    const bad = await auditLog({ ...original, descriptor: { format: "nope" } });
    expect(bad.faults.map((f) => f.code)).toContain("DESCRIPTOR_MALFORMED");
  });
});

describe("the writer — append-only, a head only over what is held, a time that never goes back", () => {
  const T = 1_800_000_000;
  const att = (claimedAtUnix: number, n: number): LogEntry => ({ v: 1, kind: "attestation", issuer: "did:web:issuer.example", salted: n.toString(16).padStart(64, "0"), claimedAtUnix });

  it("refuses an entry the guard refuses before any leaf is made, signs heads in order, proves against signed heads only", async () => {
    const pair = await generateKeyPair();
    const did = deriveDid(pair.publicKey);
    const store = new InMemoryLogStore();
    const log = await openTrustLog({ logId: `${did}/log/t`, store, signer: { keyid: did, privateKey: pair.privateKey, publicKey: pair.publicKey } });
    await expect(log.append({ ...att(T, 1), holder: "x" } as unknown as LogEntry)).rejects.toThrow("FORBIDDEN_FIELD");
    await expect(log.checkpoint(T)).rejects.toThrow("empty log");
    expect(await store.size()).toBe(0);
    for (let i = 0; i < 5; i++) await log.append(att(T + i, i));
    await expect(log.inclusionProof(0)).rejects.toThrow("no checkpoint yet");
    const h5 = await log.checkpoint(T + 10);
    expect((await verifyCheckpoint(h5)).treeSize).toBe(5);
    await expect(log.checkpoint(T + 9)).rejects.toThrow("never goes backwards");
    await log.append(att(T + 20, 5));
    const h6 = await log.checkpoint(T + 30);
    expect((await verifyCheckpoint(h6)).previous).toEqual({ treeSize: 5, rootHash: (await verifyCheckpoint(h5)).rootHash! });
    await expect(log.inclusionProof(0, 4)).rejects.toThrow("no checkpoint of size 4");
    const proof = await log.inclusionProof(2, 5);
    expect((await verifyLogInclusion(proof, { logId: log.logId })).ok).toBe(true);
    const cons = await log.consistencyProof(5, 6);
    expect((await verifyLogConsistency(cons)).ok).toBe(true);
    await expect(log.consistencyProof(3, 6)).rejects.toThrow("signed checkpoints");
    // A stranger's signer never opens the log.
    const stranger = await generateKeyPair();
    await expect(openTrustLog({ logId: `${did}/log/t`, store, signer: { keyid: deriveDid(stranger.publicKey), ...stranger } })).rejects.toThrow("signed by");
    expect(() => describeLog({ logId: "not-a-log", startedAtUnix: T })).toThrow();
    expect(describeLog({ logId: `${did}/log/t`, startedAtUnix: T }).maxBatchDelaySec).toBe(86_400);
  });

  it("the time verdict alone: pending and unwitnessed give no attested time; a claim after the witness is impossible", () => {
    const e = att(T, 1);
    const pending = timeVerdict({ entry: e, checkpointTimestampUnix: T + 5, witnesses: [{ kind: "opentimestamps", state: "pending", timeUnix: null, digestOk: true, by: "calendars", detail: "" }] });
    expect([pending.state, pending.attestedAtUnix, pending.fault]).toEqual(["pending", null, null]);
    const none = timeVerdict({ entry: e, checkpointTimestampUnix: T + 5, witnesses: [] });
    expect([none.state, none.fault]).toEqual(["unwitnessed", null]);
    const future = timeVerdict({ entry: att(T + 10_000, 1), checkpointTimestampUnix: T, witnesses: [{ kind: "rfc3161", state: "final", timeUnix: T, digestOk: true, by: "x", detail: "" }] });
    expect(future.fault).toBe("CLAIMED_AFTER_WITNESS");
    const earliest = timeVerdict({
      entry: e,
      checkpointTimestampUnix: T,
      witnesses: [
        { kind: "rfc3161", state: "final", timeUnix: T + 50, digestOk: true, by: "later", detail: "" },
        { kind: "opentimestamps", state: "final", timeUnix: T + 20, digestOk: true, by: "Bitcoin block 1", detail: "" },
        { kind: "rfc3161", state: "final", timeUnix: T - 999, digestOk: false, by: "another digest", detail: "" },
      ],
    });
    expect([earliest.attestedAtUnix, earliest.by]).toEqual([T + 20, "Bitcoin block 1"]);
  });

  it("a backfilled mark holds only for a claim from before the log began — the backdated attestation marked backfilled is caught too", async () => {
    const DAY = 86_400;
    const final = (timeUnix: number) => [{ kind: "rfc3161" as const, state: "final" as const, timeUnix, digestOk: true, by: "x", detail: "" }];
    // The verdict alone: before the log's start the mark holds; after it, the entry is judged as any other.
    const early = timeVerdict({ entry: { ...att(T - 30 * DAY, 1), backfilled: true }, checkpointTimestampUnix: T + 10 * DAY, witnesses: final(T + 10 * DAY), logStartedAtUnix: T });
    expect([early.backfilled, early.backfillRefused, early.fault]).toEqual([true, false, null]);
    const late = timeVerdict({ entry: { ...att(T + DAY, 2), backfilled: true }, checkpointTimestampUnix: T + 12 * DAY, witnesses: final(T + 12 * DAY), logStartedAtUnix: T });
    expect([late.backfilled, late.backfillRefused, late.fault]).toEqual([false, true, "CLAIMED_BEFORE_WITNESS"]);
    expect(late.text).toContain("marked backfilled, but the log had begun by");
    const unknownStart = timeVerdict({ entry: { ...att(T + DAY, 2), backfilled: true }, checkpointTimestampUnix: T + 12 * DAY, witnesses: final(T + 12 * DAY) });
    expect([unknownStart.backfilled, unknownStart.backfillRefused, unknownStart.fault]).toEqual([true, false, null]);

    // A whole log: started at T; a real backfill (a month before T) and the planted one (a day after T, logged eleven days later).
    const pair = await generateKeyPair();
    const did = deriveDid(pair.publicKey);
    const store = new InMemoryLogStore();
    const log = await openTrustLog({ logId: `${did}/log/backfill`, store, signer: { keyid: did, privateKey: pair.privateKey, publicKey: pair.publicKey } });
    await log.append(att(T + 100, 1));
    await log.append({ ...att(T - 30 * DAY, 2), backfilled: true });
    const h2 = await log.checkpoint(T + 200);
    await log.append({ ...att(T + DAY, 3), backfilled: true });
    const h3 = await log.checkpoint(T + 12 * DAY);
    const witness = async (head: typeof h2, at: number) => ({ kind: "rfc3161" as const, proofBase64: bytesToBase64(fakeTimeStampResp({ digestHex: await checkpointHash(head), genTimeUnix: at })) });
    const w2 = await witness(h2, T + 300);
    const w3 = await witness(h3, T + 12 * DAY + 100);
    const logFiles: LogFiles = {
      descriptor: describeLog({ logId: log.logId, startedAtUnix: T }),
      entries: [...(await store.entries(0, 3))],
      checkpoints: [h2, h3],
      witnesses: [
        { treeSize: 2, witness: w2 },
        { treeSize: 3, witness: w3 },
      ],
    };
    const audit = await auditLog(logFiles, { verifyRfc3161Signature: signed });
    expect(audit.ok).toBe(true); // the log is whole …
    expect(audit.timeFindings.map((f) => [f.index, f.fault])).toEqual([[2, "CLAIMED_BEFORE_WITNESS"]]); // … and the planted claim is not supported
    expect(audit.timeFindings[0]!.text).toContain("marked backfilled, but the log had begun by");
    // A proof alone does not carry the log's start: it says so, and the audit is what checks the mark.
    const proof = await log.inclusionProof(2, 3, [w3]);
    const alone = await verifyLogInclusion(proof, { verifyRfc3161Signature: signed });
    expect([alone.ok, alone.time?.backfilled]).toEqual([true, true]);
    expect(alone.notes.join(" ")).toContain("a proof does not carry the log's start");
    const withStart = await verifyLogInclusion(proof, { verifyRfc3161Signature: signed, logStartedAtUnix: T });
    expect([withStart.ok, withStart.reason, withStart.time?.backfillRefused]).toEqual([false, "TIME_NOT_SUPPORTED", true]);
  });
});
