/**
 * Unit behaviours ported from the three seeds — the "unit suite ports the
 * behaviours of all three seeds" done-when for M1.
 */

import { describe, it, expect } from "bun:test";
import {
  canonicalize,
  canonicalizeBytes,
  generateKeyPair,
  signEvent,
  verifyEvent,
  encodeHex,
} from "@kashscript/identity-core";

import { signEnvelope, verifyEnvelope, pae, DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE } from "../src/dsse";
import { signRaw, verifyRaw, bytesToBase64Url } from "../src/ed25519";
import { canonicalJson, chainBlockHash, sha256Hex, GENESIS_PREV_HASH } from "../src/chain";
import { DST_REGISTRY, lookupDst, assertRegistered, isRegisteredDst } from "../src/dst";
import { AttestError, TamperError } from "../src/errors";
import {
  InMemoryDidRegistry,
  forensicConsistencyScan,
  signLedgerBlock,
  verifyLedgerSignature,
  type LedgerBlockRecord,
} from "../src/ledger";
import { signAuditBundle, verifyAuditBundle, type AuditTrailExport } from "../src/bundle";
import {
  WitnessClient,
  computeAnchorMerkleRoot,
  InMemoryAnchorReceiptStore,
  type ChainTip,
} from "../src/witness";
import { verifyReportSignature, verifyReportChain, REPORT_DST, GRANT_DST, type ChainRow } from "../src/compat/duedale-report";
import { parseIndusToken, verifyIndusToken, INDUS_PREFIX_DST } from "../src/compat/indus-token";

const enc = new TextEncoder();
function concat(...ps: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of ps) { out.set(p, o); o += p.length; }
  return out;
}

/* ── DSSE + PAE ────────────────────────────────────────────────────────── */
describe("dsse", () => {
  it("PAE matches the DSSEv1 spec string", () => {
    const got = new TextDecoder().decode(pae("t", enc.encode("hello")));
    expect(got).toBe("DSSEv1 1 t 5 hello");
  });

  it("round-trips and verifies under the signer key", async () => {
    const kp = await generateKeyPair();
    const signer = { keyid: "did:kash:test:host", privateKey: kp.privateKey, publicKey: kp.publicKey };
    const env = await signEnvelope({ hello: "world", n: 7 }, DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE, signer);
    const res = await verifyEnvelope(env, (kid) => (kid === signer.keyid ? kp.publicKey : null));
    expect(res.ok).toBe(true);
    expect(res.verifiedKeyids).toEqual([signer.keyid]);
    expect(res.payloadJson).toEqual({ hello: "world", n: 7 });
  });

  it("fails under a foreign key and on a tampered payload", async () => {
    const kp = await generateKeyPair();
    const other = await generateKeyPair();
    const signer = { keyid: "did:kash:test:host", privateKey: kp.privateKey, publicKey: kp.publicKey };
    const env = await signEnvelope({ a: 1 }, "application/x.test", signer);
    expect((await verifyEnvelope(env, () => other.publicKey)).ok).toBe(false);
    // swap the payload for different bytes → the PAE signature no longer matches
    const t2 = { ...env, payload: Buffer.from(JSON.stringify({ a: 2 })).toString("base64") };
    expect((await verifyEnvelope(t2, () => kp.publicKey)).ok).toBe(false);
  });

  it("F2 (audit r1): honours a valid signature even when a malformed sibling is appended", async () => {
    const kp = await generateKeyPair();
    const signer = { keyid: "did:kash:test:host", privateKey: kp.privateKey, publicKey: kp.publicKey };
    const env = await signEnvelope({ a: 1 }, DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE, signer);
    // An attacker appends a junk signature entry; verification must still honour
    // the valid one (DSSE = "≥1 verifies"), not throw the whole envelope away.
    const withJunk = {
      ...env,
      signatures: [...env.signatures, { keyid: 123, sig: null } as unknown as (typeof env.signatures)[number]],
    };
    const res = await verifyEnvelope(withJunk, (kid) => (kid === signer.keyid ? kp.publicKey : null));
    expect(res.ok).toBe(true);
    expect(res.verifiedKeyids).toEqual([signer.keyid]);
  });
});

/* ── raw ed25519 ───────────────────────────────────────────────────────── */
describe("ed25519", () => {
  it("signs and verifies raw bytes; rejects a wrong signature", async () => {
    const kp = await generateKeyPair();
    const msg = enc.encode("arbitrary bytes");
    const sig = await signRaw(msg, kp.privateKey, kp.publicKey);
    expect(await verifyRaw(sig, msg, kp.publicKey)).toBe(true);
    expect(await verifyRaw(sig, enc.encode("other"), kp.publicKey)).toBe(false);
  });
});

/* ── canonicalJson byte-equivalence ────────────────────────────────────── */
describe("chain canonicalJson", () => {
  it("agrees byte-for-byte with identity-core RFC-8785 canonicalize on an ASCII corpus", () => {
    const corpus: unknown[] = [
      { b: 2, a: 1 },
      { nested: { z: [1, 2, 3], y: "x" }, arr: [{ k: 1 }, { k: 2 }] },
      [true, false, null, 0, -0, 12345, "str"],
      { unicodeSafe: "abc-123_./", empty: {}, emptyArr: [] },
    ];
    for (const v of corpus) {
      expect(canonicalJson(v)).toBe(canonicalize(v));
    }
  });

  it("chainBlockHash is deterministic", async () => {
    const p = { sessionId: "s", stepIndex: 0, actorDid: "did:kash:agent:x", payloadMutation: { k: 1 }, signature: "ed25519:00" };
    const a = await chainBlockHash(p, GENESIS_PREV_HASH);
    const b = await chainBlockHash(p, GENESIS_PREV_HASH);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

/* ── DST registry ──────────────────────────────────────────────────────── */
describe("dst registry", () => {
  it("registers every live tag from the three seeds + identity-core", () => {
    for (const tag of ["kash-record-v1\n", "kash-grant-v1\n", "kash-report-v1\n", "oreoasis-ledger-v1\n", "indus.poe.v1.qr", "indus.vfc.v1.cert", "application/vnd.oreoasis.agent-receipt+json"]) {
      expect(isRegisteredDst(tag)).toBe(true);
    }
    expect(lookupDst("indus.vfc.v1.cert")?.family).toBe("indus");
    expect(lookupDst("kash-grant-v1\n")?.family).toBe("kash-event");
    // Oreoasis Agent Receipt (OS3) — a DSSE payloadType-family DST.
    expect(lookupDst("application/vnd.oreoasis.agent-receipt+json")?.family).toBe("dsse-type");
    expect(DST_REGISTRY.length).toBeGreaterThanOrEqual(10);
  });
  it("registers Indusland's KashEvent tags as kash-event, not the indus token family", () => {
    for (const tag of ["indus.label.v1\n", "indus.mark.v1\n", "indus.mark.revoke.v1\n"]) {
      expect(lookupDst(tag)?.family).toBe("kash-event");
      expect(lookupDst(tag)?.owner).toBe("indusland");
    }
    expect(lookupDst("application/vnd.indusland.tehzeeb-enrolment+json")?.family).toBe("dsse-type");
  });
  it("registers the holder contract's trust list and status list as live dsse-type tags owned by attest", () => {
    for (const tag of ["application/vnd.kash.trust-list+json", "application/vnd.kash.status-list+json"]) {
      const e = lookupDst(tag);
      expect(e?.family).toBe("dsse-type");
      expect(e?.owner).toBe("@kashscript/attest");
      expect(e?.reserved).toBeUndefined();
    }
  });
  it("registers PL-3's predicate and thank-you vct types and the session event, owners as specified", () => {
    expect(lookupDst("https://kashscript.com/vct/predicate/1")?.family).toBe("sd-jwt-vct");
    expect(lookupDst("https://kashscript.com/vct/predicate/1")?.owner).toBe("@kashscript/attest");
    expect(lookupDst("https://kashscript.com/vct/thank-you/1")?.family).toBe("sd-jwt-vct");
    expect(lookupDst("https://kashscript.com/vct/thank-you/1")?.owner).toBe("indorania");
    expect(lookupDst("application/vnd.indorania.session-event+json")?.family).toBe("dsse-type");
    expect(lookupDst("application/vnd.indorania.session-event+json")?.owner).toBe("indorania");
    for (const tag of ["https://kashscript.com/vct/predicate/1", "https://kashscript.com/vct/thank-you/1"]) {
      // Protocol identifiers stay on the apex host — never www. (CLAUDE.md).
      expect(tag.startsWith("https://kashscript.com/")).toBe(true);
    }
  });
  it("registers PL-2's recovery-helpers tag as a live kash-event owned by attest, beside the key-claim tag it feeds", () => {
    const e = lookupDst("kash-recovery-helpers-v1\n");
    expect(e?.family).toBe("kash-event");
    expect(e?.owner).toBe("@kashscript/attest");
    expect(e?.reserved).toBeUndefined();
    // Helper claims ride the existing key-claim DST — no second claim tag.
    expect(lookupDst("kash-key-claim-v1\n")?.family).toBe("kash-event");
    expect(DST_REGISTRY.filter((x) => x.tag.startsWith("kash-key-claim")).length).toBe(1);
  });
  it("registers the three tags identity-sdk already signs under — recovery, rotation, revocation — as live kash-events owned by identity-sdk", () => {
    for (const tag of ["kash-recovery-v1\n", "kash-rotation-v1\n", "kash-revocation-v1\n"]) {
      const e = lookupDst(tag);
      expect(e?.family).toBe("kash-event");
      expect(e?.owner).toBe("@kashscript/identity-sdk");
      expect(e?.reserved).toBeUndefined();
    }
  });
  it("registers the session anchor's leaf tag as the one merkle-leaf, owned by attest (GP-6)", () => {
    const e = lookupDst("kash-session-head-v1\n");
    expect(e?.family).toBe("merkle-leaf");
    expect(e?.owner).toBe("@kashscript/attest");
    expect(e?.reserved).toBeUndefined();
    expect(DST_REGISTRY.filter((x) => x.family === "merkle-leaf").map((x) => x.tag)).toEqual(["kash-session-head-v1\n"]);
  });
  it("holds every tag exactly once — a duplicate row would silently shadow another in the lookup map", () => {
    const tags = DST_REGISTRY.map((e) => e.tag);
    expect(new Set(tags).size).toBe(tags.length);
  });
  it("throws on an unregistered DST", () => {
    expect(() => assertRegistered("made-up-v9\n")).toThrow(AttestError);
  });
});

/* ── ledger forensic scan (Oreoasis) ───────────────────────────────────── */
async function buildChain(mutations: Array<Record<string, unknown>>) {
  const kp = await generateKeyPair();
  const did = "did:kash:agent:test-runtime";
  const reg = new InMemoryDidRegistry();
  reg.register({ did, publicKeyBytes: kp.publicKey, algorithm: "ed25519" });
  const rows: LedgerBlockRecord[] = [];
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i < mutations.length; i++) {
    const payloadMutation = mutations[i]!;
    const signature = await signLedgerBlock({ sessionId: "s1", stepIndex: i, actorDid: did, previousBlockHash: prev, payloadMutation }, kp.privateKey);
    const cur = await chainBlockHash({ sessionId: "s1", stepIndex: i, actorDid: did, payloadMutation, signature }, prev);
    rows.push({ sessionId: "s1", stepIndex: i, previousBlockHash: prev, currentTransactionBlockHash: cur, actorDid: did, payloadMutation, signature, emittedAt: "2026-01-01T00:00:00.000Z", localId: i + 1 });
    prev = cur;
  }
  return { rows, reg, did, kp };
}

describe("ledger forensic scan", () => {
  it("passes a clean chain and reports rowCount", async () => {
    const { rows, reg } = await buildChain([{ event: "a" }, { event: "b" }, { event: "c" }]);
    const report = await forensicConsistencyScan("s1", rows, reg, "2026-01-01T00:00:00.000Z");
    expect(report.ok).toBe(true);
    expect(report.rowCount).toBe(3);
    expect(report.chainHashes.length).toBe(3);
  });

  it("empty chain returns ok rowCount 0", async () => {
    const { reg } = await buildChain([]);
    expect((await forensicConsistencyScan("s1", [], reg)).rowCount).toBe(0);
  });

  it("throws PAYLOAD_HASH_VARIANCE when a payload is mutated", async () => {
    const { rows, reg } = await buildChain([{ event: "a" }, { event: "b" }]);
    const tampered = rows.map((r, i) => (i === 1 ? { ...r, payloadMutation: { event: "TAMPERED" } } : r));
    await expect(forensicConsistencyScan("s1", tampered, reg)).rejects.toThrow(TamperError);
  });

  it("throws STEP_INDEX_GAP when a row is dropped", async () => {
    const { rows, reg } = await buildChain([{ event: "a" }, { event: "b" }, { event: "c" }]);
    await expect(forensicConsistencyScan("s1", [rows[0]!, rows[2]!], reg)).rejects.toThrow(/STEP_INDEX_GAP/);
  });

  it("throws PREVIOUS_HASH_MISMATCH when a prev-hash is broken", async () => {
    const { rows, reg } = await buildChain([{ event: "a" }, { event: "b" }]);
    const broken = rows.map((r, i) => (i === 1 ? { ...r, previousBlockHash: GENESIS_PREV_HASH } : r));
    await expect(forensicConsistencyScan("s1", broken, reg)).rejects.toThrow(/PREVIOUS_HASH_MISMATCH|PAYLOAD_HASH_VARIANCE/);
  });

  it("throws SIGNATURE_VERIFY_FAILED under a foreign DID key", async () => {
    const { rows } = await buildChain([{ event: "a" }]);
    const foreign = new InMemoryDidRegistry();
    const other = await generateKeyPair();
    foreign.register({ did: rows[0]!.actorDid, publicKeyBytes: other.publicKey, algorithm: "ed25519" });
    await expect(forensicConsistencyScan("s1", rows, foreign)).rejects.toThrow(/SIGNATURE_VERIFY_FAILED/);
  });

  it("verifyLedgerSignature accepts a genuine row and rejects an unknown actor", async () => {
    const { rows, reg } = await buildChain([{ event: "a" }]);
    const r = rows[0]!;
    expect(await verifyLedgerSignature({ signatureWire: r.signature, payload: { sessionId: r.sessionId, stepIndex: r.stepIndex, actorDid: r.actorDid, previousBlockHash: r.previousBlockHash, payloadMutation: r.payloadMutation }, didRegistry: reg })).toBe(true);
    await expect(verifyLedgerSignature({ signatureWire: r.signature, payload: { sessionId: r.sessionId, stepIndex: r.stepIndex, actorDid: "did:kash:agent:nobody", previousBlockHash: r.previousBlockHash, payloadMutation: r.payloadMutation }, didRegistry: reg })).rejects.toThrow(/no entry for/);
  });
});

/* ── bundle round-trip ─────────────────────────────────────────────────── */
describe("audit bundle", () => {
  it("signs and verifies an export; detects a mutated row", async () => {
    const { rows, did, kp } = await buildChain([{ event: "x" }, { event: "y" }]);
    const exp: AuditTrailExport = { sessionId: "s1", rows, dids: [{ did, publicKeyHex: encodeHex(kp.publicKey) }], exportedAtIso: "2026-01-01T00:00:00.000Z" };
    const signer = { keyid: "did:kash:test:host", privateKey: kp.privateKey, publicKey: kp.publicKey };
    const bundleExp: AuditTrailExport = { ...exp, dids: [...exp.dids, { did: signer.keyid, publicKeyHex: encodeHex(kp.publicKey) }] };
    const env = await signAuditBundle(bundleExp, signer);
    const rep = await verifyAuditBundle(env, { requireSignerDid: signer.keyid });
    expect(rep.ok).toBe(true);
    // mutate a row inside the payload → re-signing the envelope but the chain breaks
    const tamperedExp = { ...bundleExp, rows: bundleExp.rows.map((r, i) => (i === 1 ? { ...r, payloadMutation: { event: "TAMPERED" } } : r)) };
    const tenv = await signAuditBundle(tamperedExp, signer);
    await expect(verifyAuditBundle(tenv, { requireSignerDid: signer.keyid })).rejects.toThrow(TamperError);
  });
});

/* ── witness (offline) + anchor merkle + receipt store ─────────────────── */
describe("witness", () => {
  it("offline → backend none, never throws", async () => {
    const kp = await generateKeyPair();
    const client = new WitnessClient({ offline: true });
    const w = await client.witness({ merkleRootHex: "ab".repeat(32), signer: { keyid: "did:kash:test:host", privateKey: kp.privateKey, publicKey: kp.publicKey } });
    expect(w.backend).toBe("none");
    expect(w.witnessedAt).toBeNull();
  });
  it("anchor merkle root is deterministic + order-independent", async () => {
    const tips: ChainTip[] = [
      { sessionId: "b", latestHash: "22", latestStepIndex: 1 },
      { sessionId: "a", latestHash: "11", latestStepIndex: 0 },
    ];
    const r1 = await computeAnchorMerkleRoot(tips);
    const r2 = await computeAnchorMerkleRoot([...tips].reverse());
    expect(r1).toBe(r2);
  });
  it("receipt store append/latest/latestForRoot", async () => {
    const store = new InMemoryAnchorReceiptStore();
    const rec = await store.append({ publishedAt: "t", merkleRoot: "root-1", tipCount: 0, tips: [] });
    expect((await store.latest())?.id).toBe(rec.id);
    expect((await store.latestForRoot("root-1"))?.merkleRoot).toBe("root-1");
    expect(await store.latestForRoot("nope")).toBeNull();
  });
});

/* ── Duedale report crypto ─────────────────────────────────────────────── */
describe("duedale report", () => {
  async function mkReport() {
    const op = await generateKeyPair();
    const GEN = "duedale-every-rupee-chain-v1";
    const rows: ChainRow[] = [
      { grantId: "g1", toState: "ISSUED", actorDid: "did:kash:funder:x", actorClass: "FUNDER", reason: "grant issued", code: null, atUnix: 1 },
      { grantId: "g1", toState: "REDEEMED", actorDid: "did:kash:vendor:x", actorClass: "VENDOR", reason: "redeemed", code: null, atUnix: 2 },
    ];
    const links: Array<{ seq: number; row: ChainRow; rowHashHex: string; prevHashHex: string }> = [];
    let prev = await sha256Hex(enc.encode(GEN));
    let seq = 0;
    for (const row of rows) {
      const rh = await sha256Hex(concat(enc.encode(prev), canonicalizeBytes(row)));
      links.push({ seq, row, rowHashHex: rh, prevHashHex: prev });
      prev = rh; seq += 1;
    }
    const report = { meta: { reportId: "r1" }, chain: { genesisLabel: GEN, headHashHex: links[links.length - 1]!.rowHashHex, links } };
    const header = { typ: "duedale/every-rupee-report", v: 1, reportId: "r1" };
    const signature = await signEvent(header, report, op.privateKey, { dst: REPORT_DST });
    return { signed: { report, signature, operatorPublicKeyHex: encodeHex(op.publicKey) }, op };
  }

  it("verifies a genuine envelope signature + recomputes the chain genesis→head", async () => {
    const { signed, op } = await mkReport();
    expect(await verifyReportSignature(signed, op.publicKey)).toBe(true);
    expect((await verifyReportChain(signed.report)).ok).toBe(true);
  });

  it("rejects a foreign operator key and a tampered chain link", async () => {
    const { signed } = await mkReport();
    const foreign = await generateKeyPair();
    expect(await verifyReportSignature(signed, foreign.publicKey)).toBe(false);
    const t = { ...signed.report, chain: { ...signed.report.chain, links: signed.report.chain.links.map((l, i) => (i === 0 ? { ...l, row: { ...(l.row as ChainRow), reason: "TAMPERED" } } : l)) } };
    expect((await verifyReportChain(t)).ok).toBe(false);
  });

  it("domain separation — a report signature does not verify under the grant DST", async () => {
    const { signed, op } = await mkReport();
    const asGrant = await verifyEvent(
      { header: { typ: "duedale/every-rupee-report", v: 1, reportId: "r1" }, body: signed.report, signature: { ...signed.signature, dst: GRANT_DST } },
      op.publicKey,
    );
    expect(asGrant).toBe(false);
  });
});

/* ── Indus tokens ──────────────────────────────────────────────────────── */
describe("indus tokens", () => {
  async function mkToken(prefix: string, body: Record<string, unknown>, kp: { privateKey: Uint8Array; publicKey: Uint8Array }) {
    const dst = INDUS_PREFIX_DST[prefix]!;
    const header = { alg: "EdDSA", kid: "indus.platform.x", v: 1, typ: prefix };
    const hB = bytesToBase64Url(enc.encode(JSON.stringify(header)));
    const bB = bytesToBase64Url(enc.encode(canonicalize(body)));
    const si = concat(enc.encode(dst), new Uint8Array([0]), enc.encode(hB), enc.encode("."), enc.encode(bB));
    const sig = await signRaw(si, kp.privateKey, kp.publicKey);
    return `${prefix}.${hB}.${bB}.${bytesToBase64Url(sig)}`;
  }

  it("parses prefixes to the right DST", () => {
    expect(INDUS_PREFIX_DST.IVFC1).toBe("indus.vfc.v1.cert");
    expect(INDUS_PREFIX_DST.IPOE1).toBe("indus.poe.v1.qr");
  });

  it("verifies a genuine IPOE1 and rejects a mutated body / wrong key / expired window", async () => {
    const kp = await generateKeyPair();
    const now = 1_000_000;
    const token = await mkToken("IPOE1", { iss: "venue-1", poi: "poi-1", iat: now, exp: now + 300, nonce: "n1", tier: "public" }, kp);
    expect((await verifyIndusToken(token, kp.publicKey, { nowSec: now })).ok).toBe(true);
    // wrong key
    const other = await generateKeyPair();
    expect((await verifyIndusToken(token, other.publicKey, { nowSec: now })).signatureOk).toBe(false);
    // expired
    expect((await verifyIndusToken(token, kp.publicKey, { nowSec: now + 10_000 })).timeOk).toBe(false);
    // tampered body (swap a segment) → sig fails
    const parts = token.split(".");
    const bad = [parts[0], parts[1], bytesToBase64Url(enc.encode(canonicalize({ iss: "venue-EVIL", iat: now, exp: now + 300 }))), parts[3]].join(".");
    expect((await verifyIndusToken(bad, kp.publicKey, { nowSec: now })).signatureOk).toBe(false);
  });

  it("cross-prefix — an IVFC1-signed token re-labelled IPOE1 fails (DST changes)", async () => {
    const kp = await generateKeyPair();
    const token = await mkToken("IVFC1", { typ: "IVFC1", iss: "indus.platform", certId: "x", org: "o", period: { label: "2026-05" }, iat: 1 }, kp);
    const relabelled = "IPOE1" + token.slice("IVFC1".length);
    const parsed = parseIndusToken(relabelled);
    expect(parsed.dst).toBe("indus.poe.v1.qr");
    expect((await verifyIndusToken(relabelled, kp.publicKey, { nowSec: 1 })).signatureOk).toBe(false);
  });
});
