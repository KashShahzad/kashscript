/**
 * The holder contract (specs/holder-contract.md), checked with attest alone.
 *
 * The vectors in ./vectors/holder were generated once and are never
 * regenerated; these tests read them. The trust list's publisher is pinned
 * here exactly as a verifier would pin it — out of band, by its DID.
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizeBytes, deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "../src/chain";
import { base64ToBytes, base64UrlToBytes, bytesToBase64, signRaw } from "../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../src/dsse";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  DST_COUNTERSIGN_WITHDRAWAL,
  countersignRequestDigest,
} from "../src/countersign";
import {
  DST_STATUS_LIST,
  DST_TRUST_LIST,
  STATUS_LIST_FORMAT,
  STATUS_LIST_MIN_ENTRIES,
  TRUST_LIST_FORMAT,
  checkStatus,
  createStatusBitstring,
  currentTrustLists,
  decodeStatusList,
  encodeStatusList,
  fetchStatusLists,
  findListing,
  getStatusBit,
  makeKeyResolver,
  recordIdOf,
  serializeHolderExport,
  setStatusBit,
  signStatusList,
  signTrustList,
  verifyHeldRecord,
  verifyHolderExport,
  verifyStatusList,
  verifyTrustList,
  type HeldRecord,
  type HolderExport,
  type HolderExportReport,
  type TrustListPayload,
} from "../src/holder";

const VEC = join(import.meta.dir, "vectors", "holder");
const FIX = join(import.meta.dir, "fixtures");
const PUBLISHER = "did:kash:CJyXiKAaH3EeBHm4ympbXJPBNE4JoTuA4QYVvRS5u3CT";
const ORG = "did:kash:AqpfoVEdhjc73G3n4HqgmjZZy7dYMhqs3SaQPoWLvFRv";
const EXPORTED_AT = 1_790_208_000;
const PASSPHRASE = "test vector only — never a real backup";
const PIN = { pinnedPublishers: [PUBLISHER] };

const rawExport = readFileSync(join(VEC, "holder-export.v1.json"), "utf8");
const loadExport = (): HolderExport => JSON.parse(rawExport) as HolderExport;
const trustListEnv = (): DsseEnvelope => JSON.parse(readFileSync(join(VEC, "trust-list.v1.json"), "utf8")) as DsseEnvelope;
const statusListEnv = (): DsseEnvelope => JSON.parse(readFileSync(join(VEC, "status-list.v1.json"), "utf8")) as DsseEnvelope;

function recordOf(e: HolderExport, tag: string, statusIndex?: string): HeldRecord {
  const r = e.records.find(
    (x) => x.manifest.type.tag === tag && (statusIndex === undefined || x.manifest.status?.statusListIndex === statusIndex),
  );
  if (r === undefined) throw new Error(`no record ${tag}`);
  return r as HeldRecord;
}
function reportOf(rep: HolderExportReport, tag: string, statusIndex?: string) {
  const e = loadExport();
  const id = recordOf(e, tag, statusIndex).manifest.recordId;
  const r = rep.records.find((x) => x.recordId === id);
  if (r === undefined) throw new Error(`no report ${tag}`);
  return r;
}
/** Replace one record's manifest and return a fresh export. */
function withManifest(tag: string, patch: Record<string, unknown>, statusIndex?: string): HolderExport {
  const e = loadExport();
  const records = e.records.map((r) =>
    r.manifest.type.tag === tag && (statusIndex === undefined || r.manifest.status?.statusListIndex === statusIndex)
      ? { ...r, manifest: { ...r.manifest, ...patch } }
      : r,
  );
  return { ...e, records } as HolderExport;
}

/** Run `fn` with every network entry point in this process disabled. */
async function offline<T>(fn: () => Promise<T>): Promise<{ result: T; attempts: number }> {
  const realFetch = globalThis.fetch;
  let attempts = 0;
  globalThis.fetch = (() => {
    attempts += 1;
    throw new Error("network disabled for this test");
  }) as unknown as typeof fetch;
  try {
    return { result: await fn(), attempts };
  } finally {
    globalThis.fetch = realFetch;
  }
}

/* ── 1. existing vectors, untouched ────────────────────────────────────── */

describe("holder — every existing vector is untouched", () => {
  // SHA-256 over each committed fixture with line endings normalised to LF, so
  // the pin holds on every checkout. A changed hash means a vector was edited.
  const FIXTURE_SHA256: Record<string, string> = {
    "countersign-bundle.json": "55d5e7789201fc1ee1a2abed301fdcb97a073aa953a633075faa66825e164a3a",
    "duedale-report.json": "0a1cfe96dc1b193d17ea5ad96082a6d29c2cae3bfdb4e0ecb4284c1048d87498",
    "indus-ivfc1.token.txt": "85eca8936c850da9550edc3ae6f0f71c3e10db84c16fd8dde89afcb479af51ed",
    "indus-keys.json": "729fa8cd31e2560706ba2b5003f1235d9505cd0ebf8e32fb66c9ef6fd4d8b38e",
    "oreoasis-audit-bundle.dsse.json": "2ec048dffe47ad197182b0f4cf9f15eb58033483c609b937880b6f4a4f83c3cb",
    "oreoasis-host-public-key.txt": "e9ffadf9614272c6548d204926118cde494a280300fdbdcf4844b5fb612b097a",
  };
  for (const [file, pinned] of Object.entries(FIXTURE_SHA256)) {
    it(`fixtures/${file} is byte-identical to the committed vector`, async () => {
      const text = readFileSync(join(FIX, file), "utf8").replace(/\r\n/g, "\n");
      expect(await sha256Hex(new TextEncoder().encode(text))).toBe(pinned);
    });
  }

  it("the Oreoasis agent receipt and work record are the original envelopes, byte for byte", async () => {
    // JCS digests taken from Oreoasis 2.0/packages/sdk/vectors/*.json when copied.
    const expected: Record<string, string> = {
      "oreoasis-agent-receipt.json": "7344996c1775a777af3a73045dc008854677ccb6653f511d49cde9f8800cd429",
      "oreoasis-work-record.json": "a7bacf86fc0483c08656c532c0bedee29647d1b6d9b457d6031b26053d81435f",
    };
    for (const [file, digest] of Object.entries(expected)) {
      const copy = JSON.parse(readFileSync(join(VEC, "source", file), "utf8")) as { envelope: unknown };
      expect(await sha256Hex(canonicalizeBytes(copy.envelope))).toBe(digest);
      expect(loadExport().records.some((r) => r.manifest.recordId === digest)).toBe(true);
    }
  });

  it("the export carries the IVFC1 token and the countersign bundle exactly as the fixtures hold them", async () => {
    const e = loadExport();
    const token = readFileSync(join(FIX, "indus-ivfc1.token.txt"), "utf8").trim();
    expect(recordOf(e, "indus.vfc.v1.cert").artifact.value).toBe(token);
    const cs = JSON.parse(readFileSync(join(FIX, "countersign-bundle.json"), "utf8"));
    const held = recordOf(e, "application/vnd.example.delivery+json").artifact.value;
    expect(await sha256Hex(canonicalizeBytes(held))).toBe(await sha256Hex(canonicalizeBytes(cs)));
  });
});

/* ── 2. the export, offline ────────────────────────────────────────────── */

describe("holder — the export verifies with networking disabled", () => {
  it("passes with no fetch attempted, from the file alone", async () => {
    const { result, attempts } = await offline(() => verifyHolderExport(loadExport(), { ...PIN, rawText: rawExport }));
    expect(attempts).toBe(0);
    expect(result.reasons).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.network).toBe("none");
    expect(result.records).toHaveLength(12);
    expect(result.records.every((r) => r.ok && r.signatureOk)).toBe(true);
  });

  it("holds one of every kind the contract must carry untouched", async () => {
    const tags = new Set(loadExport().records.map((r) => r.manifest.type.tag));
    for (const t of [
      "indus.poe.v1.qr",
      "indus.poe.v1.geo",
      "indus.vfc.v1.cert",
      "indus.bps.v1.bpass",
      "application/vnd.oreoasis.agent-receipt+json",
      "application/vnd.oreoasis.work-record+json",
      "application/vnd.oreoasis.predicate+json",
      "application/vnd.example.delivery+json", // the countersign bundle's subject
      "application/vnd.indorania.visa+json",
      "application/vnd.indorania.day+json",
      "indus.mark.v1\n",
    ]) {
      expect(tags.has(t)).toBe(true);
    }
  });

  it("is byte-stable: the file is exactly its canonical form, whatever order the records arrive in", () => {
    const e = loadExport();
    expect(serializeHolderExport(e)).toBe(rawExport);
    const shuffled = { ...e, records: [...e.records].reverse() };
    expect(serializeHolderExport(shuffled)).toBe(rawExport);
  });

  it("reports non-canonical bytes without failing a correct export", async () => {
    const pretty = JSON.stringify(JSON.parse(rawExport), null, 2);
    const r = await verifyHolderExport(JSON.parse(pretty), { ...PIN, rawText: pretty });
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(false);
  });

  it("verifies the key-succession pair, and fails a tampered one", async () => {
    const ok = await verifyHolderExport(loadExport(), PIN);
    expect(ok.keySuccession).toHaveLength(1);
    expect(ok.keySuccession[0]!.ok).toBe(true);
    const e = loadExport() as unknown as { keySuccession: { body: { claimedAtUnix: number } }[] };
    e.keySuccession[0]!.body.claimedAtUnix += 1;
    const bad = await verifyHolderExport(e, PIN);
    expect(bad.ok).toBe(false);
    expect(bad.reasons).toContain("KEY_CLAIM_INVALID");
  });

  it("returns a report, never a throw, for junk", async () => {
    for (const junk of [null, 7, "x", {}, { formatVersion: "kashscript-holder-export/1" }]) {
      const r = await verifyHolderExport(junk);
      expect(r.ok).toBe(false);
      expect(r.reasons).toContain("MALFORMED_EXPORT");
    }
  });
});

/* ── 3. the manifest is trusted for nothing ────────────────────────────── */

describe("holder — the manifest cannot make a record stronger than its bytes", () => {
  it("IGEO1 is device-asserted and can never pass as countersigned (d49 rule 5)", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    expect(reportOf(r, "indus.poe.v1.geo").attestation).toBe("device-asserted");
    const forged = await verifyHolderExport(withManifest("indus.poe.v1.geo", { type: { tag: "indus.poe.v1.geo", family: "indus", attestation: "countersigned" } }), PIN);
    expect(forged.ok).toBe(false);
    const rec = forged.records.find((x) => x.tag === "indus.poe.v1.geo")!;
    expect(rec.reasons).toContain("MANIFEST_CLASS_MISMATCH");
    expect(rec.attestation).toBe("device-asserted");
  });

  it("Indorania's practice receipts are device-asserted too — signed only by the visitor's browser", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    expect(reportOf(r, "application/vnd.indorania.visa+json").attestation).toBe("device-asserted");
    expect(reportOf(r, "application/vnd.indorania.day+json").attestation).toBe("device-asserted");
  });

  it("only the countersign bundle counts as countersigned", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    const counted = r.records.filter((x) => x.attestation === "countersigned").map((x) => x.tag);
    expect(counted).toEqual(["application/vnd.example.delivery+json"]);
  });

  it("rejects a record id that is not the artifact's own digest", async () => {
    const r = await verifyHolderExport(withManifest("indus.poe.v1.qr", { recordId: "0".repeat(64) }), PIN);
    expect(r.records.some((x) => x.reasons.includes("RECORD_ID_MISMATCH"))).toBe(true);
  });

  it("rejects a status pointer that the signed record does not carry", async () => {
    const r = await verifyHolderExport(withManifest("application/vnd.oreoasis.predicate+json", { status: null }, "17403"), PIN);
    expect(reportOf(r, "application/vnd.oreoasis.predicate+json", "17403").reasons).toContain("MANIFEST_STATUS_MISMATCH");
  });

  it("rejects an issuer the bytes do not name", async () => {
    const r = await verifyHolderExport(withManifest("indus.bps.v1.bpass", { issuer: "someone-else" }), PIN);
    expect(reportOf(r, "indus.bps.v1.bpass").reasons).toContain("MANIFEST_ISSUER_MISMATCH");
  });
});

/* ── 4. expiry is real ─────────────────────────────────────────────────── */

describe("holder — expiry is real (d27.5)", () => {
  it("an export never carries a record past its retention", async () => {
    const r = await verifyHolderExport(withManifest("indus.poe.v1.qr", { expiresAtUnix: EXPORTED_AT - 1 }), PIN);
    expect(r.ok).toBe(false);
    expect(reportOf(r, "indus.poe.v1.qr").reasons).toContain("RECORD_PAST_RETENTION");
  });

  it("a manifest cannot keep a record longer than the issuer signed", async () => {
    const r = await verifyHolderExport(withManifest("indus.mark.v1\n", { expiresAtUnix: null }), PIN);
    expect(reportOf(r, "indus.mark.v1\n").reasons).toContain("RETENTION_EXTENDED");
    const later = await verifyHolderExport(withManifest("indus.mark.v1\n", { expiresAtUnix: 1_900_000_000 }), PIN);
    expect(reportOf(later, "indus.mark.v1\n").reasons).toContain("RETENTION_EXTENDED");
  });

  it("claims a record-signed retention only where the record signs one", async () => {
    const r = await verifyHolderExport(withManifest("indus.poe.v1.qr", { retentionSource: "record" }), PIN);
    expect(reportOf(r, "indus.poe.v1.qr").reasons).toContain("RETENTION_SOURCE_UNSUPPORTED");
  });

  it("notes, without failing, a record that has passed its retention since the export", async () => {
    const r = await verifyHolderExport(loadExport(), { ...PIN, nowSec: 1_900_000_000 });
    const mark = reportOf(r, "indus.mark.v1\n");
    expect(mark.ok).toBe(true);
    expect(mark.retention.pastNow).toBe(true);
    expect(mark.notes.join(" ")).toContain("drops it");
  });
});

/* ── 5. the trust list ─────────────────────────────────────────────────── */

describe("holder — the trust list is a policy, and an unlisted issuer never renders as trusted (d47(e))", () => {
  it("verifies the vector list offline, pinned", async () => {
    const r = await verifyTrustList(trustListEnv(), PIN);
    expect(r.ok).toBe(true);
    expect(r.pinned).toBe(true);
    expect(r.current).toBe(true);
    expect(r.listId).toBe("kash-demo-trust");
  });

  it("an unpinned publisher lists nobody: every record shows as untrusted, and the export still verifies", async () => {
    const r = await verifyHolderExport(loadExport());
    expect(r.ok).toBe(true);
    expect(r.records.every((x) => !x.trusted)).toBe(true);
    expect(reportOf(r, "indus.vfc.v1.cert").listing.evidence).toBe("unpinned-list");
    expect(r.notes.join(" ")).toContain("--trust-publisher");
  });

  it("a list signed by anyone else cannot make the holder's own unlisted record trusted", async () => {
    const e = loadExport();
    const forger = await generateKeyPair();
    const forgerDid = deriveDid(forger.publicKey);
    const work = JSON.parse(readFileSync(join(VEC, "source", "oreoasis-work-record.json"), "utf8")) as { keyid: string; publicKeyHex: string };
    const forgedList = await signTrustList(
      {
        format: TRUST_LIST_FORMAT,
        listId: "forged",
        version: 99,
        publisher: forgerDid,
        issuedAtUnix: 1_767_225_600,
        validFromUnix: 1_767_225_600,
        validUntilUnix: 2_082_758_400,
        issuers: [{ issuerId: "x", label: "forged", keys: [{ keyid: work.keyid, alg: "Ed25519", publicKeyHex: work.publicKeyHex }], dsts: ["application/vnd.oreoasis.work-record+json"], validFromUnix: 1_767_225_600, validUntilUnix: 2_082_758_400 }],
      },
      { keyid: forgerDid, privateKey: forger.privateKey, publicKey: forger.publicKey },
    );
    const r = await verifyHolderExport({ ...e, trustLists: [...e.trustLists, forgedList] }, PIN);
    const work2 = reportOf(r, "application/vnd.oreoasis.work-record+json");
    expect(work2.trusted).toBe(false);
    expect(work2.listing.evidence).toBe("unpinned-list");
  });

  it("the holder keeps an unlisted record only by explicit choice", async () => {
    const r = await verifyHolderExport(withManifest("application/vnd.oreoasis.work-record+json", { keptUnlistedAtUnix: null }), PIN);
    expect(reportOf(r, "application/vnd.oreoasis.work-record+json").reasons).toContain("UNLISTED_WITHOUT_CHOICE");
  });

  it("a manifest cannot claim a listing no presented list supports", async () => {
    const r = await verifyHolderExport(withManifest("application/vnd.oreoasis.work-record+json", { listing: "listed" }), PIN);
    expect(reportOf(r, "application/vnd.oreoasis.work-record+json").reasons).toContain("LISTING_CLAIM_UNSUPPORTED");
  });

  it("grants are exact tags: a key listed for IVFC1 is not listed for IPOE1", async () => {
    const list = await verifyTrustList(trustListEnv(), PIN);
    const now = EXPORTED_AT;
    expect(findListing("indus.platform.vfc.v1", "indus.vfc.v1.cert", [list], now)?.pinned).toBe(true);
    expect(findListing("indus.platform.vfc.v1", "indus.poe.v1.qr", [list], now)).toBeNull();
  });

  it("a tampered list fails, and fails the export that carries it", async () => {
    const env = trustListEnv();
    const payload = JSON.parse(new TextDecoder().decode(base64ToBytes(env.payload))) as TrustListPayload;
    const tampered = { ...env, payload: bytesToBase64(canonicalizeBytes({ ...payload, version: 2 })) };
    expect((await verifyTrustList(tampered, PIN)).reason).toBe("TRUST_LIST_SIGNATURE_INVALID");
    const e = loadExport();
    const r = await verifyHolderExport({ ...e, trustLists: [tampered] }, PIN);
    expect(r.reasons).toContain("TRUST_LIST_INVALID");
  });

  it("refuses to list an unregistered tag, at signing and at verifying", async () => {
    const kp = await generateKeyPair();
    const did = deriveDid(kp.publicKey);
    const payload: TrustListPayload = {
      format: TRUST_LIST_FORMAT,
      listId: "l",
      version: 1,
      publisher: did,
      issuedAtUnix: 1,
      validFromUnix: 1,
      validUntilUnix: 2_082_758_400,
      issuers: [{ issuerId: did, label: "x", keys: [], dsts: ["made-up-v9\n"], validFromUnix: 1, validUntilUnix: 2_082_758_400 }],
    };
    const signer = { keyid: did, privateKey: kp.privateKey, publicKey: kp.publicKey };
    await expect(signTrustList(payload, signer)).rejects.toThrow();
    const raw = await signEnvelope(payload, DST_TRUST_LIST, signer, { canonical: true });
    expect((await verifyTrustList(raw, { pinnedPublishers: [did] })).reason).toBe("TRUST_LIST_UNREGISTERED_DST");
  });

  it("a list outside its window lists nobody", async () => {
    const r = await verifyTrustList(trustListEnv(), { ...PIN, nowSec: 2_100_000_000 });
    expect(r.ok).toBe(true);
    expect(r.current).toBe(false);
    expect(findListing("indus.platform.vfc.v1", "indus.vfc.v1.cert", [r], 2_100_000_000)).toBeNull();
  });

  it("a higher-numbered list from an unpinned publisher never replaces a pinned publisher's list", async () => {
    const list = await verifyTrustList(trustListEnv(), PIN);
    const strangerKp = await generateKeyPair();
    const strangerDid = deriveDid(strangerKp.publicKey);
    const strangerPayload: TrustListPayload = {
      format: TRUST_LIST_FORMAT,
      listId: list.listId!,
      version: 9,
      publisher: strangerDid,
      issuedAtUnix: EXPORTED_AT,
      validFromUnix: 1,
      validUntilUnix: 2_082_758_400,
      issuers: [],
    };
    const strangerSigner = { keyid: strangerDid, privateKey: strangerKp.privateKey, publicKey: strangerKp.publicKey };
    const strangerEnv = await signEnvelope(strangerPayload, DST_TRUST_LIST, strangerSigner, { canonical: true });
    const strangerReport = await verifyTrustList(strangerEnv, { ...PIN, nowSec: EXPORTED_AT });
    expect(strangerReport.ok).toBe(true);
    expect(strangerReport.pinned).toBe(false);

    const current = currentTrustLists([list, strangerReport]);
    expect(current.some((l) => l.pinned && l.listId === list.listId)).toBe(true);
    const found = findListing("indus.platform.vfc.v1", "indus.vfc.v1.cert", [list, strangerReport], EXPORTED_AT);
    expect(found?.pinned).toBe(true);
  });
});

/* ── 6. status and revocation ──────────────────────────────────────────── */

describe("holder — status lists: the one networked check, and it says so", () => {
  it("index 0 is the left-most bit, as the W3C Bitstring Status List specifies", async () => {
    const bits = createStatusBitstring();
    setStatusBit(bits, 0, true);
    setStatusBit(bits, 9, true);
    expect(bits[0]).toBe(0x80);
    expect(bits[1]).toBe(0x40);
    const round = await decodeStatusList(await encodeStatusList(bits));
    expect(getStatusBit(round, 0)).toBe(true);
    expect(getStatusBit(round, 1)).toBe(false);
    expect(getStatusBit(round, 9)).toBe(true);
  });

  it("the vector list is 131,072 entries, signed by its issuer, and decodes offline", async () => {
    const r = await verifyStatusList(statusListEnv(), { resolveKey: makeKeyResolver(new Map(), new Map()) });
    expect(r.ok).toBe(true);
    expect(r.entries).toBe(STATUS_LIST_MIN_ENTRIES);
    expect(r.issuer).toBe(ORG);
    expect(r.issuerKeySource).toBe("self-certifying");
  });

  it("says 'valid unless revoked, as of <list time>' for a clear index, and revoked for a set one", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    const kept = reportOf(r, "application/vnd.oreoasis.predicate+json", "17403");
    const revoked = reportOf(r, "application/vnd.oreoasis.predicate+json", "90211");
    expect(kept.status.state).toBe("not-revoked");
    expect(kept.status.text).toStartWith("valid unless revoked, as of 2026-09-23T00:00:00Z");
    expect(kept.status.source).toBe("carried");
    expect(revoked.status.state).toBe("revoked");
    expect(revoked.ok).toBe(true); // revoked is a status, not a broken record
  });

  it("without the list, the verdict says the check was not made — it does not guess", async () => {
    const e = loadExport();
    const r = await verifyHolderExport({ ...e, statusLists: [] }, PIN);
    const kept = reportOf(r, "application/vnd.oreoasis.predicate+json", "17403");
    expect(kept.status.state).toBe("unknown");
    expect(kept.status.text).toContain("networked check");
  });

  it("a record with no status entry says so", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    expect(reportOf(r, "indus.vfc.v1.cert").status.state).toBe("no-status-entry");
  });

  it("fetches only through the fetch it is handed, once per list, https only — and the verdict names it", async () => {
    const calls: string[] = [];
    const fake = async (url: string) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => statusListEnv() as unknown };
    };
    const url = "https://status.example.org/oreoasis-demo/predicates/2026-q3";
    const got = await fetchStatusLists([url, url, "http://plain.example.org/list"], fake);
    expect(calls).toEqual([url]);
    expect(got.find((g) => g.url.startsWith("http:"))!.error).toContain("https");
    const e = loadExport();
    const r = await verifyHolderExport({ ...e, statusLists: [] }, { ...PIN, fetchedStatusLists: [got[0]!.envelope!] });
    const kept = reportOf(r, "application/vnd.oreoasis.predicate+json", "17403");
    expect(kept.status.source).toBe("fetched");
    expect(kept.status.text).toContain("fetched from the issuer");
    expect(r.network).toContain("fetched");
  });

  it("refuses a list too small to hide an index, at signing and at verifying", async () => {
    const kp = await generateKeyPair();
    const did = deriveDid(kp.publicKey);
    const small = "u" + (await encodeStatusList(new Uint8Array(1024))).slice(1);
    const payload = {
      format: STATUS_LIST_FORMAT,
      type: "BitstringStatusList" as const,
      id: "https://status.example.org/tiny",
      issuer: did,
      statusPurpose: "revocation" as const,
      encodedList: small,
      issuedAtUnix: 1,
      validUntilUnix: null,
    };
    const signer = { keyid: did, privateKey: kp.privateKey, publicKey: kp.publicKey };
    await expect(signStatusList(payload, signer)).rejects.toThrow();
    const raw = await signEnvelope(payload, DST_STATUS_LIST, signer, { canonical: true });
    const r = await verifyStatusList(raw, { resolveKey: makeKeyResolver(new Map(), new Map()) });
    expect(r.reason).toBe("STATUS_LIST_TOO_SMALL");
  });

  it("an entry is never trusted from the manifest alone", () => {
    const v = checkStatus(null, []);
    expect(v.state).toBe("no-status-entry");
  });
});

describe("holder — the existing withdrawals map onto the verdict unchanged", () => {
  it("a presented indus.mark.revoke.v1 revokes its own mark", async () => {
    const r = await verifyHolderExport(loadExport(), PIN);
    const mark = reportOf(r, "indus.mark.v1\n");
    expect(mark.ok).toBe(true);
    expect(mark.status.state).toBe("revoked");
    expect(mark.status.source).toBe("presented");
    expect(mark.status.text).toContain("2026-06-15T10:00:00.000Z");
  });

  it("a revocation of a different mark, or one not presented, revokes nothing", async () => {
    const e = loadExport();
    const withoutRevocations = await verifyHolderExport({ ...e, revocations: [] }, PIN);
    expect(reportOf(withoutRevocations, "indus.mark.v1\n").status.state).toBe("no-status-entry");
    const rev = JSON.parse(JSON.stringify(e.revocations[0])) as { body: { markSha256: string } };
    rev.body.markSha256 = "f".repeat(64);
    const other = await verifyHolderExport({ ...e, revocations: [rev as never] }, PIN);
    expect(reportOf(other, "indus.mark.v1\n").status.state).toBe("no-status-entry");
  });

  it("a revocation signed by anyone but the mark's issuer revokes nothing", async () => {
    const e = loadExport();
    const imposter = await generateKeyPair();
    const rev = e.revocations[0] as unknown as { header: Record<string, unknown>; body: Record<string, unknown> };
    const signature = await signEvent(rev.header, rev.body, imposter.privateKey, { dst: "indus.mark.revoke.v1\n" });
    const r = await verifyHolderExport({ ...e, revocations: [{ ...rev, signature } as never] }, PIN);
    expect(reportOf(r, "indus.mark.v1\n").status.state).toBe("no-status-entry");
  });

  it("a countersign withdrawal that predates the signing shows as withdrawn, and the signatures still verify", async () => {
    type P = KashKeyPair & { did: string };
    const mk = async (): Promise<P> => {
      const kp = await generateKeyPair();
      return { ...kp, did: deriveDid(kp.publicKey) };
    };
    const holder = await mk();
    const signer = await mk();
    const T0 = 1_700_000_000;
    const TYPE = "application/vnd.oreoasis.work-record+json";
    const subject = await signEnvelope({ thing: 1 }, TYPE, { keyid: holder.did, privateKey: holder.privateKey, publicKey: holder.publicKey }, { canonical: true });
    const reqBody = {
      requestId: "csr_00000000000000000000000000000009",
      requesterDid: holder.did,
      subjectPayloadType: TYPE,
      subjectDigestSha256: await sha256Hex(base64ToBytes(subject.payload)),
      statement: "Confirm the work.",
      disclosures: [],
      nonceB64: bytesToBase64(new Uint8Array(32).fill(3)),
      issuedAtUnix: T0,
      expiresAtUnix: T0 + 3600,
      relationshipContext: "ctx",
      withdrawalFeed: null,
    };
    const reqHeader = { typ: "countersign-request", v: 1 };
    const request = { header: reqHeader, body: reqBody, signature: await signEvent(reqHeader, reqBody, holder.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
    const bytes = base64ToBytes(subject.payload);
    const sig = await signRaw(pae(TYPE, bytes), signer.privateKey, signer.publicKey);
    const envelope = { ...subject, signatures: [...subject.signatures, { keyid: signer.did, sig: bytesToBase64(sig) }] };
    const accBody = {
      act: "countersign" as const,
      requestId: reqBody.requestId,
      requestDigestSha256: await countersignRequestDigest(request),
      subjectPayloadType: TYPE,
      subjectDigestSha256: reqBody.subjectDigestSha256,
      countersignerDid: signer.did,
      keyCustody: "subject-generated" as const,
      signedAtUnix: T0 + 600,
    };
    const accHeader = { typ: "countersign", v: 1 };
    const wBody = { act: "withdraw" as const, requestId: reqBody.requestId, requestDigestSha256: accBody.requestDigestSha256, withdrawnAtUnix: T0 + 300 };
    const wHeader = { typ: "countersign-withdrawal", v: 1 };
    const bundle = {
      formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
      subject: envelope,
      request,
      acceptances: [{ header: accHeader, body: accBody, signature: await signEvent(accHeader, accBody, signer.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) }],
      withdrawal: { header: wHeader, body: wBody, signature: await signEvent(wHeader, wBody, holder.privateKey, { dst: DST_COUNTERSIGN_WITHDRAWAL }) },
    };
    const artifact = { kind: "countersign-bundle" as const, value: bundle };
    const record: HeldRecord = {
      artifact,
      manifest: {
        recordId: await recordIdOf(artifact),
        issuer: holder.did,
        relationship: signer.did,
        type: { tag: TYPE, family: "dsse-type", attestation: "countersigned" },
        receivedAtUnix: T0 + 600,
        expiresAtUnix: null,
        retentionSource: "none-declared",
        status: null,
        listing: "unlisted",
        keptUnlistedAtUnix: T0 + 600,
      },
    };
    const r = await verifyHeldRecord(record, {
      resolveKey: makeKeyResolver(new Map(), new Map()),
      trustLists: [],
      statusLists: [],
      revocations: [],
      nowSec: T0 + 700,
      exportedAtUnix: null,
    });
    expect(r.signatureOk).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.status.state).toBe("withdrawn");
    expect(r.status.source).toBe("presented");
  });
});

/* ── 7. private keys only inside the holder's encrypted backup ─────────── */

async function decryptBackup(b: { protected: string; encrypted_key: string; iv: string; ciphertext: string; tag: string }): Promise<string> {
  const enc = new TextEncoder();
  const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(b.protected))) as { alg: string; p2s: string; p2c: number };
  const saltInput = new Uint8Array([...enc.encode(header.alg), 0, ...base64UrlToBytes(header.p2s)]);
  const pass = await crypto.subtle.importKey("raw", enc.encode(PASSPHRASE), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: saltInput, iterations: header.p2c }, pass, { name: "AES-KW", length: 128 }, false, ["unwrapKey"]);
  const cek = await crypto.subtle.unwrapKey("raw", base64UrlToBytes(b.encrypted_key) as unknown as BufferSource, kek, "AES-KW", "AES-GCM", false, ["decrypt"]);
  const sealed = new Uint8Array([...base64UrlToBytes(b.ciphertext), ...base64UrlToBytes(b.tag)]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64UrlToBytes(b.iv) as unknown as BufferSource, additionalData: enc.encode(b.protected), tagLength: 128 }, cek, sealed);
  return new TextDecoder().decode(plain);
}

describe("holder — private keys appear only as the holder's encrypted backup", () => {
  it("the backup vector verifies, and its backup is a real JWE the holder can open", async () => {
    const raw = readFileSync(join(VEC, "holder-export-backup.v1.json"), "utf8");
    const e = JSON.parse(raw) as HolderExport;
    const r = await verifyHolderExport(e, { ...PIN, rawText: raw });
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(true);
    expect(r.encryptedKeyBackup).toBe("present");
    const opened = JSON.parse(await decryptBackup(e.encryptedKeyBackup!)) as { keys: { privateKeyHex: string }[] };
    expect(opened.keys).toHaveLength(2);
    expect(opened.keys[0]!.privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("fails an export with a private key anywhere outside the backup", async () => {
    const e = loadExport();
    const leak = { ...e, heldKeys: [...e.heldKeys, { ...e.heldKeys[0]!, privateKeyHex: "00".repeat(32) }] };
    expect((await verifyHolderExport(leak, PIN)).reasons).toContain("PLAINTEXT_PRIVATE_KEY");
    const jwk = { ...e, trustLists: [...e.trustLists], revocations: [...e.revocations, { kty: "OKP", crv: "Ed25519", x: "AA", d: "AA" } as never] };
    expect((await verifyHolderExport(jwk, PIN)).reasons).toContain("PLAINTEXT_PRIVATE_KEY");
  });

  it("fails a backup that is not a JWE", async () => {
    const e = loadExport();
    const r = await verifyHolderExport({ ...e, encryptedKeyBackup: { protected: "!!", encrypted_key: "", iv: "", ciphertext: "", tag: "" } }, PIN);
    expect(r.reasons).toContain("MALFORMED_BACKUP");
  });
});
