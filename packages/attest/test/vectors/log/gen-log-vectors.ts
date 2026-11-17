#!/usr/bin/env bun
/**
 * KS-Q4 — the trust log's vectors. Generated ONCE on 2026-11-18 and never
 * regenerated: the log's key, the stranger's key and the SAMPLE time
 * authority's keys are made here and discarded. Every value is SAMPLE
 * (ECOSYSTEM d11).
 *
 * The witnesses are real RFC 3161 tokens, made by `openssl ts -reply` from a
 * SAMPLE authority this script creates — a root and a time-stamping
 * certificate under it. Only the root's certificate is kept
 * (`sample-tsa-root.crt`), so `openssl ts -verify` and `attest verify
 * --tsa-root` check every token against it. They prove the generator's own
 * clock and nothing more: no public authority saw any of this.
 *
 *   bun test/vectors/log/gen-log-vectors.ts      # refuses to run while original/ exists; needs openssl
 */

import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { bytesToHex } from "../../../src/chain";
import { describeLog, newLogSalt, openTrustLog, saltedRecordHash, type LogEntry } from "../../../src/log";
import { checkpointHash, signCheckpoint, type LogCheckpointPayload } from "../../../src/log/checkpoint";
import { decodeEnvelopePayload } from "../../../src/holder/trust-list";
import { FileLogStore, initLogDirectory, writeLogWitness } from "../../../src/log/files";
import { readRfc3161Token } from "../../../src/witness/rfc3161";

const HERE = import.meta.dir;
const ORIGINAL = join(HERE, "original");
if (existsSync(ORIGINAL)) {
  console.error("test/vectors/log/original exists — the vectors are generated once and never regenerated");
  process.exit(2);
}

/* ── a SAMPLE time authority, made with openssl and thrown away ─────────── */

const slash = (p: string): string => p.replace(/\\/g, "/");
const ossl = (args: string[], what: string): string => {
  const p = spawnSync("openssl", args, { encoding: "utf8" });
  if (p.error !== undefined || p.status !== 0) throw new Error(`openssl ${what} failed: ${p.stderr || p.error}`);
  return `${p.stdout}${p.stderr}`;
};
const TSA = mkdtempSync(join(tmpdir(), "ks-q4-sample-tsa-"));
const T = (name: string): string => slash(join(TSA, name));
writeFileSync(
  join(TSA, "tsa.cnf"),
  [
    "[ req ]",
    "distinguished_name = dn",
    "prompt = no",
    "[ dn ]",
    "CN = SAMPLE Time Authority Root",
    "[ root_ext ]",
    "basicConstraints = critical, CA:true",
    "keyUsage = critical, keyCertSign, cRLSign",
    "subjectKeyIdentifier = hash",
    "[ tsa_ext ]",
    "basicConstraints = critical, CA:false",
    "keyUsage = critical, digitalSignature, nonRepudiation",
    "extendedKeyUsage = critical, timeStamping",
    "subjectKeyIdentifier = hash",
    "authorityKeyIdentifier = keyid",
    "[ tsa ]",
    "default_tsa = sample_tsa",
    "[ sample_tsa ]",
    `serial = ${T("serial")}`,
    `signer_cert = ${T("tsa.crt")}`,
    `certs = ${T("root.crt")}`,
    `signer_key = ${T("tsa.key")}`,
    "signer_digest = sha256",
    "default_policy = 1.3.6.1.4.1.99999.1",
    "digests = sha256",
    "accuracy = secs:1",
    "ordering = no",
    "tsa_name = yes",
    "ess_cert_id_alg = sha256",
    "",
  ].join("\n"),
);
writeFileSync(join(TSA, "serial"), "01\n");
ossl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", T("root.key"), "-out", T("root.crt"), "-days", "3650", "-config", T("tsa.cnf"), "-extensions", "root_ext"], "root");
ossl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", T("tsa.key"), "-out", T("tsa.csr"), "-subj", "/CN=SAMPLE Time Authority"], "tsa key");
ossl(["x509", "-req", "-in", T("tsa.csr"), "-CA", T("root.crt"), "-CAkey", T("root.key"), "-CAcreateserial", "-out", T("tsa.crt"), "-days", "3650", "-extfile", T("tsa.cnf"), "-extensions", "tsa_ext"], "tsa certificate");

/** A real RFC 3161 token over `digestHex`, from the SAMPLE authority, checked by openssl before it is kept. */
function stamp(digestHex: string): Uint8Array {
  ossl(["ts", "-query", "-digest", digestHex, "-sha256", "-cert", "-out", T("q.tsq")], "query");
  ossl(["ts", "-reply", "-queryfile", T("q.tsq"), "-config", T("tsa.cnf"), "-out", T("r.tsr")], "reply");
  const verified = ossl(["ts", "-verify", "-digest", digestHex, "-in", T("r.tsr"), "-CAfile", T("root.crt")], "verify");
  if (!verified.includes("Verification: OK")) throw new Error("openssl did not verify the SAMPLE token");
  return new Uint8Array(readFileSync(join(TSA, "r.tsr")));
}

/* ── the log ───────────────────────────────────────────────────────────── */

const DAY = 86_400;
// The log begins ten minutes before the generator ran, so every head is witnessed after it is made.
const T0 = Math.floor(Date.now() / 1000) - 600;
const sha = async (s: string): Promise<string> => bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));

const publisher = await generateKeyPair();
const publisherDid = deriveDid(publisher.publicKey);
const stranger = await generateKeyPair();
const strangerDid = deriveDid(stranger.publicKey);
const issuerA = "did:web:issuer-a.sample.example";
const issuerB = "did:web:issuer-b.sample.example";
const logId = `${publisherDid}/log/sample`;
const signer = { keyid: publisherDid, privateKey: publisher.privateKey, publicKey: publisher.publicKey };

initLogDirectory(ORIGINAL, describeLog({ logId, startedAtUnix: T0, maxBatchDelaySec: DAY, origin: null }));
const log = await openTrustLog({ logId, store: new FileLogStore(ORIGINAL), signer, maxBatchDelaySec: DAY });

const saltA = newLogSalt();
const saltB = newLogSalt();
const saltC = newLogSalt();
const recordA = await sha("SAMPLE record A");
const recordB = await sha("SAMPLE record B");
const recordC = await sha("SAMPLE record C");

const claimed = [T0, T0, T0, T0 + 100, T0 + 300, T0 + 300, T0 - 30 * DAY, T0 + 400, T0 - 10 * DAY];
const entries: LogEntry[] = [
  { v: 1, kind: "trust-list", listId: "sample-list", publisher: publisherDid, version: 1, issuedAtUnix: claimed[0]!, sha256: await sha("SAMPLE trust list v1") },
  { v: 1, kind: "issuer-key", issuerId: issuerA, keyid: `${issuerA}#1`, alg: "Ed25519", action: "added", atUnix: claimed[1]!, listId: "sample-list", listVersion: 1 },
  { v: 1, kind: "issuer-key", issuerId: issuerB, keyid: `${issuerB}#1`, alg: "ES256", action: "added", atUnix: claimed[2]!, listId: "sample-list", listVersion: 1 },
  { v: 1, kind: "attestation", issuer: issuerA, salted: await saltedRecordHash(saltA, recordA), claimedAtUnix: claimed[3]! },
  { v: 1, kind: "trust-list", listId: "sample-list", publisher: publisherDid, version: 2, issuedAtUnix: claimed[4]!, sha256: await sha("SAMPLE trust list v2") },
  { v: 1, kind: "issuer-key", issuerId: issuerA, keyid: `${issuerA}#2`, alg: "Ed25519", action: "rotated", atUnix: claimed[5]!, listId: "sample-list", listVersion: 2 },
  // Backfilled: it claims thirty days before the log began, and says so.
  { v: 1, kind: "attestation", issuer: issuerB, salted: await saltedRecordHash(saltB, recordB), claimedAtUnix: claimed[6]!, backfilled: true },
  { v: 1, kind: "status-list", id: "https://sample.example/status/withdrawals", issuer: issuerB, statusPurpose: "withdrawal", issuedAtUnix: claimed[7]!, sha256: await sha("SAMPLE status list") },
  // The planted backdated attestation: it claims ten days before it was logged, and does not say it is backfilled.
  { v: 1, kind: "attestation", issuer: issuerA, salted: await saltedRecordHash(saltC, recordC), claimedAtUnix: claimed[8]! },
];

const heads: { size: number; at: number; witnessedAt: number }[] = [];
const atFor: Record<number, number> = { 4: T0 + 200, 7: T0 + 450, 9: T0 + 500 };
const witnessFiles: Record<number, string> = {};
for (const [i, e] of entries.entries()) {
  await log.append(e);
  const size = i + 1;
  if (atFor[size] !== undefined) {
    const env = await log.checkpoint(atFor[size]!);
    const tsr = stamp(await checkpointHash(env));
    writeLogWitness(ORIGINAL, size, "rfc3161", tsr);
    witnessFiles[size] = Buffer.from(tsr).toString("base64");
    heads.push({ size, at: atFor[size]!, witnessedAt: (await readRfc3161Token(tsr)).genTimeUnix });
  }
}

const witnessesFor = (size: number) => [{ kind: "rfc3161" as const, proofBase64: witnessFiles[size]! }];
const write = (name: string, value: unknown): void => writeFileSync(join(HERE, name), `${JSON.stringify(value, null, 2)}\n`);
write("inclusion-attestation-ok.json", await log.inclusionProof(3, 4, witnessesFor(4)));
write("inclusion-trust-list.json", await log.inclusionProof(0, 9, witnessesFor(9)));
write("inclusion-backfilled.json", await log.inclusionProof(6, 7, witnessesFor(7)));
write("inclusion-backdated.json", await log.inclusionProof(8, 9, witnessesFor(9)));
write("inclusion-later-head.json", await log.inclusionProof(3, 9, witnessesFor(9)));
write("consistency-4-7.json", await log.consistencyProof(4, 7));
write("consistency-7-9.json", await log.consistencyProof(7, 9));
write("consistency-4-9.json", await log.consistencyProof(4, 9));

// The mirror: a copy. The tampered mirrors: one change each.
cpSync(ORIGINAL, join(HERE, "mirror"), { recursive: true });
const TAMPERED = join(HERE, "tampered");
const chunk = join("entries", "000000.jsonl");
const lines = readFileSync(join(ORIGINAL, chunk), "utf8").trim().split("\n");
const tamper = async (name: string, change: (dir: string) => void | Promise<void>): Promise<void> => {
  const dir = join(TAMPERED, name);
  cpSync(ORIGINAL, dir, { recursive: true });
  await change(dir);
};
await tamper("altered", (dir) => {
  const e = JSON.parse(lines[2]!) as Record<string, unknown>;
  e.keyid = `${issuerB}#9`;
  writeFileSync(join(dir, chunk), `${[...lines.slice(0, 2), canonicalize(e), ...lines.slice(3)].join("\n")}\n`);
});
await tamper("removed", (dir) => writeFileSync(join(dir, chunk), `${[...lines.slice(0, 5), ...lines.slice(6)].join("\n")}\n`));
await tamper("reordered", (dir) => writeFileSync(join(dir, chunk), `${[lines[0]!, lines[2]!, lines[1]!, ...lines.slice(3)].join("\n")}\n`));
await tamper("stranger", async (dir) => {
  const env = JSON.parse(readFileSync(join(dir, "checkpoints", "9.json"), "utf8"));
  const p = decodeEnvelopePayload(env) as LogCheckpointPayload;
  const forged = await signCheckpoint({ ...p, logId: `${strangerDid}/log/sample` }, { keyid: strangerDid, privateKey: stranger.privateKey, publicKey: stranger.publicKey });
  // The forger keeps the log's id by rewriting the payload after signing: no signature by the log's key remains.
  const payload = JSON.parse(new TextDecoder().decode(Buffer.from(forged.payload, "base64"))) as Record<string, unknown>;
  payload.logId = logId;
  writeFileSync(join(dir, "checkpoints", "9.json"), `${JSON.stringify({ ...forged, payload: Buffer.from(canonicalize(payload)).toString("base64") }, null, 2)}\n`);
});
// The split view: the same key signs a second head of 9, forked after the head of 7 — the same eight entries, another ninth.
{
  const dir = join(TAMPERED, "split");
  cpSync(ORIGINAL, dir, { recursive: true });
  const work = join(HERE, ".split-work");
  rmSync(work, { recursive: true, force: true });
  cpSync(ORIGINAL, work, { recursive: true });
  writeFileSync(join(work, chunk), `${lines.slice(0, 8).join("\n")}\n`);
  rmSync(join(work, "checkpoints", "9.json"));
  rmSync(join(work, "checkpoint.json"));
  const forked = await openTrustLog({ logId, store: new FileLogStore(work), signer, maxBatchDelaySec: DAY });
  await forked.append({ v: 1, kind: "attestation", issuer: issuerB, salted: await saltedRecordHash(newLogSalt(), await sha("SAMPLE record D")), claimedAtUnix: T0 + 450 });
  writeFileSync(join(dir, "checkpoints", "9-other.json"), `${JSON.stringify(await forked.checkpoint(T0 + 500), null, 2)}\n`);
  rmSync(work, { recursive: true, force: true });
}

// Keep the SAMPLE authority's root, so the tokens can be checked; throw the keys away.
copyFileSync(join(TSA, "root.crt"), join(HERE, "sample-tsa-root.crt"));
rmSync(TSA, { recursive: true, force: true });

write("context.json", {
  note: "SAMPLE. Generated once on 2026-11-18; the log's key, the stranger's key and the SAMPLE time authority's keys are gone. The witness files are real RFC 3161 tokens from that SAMPLE authority, checkable against sample-tsa-root.crt; they show the generator's clock, nothing more.",
  logId,
  publisherDid,
  strangerDid,
  issuerA,
  issuerB,
  startedAtUnix: T0,
  claimed,
  maxBatchDelaySec: DAY,
  heads,
  salts: { entry3: { salt: saltA, recordHash: recordA }, entry6: { salt: saltB, recordHash: recordB }, entry8: { salt: saltC, recordHash: recordC } },
});
console.log(`wrote ${ORIGINAL}, mirror/, tampered/{altered,removed,reordered,stranger,split}, 5 inclusion proofs, 3 consistency proofs, sample-tsa-root.crt`);
