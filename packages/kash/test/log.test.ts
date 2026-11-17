/**
 * `kash log` — the publisher keeps the trust log (KS-Q4; specs/trust-log.md).
 *
 * The offline commands (init, add, checkpoint, proof) run as the bundled CLI
 * under the offline guard, so a passing run is itself the proof that they never
 * reach the network. `witness` and `upgrade` — the two that go online — run in
 * process against stub calendars and a stub time-stamp authority: nothing here
 * leaves the machine. Every key, list and record is a simulation (d11).
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  STATUS_LIST_FORMAT,
  STATUS_LIST_MIN_ENTRIES,
  TRUST_LIST_FORMAT,
  DST_WORK_RECORD,
  base64ToBytes,
  bytesToHex,
  encodeStatusList,
  hexToBytes,
  otsLeaves,
  parseOts,
  serializeOts,
  type FetchBytes,
  type OtsTimestamp,
} from "@kashscript/attest";
import { checkpointHash, newLogSalt, saltedRecordHash } from "@kashscript/attest/log";
import { opensslAvailable } from "@kashscript/attest/openssl";
import { generateKeyPair } from "@kashscript/identity-core";

import { fakeTimeStampResp } from "../../attest/test/witness/fake-tsa";
import { runLogProof, runLogUpgrade, runLogWitness } from "../src/commands/log";
import { ATTEST, bunSrc, buildBundles, didFrom, nodeDist, offlineGuardPath, removeDir, tempDir, type Run } from "./helpers";

const DAY = 86_400;
const sha256Hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

let keystore = "";
let work = "";
let publisher = "";
let station = "";

beforeAll(() => {
  buildBundles();
  keystore = join(tempDir("log-keys"), "keystore");
  work = tempDir("log-work");
  publisher = didFrom(bunSrc(["station", "init", "--name", "publisher", "--keystore", keystore]).stdout);
  station = didFrom(bunSrc(["station", "init", "--name", "station", "--keystore", keystore]).stdout);
}, 180_000);
afterAll(() => {
  removeDir(keystore);
  removeDir(work);
});

function write(name: string, value: unknown): string {
  const path = join(work, name);
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  return path;
}
const lines = (dir: string): Record<string, unknown>[] =>
  readFileSync(join(dir, "entries", "000000.jsonl"), "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>);
const descriptor = (dir: string): Record<string, any> => JSON.parse(readFileSync(join(dir, "log.json"), "utf8"));

/** attest's own bundled CLI, under the same offline guard. */
function attest(args: readonly string[]): Run {
  const r = spawnSync("node", [join(ATTEST, "dist", "bin", "attest.js"), ...args], {
    encoding: "utf8",
    env: { ...process.env, NODE_OPTIONS: `--require ${offlineGuardPath()}` },
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/** A web issuer's listed key: real bytes, so the list's structural check reads them. */
async function listedKey(keyid: string): Promise<{ keyid: string; alg: "Ed25519"; publicKeyHex: string }> {
  return { keyid, alg: "Ed25519", publicKeyHex: bytesToHex((await generateKeyPair()).publicKey) };
}

/** Sign a trust list with the publisher key through `kash trust sign`, and write the envelope. */
function signList(name: string, payload: Record<string, unknown>): string {
  const r = bunSrc(["trust", "sign", write(`${name}.unsigned.json`, payload), "--keystore", keystore]);
  if (r.status !== 0) throw new Error(`trust sign ${name} failed:\n${r.stderr}`);
  return write(`${name}.json`, r.stdout);
}

function trustList(version: number, issuedAtUnix: number, issuers: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    format: TRUST_LIST_FORMAT,
    listId: "sample-scheme",
    version,
    issuedAtUnix,
    validFromUnix: issuedAtUnix - DAY,
    validUntilUnix: issuedAtUnix + 365 * DAY,
    floor: { version: "SAMPLE floor 1" },
    issuers,
  };
}
function issuer(issuerId: string, keys: readonly unknown[], at: number): Record<string, unknown> {
  return { issuerId, label: "Sample issuer (simulation)", keys, dsts: [DST_WORK_RECORD], validFromUnix: at - DAY, validUntilUnix: at + 365 * DAY, class: "counterparty", standing: "listed", grade: 1 };
}

describe("kash log — the offline commands, as the bundled CLI under the offline guard", () => {
  let dir = "";
  let start = 0;
  let v1 = "";
  let v2 = "";
  const webIssuer = "did:web:issuer.sample.example";

  it("init writes log.json naming the publisher key — once; a bad name and an existing log are refused", () => {
    dir = join(work, "log");
    const r = nodeDist(["log", "init", dir, "--name", "sample", "--keystore", keystore]);
    expect(r.status).toBe(0);
    const d = descriptor(dir);
    expect(d.logId).toBe(`${publisher}/log/sample`);
    expect(d.key).toBe(publisher);
    expect(d.maxBatchDelaySec).toBe(86_400);
    expect(d.origin).toBeNull();
    expect(d.note).toContain("never holds a person");
    start = d.startedAtUnix;
    for (const sub of ["entries", "checkpoints", "witness"]) expect(existsSync(join(dir, sub))).toBe(true);

    const again = nodeDist(["log", "init", dir, "--name", "sample", "--keystore", keystore]);
    expect(again.status).toBe(1);
    expect(again.stderr).toContain("already holds a log");
    const badName = nodeDist(["log", "init", join(work, "bad"), "--name", "Not_A_Slug", "--keystore", keystore]);
    expect(badName.status).toBe(1);
    expect(badName.stderr).toContain("short slug");

    const other = join(work, "log-with-origin");
    expect(nodeDist(["log", "init", other, "--name", "other", "--max-batch-delay", "3600", "--origin", "https://log.sample.example/", "--keystore", keystore]).status).toBe(0);
    expect([descriptor(other).maxBatchDelaySec, descriptor(other).origin]).toEqual([3600, "https://log.sample.example/"]);
  }, 120_000);

  it("add: a signed trust list goes in as its version and its key events — every key named, nothing else", async () => {
    v1 = signList("list-v1", trustList(1, start + 1, [issuer(station, [], start), issuer(webIssuer, [await listedKey(`${webIssuer}#k1`)], start)]));
    const r = nodeDist(["log", "add", dir, v1]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("trust-list   sample-scheme v1");
    const got = lines(dir);
    expect(got.map((e) => [e.kind, e.action ?? null, e.keyid ?? null])).toEqual([
      ["trust-list", null, null],
      ["issuer-key", "added", station],
      ["issuer-key", "added", `${webIssuer}#k1`],
    ]);
    // The trust-list entry names the bytes the publisher signed, by hash — and nothing of the list itself.
    const env = JSON.parse(readFileSync(v1, "utf8"));
    expect(got[0]).toEqual({ v: 1, kind: "trust-list", listId: "sample-scheme", publisher, version: 1, issuedAtUnix: start + 1, sha256: sha256Hex(base64ToBytes(env.payload)) });
    expect(JSON.stringify(got)).not.toContain("Sample issuer");
  }, 120_000);

  it("add: an attestation goes in by its salted hash; a claim before the log began must say it is backfilled", async () => {
    const salted = await saltedRecordHash(newLogSalt(), sha256Hex(new TextEncoder().encode("SAMPLE record")));
    const att = { v: 1, kind: "attestation", issuer: station, salted, claimedAtUnix: start + 2 };
    expect(nodeDist(["log", "add", dir, write("att.json", att)]).status).toBe(0);
    const early = { ...att, salted: await saltedRecordHash(newLogSalt(), salted), claimedAtUnix: start - 30 * DAY };
    const refused = nodeDist(["log", "add", dir, write("att-early.json", early)]);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("before the log began");
    const backfilled = nodeDist(["log", "add", dir, write("att-backfilled.json", { ...early, backfilled: true })]);
    expect(backfilled.status).toBe(0);
    expect(backfilled.stderr).toContain("their time will be the witness's, never the claim");
    expect(lines(dir)).toHaveLength(5);
  }, 120_000);

  it("add refuses, and writes nothing: a person's field, a false backfill, a list entry by hand, a record, a duplicate, a bad batch", async () => {
    const before = lines(dir).length;
    const salted = await saltedRecordHash(newLogSalt(), "ab".repeat(32));
    const refusals: [string, unknown, string][] = [
      ["holder.json", { v: 1, kind: "attestation", issuer: station, salted, claimedAtUnix: start + 3, holder: "did:kash:someone" }, "FORBIDDEN_FIELD"],
      ["false-backfill.json", { v: 1, kind: "attestation", issuer: station, salted, claimedAtUnix: start + 3, backfilled: true }, "Only a claim from before the log began"],
      ["by-hand.json", { v: 1, kind: "trust-list", listId: "x", publisher, version: 9, issuedAtUnix: start + 3, sha256: "cd".repeat(32) }, "written from the signed list itself"],
      ["record.json", { payloadType: DST_WORK_RECORD, payload: "e30=", signatures: [{ keyid: station, sig: "AA==" }] }, "not something a log holds"],
      ["unknown.json", { v: 1, kind: "presentation", vp_token: "x" }, "UNKNOWN_KIND"],
    ];
    for (const [name, value, why] of refusals) {
      const r = nodeDist(["log", "add", dir, write(name, value)]);
      expect([name, r.status]).toEqual([name, 1]);
      expect(r.stderr).toContain(why);
      expect(r.stderr).toContain("Nothing was written");
    }
    const dup = nodeDist(["log", "add", dir, v1]);
    expect(dup.status).toBe(1);
    expect(dup.stderr).toContain("already in the log");
    // A batch is checked whole: a good entry before a bad one is not written either.
    const good = write("good.json", { v: 1, kind: "attestation", issuer: station, salted, claimedAtUnix: start + 3 });
    const batch = nodeDist(["log", "add", dir, good, join(work, "holder.json")]);
    expect(batch.status).toBe(1);
    expect(lines(dir)).toHaveLength(before);
    // The same entry twice in one batch is a duplicate too.
    expect(nodeDist(["log", "add", dir, good, good]).stderr).toContain("earlier in this batch");
    expect(lines(dir)).toHaveLength(before);
  }, 120_000);

  it("checkpoint signs the head with the publisher key only; with nothing new, nothing is signed", () => {
    const wrong = nodeDist(["log", "checkpoint", dir, "--key", "station", "--keystore", keystore]);
    expect(wrong.status).toBe(1);
    expect(wrong.stderr).toContain(`signed by ${publisher}`);
    const r = nodeDist(["log", "checkpoint", dir, "--keystore", keystore]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("head      : 5 entries — the log's first");
    expect(r.stdout).toContain("the log's own claim until a public witness stamps it");
    expect(existsSync(join(dir, "checkpoints", "5.json"))).toBe(true);
    const again = nodeDist(["log", "checkpoint", dir, "--keystore", keystore]);
    expect(again.status).toBe(0);
    expect(again.stderr).toContain("nothing signed");
    expect(readdirSync(join(dir, "checkpoints"))).toEqual(["5.json"]);
  }, 120_000);

  it("a list's next version needs the version the log holds, and logs the rotation: rotated in, revoked out", async () => {
    v2 = signList("list-v2", trustList(2, start + 4, [issuer(webIssuer, [await listedKey(`${webIssuer}#k2`)], start)]));
    const missing = nodeDist(["log", "add", dir, v2]);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("Pass --previous");
    const wrongPrevious = nodeDist(["log", "add", dir, v2, "--previous", v2]);
    expect(wrongPrevious.status).toBe(1);
    expect(wrongPrevious.stderr).toContain("this file is not it");
    const r = nodeDist(["log", "add", dir, v2, "--previous", v1]);
    expect(r.status).toBe(0);
    expect(lines(dir).slice(5).map((e) => [e.kind, e.action ?? e.version, e.keyid ?? null])).toEqual([
      ["trust-list", 2, null],
      ["issuer-key", "rotated", `${webIssuer}#k2`],
      ["issuer-key", "revoked", station],
      ["issuer-key", "revoked", `${webIssuer}#k1`],
    ]);
    const stale = nodeDist(["log", "add", dir, v1]);
    expect(stale.status).toBe(1);
    expect(stale.stderr).toContain("already in the log");
  }, 120_000);

  it("a status list goes in by the hash of what its issuer signed", async () => {
    const encodedList = await encodeStatusList(new Uint8Array(STATUS_LIST_MIN_ENTRIES / 8));
    const signed = bunSrc([
      "trust", "sign",
      write("status.unsigned.json", { format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: "https://lists.sample.example/withdrawal/1", statusPurpose: "withdrawal", encodedList, issuedAtUnix: start + 5, validUntilUnix: start + 30 * DAY }),
      "--keystore", keystore,
    ]);
    expect(signed.status).toBe(0);
    const file = write("status.json", signed.stdout);
    const r = nodeDist(["log", "add", dir, file]);
    expect(r.status).toBe(0);
    const last = lines(dir).at(-1)!;
    expect(last).toEqual({ v: 1, kind: "status-list", id: "https://lists.sample.example/withdrawal/1", issuer: publisher, statusPurpose: "withdrawal", issuedAtUnix: start + 5, sha256: sha256Hex(base64ToBytes(JSON.parse(signed.stdout).payload)) });
    expect(nodeDist(["log", "checkpoint", dir, "--keystore", keystore]).status).toBe(0);
  }, 120_000);

  it("proof: against the first head that held the entry, checked offline, naming that entry alone", () => {
    const r = nodeDist(["log", "proof", dir, "3", "--out", join(work, "proof-3.json")]);
    expect(r.status).toBe(0);
    const proof = JSON.parse(r.stdout);
    expect([proof.format, proof.leafIndex, proof.treeSize, proof.entry.kind]).toEqual(["kashscript-log-inclusion/1", 3, 5, "attestation"]);
    expect(r.stderr).toContain("the first head that held it");
    expect(r.stderr).toContain("has no witness yet");
    // It carries no other entry: the station's list entries are not in it, only sibling hashes.
    expect(JSON.stringify(proof)).not.toContain("sample-scheme");
    const later = nodeDist(["log", "proof", dir, "3", "--size", "10"]);
    expect(later.status).toBe(0);
    expect(later.stderr).toContain("a later head than its first");
    expect(nodeDist(["log", "proof", dir, "99"]).status).toBe(1);
    // A stranger checks it with attest alone.
    const check = nodeDist(["verify", join(work, "proof-3.json")]);
    expect(check.stdout).toContain("Trust log inclusion proof");
    expect(check.stdout).toContain("RESULT: PASS");
  }, 120_000);

  it("attest log verify passes on the folder, and on a copy of it — a mirror is a copy", () => {
    const mirror = join(work, "log-mirror");
    cpSync(dir, mirror, { recursive: true });
    const r = attest(["log", "verify", dir, "--mirror", mirror]);
    expect(r.stdout).toContain("RESULT: PASS");
    expect(r.status).toBe(0);
    // The backfilled attestation is not faulted: it claims a time before the log began, and says so.
    expect(r.stdout).not.toContain("CLAIMED_BEFORE_WITNESS");
  }, 120_000);
});

/* ── the two online commands, against stubs ─────────────────────────────── */

/** What a calendar answers to a submitted commitment: a pending attestation naming itself. */
const pendingFor = (uri: string, msg: Uint8Array): Uint8Array =>
  serializeOts({ hashOp: "sha256", digest: msg, timestamp: { msg, attestations: [{ kind: "pending", uri }], ops: [] } }).slice(31 + 1 + 1 + 32);
/** What a calendar answers once its commitment is in a block: one more hash, then a Bitcoin attestation. */
const blockFor = (msg: Uint8Array): Uint8Array => {
  const t: OtsTimestamp = { msg, attestations: [], ops: [{ op: { op: "sha256" }, next: { msg: new Uint8Array(32), attestations: [{ kind: "bitcoin", height: 1 }], ops: [] } }] };
  return serializeOts({ hashOp: "sha256", digest: msg, timestamp: t }).slice(31 + 1 + 1 + 32);
};
/** A TimeStampReq's hashed message and nonce (RFC 3161 §2.4.1): SEQUENCE { version, messageImprint { hashAlgorithm, hashedMessage }, nonce, certReq }. */
function readRequest(req: Uint8Array): { readonly digestHex: string; readonly nonceHex: string } {
  let i = 0;
  const len = (): number => {
    let n = req[i++]!;
    if (n & 0x80) {
      const k = n & 0x7f;
      n = 0;
      for (let j = 0; j < k; j++) n = n * 256 + req[i++]!;
    }
    return n;
  };
  const enter = (tag: number): number => {
    if (req[i++] !== tag) throw new Error(`not a TimeStampReq: expected tag ${tag} at ${i - 1}`);
    return len();
  };
  const skip = (): void => {
    i++;
    const n = len();
    i += n;
  };
  enter(0x30); // TimeStampReq
  skip(); // version
  enter(0x30); // messageImprint
  skip(); // hashAlgorithm
  const dl = enter(0x04);
  const digestHex = bytesToHex(req.subarray(i, i + dl));
  i += dl;
  const nl = enter(0x02); // nonce
  return { digestHex, nonceHex: bytesToHex(req.subarray(i, i + nl)) };
}

const CALENDARS = ["https://a.calendar.sample.example", "https://b.calendar.sample.example"];
const TSA = "https://tsa.sample.example";

interface Stub {
  readonly fetch: FetchBytes;
  readonly requests: { url: string; method: string; body: Uint8Array | null }[];
}
function stub(answer: (url: string, body: Uint8Array | null) => { ok: boolean; status: number; bytes: Uint8Array }, events?: string[]): Stub {
  const requests: Stub["requests"] = [];
  return {
    requests,
    fetch: async (url, init) => {
      events?.push(`request ${url}`);
      requests.push({ url, method: init.method, body: init.body ?? null });
      const a = answer(url, init.body ?? null);
      return { ok: a.ok, status: a.status, bytes: async () => a.bytes };
    },
  };
}
/** Calendars that take every commitment, and an authority that grants every request, at `genTimeUnix`. */
const witnesses = (genTimeUnix: number, events?: string[]): Stub =>
  stub((url, body) => {
    if (url.endsWith("/digest")) return { ok: true, status: 200, bytes: pendingFor(url.replace("/digest", ""), body!) };
    if (url === TSA) return { ok: true, status: 200, bytes: fakeTimeStampResp({ ...readRequest(body!), genTimeUnix, tsaName: "SAMPLE TSA" }) };
    return { ok: false, status: 404, bytes: new Uint8Array(0) };
  }, events);

/** Run a command in process with its output caught; the events list records output beside the stub's requests, in order. */
async function caught(run: () => Promise<void>, events?: string[]): Promise<{ out: string; err: string; error: unknown }> {
  const out: string[] = [];
  const err: string[] = [];
  const o = process.stdout.write.bind(process.stdout);
  const e = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: unknown) => {
    out.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown) => {
    err.push(String(chunk));
    events?.push(`stderr ${String(chunk)}`);
    return true;
  }) as typeof process.stderr.write;
  let error: unknown = null;
  try {
    await run();
  } catch (x) {
    error = x;
  } finally {
    process.stdout.write = o;
    process.stderr.write = e;
  }
  return { out: out.join(""), err: err.join(""), error };
}

describe("kash log witness and upgrade — the only two commands that go online, against stubs", () => {
  let dir = "";
  let digest = "";

  beforeAll(async () => {
    dir = join(work, "online-log");
    expect(bunSrc(["log", "init", dir, "--name", "online", "--keystore", keystore]).status).toBe(0);
    const start = descriptor(dir).startedAtUnix as number;
    const salted = await saltedRecordHash(newLogSalt(), "ef".repeat(32));
    expect(bunSrc(["log", "add", dir, write("online-att.json", { v: 1, kind: "attestation", issuer: station, salted, claimedAtUnix: start })]).status).toBe(0);
    expect(bunSrc(["log", "checkpoint", dir, "--keystore", keystore]).status).toBe(0);
    digest = await checkpointHash(JSON.parse(readFileSync(join(dir, "checkpoints", "1.json"), "utf8")));
  }, 60_000);

  it("says it is going online before the first request, sends only 32-byte hashes, and keeps both proofs", async () => {
    const events: string[] = [];
    const net = witnesses(Math.floor(Date.now() / 1000), events);
    const r = await caught(() => runLogWitness(dir, { tsa: TSA, calendar: CALENDARS, fetch: net.fetch }), events);
    expect(r.error).toBeNull();
    const firstRequest = events.findIndex((e) => e.startsWith("request"));
    const goingOnline = events.findIndex((e) => e.includes("Going online"));
    expect(goingOnline).toBeGreaterThanOrEqual(0);
    expect(goingOnline).toBeLessThan(firstRequest);
    // The calendars get a 32-byte commitment (the hash with a nonce, hashed again) — not even the head's hash itself.
    const toCalendars = net.requests.filter((q) => q.url.endsWith("/digest"));
    expect(toCalendars.map((q) => q.url).sort()).toEqual(CALENDARS.map((c) => `${c}/digest`));
    for (const q of toCalendars) {
      expect(q.body!.length).toBe(32);
      expect(bytesToHex(q.body!)).not.toBe(digest);
    }
    // The authority gets a TimeStampReq over the head's hash, and nothing else.
    const toTsa = net.requests.filter((q) => q.url === TSA);
    expect(toTsa).toHaveLength(1);
    expect(bytesToHex(toTsa[0]!.body!)).toContain(digest);
    expect(existsSync(join(dir, "witness", "1.ots"))).toBe(true);
    expect(existsSync(join(dir, "witness", "1.tsr"))).toBe(true);
    expect(r.out).toContain("ots       : pending at a.calendar.sample.example, b.calendar.sample.example");
    expect(r.out).toContain("rfc3161   : ");
    expect(r.err).toContain("Its signature was not checked here");
    // The folder still checks, offline: the proofs name the head's hash.
    const audit = attest(["log", "verify", dir]);
    expect(audit.stdout).toContain("RESULT: PASS");
  }, 120_000);

  it("a second proof of one kind is numbered, never written over", async () => {
    const r = await caught(() => runLogWitness(dir, { ots: false, tsa: TSA, fetch: witnesses(Math.floor(Date.now() / 1000)).fetch }));
    expect(r.error).toBeNull();
    expect(readdirSync(join(dir, "witness")).sort()).toEqual(["1.2.tsr", "1.ots", "1.tsr"]);
    // Leaving out both witnesses is refused before anything is sent.
    const none = stub(() => ({ ok: true, status: 200, bytes: new Uint8Array(0) }));
    const refused = await caught(() => runLogWitness(dir, { ots: false, fetch: none.fetch }));
    expect(String((refused.error as Error).message)).toContain("leaves no witness");
    expect(none.requests).toHaveLength(0);
  }, 120_000);

  it("a witness that fails is named, the other is still kept, and the command fails", async () => {
    const net = stub((url, body) =>
      url === TSA ? { ok: true, status: 200, bytes: fakeTimeStampResp({ ...readRequest(body!), genTimeUnix: Math.floor(Date.now() / 1000) }) } : { ok: false, status: 503, bytes: new Uint8Array(0) },
    );
    const r = await caught(() => runLogWitness(dir, { ots: true, tsa: TSA, calendar: CALENDARS, fetch: net.fetch }));
    expect((r.error as { code?: string }).code).toBe("WITNESS_FAILED");
    expect(String((r.error as Error).message)).toContain("OpenTimestamps:");
    expect(String((r.error as Error).message)).toContain("only 0 calendar(s) accepted");
    expect(String((r.error as Error).message)).toContain("the other witness was kept");
    expect(readdirSync(join(dir, "witness")).sort()).toEqual(["1.2.tsr", "1.3.tsr", "1.ots", "1.tsr"]);
  }, 120_000);

  it.skipIf(!opensslAvailable())("--tsa-root keeps a token only when openssl verifies its signature against that root", async () => {
    const before = readdirSync(join(dir, "witness")).length;
    const root = join(ATTEST, "test", "vectors", "log", "sample-tsa-root.crt");
    const r = await caught(() => runLogWitness(dir, { ots: false, tsa: TSA, tsaRoot: root, fetch: witnesses(Math.floor(Date.now() / 1000)).fetch }));
    expect((r.error as { code?: string }).code).toBe("WITNESS_FAILED");
    expect(String((r.error as Error).message)).toContain("does not verify against");
    expect(readdirSync(join(dir, "witness"))).toHaveLength(before);
  }, 120_000);

  it("the proof carries its head's witnesses", async () => {
    const r = await caught(() => runLogProof(dir, "0"));
    expect(r.error).toBeNull();
    const proof = JSON.parse(r.out);
    expect(proof.witnesses.map((w: { kind: string }) => w.kind).sort()).toEqual(["opentimestamps", "rfc3161", "rfc3161", "rfc3161"]);
  }, 120_000);

  it("upgrade asks only the calendars a pending proof names, keeps the Bitcoin attestation it gets, and then has nothing to ask", async () => {
    const before = new Uint8Array(readFileSync(join(dir, "witness", "1.ots")));
    const events: string[] = [];
    const net = stub((url) => {
      const m = /\/timestamp\/([0-9a-f]{64})$/.exec(url);
      return m !== null && url.startsWith(CALENDARS[0]!) ? { ok: true, status: 200, bytes: blockFor(hexToBytes(m[1]!)) } : { ok: false, status: 404, bytes: new Uint8Array(0) };
    }, events);
    const r = await caught(() => runLogUpgrade(dir, { calendar: CALENDARS, fetch: net.fetch }), events);
    expect(r.error).toBeNull();
    expect(net.requests.every((q) => q.method === "GET" && CALENDARS.some((c) => q.url.startsWith(`${c}/timestamp/`)))).toBe(true);
    expect(events.findIndex((e) => e.includes("Going online"))).toBeLessThan(events.findIndex((e) => e.startsWith("request")));
    expect(r.out).toContain("upgraded");
    expect(r.out).toContain("Bitcoin block 1");
    const after = new Uint8Array(readFileSync(join(dir, "witness", "1.ots")));
    expect(bytesToHex(after)).not.toBe(bytesToHex(before));
    expect(otsLeaves((await parseOts(after)).timestamp).some((l) => l.attestation.kind === "bitcoin")).toBe(true);

    const quiet = stub(() => ({ ok: false, status: 500, bytes: new Uint8Array(0) }));
    const again = await caught(() => runLogUpgrade(dir, { calendar: CALENDARS, fetch: quiet.fetch }));
    expect(again.error).toBeNull();
    expect(quiet.requests).toHaveLength(0);
    expect(again.err).toContain("Nothing was sent");
  }, 120_000);
});
