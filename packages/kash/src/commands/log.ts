/**
 * `kash log …` — the publisher keeps the trust log (KS-Q4; specs/trust-log.md;
 * ECOSYSTEM d84 P6, d91(a), (f) and (i)).
 *
 * A log is a folder — `log.json`, `entries/`, `checkpoints/`, `witness/`, the
 * layout attest's `log-files` reads and writes — which any static host serves
 * and any host mirrors by copying. It holds issuers and lists, and
 * attestations by salted hash: never a person, a presentation or a record's
 * content. attest's guard refuses anything else before a leaf is made, and
 * `add` checks a whole batch before it writes any of it.
 *
 *   kash log init <dir> --name <slug>     start a log whose key is the publisher key
 *   kash log add <dir> <file>…            a signed trust list's version and its key changes,
 *                                         a signed status list's version, or attestation entries
 *   kash log checkpoint <dir>             sign the head with the publisher key
 *   kash log witness <dir>                ONLINE — the head's hash to public witnesses
 *   kash log upgrade <dir>                ONLINE — the Bitcoin attestations pending proofs wait for
 *   kash log proof <dir> <index>          one entry's inclusion proof, with its head's witnesses
 *
 * Only `witness` and `upgrade` open a socket, and each says so before it does.
 * What they send is a checkpoint's 32-byte hash, or a calendar's own
 * commitment: neither names anything. A stranger checks the folder with
 * `attest log verify <dir>` — without kash, the publisher or the network.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  AttestError,
  DST_STATUS_LIST,
  DST_TRUST_LIST,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  makeKeyResolver,
  trustListKeyMap,
  verifyStatusList,
  verifyTrustList,
  type DsseEnvelope,
  type TrustListReport,
} from "@kashscript/attest";
import {
  LOG_INCLUSION_FORMAT,
  checkpointHash,
  checkpointPayloadOf,
  claimedTimeOf,
  describeLog,
  logEntryFaults,
  logLeafHash,
  openTrustLog,
  verifyCheckpoint,
  verifyLogInclusion,
  type IssuerKeyLogEntry,
  type LogCheckpointPayload,
  type LogDescriptor,
  type LogEntry,
  type LogInclusionProof,
  type LogWitness,
  type StatusListLogEntry,
  type TrustListLogEntry,
} from "@kashscript/attest/log";
import { FileLogStore, initLogDirectory, listLogWitnesses, readLogDescriptor, replaceLogWitness, writeLogWitness } from "@kashscript/attest/log-files";
import { opensslAvailable, opensslRfc3161Check, type OpensslCheck } from "@kashscript/attest/openssl";
import {
  DEFAULT_OTS_CALENDARS,
  DEFAULT_RFC3161_URL,
  KNOWN_OTS_CALENDARS,
  rfc3161Stamp,
  rfc6962Tree,
  stampOpenTimestamps,
  upgradeOpenTimestamps,
  verifyOpenTimestamps,
  type FetchBytes,
} from "@kashscript/attest/witness";
import { didKeyType } from "@kashscript/identity-core";

import { KashCliError } from "../errors";
import { loadKey } from "../keystore/store";
import { writeOutput } from "../utils/files";

export interface LogKeyOptions {
  /** The log's key: default `publisher` — the role that signs trust lists (d62(d)5), never the station's. */
  readonly key?: string;
  readonly keystore?: string;
}

const say = (line: string): void => {
  process.stdout.write(`${line}\n`);
};
const note = (line: string): void => {
  process.stderr.write(`${line}\n`);
};
const nowSec = (): number => Math.floor(Date.now() / 1000);
const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(".000Z", "Z");
const sha256Hex = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const host = (url: string): string => url.replace(/^https?:\/\//, "").replace(/\/+$/, "");
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

/** attest's refusals become the CLI's, with what was being done in front. */
async function attempt<T>(what: string, run: () => T | Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof AttestError) throw new KashCliError(`${what}: ${err.message}`, "RECORD_INVALID", err);
    throw err;
  }
}

function logDir(dir: string): string {
  const abs = resolve(dir);
  if (!existsSync(resolve(abs, "log.json"))) {
    throw new KashCliError(`${abs} holds no log.json. Start a log there first: kash log init ${dir} --name <slug>`, "INVALID_INPUT");
  }
  return abs;
}

function readDescriptor(abs: string): LogDescriptor {
  try {
    return readLogDescriptor(abs);
  } catch (err) {
    throw new KashCliError(`log.json does not read: ${(err as Error).message}`, "RECORD_INVALID", err);
  }
}

function wholeNumber(raw: string, flag: string, min: number): number {
  const n = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(n) || n < min) throw new KashCliError(`${flag} is a whole number from ${min}; got ${JSON.stringify(raw)}.`, "INVALID_INPUT");
  return n;
}

/** The real network — for `witness` and `upgrade` only; tests hand in their own. 30 seconds a request. */
const networkFetch: FetchBytes = async (url, init) => {
  const res = await fetch(url, {
    method: init.method,
    headers: init.headers,
    ...(init.body !== undefined ? { body: init.body as unknown as BodyInit } : {}),
    signal: AbortSignal.timeout(30_000),
  });
  return { ok: res.ok, status: res.status, bytes: async () => new Uint8Array(await res.arrayBuffer()) };
};

/* ── init ─────────────────────────────────────────────────────────────── */

export interface LogInitOptions extends LogKeyOptions {
  readonly name: string;
  readonly maxBatchDelay?: string;
  readonly origin?: string;
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function runLogInit(dir: string, opts: LogInitOptions): Promise<void> {
  if (!SLUG.test(opts.name)) {
    throw new KashCliError(`--name is a short slug: lowercase letters, digits and hyphens, at most 63. Got ${JSON.stringify(opts.name)}.`, "INVALID_INPUT");
  }
  const abs = resolve(dir);
  if (existsSync(resolve(abs, "log.json"))) throw new KashCliError(`${abs} already holds a log. A log is started once; kash never rewrites one.`, "UNSAFE_WRITE");
  const publisher = await loadKey(opts.key ?? "publisher", opts.keystore);
  const maxBatchDelaySec = opts.maxBatchDelay === undefined ? undefined : wholeNumber(opts.maxBatchDelay, "--max-batch-delay", 0);
  const descriptor = await attempt("The log was not started", () =>
    describeLog({
      logId: `${publisher.did}/log/${opts.name}`,
      startedAtUnix: nowSec(),
      ...(maxBatchDelaySec !== undefined ? { maxBatchDelaySec } : {}),
      ...(opts.origin !== undefined ? { origin: opts.origin } : {}),
    }),
  );
  await attempt("The log was not started", () => initLogDirectory(abs, descriptor));
  say(`log       : ${descriptor.logId}`);
  say(`key       : ${descriptor.key} — the publisher key; only it signs this log's heads`);
  say(`folder    : ${abs}`);
  say(`started   : ${iso(descriptor.startedAtUnix)} — the log's own word; its first head's witness bounds it`);
  say(`allowance : ${descriptor.maxBatchDelaySec} s between an entry's claimed time and its first witnessed head`);
  say(`origin    : ${descriptor.origin ?? "not set — put the https address you serve the folder from in log.json"}`);
  note("✓ Started. Next: kash log add <dir> <signed trust list>, then kash log checkpoint <dir>, then kash log witness <dir>.");
  note("  The folder is the log. Serve it from any static host; anyone may mirror it by copying it.");
}

/* ── add ──────────────────────────────────────────────────────────────── */

export interface LogAddOptions {
  /** Signed versions of trust lists the log already holds, so the key changes to the next version can be logged. */
  readonly previous?: readonly string[];
  /** Signed trust lists whose keys check a status list's signature, when its issuer's identifier is not its key. */
  readonly trustList?: readonly string[];
}

type FileItem = { readonly envelope: DsseEnvelope } | { readonly entries: readonly unknown[] };

function isEnvelope(v: unknown): v is DsseEnvelope {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  return typeof o["payloadType"] === "string" && typeof o["payload"] === "string" && Array.isArray(o["signatures"]);
}

function readItem(file: string): FileItem {
  const abs = resolve(file);
  if (!existsSync(abs)) throw new KashCliError(`${file}: no file at ${abs}.`, "INVALID_INPUT");
  const text = readFileSync(abs, "utf8");
  if (abs.endsWith(".jsonl")) {
    const entries: unknown[] = [];
    for (const [i, line] of text.split("\n").entries()) {
      if (line.trim() === "") continue;
      try {
        entries.push(JSON.parse(line));
      } catch (err) {
        throw new KashCliError(`${file}: line ${i + 1} is not JSON.`, "INVALID_INPUT", err);
      }
    }
    return { entries };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new KashCliError(`${file}: not valid JSON.`, "INVALID_INPUT", err);
  }
  if (isEnvelope(value)) return { envelope: value };
  return { entries: Array.isArray(value) ? value : [value] };
}

async function signedTrustList(file: string, flag: string): Promise<{ readonly report: TrustListReport; readonly sha256: string }> {
  const item = readItem(file);
  if (!("envelope" in item) || item.envelope.payloadType !== DST_TRUST_LIST) throw new KashCliError(`${flag}${file}: not a signed trust list.`, "INVALID_INPUT");
  const report = await verifyTrustList(item.envelope, {});
  if (!report.ok || report.listId === null || report.publisher === null || report.version === null || report.issuedAtUnix === null) {
    throw new KashCliError(`${flag}${file}: the trust list does not verify (${report.reason}).`, "RECORD_INVALID");
  }
  return { report, sha256: sha256Hex(base64ToBytes(item.envelope.payload)) };
}

const listKey = (publisher: string, listId: string): string => `${publisher} ${listId}`;

interface KeyRow {
  readonly issuerId: string;
  readonly keyid: string;
  readonly alg: "Ed25519" | "ES256";
}

/** The keys a list names: each listed key, or — for an issuer whose identifier is its key — the identifier itself. */
function keysOf(report: TrustListReport): KeyRow[] {
  const rows: KeyRow[] = [];
  for (const issuer of report.issuers) {
    if (issuer.keys.length > 0) {
      for (const k of issuer.keys) rows.push({ issuerId: issuer.issuerId, keyid: k.keyid, alg: k.alg });
      continue;
    }
    const type = didKeyType(issuer.issuerId);
    if (type !== null) rows.push({ issuerId: issuer.issuerId, keyid: issuer.issuerId, alg: type === "Ed25519" ? "Ed25519" : "ES256" });
  }
  return rows;
}

/**
 * The key changes from one version of a list to the next: a key that appears
 * is `added` — or `rotated` when the same issuer lost a key in this version —
 * and a key that is gone is `revoked` (retired or withdrawn; the log does not
 * say which). A change of standing is in the list's own version, which the
 * trust-list entry hashes; it is not a key event.
 */
function keyChanges(before: TrustListReport | null, after: TrustListReport): { readonly row: KeyRow; readonly action: IssuerKeyLogEntry["action"] }[] {
  const id = (r: KeyRow): string => `${r.issuerId} ${r.keyid} ${r.alg}`;
  const old = before === null ? [] : keysOf(before);
  const now = keysOf(after);
  const oldIds = new Set(old.map(id));
  const nowIds = new Set(now.map(id));
  const lostKey = new Set(old.filter((r) => !nowIds.has(id(r))).map((r) => r.issuerId));
  const out: { row: KeyRow; action: IssuerKeyLogEntry["action"] }[] = [];
  for (const r of now) if (!oldIds.has(id(r))) out.push({ row: r, action: lostKey.has(r.issuerId) ? "rotated" : "added" });
  for (const r of old) if (!nowIds.has(id(r))) out.push({ row: r, action: "revoked" });
  return out;
}

interface Pending {
  readonly entry: LogEntry;
  readonly what: string;
}

export async function runLogAdd(dir: string, files: readonly string[], opts: LogAddOptions = {}): Promise<void> {
  const abs = logDir(dir);
  const descriptor = readDescriptor(abs);
  const start = descriptor.startedAtUnix;
  const store = new FileLogStore(abs);
  const held = await attempt("The log does not read", async () => store.entries(0, await store.size()));

  // What the log holds, for duplicates and for the order of a list's versions.
  const leaves = new Map<string, string>();
  for (const [i, e] of held.entries()) leaves.set(bytesToHex(await logLeafHash(e)), `entry ${i}`);
  const versions = new Map<string, { version: number; sha256: string; at: string }>();
  const listHashes = new Map<string, { version: number; at: string }>();
  for (const [i, e] of held.entries()) {
    if (e.kind !== "trust-list") continue;
    listHashes.set(e.sha256, { version: e.version, at: `entry ${i}` });
    const k = listKey(e.publisher, e.listId);
    const cur = versions.get(k);
    if (cur === undefined || e.version > cur.version) versions.set(k, { version: e.version, sha256: e.sha256, at: `entry ${i}` });
  }

  // The versions the log holds, handed in so the next version's key changes can be written.
  const reports = new Map<string, TrustListReport>();
  for (const file of opts.previous ?? []) {
    const { report, sha256 } = await signedTrustList(file, "--previous ");
    const k = listKey(report.publisher!, report.listId!);
    const logged = versions.get(k);
    if (logged === undefined) {
      throw new KashCliError(`--previous ${file}: the log holds no version of ${report.listId}. Its first version logs every key as added — drop --previous.`, "INVALID_INPUT");
    }
    if (sha256 !== logged.sha256) throw new KashCliError(`--previous ${file}: the log holds version ${logged.version} of ${report.listId} (${logged.at}), and this file is not it.`, "RECORD_INVALID");
    reports.set(k, report);
  }

  // Keys from lists the caller hands in — and from lists this batch adds — check a status list's signature.
  const keyLists: TrustListReport[] = [];
  for (const file of opts.trustList ?? []) {
    const item = readItem(file);
    if (!("envelope" in item) || item.envelope.payloadType !== DST_TRUST_LIST) throw new KashCliError(`--trust-list ${file}: not a signed trust list.`, "INVALID_INPUT");
    const first = await verifyTrustList(item.envelope, {});
    if (!first.ok || first.publisher === null) throw new KashCliError(`--trust-list ${file}: the trust list does not verify (${first.reason}).`, "RECORD_INVALID");
    keyLists.push(await verifyTrustList(item.envelope, { pinnedPublishers: [first.publisher] }));
  }

  const pending: Pending[] = [];
  const batch = new Map<string, string>();
  const mark = (claimed: number): { backfilled?: true } => (claimed < start ? { backfilled: true } : {});
  const queue = async (entry: LogEntry, what: string, from: string): Promise<void> => {
    const faults = logEntryFaults(entry);
    if (faults.length > 0) throw new KashCliError(`${from}: refused — ${faults.map((f) => `${f.code} ${f.message}`).join("; ")}. Nothing was written.`, "RECORD_INVALID");
    const leaf = bytesToHex(await logLeafHash(entry));
    const seen = leaves.get(leaf) ?? batch.get(leaf);
    if (seen !== undefined) throw new KashCliError(`${from}: already in the log (${seen}). A log holds each entry once. Nothing was written.`, "RECORD_INVALID");
    batch.set(leaf, `${from}, earlier in this batch`);
    pending.push({ entry, what });
  };

  for (const file of files) {
    const item = readItem(file);
    if ("envelope" in item) {
      const env = item.envelope;
      if (env.payloadType === DST_TRUST_LIST) {
        const { report, sha256 } = await signedTrustList(file, "");
        const k = listKey(report.publisher!, report.listId!);
        const logged = versions.get(k);
        const same = listHashes.get(sha256);
        if (same !== undefined) throw new KashCliError(`${file}: version ${same.version} of ${report.listId} is already in the log (${same.at}). Nothing was written.`, "RECORD_INVALID");
        if (logged !== undefined) {
          if (report.version! <= logged.version) {
            throw new KashCliError(`${file}: the log holds version ${logged.version} of ${report.listId} (${logged.at}); versions go in once, in rising order. Nothing was written.`, "RECORD_INVALID");
          }
          if (!reports.has(k)) {
            throw new KashCliError(
              `${file}: the log holds version ${logged.version} of ${report.listId}. Pass --previous <that version's signed file>, so the key changes from ${logged.version} to ${report.version} are logged. Nothing was written.`,
              "INVALID_INPUT",
            );
          }
        }
        const issued = report.issuedAtUnix!;
        const tl: TrustListLogEntry = { v: 1, kind: "trust-list", listId: report.listId!, publisher: report.publisher!, version: report.version!, issuedAtUnix: issued, sha256, ...mark(issued) };
        await queue(tl, `trust-list   ${report.listId} v${report.version} by ${report.publisher} — ${plural(report.issuers.length, "issuer", "issuers")}${report.current ? "" : " (outside its window now)"}`, file);
        for (const { row, action } of keyChanges(reports.get(k) ?? null, report)) {
          const ke: IssuerKeyLogEntry = { v: 1, kind: "issuer-key", issuerId: row.issuerId, keyid: row.keyid, alg: row.alg, action, atUnix: issued, listId: report.listId!, listVersion: report.version!, ...mark(issued) };
          await queue(ke, `issuer-key   ${action} ${row.keyid === row.issuerId ? row.keyid : `${row.keyid} of ${row.issuerId}`} (${row.alg})`, file);
        }
        versions.set(k, { version: report.version!, sha256, at: `${file}, earlier in this batch` });
        listHashes.set(sha256, { version: report.version!, at: `${file}, earlier in this batch` });
        reports.set(k, report);
        keyLists.push(await verifyTrustList(env, { pinnedPublishers: [report.publisher!] }));
        continue;
      }
      if (env.payloadType === DST_STATUS_LIST) {
        const r = await verifyStatusList(env, { resolveKey: makeKeyResolver(trustListKeyMap(keyLists), new Map()) });
        if (!r.ok || r.id === null || r.issuer === null || r.statusPurpose === null || r.issuedAtUnix === null) {
          throw new KashCliError(
            `${file}: the status list does not verify (${r.reason}). When its issuer's identifier is not its key, pass --trust-list <the signed list that names the key>. Nothing was written.`,
            "RECORD_INVALID",
          );
        }
        const sl: StatusListLogEntry = { v: 1, kind: "status-list", id: r.id, issuer: r.issuer, statusPurpose: r.statusPurpose, issuedAtUnix: r.issuedAtUnix, sha256: sha256Hex(base64ToBytes(env.payload)), ...mark(r.issuedAtUnix) };
        await queue(sl, `status-list  ${r.statusPurpose} ${r.id} by ${r.issuer}, as of ${iso(r.issuedAtUnix)}`, file);
        continue;
      }
      throw new KashCliError(
        `${file}: a signed ${env.payloadType} is not something a log holds. It holds trust lists, status lists, issuer keys and attestations — an attestation by its salted hash, never the record. Nothing was written.`,
        "INVALID_INPUT",
      );
    }
    for (const [n, value] of item.entries.entries()) {
      const from = item.entries.length === 1 ? file : `${file} [${n}]`;
      const faults = logEntryFaults(value);
      if (faults.length > 0) throw new KashCliError(`${from}: refused — ${faults.map((f) => `${f.code} ${f.message}`).join("; ")}. Nothing was written.`, "RECORD_INVALID");
      const entry = value as LogEntry;
      if (entry.kind !== "attestation") {
        throw new KashCliError(`${from}: a ${entry.kind} entry is written from the signed list itself — hand kash the signed file, so the entry names what was really signed. Nothing was written.`, "INVALID_INPUT");
      }
      const claimed = claimedTimeOf(entry);
      if (entry.backfilled === true && claimed >= start) {
        throw new KashCliError(
          `${from}: marked backfilled, but it claims ${iso(claimed)}, after the log began (${iso(start)}). Only a claim from before the log began is backfilled (d91(i)). Nothing was written.`,
          "RECORD_INVALID",
        );
      }
      if (entry.backfilled !== true && claimed < start) {
        throw new KashCliError(
          `${from}: it claims ${iso(claimed)}, before the log began (${iso(start)}). Mark it "backfilled": true — its time will be the witness's, never the claim (d91(i)). Nothing was written.`,
          "RECORD_INVALID",
        );
      }
      await queue(entry, `attestation  by ${entry.issuer}, claimed ${iso(claimed)}${entry.backfilled === true ? " (backfilled)" : ""}`, from);
    }
  }

  // A claim older than the allowance will be reported as not supported once a witness stamps its head: say so before it is written for good.
  const late = nowSec() - descriptor.maxBatchDelaySec;
  for (const p of pending) {
    const claimed = claimedTimeOf(p.entry);
    if (p.entry.backfilled !== true && claimed < late) {
      note(`! ${p.entry.kind} claiming ${iso(claimed)}: more than ${descriptor.maxBatchDelaySec} s ago, so a checker will report its claimed time as not supported. Log things when they happen.`);
    }
  }

  for (const p of pending) {
    const index = await store.append(p.entry, await logLeafHash(p.entry));
    say(`entry ${String(index).padStart(6)}  ${p.what}`);
  }
  note(`✓ Appended ${plural(pending.length, "entry", "entries")} — not yet in a signed head. Next: kash log checkpoint ${dir}`);
  if (pending.some((p) => p.entry.backfilled === true)) {
    note("  Backfilled entries claim a time before the log began: their time will be the witness's, never the claim (d91(i)).");
  }
}

/* ── checkpoint ───────────────────────────────────────────────────────── */

export async function runLogCheckpoint(dir: string, opts: LogKeyOptions = {}): Promise<void> {
  const abs = logDir(dir);
  const descriptor = readDescriptor(abs);
  const publisher = await loadKey(opts.key ?? "publisher", opts.keystore);
  if (publisher.did !== descriptor.key) {
    throw new KashCliError(`This log's heads are signed by ${descriptor.key}; the key given is ${publisher.did}. Nothing was signed.`, "KEY_INVALID");
  }
  const store = new FileLogStore(abs);
  const log = await attempt("The log does not open", () =>
    openTrustLog({
      logId: descriptor.logId,
      store,
      signer: { keyid: publisher.did, privateKey: publisher.privateKey, publicKey: publisher.publicKey },
      maxBatchDelaySec: descriptor.maxBatchDelaySec,
    }),
  );
  const size = await log.size();
  if (size === 0) throw new KashCliError("The log holds no entries yet, so it has no head to sign. Add one first: kash log add <dir> <file>", "INVALID_INPUT");
  const last = await log.latestCheckpoint();
  const lastSize = last === null ? null : (checkpointPayloadOf(last)?.treeSize ?? null);
  if (lastSize === size) {
    note(`No entries since the head of ${size} — nothing signed.`);
    return;
  }
  const env = await attempt("The head was not signed", () => log.checkpoint(nowSec()));
  const report = await verifyCheckpoint(env, { logId: descriptor.logId });
  if (!report.ok) throw new KashCliError(`The signed head does not verify (${report.reason}).`, "RECORD_INVALID");
  say(`head      : ${report.treeSize} entries${report.previous === null ? " — the log's first" : `, extending the head of ${report.previous.treeSize}`}`);
  say(`root      : ${report.rootHash}`);
  say(`log time  : ${iso(report.timestampUnix!)} — the log's own claim until a public witness stamps it`);
  say(`file      : ${resolve(abs, "checkpoints", `${report.treeSize}.json`)}`);
  note(`✓ Signed by the publisher ${publisher.did}. Next: kash log witness ${dir}`);
}

/* ── witness (online) ─────────────────────────────────────────────────── */

export interface LogWitnessOptions {
  readonly size?: string;
  /** OpenTimestamps runs unless this is false (`--no-ots`). */
  readonly ots?: boolean;
  readonly calendar?: readonly string[];
  /** An RFC 3161 authority: `true` for the default, or its URL. */
  readonly tsa?: string | true;
  readonly tsaRoot?: string;
  /** The network. Tests hand in their own; the CLI uses the real one. */
  readonly fetch?: FetchBytes;
}

async function headsOf(abs: string, logId: string): Promise<{ readonly env: DsseEnvelope; readonly p: LogCheckpointPayload }[]> {
  const store = new FileLogStore(abs);
  const envs = await attempt("The log does not read", () => store.checkpoints());
  return envs.flatMap((env) => {
    const p = checkpointPayloadOf(env);
    return p !== null && p.logId === logId ? [{ env, p }] : [];
  });
}

export async function runLogWitness(dir: string, opts: LogWitnessOptions = {}): Promise<void> {
  const abs = logDir(dir);
  const descriptor = readDescriptor(abs);
  const heads = await headsOf(abs, descriptor.logId);
  if (heads.length === 0) throw new KashCliError("The log has no signed head yet. Sign one first: kash log checkpoint <dir>", "INVALID_INPUT");
  const want = opts.size === undefined ? null : wholeNumber(opts.size, "--size", 1);
  const head = want === null ? heads[heads.length - 1] : heads.find((h) => h.p.treeSize === want);
  if (head === undefined) throw new KashCliError(`The log has no head of ${want}. Its heads: ${heads.map((h) => h.p.treeSize).join(", ")}.`, "INVALID_INPUT");
  const report = await verifyCheckpoint(head.env, { logId: descriptor.logId });
  if (!report.ok) throw new KashCliError(`The head of ${head.p.treeSize} does not verify (${report.reason}); nothing was sent.`, "RECORD_INVALID");
  const size = head.p.treeSize;
  const digest = await checkpointHash(head.env);
  // Two witnesses that fail differently (GOV-5): OpenTimestamps by default, and an RFC 3161 authority beside it when asked.
  const useTsa = opts.tsa !== undefined;
  const useOts = opts.ots !== false;
  if (!useOts && !useTsa) throw new KashCliError("--no-ots leaves no witness: add --tsa [url], or drop --no-ots. Nothing was sent.", "INVALID_INPUT");
  const calendars = opts.calendar !== undefined && opts.calendar.length > 0 ? opts.calendar : DEFAULT_OTS_CALENDARS;
  const tsaUrl = typeof opts.tsa === "string" ? opts.tsa : DEFAULT_RFC3161_URL;

  // Everything that can fail without the network fails before it.
  let rootCheck: OpensslCheck | null = null;
  if (useTsa && opts.tsaRoot !== undefined) {
    if (!opensslAvailable()) {
      throw new KashCliError(
        "--tsa-root needs openssl on this machine, to check the token before it is kept. Install it, or drop --tsa-root: the token is then kept unchecked, and attest log verify --tsa-root checks it later. Nothing was sent.",
        "VERIFIER_NOT_FOUND",
      );
    }
    try {
      rootCheck = opensslRfc3161Check(resolve(opts.tsaRoot));
    } catch (err) {
      throw new KashCliError(`--tsa-root ${opts.tsaRoot}: ${(err as Error).message}. Nothing was sent.`, "INVALID_INPUT", err);
    }
  }
  const fetchImpl = opts.fetch ?? networkFetch;
  const to = [useOts ? `${plural(calendars.length, "OpenTimestamps calendar", "OpenTimestamps calendars")} (${calendars.map(host).join(", ")})` : null, useTsa ? `the RFC 3161 authority ${host(tsaUrl)}` : null]
    .filter((s): s is string => s !== null)
    .join(" and ");
  note(`Going online: the head of ${size}'s hash — 32 bytes that name nothing — goes to ${to}.`);
  say(`head      : ${size} entries, root ${report.rootHash}, the log's time ${iso(report.timestampUnix!)}`);
  say(`digest    : ${digest} — SHA-256 of the head's signed payload, what a witness stamps`);

  const failures: string[] = [];
  if (useOts) {
    try {
      const stamped = await stampOpenTimestamps(digest, { fetch: fetchImpl, calendars });
      const path = writeLogWitness(abs, size, "opentimestamps", stamped.ots);
      say(`ots       : pending at ${stamped.accepted.map(host).join(", ")} → ${path}`);
      for (const p of stamped.problems) note(`  ! ${p}`);
      note(`  Pending until a calendar's commitment reaches a Bitcoin block, usually within hours. Then: kash log upgrade ${dir}`);
    } catch (err) {
      failures.push(`OpenTimestamps: ${(err as Error).message}`);
    }
  }
  if (useTsa) {
    try {
      const got = await rfc3161Stamp(digest, { fetch: fetchImpl, url: tsaUrl });
      if (rootCheck !== null && !(await rootCheck.check(got.tsr, digest))) {
        throw new Error(`the token's signature does not verify against ${opts.tsaRoot} (sha256 ${rootCheck.rootSha256}), so it was not kept`);
      }
      const path = writeLogWitness(abs, size, "rfc3161", got.tsr);
      say(`rfc3161   : ${got.token.genTime} by ${got.token.tsaName ?? host(tsaUrl)}, serial ${got.token.serialHex} → ${path}`);
      if (rootCheck !== null) say(`tsa root  : sha256 ${rootCheck.rootSha256} — signature and chain checked by openssl; compare it with the authority's published fingerprint`);
      else note("  Its signature was not checked here: attest log verify <dir> --tsa-root <pem> checks it, and only then is its time relied on.");
    } catch (err) {
      failures.push(`RFC 3161: ${(err as Error).message}`);
    }
  }
  if (failures.length > 0) {
    throw new KashCliError(`${failures.join(" · ")}${failures.length < (useOts ? 1 : 0) + (useTsa ? 1 : 0) ? " (the other witness was kept)" : ""}`, "WITNESS_FAILED");
  }
  note("✓ Kept in witness/. A checker reads the head's time from these proofs, never from the log's own claim.");
}

/* ── upgrade (online) ─────────────────────────────────────────────────── */

export interface LogUpgradeOptions {
  /** Calendars a pending proof may be upgraded from. Default: the four known calendars. */
  readonly calendar?: readonly string[];
  readonly fetch?: FetchBytes;
}

export async function runLogUpgrade(dir: string, opts: LogUpgradeOptions = {}): Promise<void> {
  const abs = logDir(dir);
  const descriptor = readDescriptor(abs);
  const heads = new Map((await headsOf(abs, descriptor.logId)).map((h) => [h.p.treeSize, h.env]));
  const proofs = listLogWitnesses(abs).filter((w) => w.kind === "opentimestamps");
  if (proofs.length === 0) {
    note("No OpenTimestamps proofs in witness/ — nothing to upgrade. Nothing was sent.");
    return;
  }
  const waiting: { path: string; digest: string; bytes: Uint8Array }[] = [];
  for (const w of proofs) {
    const head = heads.get(w.treeSize);
    if (head === undefined) {
      note(`! ${w.path}: no head of ${w.treeSize} in checkpoints/ — skipped.`);
      continue;
    }
    const digest = await checkpointHash(head);
    const bytes = new Uint8Array(readFileSync(w.path));
    const v = await verifyOpenTimestamps(bytes, digest);
    if (!v.digestOk || v.state === "invalid") note(`! ${w.path}: ${v.detail} — skipped.`);
    else if (v.state === "pending") waiting.push({ path: w.path, digest, bytes });
    else say(`complete  : ${w.path} — ${v.by}`);
  }
  if (waiting.length === 0) {
    note("No proof waits for a block. Nothing was sent.");
    return;
  }
  const known = opts.calendar !== undefined && opts.calendar.length > 0 ? opts.calendar : KNOWN_OTS_CALENDARS;
  note(`Going online: asking the calendars named in ${plural(waiting.length, "pending proof", "pending proofs")} for their Bitcoin attestations. Each request names a calendar's own commitment, nothing else.`);
  for (const w of waiting) {
    const up = await attempt(w.path, () => upgradeOpenTimestamps(w.bytes, { fetch: opts.fetch ?? networkFetch, knownCalendars: known }));
    if (!up.changed) {
      say(`pending   : ${w.path}${up.notes.length > 0 ? ` — ${up.notes.join("; ")}` : ""}`);
      continue;
    }
    replaceLogWitness(w.path, up.ots);
    const v = await verifyOpenTimestamps(up.ots, w.digest);
    say(`upgraded  : ${w.path} — ${v.by}`);
  }
  note("  A proof that reached a block is final where a checker holds that block's header: attest log verify <dir> --header <file>.");
}

/* ── proof (offline) ──────────────────────────────────────────────────── */

export interface LogProofOptions {
  readonly size?: string;
  readonly out?: string;
}

export async function runLogProof(dir: string, indexArg: string, opts: LogProofOptions = {}): Promise<void> {
  const abs = logDir(dir);
  const descriptor = readDescriptor(abs);
  const index = wholeNumber(indexArg, "<index>", 0);
  const store = new FileLogStore(abs);
  const size = await attempt("The log does not read", () => store.size());
  if (index >= size) throw new KashCliError(`The log holds ${plural(size, "entry", "entries")}; there is no entry ${index}.`, "INVALID_INPUT");
  const heads = await headsOf(abs, descriptor.logId);
  const want = opts.size === undefined ? null : wholeNumber(opts.size, "--size", 1);
  // By default, the first head that held the entry: only its witness can judge the entry's claimed time.
  const head = want === null ? heads.find((h) => h.p.treeSize > index) : heads.find((h) => h.p.treeSize === want);
  if (head === undefined) {
    throw new KashCliError(want === null ? `No signed head holds entry ${index} yet. Sign one first: kash log checkpoint ${dir}` : `The log has no head of ${want}.`, "INVALID_INPUT");
  }
  if (head.p.treeSize <= index) throw new KashCliError(`The head of ${head.p.treeSize} does not hold entry ${index}.`, "INVALID_INPUT");
  const entry = await store.entry(index);
  if (entry === null) throw new KashCliError(`The log has no entry ${index}.`, "INVALID_INPUT");
  const tree = await rfc6962Tree(await store.leafHashes(0, head.p.treeSize));
  const witnesses: LogWitness[] = listLogWitnesses(abs)
    .filter((w) => w.treeSize === head.p.treeSize)
    .map((w) => ({ kind: w.kind, proofBase64: bytesToBase64(new Uint8Array(readFileSync(w.path))) }));
  const proof: LogInclusionProof = {
    format: LOG_INCLUSION_FORMAT,
    logId: descriptor.logId,
    entry,
    leafIndex: index,
    treeSize: head.p.treeSize,
    path: tree.path(index).map(bytesToHex),
    checkpoint: head.env,
    witnesses,
  };
  const check = await verifyLogInclusion(proof, { logId: descriptor.logId, maxBatchDelaySec: descriptor.maxBatchDelaySec, logStartedAtUnix: descriptor.startedAtUnix });
  if (!check.included || check.checkpoint?.ok !== true) {
    throw new KashCliError(`The proof does not check (${check.reason}), so nothing was written. The folder may have changed under it: attest log verify ${dir}`, "RECORD_INVALID");
  }
  const text = `${JSON.stringify(proof, null, 2)}\n`;
  if (opts.out !== undefined) note(`✓ Wrote ${writeOutput(opts.out, text)}`);
  process.stdout.write(text);
  const first = head.p.previous === null || index >= head.p.previous.treeSize;
  note(
    `✓ Entry ${index} (${entry.kind}) in the head of ${head.p.treeSize}` +
      (first ? " — the first head that held it, so its witness can judge the claimed time." : " — a later head than its first: its witness is an upper bound, and the claimed time is not judged."),
  );
  if (witnesses.length === 0) note(`  The head of ${head.p.treeSize} has no witness yet: kash log witness ${dir} --size ${head.p.treeSize}, then make the proof again.`);
  note("  The proof names this entry alone. Anyone checks it offline: attest verify <proof>");
}
