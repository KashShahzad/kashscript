/**
 * The trust log as files (KS-Q4; specs/trust-log.md §6) — the one module of
 * `@kashscript/attest/log` that touches a disk, exported as
 * `@kashscript/attest/log-files` and never from the package's index, so the
 * browser never sees `node:fs`. A static host serves these files; a mirror
 * copies them; `kash log` writes them; `attest log verify` reads them.
 *
 *   <dir>/log.json                  the descriptor
 *   <dir>/entries/000000.jsonl      entries 0–999, one canonical JSON object a line; 000001.jsonl the next thousand …
 *   <dir>/checkpoints/<size>.json   the signed head of that size
 *   <dir>/checkpoint.json           a copy of the newest head
 *   <dir>/witness/<size>.ots        an OpenTimestamps proof over the head's payload hash
 *   <dir>/witness/<size>.tsr        an RFC 3161 token over it (several of a kind: <size>.2.tsr …)
 */

import { canonicalize } from "@kashscript/identity-core";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToBase64 } from "../ed25519";
import { AttestError } from "../errors";
import type { DsseEnvelope } from "../dsse";
import type { LogWitness } from "../witness/verdict";
import type { LogFiles } from "./audit";
import { checkpointPayloadOf } from "./checkpoint";
import { logEntryFaults, logLeafHash, type LogEntry } from "./entries";
import { type LogDescriptor, type LogStore, logDescriptorFaults } from "./log";

export const ENTRIES_PER_FILE = 1000;
const CHUNK = /^(\d{6})\.jsonl$/;
const CHECKPOINT_FILE = /^(\d+)\.json$/;
/** What an auditor reads: every `.json` under checkpoints/ whose name starts with a size — a second view of one size included. */
const ANY_CHECKPOINT_FILE = /^(\d+)[^/\\]*\.json$/;
const WITNESS_FILE = /^(\d+)(?:\.\d+)?\.(ots|tsr)$/;

const chunkName = (index: number): string => `${String(Math.floor(index / ENTRIES_PER_FILE)).padStart(6, "0")}.jsonl`;

/** Write a file whole, then move it into place, so a reader never sees half of it. */
function writeAtomic(path: string, data: string | Uint8Array): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

/** Read every entry file in order and parse each line. Throws on a line that is not JSON. */
export function readLogEntries(dir: string): unknown[] {
  const folder = join(dir, "entries");
  if (!existsSync(folder)) return [];
  const names = readdirSync(folder).filter((n) => CHUNK.test(n)).sort();
  const out: unknown[] = [];
  for (const name of names) {
    const text = readFileSync(join(folder, name), "utf8");
    for (const line of text.split("\n")) {
      if (line.trim().length === 0) continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        throw new AttestError("MALFORMED_PAYLOAD", `${name}: a line is not JSON`);
      }
    }
  }
  return out;
}

/** Read a log directory into the shape the audit takes. Reads only; never follows a link out of the directory. */
export function readLogDirectory(dir: string): LogFiles {
  if (!existsSync(join(dir, "log.json"))) throw new AttestError("IO_ERROR", `${dir} holds no log.json`);
  const descriptor: unknown = JSON.parse(readFileSync(join(dir, "log.json"), "utf8"));
  const entries = readLogEntries(dir);
  const checkpoints: unknown[] = [];
  const cpDir = join(dir, "checkpoints");
  if (existsSync(cpDir)) {
    const sizeOf = (n: string): number => Number(ANY_CHECKPOINT_FILE.exec(n)![1]);
    const names = readdirSync(cpDir)
      .filter((n) => ANY_CHECKPOINT_FILE.test(n))
      .sort((a, b) => sizeOf(a) - sizeOf(b) || (a < b ? -1 : a > b ? 1 : 0));
    for (const name of names) checkpoints.push(JSON.parse(readFileSync(join(cpDir, name), "utf8")));
  }
  const witnesses: { treeSize: number; witness: LogWitness }[] = [];
  const wDir = join(dir, "witness");
  if (existsSync(wDir)) {
    for (const name of readdirSync(wDir).sort()) {
      const m = WITNESS_FILE.exec(name);
      if (m === null) continue;
      witnesses.push({ treeSize: Number(m[1]), witness: { kind: m[2] === "ots" ? "opentimestamps" : "rfc3161", proofBase64: bytesToBase64(new Uint8Array(readFileSync(join(wDir, name)))) } });
    }
  }
  return { descriptor, entries, checkpoints, witnesses };
}

/** Start a log directory: `log.json` and the empty folders. Refuses a directory that already holds a log. */
export function initLogDirectory(dir: string, descriptor: LogDescriptor): void {
  const faults = logDescriptorFaults(descriptor);
  if (faults.length > 0) throw new AttestError("INVALID_INPUT", faults.join("; "));
  if (existsSync(join(dir, "log.json"))) throw new AttestError("INVALID_INPUT", `${dir} already holds a log`);
  mkdirSync(join(dir, "entries"), { recursive: true });
  mkdirSync(join(dir, "checkpoints"), { recursive: true });
  mkdirSync(join(dir, "witness"), { recursive: true });
  writeAtomic(join(dir, "log.json"), `${JSON.stringify(descriptor, null, 2)}\n`);
}

/** The descriptor of a log directory, checked. */
export function readLogDescriptor(dir: string): LogDescriptor {
  const d: unknown = JSON.parse(readFileSync(join(dir, "log.json"), "utf8"));
  const faults = logDescriptorFaults(d);
  if (faults.length > 0) throw new AttestError("MALFORMED_PAYLOAD", `log.json: ${faults.join("; ")}`);
  return d as LogDescriptor;
}

/** Add a witness file for the head of `treeSize`. Numbers a second file of the same kind rather than overwrite. */
export function writeLogWitness(dir: string, treeSize: number, kind: "opentimestamps" | "rfc3161", bytes: Uint8Array): string {
  const ext = kind === "opentimestamps" ? "ots" : "tsr";
  const folder = join(dir, "witness");
  mkdirSync(folder, { recursive: true });
  let name = `${treeSize}.${ext}`;
  for (let n = 2; existsSync(join(folder, name)); n++) name = `${treeSize}.${n}.${ext}`;
  writeAtomic(join(folder, name), bytes);
  return join(folder, name);
}

/** Replace a witness file in place (an upgraded OpenTimestamps proof). */
export function replaceLogWitness(path: string, bytes: Uint8Array): void {
  writeAtomic(path, bytes);
}

/** Every witness file of a log, with its path. */
export function listLogWitnesses(dir: string): { readonly path: string; readonly treeSize: number; readonly kind: "opentimestamps" | "rfc3161" }[] {
  const folder = join(dir, "witness");
  if (!existsSync(folder)) return [];
  return readdirSync(folder)
    .sort()
    .flatMap((name) => {
      const m = WITNESS_FILE.exec(name);
      return m === null ? [] : [{ path: join(folder, name), treeSize: Number(m[1]), kind: m[2] === "ots" ? ("opentimestamps" as const) : ("rfc3161" as const) }];
    });
}

/**
 * A `LogStore` over a directory in the layout above. Entries are appended to
 * the current thousand's file; a checkpoint is written to its own file and
 * copied to `checkpoint.json`. Everything is read once at open and kept in
 * memory; two writers on one directory are not supported (one publisher, one log).
 */
export class FileLogStore implements LogStore {
  private readonly rows: { entry: LogEntry; leaf: Uint8Array }[] = [];
  private readonly heads: DsseEnvelope[] = [];
  private ready: Promise<void> | null = null;

  constructor(private readonly dir: string) {}

  private load(): Promise<void> {
    this.ready ??= (async () => {
      for (const [index, e] of readLogEntries(this.dir).entries()) {
        const faults = logEntryFaults(e);
        if (faults.length > 0) throw new AttestError("MALFORMED_PAYLOAD", `entry ${index} is not a log entry: ${faults.map((f) => f.message).join("; ")}`);
        this.rows.push({ entry: e as LogEntry, leaf: await logLeafHash(e as LogEntry) });
      }
      const cpDir = join(this.dir, "checkpoints");
      if (existsSync(cpDir)) {
        const files = readdirSync(cpDir).filter((n) => CHECKPOINT_FILE.test(n)).sort((a, b) => Number(a.split(".")[0]) - Number(b.split(".")[0]));
        for (const name of files) {
          const env = JSON.parse(readFileSync(join(cpDir, name), "utf8")) as DsseEnvelope;
          if (checkpointPayloadOf(env) === null) throw new AttestError("MALFORMED_PAYLOAD", `checkpoints/${name} is not a checkpoint`);
          this.heads.push(env);
        }
      }
    })();
    return this.ready;
  }

  async size(): Promise<number> {
    await this.load();
    return this.rows.length;
  }
  async append(entry: LogEntry, leafHash: Uint8Array): Promise<number> {
    await this.load();
    const index = this.rows.length;
    const path = join(this.dir, "entries", chunkName(index));
    mkdirSync(join(this.dir, "entries"), { recursive: true });
    writeFileSync(path, `${canonicalize(entry)}\n`, { flag: "a" });
    this.rows.push({ entry: structuredClone(entry), leaf: new Uint8Array(leafHash) });
    return index;
  }
  async entry(index: number): Promise<LogEntry | null> {
    await this.load();
    return this.rows[index]?.entry ?? null;
  }
  async entries(from: number, to: number): Promise<readonly LogEntry[]> {
    await this.load();
    return this.rows.slice(from, to).map((r) => r.entry);
  }
  async leafHashes(from: number, to: number): Promise<readonly Uint8Array[]> {
    await this.load();
    return this.rows.slice(from, to).map((r) => r.leaf);
  }
  async checkpoints(): Promise<readonly DsseEnvelope[]> {
    await this.load();
    return [...this.heads];
  }
  async putCheckpoint(envelope: DsseEnvelope): Promise<void> {
    await this.load();
    const p = checkpointPayloadOf(envelope);
    if (p === null) throw new AttestError("INVALID_INPUT", "not a checkpoint");
    const text = `${JSON.stringify(envelope, null, 2)}\n`;
    mkdirSync(join(this.dir, "checkpoints"), { recursive: true });
    const own = join(this.dir, "checkpoints", `${p.treeSize}.json`);
    if (existsSync(own)) throw new AttestError("INVALID_INPUT", `a checkpoint of ${p.treeSize} already exists — a log never rewrites a head`);
    writeAtomic(own, text);
    writeAtomic(join(this.dir, "checkpoint.json"), text);
    this.heads.push(envelope);
  }
}
