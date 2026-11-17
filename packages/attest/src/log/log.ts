/**
 * The trust log's writer (KS-Q4; specs/trust-log.md §4). Pure: a store the
 * caller provides, a signer for the log's key, Web Crypto. No file, no socket.
 * `kash log` puts a directory of files behind the store; an engine puts its
 * database; a test puts memory. A mirror needs none of this — it rebuilds the
 * tree from the entries alone ({@link rebuildFromEntries}) and compares roots.
 */

import { bytesToHex } from "../chain";
import type { DsseEnvelope, DsseSigner } from "../dsse";
import { AttestError } from "../errors";
import { rfc6962ConsistencyProof, rfc6962Tree } from "../witness/rfc6962";
import { checkpointPayloadOf, isLogId, logKeyOf, signCheckpoint, type LogCheckpointPayload, type TreeHeadRef } from "./checkpoint";
import { DST_LOG_CHECKPOINT } from "./checkpoint";
import { LOG_ENTRY_LEAF_DST, logEntryFaults, logLeafHash, type LogEntry } from "./entries";
import { LOG_CONSISTENCY_FORMAT, LOG_INCLUSION_FORMAT, type LogConsistencyProof, type LogInclusionProof, type LogWitness } from "./proofs";

/* ── the descriptor: log.json ──────────────────────────────────────────── */

export const LOG_DESCRIPTOR_FORMAT = "kashscript-log/1" as const;
/** The founder's number until he sets another (plan decision 6): how long an entry may wait for its first witnessed checkpoint. */
export const DEFAULT_MAX_BATCH_DELAY_SEC = 86_400;

export interface LogDescriptor {
  readonly format: typeof LOG_DESCRIPTOR_FORMAT;
  readonly logId: string;
  /** The log's key: the `did:kash` in its id, written out so a reader need not parse it. */
  readonly key: string;
  readonly leaf: typeof LOG_ENTRY_LEAF_DST;
  readonly checkpointType: typeof DST_LOG_CHECKPOINT;
  /** An attestation claiming a time earlier than its first witness by more than this is reported as unsupported. */
  readonly maxBatchDelaySec: number;
  readonly startedAtUnix: number;
  /** Where the publisher serves the files, or null while it is not published. Any host may mirror them. */
  readonly origin: string | null;
  readonly note: string;
}

export const LOG_DESCRIPTOR_NOTE =
  "An append-only log of issuers and lists, and of attestations by salted hash. It never holds a person, a presentation or a record's content. " +
  "Its checkpoints' times are the log's own claims; a public witness over each checkpoint's payload hash is what makes a time stand. " +
  "Anyone may mirror these files and rebuild the tree from entries/ alone. Without gossip between mirrors, a checker shown one view cannot see a split view it was not shown.";

export function describeLog(input: {
  readonly logId: string;
  readonly startedAtUnix: number;
  readonly maxBatchDelaySec?: number;
  readonly origin?: string | null;
}): LogDescriptor {
  const key = logKeyOf(input.logId);
  if (key === null) throw new AttestError("INVALID_INPUT", "a log id is <did:kash>/log/<slug>, the did naming a key");
  const delay = input.maxBatchDelaySec ?? DEFAULT_MAX_BATCH_DELAY_SEC;
  if (!Number.isSafeInteger(delay) || delay < 0) throw new AttestError("INVALID_INPUT", "maxBatchDelaySec is a whole number of seconds");
  if (!Number.isSafeInteger(input.startedAtUnix) || input.startedAtUnix < 0) throw new AttestError("INVALID_INPUT", "startedAtUnix is a unix time");
  const origin = input.origin ?? null;
  if (origin !== null && !/^https:\/\/[^\s]+$/.test(origin)) throw new AttestError("INVALID_INPUT", "an origin is an https URL");
  return {
    format: LOG_DESCRIPTOR_FORMAT,
    logId: input.logId,
    key,
    leaf: LOG_ENTRY_LEAF_DST,
    checkpointType: DST_LOG_CHECKPOINT,
    maxBatchDelaySec: delay,
    startedAtUnix: input.startedAtUnix,
    origin,
    note: LOG_DESCRIPTOR_NOTE,
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** What is wrong with a descriptor, in words; empty when it reads. */
export function logDescriptorFaults(d: unknown): readonly string[] {
  const out: string[] = [];
  if (!isPlainObject(d)) return ["log.json is a JSON object"];
  if (d.format !== LOG_DESCRIPTOR_FORMAT) out.push(`format is ${LOG_DESCRIPTOR_FORMAT}`);
  if (!isLogId(d.logId)) out.push("logId is <did:kash>/log/<slug>");
  else if (d.key !== logKeyOf(d.logId)) out.push("key is the did:kash in logId");
  if (d.leaf !== LOG_ENTRY_LEAF_DST) out.push(`leaf is ${JSON.stringify(LOG_ENTRY_LEAF_DST)}`);
  if (d.checkpointType !== DST_LOG_CHECKPOINT) out.push(`checkpointType is ${DST_LOG_CHECKPOINT}`);
  if (!(typeof d.maxBatchDelaySec === "number" && Number.isSafeInteger(d.maxBatchDelaySec) && d.maxBatchDelaySec >= 0)) out.push("maxBatchDelaySec is a whole number of seconds");
  if (!(typeof d.startedAtUnix === "number" && Number.isSafeInteger(d.startedAtUnix) && d.startedAtUnix >= 0)) out.push("startedAtUnix is a unix time");
  if (!(d.origin === null || (typeof d.origin === "string" && /^https:\/\/[^\s]+$/.test(d.origin)))) out.push("origin is null or an https URL");
  return out;
}

/* ── the store ─────────────────────────────────────────────────────────── */

/** What a log writes to and reads from. Append-only by contract: nothing here removes or rewrites. */
export interface LogStore {
  size(): Promise<number>;
  /** Append one entry with its leaf hash; returns its index. */
  append(entry: LogEntry, leafHash: Uint8Array): Promise<number>;
  entry(index: number): Promise<LogEntry | null>;
  /** Entries `[from, to)`, in order. */
  entries(from: number, to: number): Promise<readonly LogEntry[]>;
  /** Leaf hashes `[from, to)`, in order. */
  leafHashes(from: number, to: number): Promise<readonly Uint8Array[]>;
  /** Every checkpoint, by rising tree size. */
  checkpoints(): Promise<readonly DsseEnvelope[]>;
  putCheckpoint(envelope: DsseEnvelope): Promise<void>;
}

export class InMemoryLogStore implements LogStore {
  private readonly rows: { entry: LogEntry; leaf: Uint8Array }[] = [];
  private readonly heads: DsseEnvelope[] = [];

  async size(): Promise<number> {
    return this.rows.length;
  }
  async append(entry: LogEntry, leafHash: Uint8Array): Promise<number> {
    this.rows.push({ entry: structuredClone(entry), leaf: new Uint8Array(leafHash) });
    return this.rows.length - 1;
  }
  async entry(index: number): Promise<LogEntry | null> {
    return this.rows[index]?.entry ?? null;
  }
  async entries(from: number, to: number): Promise<readonly LogEntry[]> {
    return this.rows.slice(from, to).map((r) => r.entry);
  }
  async leafHashes(from: number, to: number): Promise<readonly Uint8Array[]> {
    return this.rows.slice(from, to).map((r) => r.leaf);
  }
  async checkpoints(): Promise<readonly DsseEnvelope[]> {
    return [...this.heads];
  }
  async putCheckpoint(envelope: DsseEnvelope): Promise<void> {
    this.heads.push(envelope);
  }
}

/* ── the log ───────────────────────────────────────────────────────────── */

export interface AppendResult {
  readonly index: number;
  readonly leafHash: string;
}

export interface TrustLog {
  readonly logId: string;
  readonly key: string;
  readonly maxBatchDelaySec: number;
  size(): Promise<number>;
  /** Append an entry the guard admits. Refuses anything else before a leaf is made. */
  append(entry: LogEntry): Promise<AppendResult>;
  /** Sign the current head. `timestampUnix` is the log's claim; it never goes backwards. */
  checkpoint(timestampUnix: number): Promise<DsseEnvelope>;
  latestCheckpoint(): Promise<DsseEnvelope | null>;
  /** The proof that entry `index` is in the head of `treeSize` (the latest head by default). The head must be a signed checkpoint. */
  inclusionProof(index: number, treeSize?: number, witnesses?: readonly LogWitness[]): Promise<LogInclusionProof>;
  /** The proof that the head of `second` extends the head of `first`. Both must be signed checkpoints. */
  consistencyProof(first: number, second: number): Promise<LogConsistencyProof>;
}

export interface OpenTrustLogInput {
  readonly logId: string;
  readonly store: LogStore;
  /** The log's key: a seed, or a `sign(bytes)` callback to a key service. Its keyid is the did in the log id. */
  readonly signer: DsseSigner;
  readonly maxBatchDelaySec?: number;
}

export async function openTrustLog(input: OpenTrustLogInput): Promise<TrustLog> {
  const key = logKeyOf(input.logId);
  if (key === null) throw new AttestError("INVALID_INPUT", "a log id is <did:kash>/log/<slug>, the did naming a key");
  if (input.signer.keyid !== key) throw new AttestError("INVALID_INPUT", `the log ${input.logId} is signed by ${key}; the signer given is ${input.signer.keyid}`);
  const maxBatchDelaySec = input.maxBatchDelaySec ?? DEFAULT_MAX_BATCH_DELAY_SEC;
  const { store, signer, logId } = input;

  const headsByTreeSize = async (): Promise<Map<number, DsseEnvelope>> => {
    const out = new Map<number, DsseEnvelope>();
    for (const env of await store.checkpoints()) {
      const p = checkpointPayloadOf(env);
      if (p !== null && p.logId === logId) out.set(p.treeSize, env);
    }
    return out;
  };
  const latest = async (): Promise<{ env: DsseEnvelope; payload: LogCheckpointPayload } | null> => {
    const heads = await store.checkpoints();
    for (let i = heads.length - 1; i >= 0; i--) {
      const p = checkpointPayloadOf(heads[i]);
      if (p !== null && p.logId === logId) return { env: heads[i]!, payload: p };
    }
    return null;
  };
  const rootOver = async (treeSize: number): Promise<string> => {
    const leaves = await store.leafHashes(0, treeSize);
    if (leaves.length !== treeSize) throw new AttestError("INVALID_INPUT", `the store holds ${leaves.length} of the ${treeSize} leaves asked for`);
    return bytesToHex((await rfc6962Tree(leaves)).root);
  };

  return {
    logId,
    key,
    maxBatchDelaySec,
    size: () => store.size(),

    async append(entry) {
      const faults = logEntryFaults(entry);
      if (faults.length > 0) throw new AttestError("INVALID_INPUT", `refused: ${faults.map((f) => `${f.code} ${f.message}`).join("; ")}`);
      const leaf = await logLeafHash(entry);
      const index = await store.append(entry, leaf);
      return { index, leafHash: bytesToHex(leaf) };
    },

    async checkpoint(timestampUnix) {
      if (!Number.isSafeInteger(timestampUnix) || timestampUnix < 0) throw new AttestError("INVALID_INPUT", "a checkpoint's time is a unix time");
      const treeSize = await store.size();
      if (treeSize === 0) throw new AttestError("INVALID_INPUT", "an empty log has no head to sign");
      const prev = await latest();
      if (prev !== null) {
        if (prev.payload.treeSize > treeSize) throw new AttestError("INVALID_INPUT", "the store holds fewer entries than the last checkpoint covered — the log is not append-only");
        if (prev.payload.timestampUnix > timestampUnix) throw new AttestError("INVALID_INPUT", "a checkpoint's time never goes backwards");
      }
      const previous: TreeHeadRef | null = prev === null ? null : { treeSize: prev.payload.treeSize, rootHash: prev.payload.rootHash };
      const env = await signCheckpoint({ format: "kashscript-log-checkpoint/1", logId, treeSize, rootHash: await rootOver(treeSize), timestampUnix, previous }, signer);
      await store.putCheckpoint(env);
      return env;
    },

    async latestCheckpoint() {
      return (await latest())?.env ?? null;
    },

    async inclusionProof(index, treeSize, witnesses) {
      const heads = await headsByTreeSize();
      const size = treeSize ?? (await latest())?.payload.treeSize;
      if (size === undefined) throw new AttestError("INVALID_INPUT", "no checkpoint yet — sign a head before proving inclusion in it");
      const head = heads.get(size);
      if (head === undefined) throw new AttestError("INVALID_INPUT", `no checkpoint of size ${size} — a proof is against a signed head`);
      if (!Number.isSafeInteger(index) || index < 0 || index >= size) throw new AttestError("INVALID_INPUT", `no entry ${String(index)} in a head of ${size}`);
      const entry = await store.entry(index);
      if (entry === null) throw new AttestError("INVALID_INPUT", `the store has no entry ${index}`);
      const tree = await rfc6962Tree(await store.leafHashes(0, size));
      return {
        format: LOG_INCLUSION_FORMAT,
        logId,
        entry,
        leafIndex: index,
        treeSize: size,
        path: tree.path(index).map(bytesToHex),
        checkpoint: head,
        witnesses: [...(witnesses ?? [])],
      };
    },

    async consistencyProof(first, second) {
      const heads = await headsByTreeSize();
      const a = heads.get(first);
      const b = heads.get(second);
      if (a === undefined || b === undefined) throw new AttestError("INVALID_INPUT", "a consistency proof runs between two signed checkpoints");
      const path = await rfc6962ConsistencyProof(await store.leafHashes(0, second), first, second);
      return { format: LOG_CONSISTENCY_FORMAT, logId, first, second, path: path.map(bytesToHex), checkpoints: { first: a, second: b } };
    },
  };
}

/* ── what a mirror does ────────────────────────────────────────────────── */

export interface RebuiltLog {
  readonly ok: boolean;
  /** Entries the guard refused, by index. A mirror holding one is not this log. */
  readonly refused: readonly { readonly index: number; readonly message: string }[];
  readonly leafHashes: readonly Uint8Array[];
  /** The root over the first `size` entries, hex. */
  rootAt(size: number): Promise<string>;
}

/** Rebuild the tree from the entries alone — the whole of what a mirror or an auditor needs. Never throws. */
export async function rebuildFromEntries(entries: readonly unknown[]): Promise<RebuiltLog> {
  const refused: { index: number; message: string }[] = [];
  const leafHashes: Uint8Array[] = [];
  for (const [index, e] of entries.entries()) {
    const faults = logEntryFaults(e);
    if (faults.length > 0) {
      refused.push({ index, message: faults.map((f) => f.message).join("; ") });
      continue;
    }
    leafHashes.push(await logLeafHash(e as LogEntry));
  }
  const ok = refused.length === 0;
  return {
    ok,
    refused,
    leafHashes,
    async rootAt(size: number): Promise<string> {
      if (!ok) throw new AttestError("INVALID_INPUT", "a log with a refused entry has no root");
      if (!Number.isSafeInteger(size) || size < 1 || size > leafHashes.length) throw new AttestError("INVALID_INPUT", `no head of ${String(size)} over ${leafHashes.length} entries`);
      return bytesToHex((await rfc6962Tree(leafHashes.slice(0, size))).root);
    },
  };
}
