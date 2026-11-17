/**
 * What a receipt carries from the log, and what a stranger checks (KS-Q4;
 * specs/trust-log.md §5). Two shapes, both self-contained: an **inclusion
 * proof** — one entry, its place, its path, the signed checkpoint it reaches
 * and the public witnesses over that checkpoint — and a **consistency proof**
 * between two checkpoints. Nothing here fetches anything; a witness is a file
 * carried inside the proof.
 */

import { hexToBytes } from "../chain";
import type { DsseEnvelope } from "../dsse";
import { rfc6962VerifyConsistency, rfc6962VerifyInclusion } from "../witness/rfc6962";
import { witnessVerdictsFor, type BitcoinHeader, type LogWitness, type Rfc3161SignatureCheck, type WitnessVerdict } from "../witness/verdict";
import { checkpointPayloadOf, verifyCheckpoint, type CheckpointReport } from "./checkpoint";
import { logEntryFaults, logLeafHash, type LogEntry } from "./entries";
import { timeVerdict, type TimeVerdict } from "./time";

export type { LogWitness } from "../witness/verdict";

export const LOG_INCLUSION_FORMAT = "kashscript-log-inclusion/1" as const;
export const LOG_CONSISTENCY_FORMAT = "kashscript-log-consistency/1" as const;

export interface LogInclusionProof {
  readonly format: typeof LOG_INCLUSION_FORMAT;
  readonly logId: string;
  readonly entry: LogEntry;
  readonly leafIndex: number;
  readonly treeSize: number;
  /** Sibling hashes, hex, nearest first (RFC 6962 §2.1.1). */
  readonly path: readonly string[];
  /** The signed head the path reaches. */
  readonly checkpoint: DsseEnvelope;
  /** Public witnesses over the checkpoint's payload hash. May be empty; the report then says the time is the log's claim. */
  readonly witnesses: readonly LogWitness[];
}

export interface LogConsistencyProof {
  readonly format: typeof LOG_CONSISTENCY_FORMAT;
  readonly logId: string;
  readonly first: number;
  readonly second: number;
  readonly path: readonly string[];
  readonly checkpoints: { readonly first: DsseEnvelope; readonly second: DsseEnvelope };
}

export function isLogInclusionProof(v: unknown): v is LogInclusionProof {
  return isPlainObject(v) && v.format === LOG_INCLUSION_FORMAT;
}
export function isLogConsistencyProof(v: unknown): v is LogConsistencyProof {
  return isPlainObject(v) && v.format === LOG_CONSISTENCY_FORMAT;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const HEX64 = /^[0-9a-f]{64}$/;
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);
const isHexPath = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 64 && v.every((p) => typeof p === "string" && HEX64.test(p));

export type LogInclusionFailureReason =
  | "MALFORMED_PROOF"
  | "ENTRY_REFUSED"
  | "CHECKPOINT_INVALID"
  | "LOG_ID_MISMATCH"
  | "NOT_INCLUDED"
  /** The entry's claimed time is not supported by the witness (plan decision 6). */
  | "TIME_NOT_SUPPORTED";

export interface LogInclusionReport {
  readonly ok: boolean;
  readonly reason: LogInclusionFailureReason | null;
  readonly logId: string | null;
  readonly entry: LogEntry | null;
  readonly leafIndex: number | null;
  readonly treeSize: number | null;
  readonly rootHash: string | null;
  /** The path leads from this entry's leaf to the checkpoint's root. */
  readonly included: boolean;
  readonly checkpoint: CheckpointReport | null;
  readonly witnesses: readonly WitnessVerdict[];
  readonly time: TimeVerdict | null;
  readonly notes: readonly string[];
}

export interface VerifyLogInclusionOptions {
  /** The log this proof must be of. */
  readonly logId?: string;
  /** The log's declared allowance between an attestation's claimed time and its first witness (`log.json`'s `maxBatchDelaySec`). */
  readonly maxBatchDelaySec?: number;
  /** Bitcoin block headers the checker holds, for OpenTimestamps proofs that reached a block. */
  readonly headers?: readonly BitcoinHeader[];
  /** Verifies an RFC 3161 token's signature and chain (the CLI's openssl). Without it a token's time is read, never relied on. */
  readonly verifyRfc3161Signature?: Rfc3161SignatureCheck;
  /** Verdicts already computed for the proof's witnesses, in their order — skips parsing them again. */
  readonly witnessVerdicts?: readonly WitnessVerdict[];
  /** A time by which the log had certainly begun (the audit's reading of `log.json` and the first head's witness). A proof alone does not carry it. */
  readonly logStartedAtUnix?: number;
}

function failedInclusion(reason: LogInclusionFailureReason, note: string, partial: Partial<LogInclusionReport> = {}): LogInclusionReport {
  return {
    ok: false,
    logId: null,
    entry: null,
    leafIndex: null,
    treeSize: null,
    rootHash: null,
    included: false,
    checkpoint: null,
    witnesses: [],
    time: null,
    ...partial,
    reason,
    notes: [...(partial.notes ?? []), note],
  };
}

/**
 * Verify an inclusion proof offline. The entry passes the guard; the
 * checkpoint is the log's own; the path leads from the entry's leaf to the
 * checkpoint's root; each witness names the checkpoint's hash; and the entry's
 * claimed time is read against the attested one. Junk input returns a report.
 */
export async function verifyLogInclusion(proof: unknown, opts: VerifyLogInclusionOptions = {}): Promise<LogInclusionReport> {
  if (!isLogInclusionProof(proof)) return failedInclusion("MALFORMED_PROOF", "not a kashscript-log-inclusion/1 proof");
  const p = proof as unknown as Record<string, unknown>;
  if (!isInt(p.leafIndex) || !isInt(p.treeSize) || p.leafIndex < 0 || p.treeSize < 1 || p.leafIndex >= p.treeSize || !isHexPath(p.path) || !Array.isArray(p.witnesses)) {
    return failedInclusion("MALFORMED_PROOF", "leafIndex, treeSize, path or witnesses are malformed");
  }
  const faults = logEntryFaults(p.entry);
  if (faults.length > 0) {
    return failedInclusion("ENTRY_REFUSED", `the entry is refused: ${faults.map((f) => f.message).join("; ")}`, { logId: typeof p.logId === "string" ? p.logId : null });
  }
  const entry = p.entry as LogEntry;
  const checkpoint = await verifyCheckpoint(p.checkpoint, { ...(opts.logId !== undefined ? { logId: opts.logId } : {}) });
  const partial: Partial<LogInclusionReport> = {
    logId: typeof p.logId === "string" ? p.logId : null,
    entry,
    leafIndex: p.leafIndex,
    treeSize: p.treeSize,
    rootHash: checkpoint.rootHash,
    checkpoint,
  };
  if (!checkpoint.ok) return failedInclusion("CHECKPOINT_INVALID", `the checkpoint does not verify (${checkpoint.reason})`, partial);
  if (checkpoint.logId !== p.logId) return failedInclusion("LOG_ID_MISMATCH", "the proof names one log and its checkpoint another", partial);
  if (checkpoint.treeSize !== p.treeSize) return failedInclusion("NOT_INCLUDED", `the proof is for a head of ${p.treeSize}, the checkpoint signs one of ${checkpoint.treeSize}`, partial);

  let included = false;
  try {
    included = await rfc6962VerifyInclusion(await logLeafHash(entry), p.leafIndex, p.treeSize, (p.path as string[]).map(hexToBytes), hexToBytes(checkpoint.rootHash!));
  } catch {
    included = false;
  }
  if (!included) return failedInclusion("NOT_INCLUDED", `the path does not lead from this entry's leaf to the root the checkpoint signs (leaf ${p.leafIndex} of ${p.treeSize})`, partial);

  const witnesses =
    opts.witnessVerdicts ??
    (await witnessVerdictsFor(p.witnesses, checkpoint.payloadSha256!, {
      ...(opts.headers !== undefined ? { headers: opts.headers } : {}),
      ...(opts.verifyRfc3161Signature !== undefined ? { verifyRfc3161Signature: opts.verifyRfc3161Signature } : {}),
    }));
  // The head is the entry's first when the head before it did not hold the entry — read from the signed checkpoint itself.
  const firstHead = checkpoint.previous === null || p.leafIndex >= checkpoint.previous.treeSize;
  const time = timeVerdict({
    entry,
    checkpointTimestampUnix: checkpoint.timestampUnix!,
    witnesses,
    firstHead,
    ...(opts.maxBatchDelaySec !== undefined ? { maxBatchDelaySec: opts.maxBatchDelaySec } : {}),
    ...(opts.logStartedAtUnix !== undefined ? { logStartedAtUnix: opts.logStartedAtUnix } : {}),
  });
  const notes: string[] = [
    `leaf ${p.leafIndex} of ${p.treeSize}: its own path reaches the root the log's key signed; this proof carries no other entry`,
    time.text,
  ];
  if (witnesses.length === 0) notes.push("no public witness carried — the time is the log's claim, and the log's key could have signed this head at any time");
  if (entry.backfilled === true && opts.logStartedAtUnix === undefined) {
    notes.push("marked backfilled: a proof does not carry the log's start, so the mark is taken as written here — `attest log verify <dir>` checks it against the log's files");
  }
  if (time.fault !== null) {
    return { ...failedInclusion("TIME_NOT_SUPPORTED", time.text, { ...partial, included, witnesses, time }), notes };
  }
  return { ok: true, reason: null, logId: p.logId as string, entry, leafIndex: p.leafIndex, treeSize: p.treeSize, rootHash: checkpoint.rootHash, included, checkpoint, witnesses, time, notes };
}

export type LogConsistencyFailureReason = "MALFORMED_PROOF" | "CHECKPOINT_INVALID" | "LOG_ID_MISMATCH" | "NOT_CONSISTENT";

export interface LogConsistencyReport {
  readonly ok: boolean;
  readonly reason: LogConsistencyFailureReason | null;
  readonly logId: string | null;
  readonly first: CheckpointReport | null;
  readonly second: CheckpointReport | null;
  /** The second head is an append-only extension of the first. */
  readonly consistent: boolean;
  readonly notes: readonly string[];
}

/** Verify that the second checkpoint extends the first, by the proof's path. Offline; never throws. */
export async function verifyLogConsistency(proof: unknown, opts: { readonly logId?: string } = {}): Promise<LogConsistencyReport> {
  const fail = (reason: LogConsistencyFailureReason, note: string, partial: Partial<LogConsistencyReport> = {}): LogConsistencyReport => ({
    ok: false,
    logId: null,
    first: null,
    second: null,
    consistent: false,
    ...partial,
    reason,
    notes: [note],
  });
  if (!isLogConsistencyProof(proof)) return fail("MALFORMED_PROOF", "not a kashscript-log-consistency/1 proof");
  const p = proof as unknown as Record<string, unknown>;
  const heads = isPlainObject(p.checkpoints) ? p.checkpoints : null;
  if (!isInt(p.first) || !isInt(p.second) || p.first < 1 || p.first > p.second || !isHexPath(p.path) || heads === null) {
    return fail("MALFORMED_PROOF", "first, second, path or checkpoints are malformed");
  }
  const logOpt = opts.logId !== undefined ? { logId: opts.logId } : {};
  const first = await verifyCheckpoint(heads.first, logOpt);
  const second = await verifyCheckpoint(heads.second, logOpt);
  const partial = { logId: typeof p.logId === "string" ? p.logId : null, first, second };
  if (!first.ok || !second.ok) return fail("CHECKPOINT_INVALID", `a checkpoint does not verify (${first.reason ?? second.reason})`, partial);
  if (first.logId !== p.logId || second.logId !== p.logId) return fail("LOG_ID_MISMATCH", "the proof names one log and a checkpoint another", partial);
  if (first.treeSize !== p.first || second.treeSize !== p.second) return fail("NOT_CONSISTENT", "the checkpoints sign other sizes than the proof names", partial);
  const consistent = await rfc6962VerifyConsistency(p.first, p.second, (p.path as string[]).map(hexToBytes), hexToBytes(first.rootHash!), hexToBytes(second.rootHash!));
  if (!consistent) return fail("NOT_CONSISTENT", `the head of ${p.second} is not an append-only extension of the head of ${p.first} by this path`, partial);
  const notes = [`the head of ${p.second} extends the head of ${p.first}: nothing in the first ${p.first} entries was changed or removed`];
  if (second.previous !== null && (second.previous.treeSize !== first.treeSize || second.previous.rootHash !== first.rootHash)) {
    notes.push("the second checkpoint names another head as its previous — consistent with the first, but not its direct successor");
  }
  return { ok: true, reason: null, logId: p.logId as string, first, second, consistent, notes };
}

/** The checkpoint inside a proof, read without verifying — for a CLI to name what it is about to check. */
export function proofCheckpointPayload(proof: LogInclusionProof): ReturnType<typeof checkpointPayloadOf> {
  return checkpointPayloadOf(proof.checkpoint);
}
