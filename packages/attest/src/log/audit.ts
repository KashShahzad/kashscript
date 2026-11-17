/**
 * The audit of a whole log (KS-Q4; specs/trust-log.md §7): what a mirror or a
 * stranger does with the files alone. It rebuilds the tree from the entries,
 * checks every checkpoint's signature against the log's key and its root
 * against the rebuilt tree, the chain of `previous` heads, the consistency
 * between consecutive heads by the RFC's proof, and each witness file's digest
 * against its checkpoint. Given a second file set, it compares the two.
 *
 * **What it cannot catch, said plainly:** without gossip between mirrors, a
 * checker shown one view cannot see a split view it was not shown. It can only
 * compare the views it holds (`SPLIT_VIEW`).
 */

import { hexToBytes } from "../chain";
import { rfc6962ConsistencyProof, rfc6962VerifyConsistency } from "../witness/rfc6962";
import { witnessVerdictsFor, type BitcoinHeader, type LogWitness, type Rfc3161SignatureCheck, type WitnessVerdict } from "../witness/verdict";
import { verifyCheckpoint, type CheckpointReport } from "./checkpoint";
import type { LogEntry, LogEntryKind } from "./entries";
import { DEFAULT_MAX_BATCH_DELAY_SEC, logDescriptorFaults, rebuildFromEntries } from "./log";
import { timeVerdict, type TimeFault } from "./time";

/** A log's files, read by whoever holds them — a directory, a bucket, a zip. The library never reads a file itself. */
export interface LogFiles {
  /** `log.json`. */
  readonly descriptor: unknown;
  /** Every entry in order, concatenated from `entries/*.jsonl`. */
  readonly entries: readonly unknown[];
  /** Every checkpoint file, in any order. */
  readonly checkpoints: readonly unknown[];
  /** Witness files, each named for the checkpoint size it stamps. */
  readonly witnesses: readonly { readonly treeSize: number; readonly witness: LogWitness }[];
}

export type LogAuditFaultCode =
  | "DESCRIPTOR_MALFORMED"
  | "ENTRY_REFUSED"
  | "CHECKPOINT_INVALID"
  | "CHECKPOINT_FOREIGN"
  | "SIZE_BEYOND_ENTRIES"
  | "ROOT_MISMATCH"
  | "PREVIOUS_MISMATCH"
  | "TIMESTAMP_REGRESSION"
  | "CONSISTENCY_FAILED"
  | "WITNESS_DIGEST_MISMATCH"
  | "WITNESS_INVALID"
  | "SPLIT_VIEW"
  | "MIRROR_DESCRIPTOR_DIFFERS"
  | "MIRROR_ROOT_MISMATCH"
  | "MIRROR_ENTRY_REFUSED"
  /** The mirror serves a checkpoint the log's key did not sign: it is not a faithful copy, whatever its entries say. */
  | "MIRROR_CHECKPOINT_INVALID";

export interface LogAuditFault {
  readonly code: LogAuditFaultCode;
  /** The entry index or checkpoint size it is about, or null. */
  readonly at: number | null;
  readonly detail: string;
}

export interface AuditedCheckpoint {
  readonly treeSize: number;
  readonly rootHash: string;
  readonly timestampUnix: number;
  readonly report: CheckpointReport;
  readonly rootMatches: boolean;
  readonly previousOk: boolean;
  readonly consistentWithPrevious: boolean | null;
  readonly witnesses: readonly WitnessVerdict[];
  /** The earliest final witness time over this head, or null. */
  readonly attestedAtUnix: number | null;
}

/** An entry whose claimed time the witness of its first head does not support. A finding about the entry's claim, never a fault in the log. */
export interface LogTimeFinding {
  readonly index: number;
  readonly kind: LogEntryKind;
  readonly fault: TimeFault;
  /** The first head that held the entry. */
  readonly headSize: number;
  readonly text: string;
}

export interface LogAuditReport {
  /** The log is whole: every check of its integrity passed. Says nothing about whether its entries' claims are true. */
  readonly ok: boolean;
  readonly logId: string | null;
  readonly key: string | null;
  readonly entries: number;
  readonly checkpoints: readonly AuditedCheckpoint[];
  readonly latest: AuditedCheckpoint | null;
  readonly faults: readonly LogAuditFault[];
  /** Entries that claim a time their first head's witness does not support (the backdated attestation). */
  readonly timeFindings: readonly LogTimeFinding[];
  /** What was checked and what was not. Always non-empty. */
  readonly notes: readonly string[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export interface AuditLogOptions {
  /** A second copy of the same log, to compare. */
  readonly mirror?: LogFiles;
  readonly headers?: readonly BitcoinHeader[];
  /** Verifies an RFC 3161 token's signature and chain (the CLI's openssl). Without it a token's time is read, never relied on. */
  readonly verifyRfc3161Signature?: Rfc3161SignatureCheck;
}

/** Audit a log from its files. Never throws. */
export async function auditLog(files: LogFiles, opts: AuditLogOptions = {}): Promise<LogAuditReport> {
  const faults: LogAuditFault[] = [];
  const notes: string[] = [];
  const fault = (code: LogAuditFaultCode, at: number | null, detail: string): void => {
    faults.push({ code, at, detail });
  };

  const dFaults = logDescriptorFaults(files.descriptor);
  for (const f of dFaults) fault("DESCRIPTOR_MALFORMED", null, f);
  const d = isPlainObject(files.descriptor) ? files.descriptor : {};
  const logId = typeof d.logId === "string" ? d.logId : null;
  const key = typeof d.key === "string" ? d.key : null;

  const rebuilt = await rebuildFromEntries(files.entries);
  for (const r of rebuilt.refused) fault("ENTRY_REFUSED", r.index, r.message);

  // Every checkpoint: the log's own, signed by its key, over a size the entries reach, with the rebuilt root.
  const audited: AuditedCheckpoint[] = [];
  const bySize = new Map<number, AuditedCheckpoint[]>();
  for (const env of files.checkpoints) {
    const report = await verifyCheckpoint(env, logId !== null ? { logId } : {});
    if (!report.ok) {
      fault(report.reason === "LOG_ID_MISMATCH" ? "CHECKPOINT_FOREIGN" : "CHECKPOINT_INVALID", report.treeSize, `checkpoint${report.treeSize !== null ? ` of ${report.treeSize}` : ""}: ${report.reason} — ${report.notes.join("; ")}`);
      continue;
    }
    const size = report.treeSize!;
    let rootMatches = false;
    if (size > rebuilt.leafHashes.length || !rebuilt.ok) {
      fault("SIZE_BEYOND_ENTRIES", size, `checkpoint of ${size} covers more entries than the ${rebuilt.leafHashes.length} held${rebuilt.ok ? "" : ", or an entry was refused"}`);
    } else {
      rootMatches = (await rebuilt.rootAt(size)) === report.rootHash;
      if (!rootMatches) fault("ROOT_MISMATCH", size, `checkpoint of ${size}: its root is not the root rebuilt from the entries`);
    }
    const witnesses = await witnessVerdictsFor(
      files.witnesses.filter((w) => w.treeSize === size).map((w) => w.witness),
      report.payloadSha256!,
      {
        ...(opts.headers !== undefined ? { headers: opts.headers } : {}),
        ...(opts.verifyRfc3161Signature !== undefined ? { verifyRfc3161Signature: opts.verifyRfc3161Signature } : {}),
      },
    );
    for (const w of witnesses) {
      if (!w.digestOk) fault("WITNESS_DIGEST_MISMATCH", size, `checkpoint of ${size}: a ${w.kind} witness stamps another digest — ${w.detail}`);
      else if (w.state === "invalid") fault("WITNESS_INVALID", size, `checkpoint of ${size}: ${w.kind} — ${w.detail}`);
    }
    const finals = witnesses.filter((w) => w.state === "final" && w.digestOk && w.timeUnix !== null).map((w) => w.timeUnix as number);
    const row: AuditedCheckpoint = {
      treeSize: size,
      rootHash: report.rootHash!,
      timestampUnix: report.timestampUnix!,
      report,
      rootMatches,
      previousOk: true,
      consistentWithPrevious: null,
      witnesses,
      attestedAtUnix: finals.length === 0 ? null : Math.min(...finals),
    };
    audited.push(row);
    const same = bySize.get(size) ?? [];
    same.push(row);
    bySize.set(size, same);
  }
  for (const [size, rows] of bySize) {
    const roots = new Set(rows.map((r) => r.rootHash));
    if (roots.size > 1) fault("SPLIT_VIEW", size, `two checkpoints of ${size} with different roots, both signed by the log's key — the log showed two views`);
  }

  // The chain of heads: each names the one before it, time never goes backwards, and each extends the last by the RFC's proof.
  audited.sort((a, b) => a.treeSize - b.treeSize || a.timestampUnix - b.timestampUnix);
  const chained: AuditedCheckpoint[] = [];
  for (let i = 0; i < audited.length; i++) {
    const row = audited[i]!;
    const prev = i === 0 ? null : audited[i - 1]!;
    let previousOk = true;
    let consistentWithPrevious: boolean | null = null;
    if (prev !== null) {
      const named = row.report.previous;
      if (named === null || named.treeSize !== prev.treeSize || named.rootHash !== prev.rootHash) {
        previousOk = false;
        fault("PREVIOUS_MISMATCH", row.treeSize, `checkpoint of ${row.treeSize} does not name the checkpoint of ${prev.treeSize} as its previous`);
      }
      if (row.timestampUnix < prev.timestampUnix) fault("TIMESTAMP_REGRESSION", row.treeSize, `checkpoint of ${row.treeSize} claims an earlier time than the checkpoint of ${prev.treeSize}`);
      if (rebuilt.ok && row.rootMatches && prev.rootMatches && prev.treeSize <= row.treeSize) {
        try {
          const path = await rfc6962ConsistencyProof(rebuilt.leafHashes.slice(0, row.treeSize), prev.treeSize, row.treeSize);
          consistentWithPrevious = await rfc6962VerifyConsistency(prev.treeSize, row.treeSize, path, hexToBytes(prev.rootHash), hexToBytes(row.rootHash));
        } catch {
          consistentWithPrevious = false;
        }
        if (consistentWithPrevious === false) fault("CONSISTENCY_FAILED", row.treeSize, `the head of ${row.treeSize} does not extend the head of ${prev.treeSize}`);
      }
    } else if (row.report.previous !== null) {
      previousOk = false;
      fault("PREVIOUS_MISMATCH", row.treeSize, `the first checkpoint held (${row.treeSize}) names a previous head this file set does not hold`);
    }
    chained.push({ ...row, previousOk, consistentWithPrevious });
  }

  // The mirror: the same descriptor, the same roots at every checkpoint size.
  if (opts.mirror !== undefined) {
    const m = opts.mirror;
    const md = isPlainObject(m.descriptor) ? m.descriptor : {};
    if (md.logId !== d.logId || md.key !== d.key) fault("MIRROR_DESCRIPTOR_DIFFERS", null, "the mirror describes another log");
    const mirrorBuilt = await rebuildFromEntries(m.entries);
    for (const r of mirrorBuilt.refused) fault("MIRROR_ENTRY_REFUSED", r.index, `mirror entry ${r.index}: ${r.message}`);
    for (const row of chained) {
      if (!row.rootMatches) continue;
      if (!mirrorBuilt.ok || row.treeSize > mirrorBuilt.leafHashes.length) {
        fault("MIRROR_ROOT_MISMATCH", row.treeSize, `the mirror holds ${mirrorBuilt.leafHashes.length} entries and cannot reach the head of ${row.treeSize}`);
        continue;
      }
      const mirrorRoot = await mirrorBuilt.rootAt(row.treeSize);
      if (mirrorRoot !== row.rootHash) fault("MIRROR_ROOT_MISMATCH", row.treeSize, `the mirror's first ${row.treeSize} entries do not rebuild the signed root — an entry differs, is missing or is out of order`);
    }
    for (const env of m.checkpoints) {
      const r = await verifyCheckpoint(env, logId !== null ? { logId } : {});
      if (!r.ok) {
        fault("MIRROR_CHECKPOINT_INVALID", r.treeSize, `the mirror holds a checkpoint${r.treeSize !== null ? ` of ${r.treeSize}` : ""} that is not the log's: ${r.reason} — ${r.notes.join("; ")}`);
        continue;
      }
      const ours = bySize.get(r.treeSize!);
      if (ours !== undefined && ours.every((o) => o.rootHash !== r.rootHash)) {
        fault("SPLIT_VIEW", r.treeSize, `the mirror holds a checkpoint of ${r.treeSize} with another root than ours, both signed by the log's key — the log showed two views`);
      }
    }
    notes.push(`a mirror was compared: ${m.entries.length} entries, ${m.checkpoints.length} checkpoints`);
  }

  // Every entry's claimed time, against the witness of the first head that held it.
  const timeFindings: LogTimeFinding[] = [];
  if (rebuilt.ok) {
    const allowance = typeof d.maxBatchDelaySec === "number" && Number.isSafeInteger(d.maxBatchDelaySec) ? d.maxBatchDelaySec : DEFAULT_MAX_BATCH_DELAY_SEC;
    const goodHeads = chained.filter((c) => c.rootMatches);
    // The log had certainly begun by the earlier of its own declared start and its first head's witness: a backfilled mark holds only for a claim before that.
    const starts = [typeof d.startedAtUnix === "number" && Number.isSafeInteger(d.startedAtUnix) ? d.startedAtUnix : null, goodHeads[0]?.attestedAtUnix ?? null].filter((t): t is number => t !== null);
    const logStartedAtUnix = starts.length === 0 ? undefined : Math.min(...starts);
    for (const [index, e] of files.entries.entries()) {
      const head = goodHeads.find((c) => c.treeSize > index);
      if (head === undefined) continue;
      const entry = e as LogEntry;
      const v = timeVerdict({ entry, checkpointTimestampUnix: head.timestampUnix, witnesses: head.witnesses, maxBatchDelaySec: allowance, firstHead: true, ...(logStartedAtUnix !== undefined ? { logStartedAtUnix } : {}) });
      if (v.fault !== null) timeFindings.push({ index, kind: entry.kind, fault: v.fault, headSize: head.treeSize, text: v.text });
    }
  }

  const latest = chained.length === 0 ? null : chained[chained.length - 1]!;
  notes.push(
    `rebuilt the tree from ${files.entries.length} entries alone and checked ${chained.length} checkpoint(s) against it: signature by the log's key, root, previous head, time order, consistency by the RFC 9162 proof, witness digests`,
  );
  if (timeFindings.length > 0) {
    notes.push(`${timeFindings.length} entr${timeFindings.length === 1 ? "y claims" : "ies claim"} a time the witness of its first head does not support — the log is whole; those claims are not`);
  }
  notes.push(
    latest === null
      ? "no checkpoint held — nothing has been signed"
      : latest.attestedAtUnix === null
        ? "no final public witness over the latest head — its time is the log's own claim"
        : `the latest head's attested time is the earliest final witness over it`,
  );
  notes.push("without gossip between mirrors, this check sees only the views it was shown: a split view shown to someone else is not caught here");
  return { ok: faults.length === 0, logId, key, entries: files.entries.length, checkpoints: chained, latest, faults, timeFindings, notes };
}
