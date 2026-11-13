// ============================================================================
// @kashscript/identity-server — Personal Data Store (PDS) contract
// ----------------------------------------------------------------------------
// identity-server owns the PDS *contract* (record shape, CID derivation,
// optimistic-revision + size discipline) — NOT the durable store. The durable,
// content-addressed PDS is `@kashscript/muffler` (M3). `stores.ts` ships an
// in-memory reference so the surface is covered + testable now.
//
// The CID is a deterministic content hash of the record body, so identical
// content yields an identical CID (idempotent writes are detectable downstream).
// ============================================================================

import { sha256HexOfUtf8 } from "./hashing";
import { assertDidWellFormed, newTraceId, nowUnix } from "./internal";
import { KashscriptIdentityMalformedPayloadError } from "./errors";
import type {
  Did,
  PdsCollection,
  PdsRecord,
  ReadPdsRecordResult,
  UnixSeconds,
  WritePdsRecordResult,
} from "./types";

/** Upper bound on a single record's canonical-JSON body: 1 MiB. */
export const MAX_PDS_RECORD_BYTES = 1024 * 1024;

/** A persisted PDS record + its content identifier and revision. */
export interface PdsStoredRecord {
  readonly record: PdsRecord;
  readonly cid: string;
  readonly revision: number;
  readonly writtenAtUnix: UnixSeconds;
}

/**
 * Store contract for PDS records. The venture injects a muffler-backed adapter
 * (M3); `InMemoryPdsStore` (stores.ts) is the reference impl. The protocol
 * layer (below) owns CID derivation + revision-conflict detection, so the
 * store itself is a dumb revisioned key-value.
 */
export interface PdsStore {
  /** Whether `did` has a provisioned PDS. */
  isProvisioned(did: Did): Promise<boolean>;
  /** The current record at (did, collection, recordKey), or null. */
  read(did: Did, collection: PdsCollection, recordKey: string): Promise<PdsStoredRecord | null>;
  /** Persist `stored` verbatim (revision already computed by the caller). */
  put(did: Did, stored: PdsStoredRecord): Promise<void>;
}

/** Deterministic content identifier for a record body. */
async function deriveCid(contentJson: string): Promise<string> {
  return `cid_sha256_${await sha256HexOfUtf8(contentJson)}`;
}

function assertRecordShape(record: PdsRecord): void {
  if (typeof record !== "object" || record === null) {
    throw new KashscriptIdentityMalformedPayloadError("record");
  }
  if (typeof record.collection !== "string" || record.collection.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("record.collection");
  }
  if (typeof record.recordKey !== "string" || record.recordKey.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("record.recordKey");
  }
  if (typeof record.contentJson !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("record.contentJson");
  }
}

/**
 * Writes a signed record to a participant's PDS, returning a content-addressed
 * identifier.
 *
 * State paths:
 *   - Happy                     → { ok: true, cid, revision, writtenAtUnix }
 *   - Nil (no provisioned PDS)  → { ok: false, reason: "PDS_UNPROVISIONED" }
 *   - Empty/over-bound body     → { ok: false, reason: "RECORD_TOO_LARGE" }
 *   - Revision conflict         → { ok: false, reason: "REVISION_CONFLICT" }
 *
 * @throws KashscriptIdentityMalformedDidError / MalformedPayloadError on
 *         invalid input.
 */
export async function writePdsRecord(
  store: PdsStore,
  did: Did,
  record: PdsRecord,
  nowSec: UnixSeconds = nowUnix(),
): Promise<WritePdsRecordResult> {
  assertDidWellFormed(did);
  assertRecordShape(record);

  if (new TextEncoder().encode(record.contentJson).length > MAX_PDS_RECORD_BYTES) {
    return { ok: false, reason: "RECORD_TOO_LARGE", traceId: newTraceId() };
  }
  if (!(await store.isProvisioned(did))) {
    return { ok: false, reason: "PDS_UNPROVISIONED", traceId: newTraceId() };
  }

  const existing = await store.read(did, record.collection, record.recordKey);
  const currentRevision = existing?.revision ?? 0;
  if (record.expectedRevision !== null && record.expectedRevision !== currentRevision) {
    return { ok: false, reason: "REVISION_CONFLICT", traceId: newTraceId() };
  }

  const stored: PdsStoredRecord = {
    record,
    cid: await deriveCid(record.contentJson),
    revision: currentRevision + 1,
    writtenAtUnix: nowSec,
  };
  await store.put(did, stored);
  return { ok: true, cid: stored.cid, revision: stored.revision, writtenAtUnix: stored.writtenAtUnix };
}

/**
 * Reads a record from a participant's PDS.
 *
 * State paths:
 *   - Happy                     → { ok: true, record, cid, revision }
 *   - Nil (no provisioned PDS)  → { ok: false, reason: "PDS_UNPROVISIONED" }
 *   - Empty (no such record)    → { ok: false, reason: "NOT_FOUND" }
 *
 * @throws KashscriptIdentityMalformedDidError / MalformedPayloadError on
 *         invalid input.
 */
export async function readPdsRecord(
  store: PdsStore,
  did: Did,
  collection: PdsCollection,
  recordKey: string,
): Promise<ReadPdsRecordResult> {
  assertDidWellFormed(did);
  if (typeof collection !== "string" || collection.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("collection");
  }
  if (typeof recordKey !== "string" || recordKey.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("recordKey");
  }

  if (!(await store.isProvisioned(did))) {
    return { ok: false, reason: "PDS_UNPROVISIONED", traceId: newTraceId() };
  }
  const existing = await store.read(did, collection, recordKey);
  if (existing === null) {
    return { ok: false, reason: "NOT_FOUND", traceId: newTraceId() };
  }
  return { ok: true, record: existing.record, cid: existing.cid, revision: existing.revision };
}
