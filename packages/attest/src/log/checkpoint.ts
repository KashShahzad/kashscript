/**
 * The log's signed tree head — a checkpoint (RFC 9162 §4.9–4.10's fields; KS-Q4;
 * specs/trust-log.md §3).
 *
 * A DSSE envelope, `payloadType` {@link DST_LOG_CHECKPOINT}, signed by the log's
 * own key — the self-certifying `did:kash` inside its log id — and by nobody
 * else. It names the tree's size, its root, the time the log claims, and the
 * head before it. **Its time is the log's claim.** What makes a time stand is
 * a public witness over {@link checkpointHash}, the SHA-256 of the signed
 * payload bytes: a witness stamps the size, the root and the claimed time
 * together, so none can be moved afterwards.
 */

import { isAlgorithmUnsupported } from "@kashscript/identity-core";
import { sha256Hex } from "../chain";
import { signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "../dsse";
import { base64ToBytes } from "../ed25519";
import { AttestError } from "../errors";
import { decodeEnvelopePayload } from "../holder/trust-list";
import { selfCertifyingTypedKey } from "../holder/keys";

export const DST_LOG_CHECKPOINT = "application/vnd.kash.log-checkpoint+json" as const;
export const LOG_CHECKPOINT_FORMAT = "kashscript-log-checkpoint/1" as const;

/** `<publisher did:kash>/log/<slug>` — the log is its publisher's, and its key is in its name. */
const LOG_ID = /^(did:kash:[1-9A-HJ-NP-Za-km-z]+)\/log\/([a-z0-9][a-z0-9-]{0,62})$/;
const HEX64 = /^[0-9a-f]{64}$/;

export interface TreeHeadRef {
  readonly treeSize: number;
  readonly rootHash: string;
}

export interface LogCheckpointPayload {
  readonly format: typeof LOG_CHECKPOINT_FORMAT;
  readonly logId: string;
  /** How many entries the head covers. */
  readonly treeSize: number;
  /** The RFC 6962 root over them, hex. */
  readonly rootHash: string;
  /** When the log says it made this head. A claim until a witness stamps it. */
  readonly timestampUnix: number;
  /** The head before this one, or null for the first. */
  readonly previous: TreeHeadRef | null;
}

/** The `did:kash` that may sign a log's checkpoints, or null when the id is not a log id. */
export function logKeyOf(logId: unknown): string | null {
  if (typeof logId !== "string") return null;
  const m = LOG_ID.exec(logId);
  if (m === null) return null;
  return selfCertifyingTypedKey(m[1]!) === null ? null : m[1]!;
}

/** True when `logId` is `<did:kash>/log/<slug>` and the did names a key. */
export function isLogId(logId: unknown): logId is string {
  return logKeyOf(logId) !== null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);

function isTreeHeadRef(v: unknown): v is TreeHeadRef {
  return isPlainObject(v) && isInt(v.treeSize) && v.treeSize >= 1 && typeof v.rootHash === "string" && HEX64.test(v.rootHash);
}

/** Structural: is this a checkpoint payload? */
export function isCheckpointPayload(p: unknown): p is LogCheckpointPayload {
  return (
    isPlainObject(p) &&
    p.format === LOG_CHECKPOINT_FORMAT &&
    isLogId(p.logId) &&
    isInt(p.treeSize) &&
    p.treeSize >= 1 &&
    typeof p.rootHash === "string" &&
    HEX64.test(p.rootHash) &&
    isInt(p.timestampUnix) &&
    p.timestampUnix >= 0 &&
    (p.previous === null || isTreeHeadRef(p.previous)) &&
    Object.keys(p).length === 6
  );
}

/** Sign a checkpoint. The signer must be the log's own key. */
export async function signCheckpoint(payload: LogCheckpointPayload, signer: DsseSigner): Promise<DsseEnvelope> {
  if (!isCheckpointPayload(payload)) throw new AttestError("INVALID_INPUT", "not a kashscript-log-checkpoint/1 payload");
  const key = logKeyOf(payload.logId);
  if (signer.keyid !== key) throw new AttestError("INVALID_INPUT", `a checkpoint of ${payload.logId} is signed by ${key}, not ${signer.keyid}`);
  if (payload.previous !== null && payload.previous.treeSize > payload.treeSize) {
    throw new AttestError("INVALID_INPUT", "a checkpoint never shrinks the tree");
  }
  return signEnvelope(payload, DST_LOG_CHECKPOINT, signer, { canonical: true });
}

export type CheckpointFailureReason =
  | "MALFORMED_CHECKPOINT"
  | "CHECKPOINT_TYPE_MISMATCH"
  | "LOG_ID_INVALID"
  | "LOG_ID_MISMATCH"
  | "CHECKPOINT_SIGNATURE_INVALID"
  /** This runtime cannot run the log key's algorithm. Nothing was judged. */
  | "RUNTIME_CANNOT_CHECK";

export interface CheckpointReport {
  readonly ok: boolean;
  readonly reason: CheckpointFailureReason | null;
  readonly logId: string | null;
  /** The log's key — the only key that may sign its checkpoints. */
  readonly key: string | null;
  readonly treeSize: number | null;
  readonly rootHash: string | null;
  /** The log's claim. The witness's time is read elsewhere. */
  readonly timestampUnix: number | null;
  readonly previous: TreeHeadRef | null;
  /** SHA-256 of the signed payload bytes — what a public witness stamps. */
  readonly payloadSha256: string | null;
  readonly notes: readonly string[];
}

function failed(reason: CheckpointFailureReason, note: string, partial: Partial<CheckpointReport> = {}): CheckpointReport {
  return { ok: false, logId: null, key: null, treeSize: null, rootHash: null, timestampUnix: null, previous: null, payloadSha256: null, ...partial, reason, notes: [note] };
}

/**
 * Verify a checkpoint offline: its type, its shape, and that the log's own key
 * — and only it — signed it. With `opts.logId`, that it is that log's. Never
 * throws; a runtime without the key's algorithm reports `RUNTIME_CANNOT_CHECK`.
 */
export async function verifyCheckpoint(envelope: unknown, opts: { readonly logId?: string } = {}): Promise<CheckpointReport> {
  if (!isPlainObject(envelope) || typeof envelope.payloadType !== "string" || typeof envelope.payload !== "string" || !Array.isArray(envelope.signatures)) {
    return failed("MALFORMED_CHECKPOINT", "not a DSSE envelope");
  }
  if (envelope.payloadType !== DST_LOG_CHECKPOINT) return failed("CHECKPOINT_TYPE_MISMATCH", `payloadType is ${JSON.stringify(envelope.payloadType)}`);
  const p = decodeEnvelopePayload(envelope);
  if (!isCheckpointPayload(p)) return failed("MALFORMED_CHECKPOINT", "payload is not a kashscript-log-checkpoint/1 document");
  const partial: Partial<CheckpointReport> = {
    logId: p.logId,
    treeSize: p.treeSize,
    rootHash: p.rootHash,
    timestampUnix: p.timestampUnix,
    previous: p.previous,
  };
  const key = logKeyOf(p.logId);
  if (key === null) return failed("LOG_ID_INVALID", "the log id names no self-certifying key", partial);
  if (opts.logId !== undefined && opts.logId !== p.logId) return failed("LOG_ID_MISMATCH", `a checkpoint of ${p.logId}, not ${opts.logId}`, { ...partial, key });
  const typed = selfCertifyingTypedKey(key)!;
  let signed = false;
  try {
    const res = await verifyEnvelope(envelope as unknown as DsseEnvelope, (kid) => (kid === key ? typed : null));
    signed = res.verifiedKeyids.includes(key);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) {
      return failed("RUNTIME_CANNOT_CHECK", "this runtime cannot run the log key's algorithm — nothing was judged", { ...partial, key });
    }
    return failed("MALFORMED_CHECKPOINT", "the envelope does not parse", { ...partial, key });
  }
  if (!signed) return failed("CHECKPOINT_SIGNATURE_INVALID", "not signed by the log's own key", { ...partial, key });
  if (p.previous !== null && p.previous.treeSize > p.treeSize) return failed("MALFORMED_CHECKPOINT", "the tree shrank", { ...partial, key });
  const payloadSha256 = await sha256Hex(base64ToBytes(envelope.payload));
  return {
    ok: true,
    reason: null,
    logId: p.logId,
    key,
    treeSize: p.treeSize,
    rootHash: p.rootHash,
    timestampUnix: p.timestampUnix,
    previous: p.previous,
    payloadSha256,
    notes: ["the checkpoint's time is the log's own claim; a public witness over its payload hash is what makes a time stand"],
  };
}

/** SHA-256, hex, of a checkpoint's signed payload bytes — the digest a public witness stamps. */
export async function checkpointHash(envelope: DsseEnvelope): Promise<string> {
  if (!isPlainObject(envelope) || typeof envelope.payload !== "string") throw new AttestError("INVALID_INPUT", "not a DSSE envelope");
  return sha256Hex(base64ToBytes(envelope.payload));
}

/** The payload of a checkpoint that already verified, or null. */
export function checkpointPayloadOf(envelope: unknown): LogCheckpointPayload | null {
  const p = decodeEnvelopePayload(envelope);
  return isCheckpointPayload(p) ? p : null;
}
