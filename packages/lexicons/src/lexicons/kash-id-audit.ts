/**
 * Lexicon: kash.id.audit@1.0.0
 *
 * Append-only ledger of identity-state changes. Each record references the
 * corresponding op-log entry from the Identity Protocol so consumers can
 * audit history without re-replaying the full chain.
 */

import { S, type ObjectSchema } from "../schema";

export const KASH_AUDIT_NSID    = "kash.id.audit" as const;
export const KASH_AUDIT_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_AUDIT_ID      = "kash.id.audit@1.0.0" as const;

/* ── types ──────────────────────────────────────────────────────── */

export type KashAuditEventType =
  | "key-rotated"
  | "key-revoked"
  | "pds-migrated"
  | "witnesses-changed"
  | "quorum-set"
  | "quorum-recovered"
  | "deactivated";

export interface KashAuditBody {
  /** Type of identity-state event being logged. */
  readonly event: KashAuditEventType;
  /** CID of the underlying op-log entry (Identity Protocol §3.4 head.opCid). */
  readonly opCid: string;
  /** Sequence number from the op log (Identity Protocol §4.2). */
  readonly opSeq: number;
  /** Op-log entry type ("update", "recover", "quorum-recover", etc.). */
  readonly opType: string;
  /** Human-readable summary for audit-log UIs. 1–280 chars. */
  readonly summary: string;
  /** Optional structured details; shape is per-event-type, free-form here. */
  readonly details?: Readonly<Record<string, unknown>>;
}

/* ── runtime schema ─────────────────────────────────────────────── */

export const KASH_AUDIT_BODY_SCHEMA: ObjectSchema = S.object(
  {
    event:   S.enum(
      "key-rotated",
      "key-revoked",
      "pds-migrated",
      "witnesses-changed",
      "quorum-set",
      "quorum-recovered",
      "deactivated",
    ),
    opCid:   S.string({ format: "cid" }),
    opSeq:   S.number({ integer: true, min: 0 }),
    opType:  S.string({ minLength: 1, maxLength: 64 }),
    summary: S.string({ minLength: 1, maxLength: 280 }),
    details: S.optional(S.record(S.any())),
  },
  ["event", "opCid", "opSeq", "opType", "summary"],
);
