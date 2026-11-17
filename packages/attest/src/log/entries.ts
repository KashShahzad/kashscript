/**
 * The trust log's entries (KS-Q4; specs/trust-log.md §2; ECOSYSTEM d84 P6,
 * d91(a) and (f)).
 *
 * A log holds **issuers and lists, and the salted hashes of attestations —
 * never people, never presentations, never a record's content**. Four kinds,
 * each a closed shape: a trust list's version, a status list's version, an
 * issuer key added, rotated or revoked, and an attestation's salted hash. The
 * guard refuses anything else — an unknown kind, an extra field, free text, a
 * field whose name says it carries a person or a record — before a leaf is
 * ever made, and the verifier runs the same guard on every entry it reads.
 *
 * The leaf is `SHA-256(0x00 ‖ "kash-log-entry-v1\n" ‖ JCS(entry))`: RFC 6962's
 * leaf prefix, the registered tag, and the entry in RFC 8785 canonical form, so
 * a mirror rebuilt from the entries alone reaches the same root.
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import { bytesToHex, hexToBytes } from "../chain";
import { AttestError } from "../errors";
import { rfc6962LeafHash } from "../witness/rfc6962";

/** The leaf's tag. Registered in `../dst` (family `merkle-leaf`). */
export const LOG_ENTRY_LEAF_DST = "kash-log-entry-v1\n" as const;
/** The domain of a salted record hash: `SHA-256(tag ‖ salt ‖ record hash)`. */
export const LOG_SALT_DST = "kash-log-salt-v1\n" as const;

export type LogEntryKind = "trust-list" | "status-list" | "issuer-key" | "attestation";
export const LOG_ENTRY_KINDS: readonly LogEntryKind[] = ["trust-list", "status-list", "issuer-key", "attestation"];

interface LogEntryBase {
  readonly v: 1;
  readonly kind: LogEntryKind;
  /** Logged after the log began, about something that happened before it: its time is the log's, never the claimed one (d91(i)). */
  readonly backfilled?: boolean;
}

/** One version of a trust list, by the hash of the bytes its publisher signed. */
export interface TrustListLogEntry extends LogEntryBase {
  readonly kind: "trust-list";
  readonly listId: string;
  readonly publisher: string;
  readonly version: number;
  readonly issuedAtUnix: number;
  /** SHA-256, hex, of the signed payload bytes (the record's CID basis). */
  readonly sha256: string;
}

/** One version of an issuer's status list — so a withdrawal's time has a witness. */
export interface StatusListLogEntry extends LogEntryBase {
  readonly kind: "status-list";
  /** The list's https URL, as records point at it. Shared by many records, never one per record. */
  readonly id: string;
  readonly issuer: string;
  readonly statusPurpose: string;
  readonly issuedAtUnix: number;
  readonly sha256: string;
}

export type IssuerKeyAction = "added" | "rotated" | "revoked";

/** An issuer key event, as the trust list that records it says. */
export interface IssuerKeyLogEntry extends LogEntryBase {
  readonly kind: "issuer-key";
  readonly issuerId: string;
  readonly keyid: string;
  readonly alg: "Ed25519" | "ES256";
  readonly action: IssuerKeyAction;
  readonly atUnix: number;
  /** The trust list version that says so. */
  readonly listId: string;
  readonly listVersion: number;
}

/** An attestation, by its salted hash. The issuer keeps the salt beside the record and hands it to the holder; the log never sees the record. */
export interface AttestationLogEntry extends LogEntryBase {
  readonly kind: "attestation";
  readonly issuer: string;
  /** `SHA-256("kash-log-salt-v1\n" ‖ salt ‖ record hash)`, hex — see {@link saltedRecordHash}. */
  readonly salted: string;
  /** The issuer's own claim of when it was made. The witness decides what stands. */
  readonly claimedAtUnix: number;
}

export type LogEntry = TrustListLogEntry | StatusListLogEntry | IssuerKeyLogEntry | AttestationLogEntry;

/* ── the guard ─────────────────────────────────────────────────────────── */

export type LogEntryFaultCode =
  | "NOT_AN_OBJECT"
  | "BAD_VERSION"
  | "UNKNOWN_KIND"
  | "MISSING_FIELD"
  | "EXTRA_FIELD"
  /** A field whose name says it carries what a log never holds: a person, a record, a presentation. */
  | "FORBIDDEN_FIELD"
  | "BAD_VALUE"
  | "TEXT_TOO_LONG";

export interface LogEntryFault {
  readonly code: LogEntryFaultCode;
  readonly path: string;
  readonly message: string;
}

/** Names that would carry what the log must not hold. Refused by name, whatever the value. */
export const FORBIDDEN_LOG_FIELDS: readonly string[] = [
  "holder", "subject", "person", "people", "user", "name", "email", "phone", "address",
  "presentation", "vp_token", "nonce", "audience", "relationship",
  "record", "payload", "content", "claims", "disclosures", "amount", "total", "wallet", "salt",
];

const MAX_TEXT = 256;
const MAX_UNIX = 2 ** 40;
const HEX64 = /^[0-9a-f]{64}$/;
const HTTPS = /^https:\/\/[^\s]+$/;

type Check = (v: unknown) => string | null;
const text = (v: unknown): string | null =>
  typeof v !== "string" ? "a string" : v.length === 0 ? "not empty" : v.length > MAX_TEXT ? `at most ${MAX_TEXT} characters` : /[\r\n\t]/.test(v) ? "one line" : null;
const hex64: Check = (v) => (typeof v === "string" && HEX64.test(v) ? null : "64 lowercase hex characters");
const unix: Check = (v) => (typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_UNIX ? null : "a unix time in seconds");
const version: Check = (v) => (typeof v === "number" && Number.isInteger(v) && v >= 1 ? null : "a version number from 1");
const https: Check = (v) => (typeof v === "string" && v.length <= 2048 && HTTPS.test(v) ? null : "an https URL");
const oneOf =
  (values: readonly string[]): Check =>
  (v) =>
    typeof v === "string" && values.includes(v) ? null : `one of ${values.join(", ")}`;

const FIELDS: Readonly<Record<LogEntryKind, Readonly<Record<string, Check>>>> = {
  "trust-list": { listId: text, publisher: text, version, issuedAtUnix: unix, sha256: hex64 },
  "status-list": { id: https, issuer: text, statusPurpose: oneOf(["revocation", "suspension", "supersession", "withdrawal"]), issuedAtUnix: unix, sha256: hex64 },
  "issuer-key": { issuerId: text, keyid: text, alg: oneOf(["Ed25519", "ES256"]), action: oneOf(["added", "rotated", "revoked"]), atUnix: unix, listId: text, listVersion: version },
  attestation: { issuer: text, salted: hex64, claimedAtUnix: unix },
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The rules an entry must meet before it becomes a leaf. Empty means admitted. Never throws. */
export function logEntryFaults(entry: unknown): readonly LogEntryFault[] {
  const out: LogEntryFault[] = [];
  const fault = (code: LogEntryFaultCode, path: string, message: string): void => {
    out.push({ code, path, message });
  };
  if (!isPlainObject(entry)) return [{ code: "NOT_AN_OBJECT", path: "", message: "an entry is a JSON object" }];
  if (entry.v !== 1) fault("BAD_VERSION", "v", "this log's entries are version 1");
  const kind = entry.kind;
  if (typeof kind !== "string" || !(LOG_ENTRY_KINDS as readonly string[]).includes(kind)) {
    fault("UNKNOWN_KIND", "kind", `one of ${LOG_ENTRY_KINDS.join(", ")} — the log holds issuers and lists, and attestations by salted hash`);
    return out;
  }
  const spec = FIELDS[kind as LogEntryKind];
  for (const [name, check] of Object.entries(spec)) {
    if (!(name in entry)) {
      fault("MISSING_FIELD", name, `${name} is required`);
      continue;
    }
    const why = check(entry[name]);
    if (why !== null) fault(typeof entry[name] === "string" && entry[name].length > MAX_TEXT ? "TEXT_TOO_LONG" : "BAD_VALUE", name, `${name}: ${why}`);
  }
  for (const name of Object.keys(entry)) {
    if (name === "v" || name === "kind" || name in spec) continue;
    if (name === "backfilled") {
      if (typeof entry.backfilled !== "boolean") fault("BAD_VALUE", "backfilled", "backfilled: true or false");
      continue;
    }
    if (FORBIDDEN_LOG_FIELDS.includes(name.toLowerCase())) {
      fault("FORBIDDEN_FIELD", name, `${name}: a log entry never carries a person, a record, a presentation or a salt`);
    } else {
      fault("EXTRA_FIELD", name, `${name} is not part of a ${kind} entry`);
    }
  }
  return out;
}

/** True when the guard admits it; narrows the type. */
export function isLogEntry(entry: unknown): entry is LogEntry {
  return logEntryFaults(entry).length === 0;
}

/** The time an entry's author claims for the thing it records. The witness, not this, says when it existed. */
export function claimedTimeOf(entry: LogEntry): number {
  switch (entry.kind) {
    case "attestation":
      return entry.claimedAtUnix;
    case "issuer-key":
      return entry.atUnix;
    case "trust-list":
    case "status-list":
      return entry.issuedAtUnix;
  }
}

/* ── the leaf and the salt ─────────────────────────────────────────────── */

const enc = new TextEncoder();

/** The bytes under the leaf prefix: the tag, then the entry in RFC 8785 canonical form. */
export function logLeafData(entry: LogEntry): Uint8Array {
  const faults = logEntryFaults(entry);
  if (faults.length > 0) throw new AttestError("INVALID_INPUT", `not a log entry: ${faults.map((f) => f.message).join("; ")}`);
  const tag = enc.encode(LOG_ENTRY_LEAF_DST);
  const body = canonicalizeBytes(entry);
  const out = new Uint8Array(tag.length + body.length);
  out.set(tag, 0);
  out.set(body, tag.length);
  return out;
}

/** `SHA-256(0x00 ‖ "kash-log-entry-v1\n" ‖ JCS(entry))` — the leaf a mirror recomputes from the entry alone. */
export function logLeafHash(entry: LogEntry): Promise<Uint8Array> {
  return rfc6962LeafHash(logLeafData(entry));
}

/** 32 random bytes, hex — one salt per attestation, kept by the issuer beside the record and handed to its holder. */
export function newLogSalt(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The salted hash the log holds for an attestation:
 * `SHA-256("kash-log-salt-v1\n" ‖ salt ‖ record hash)`, hex. Without the salt
 * the log entry names no record; with it, the holder proves which record was logged.
 */
export async function saltedRecordHash(saltHex: string, recordHashHex: string): Promise<string> {
  if (typeof saltHex !== "string" || !HEX64.test(saltHex)) throw new AttestError("INVALID_INPUT", "a log salt is 32 bytes, as 64 lowercase hex characters");
  if (typeof recordHashHex !== "string" || !HEX64.test(recordHashHex)) throw new AttestError("INVALID_INPUT", "a record hash is 64 lowercase hex characters");
  const tag = enc.encode(LOG_SALT_DST);
  const buf = new Uint8Array(tag.length + 64);
  buf.set(tag, 0);
  buf.set(hexToBytes(saltHex), tag.length);
  buf.set(hexToBytes(recordHashHex), tag.length + 32);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf as unknown as BufferSource)));
}
