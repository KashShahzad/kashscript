/**
 * Status and revocation — the one check that may touch the network
 * (specs/holder-contract.md §4).
 *
 * Aligned to **W3C Bitstring Status List v1.0**: a record carries a
 * `BitstringStatusListEntry` as `credentialStatus` inside its own signed
 * payload; the issuer publishes one list whose `encodedList` is the multibase
 * (`u`, base64url) GZIP of a bitstring, index 0 being the left-most bit. The
 * envelope is ours — a DSSE envelope, `payloadType` = {@link DST_STATUS_LIST} —
 * so this is "aligned to" the standard, never "a Verifiable Credential".
 *
 * Why this is consistent with ADR-0018's rejection of a hosted status
 * endpoint: the list is the **issuer's**, never ours; a record's signature
 * verifies without it; the status is a separate verdict that names its own
 * time; and a list can be **carried** (prefetched by the holder, presented with
 * the record) as well as fetched. {@link fetchStatusLists} is the only function
 * in attest that takes a `fetch`, and nothing calls it unless asked.
 *
 * Status lists correlate, so: never a per-record list, at least
 * {@link STATUS_LIST_MIN_ENTRIES} entries (the standard's own floor), indexes
 * assigned at random, and the holder prefetches on its own schedule.
 */

import { AttestError } from "../errors";
import { base64UrlToBytes, bytesToBase64Url } from "../ed25519";
import { isAlgorithmUnsupported } from "@kashscript/identity-core";
import { signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "../dsse";
import { gunzip, gzip, type InflateFunction } from "./gzip";
import { decodeEnvelopePayload } from "./trust-list";
import { keyOfResolved, type KeyResolver, type KeySource } from "./keys";

export const DST_STATUS_LIST = "application/vnd.kash.status-list+json" as const;
export const STATUS_LIST_FORMAT = "kashscript-status-list/1" as const;
/** 131,072 entries = 16 KiB uncompressed — W3C Bitstring Status List's minimum. */
export const STATUS_LIST_MIN_ENTRIES = 131_072;

export type StatusPurpose = "revocation" | "suspension";

/** What a record carries as `credentialStatus` — W3C `BitstringStatusListEntry`. */
export interface StatusListEntry {
  readonly type: "BitstringStatusListEntry";
  readonly statusPurpose: StatusPurpose;
  /** A decimal integer, written as a string as the standard writes it. */
  readonly statusListIndex: string;
  /** The URL of the list — shared by many records, never one per record. */
  readonly statusListCredential: string;
}

export interface StatusListPayload {
  readonly format: typeof STATUS_LIST_FORMAT;
  readonly type: "BitstringStatusList";
  /** The URL the list is served at. Entries point here. */
  readonly id: string;
  /** The keyid that signs the envelope. */
  readonly issuer: string;
  readonly statusPurpose: StatusPurpose;
  /** `u` + base64url(GZIP(bitstring)). */
  readonly encodedList: string;
  /** The issuer's own claim of when this list was true — the "as of" in every verdict. */
  readonly issuedAtUnix: number;
  readonly validUntilUnix: number | null;
  /** Milliseconds a verifier may cache it (the standard's `ttl`). */
  readonly ttl?: number;
}

export type StatusListFailureReason =
  | "MALFORMED_STATUS_LIST"
  | "STATUS_LIST_TYPE_MISMATCH"
  | "STATUS_LIST_SIGNATURE_INVALID"
  | "STATUS_LIST_UNDECODABLE"
  | "STATUS_LIST_TOO_SMALL";

export interface StatusListReport {
  readonly ok: boolean;
  readonly id: string | null;
  readonly issuer: string | null;
  readonly issuerKeySource: KeySource | null;
  readonly statusPurpose: StatusPurpose | null;
  readonly issuedAtUnix: number | null;
  readonly validUntilUnix: number | null;
  /** `validUntilUnix` is null or not yet passed. An expired list decides nothing. */
  readonly current: boolean;
  readonly entries: number;
  /** How the verifier got it. `fetched` is the only networked path in attest. */
  readonly source: "carried" | "fetched";
  readonly reason: StatusListFailureReason | null;
  readonly notes: readonly string[];
  /** The decoded bitstring (not part of any wire format). */
  readonly bits: Uint8Array | null;
}

export type StatusState =
  | "not-revoked"
  | "revoked"
  | "suspended"
  | "withdrawn"
  | "unknown"
  | "no-status-entry";

export interface StatusVerdict {
  readonly state: StatusState;
  /** The time the verdict is true as of — a list's `issuedAtUnix`, or a revocation's own date. */
  readonly asOfUnix: number | null;
  readonly source: "carried" | "fetched" | "presented" | null;
  readonly listId: string | null;
  /** The sentence a surface shows. It always says what it rests on. */
  readonly text: string;
}

/* ── the bitstring ─────────────────────────────────────────────────────── */

/** A zeroed bitstring of `entries` bits (a multiple of 8, at least the minimum). */
export function createStatusBitstring(entries: number = STATUS_LIST_MIN_ENTRIES): Uint8Array {
  if (!Number.isInteger(entries) || entries < STATUS_LIST_MIN_ENTRIES || entries % 8 !== 0) {
    throw new AttestError("INVALID_INPUT", `a status list needs a multiple of 8 entries, at least ${STATUS_LIST_MIN_ENTRIES}`);
  }
  return new Uint8Array(entries / 8);
}

/** Index 0 is the left-most bit: the most significant bit of the first byte. */
export function getStatusBit(bits: Uint8Array, index: number): boolean {
  const byte = bits[index >> 3];
  if (byte === undefined) throw new AttestError("INVALID_INPUT", `status index ${index} is outside the list`);
  return (byte & (0x80 >> (index & 7))) !== 0;
}

export function setStatusBit(bits: Uint8Array, index: number, on: boolean): void {
  const i = index >> 3;
  if (!Number.isInteger(index) || index < 0 || i >= bits.length) {
    throw new AttestError("INVALID_INPUT", `status index ${index} is outside the list`);
  }
  const mask = 0x80 >> (index & 7);
  bits[i] = on ? bits[i]! | mask : bits[i]! & ~mask;
}

export async function encodeStatusList(bits: Uint8Array): Promise<string> {
  return "u" + bytesToBase64Url(await gzip(bits));
}

export async function decodeStatusList(encoded: string, opts?: { inflate?: InflateFunction | undefined }): Promise<Uint8Array> {
  if (typeof encoded !== "string" || !encoded.startsWith("u")) {
    throw new AttestError("MALFORMED_PAYLOAD", "encodedList must be multibase base64url (a leading 'u')");
  }
  return gunzip(base64UrlToBytes(encoded.slice(1)), opts?.inflate);
}

/* ── reading a record's pointer ────────────────────────────────────────── */

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The well-formed `credentialStatus` of a signed payload, or null. */
export function statusEntryOf(signedPayload: unknown): StatusListEntry | null {
  if (!isPlainObject(signedPayload)) return null;
  const s = signedPayload.credentialStatus;
  if (
    !isPlainObject(s) ||
    s.type !== "BitstringStatusListEntry" ||
    (s.statusPurpose !== "revocation" && s.statusPurpose !== "suspension") ||
    typeof s.statusListIndex !== "string" ||
    !/^(0|[1-9][0-9]*)$/.test(s.statusListIndex) ||
    typeof s.statusListCredential !== "string"
  ) {
    return null;
  }
  return {
    type: "BitstringStatusListEntry",
    statusPurpose: s.statusPurpose,
    statusListIndex: s.statusListIndex,
    statusListCredential: s.statusListCredential,
  };
}

/* ── the list ──────────────────────────────────────────────────────────── */

function failedList(reason: StatusListFailureReason, note: string, source: "carried" | "fetched", partial: Partial<StatusListReport> = {}): StatusListReport {
  return {
    ok: false,
    id: null,
    issuer: null,
    issuerKeySource: null,
    statusPurpose: null,
    issuedAtUnix: null,
    validUntilUnix: null,
    current: false,
    entries: 0,
    bits: null,
    ...partial,
    source,
    reason,
    notes: [note],
  };
}

export interface VerifyStatusListOptions {
  /** Resolves the issuer's key: self-certifying DID, trust list, or held key. */
  readonly resolveKey: KeyResolver;
  readonly nowSec?: number | undefined;
  readonly source?: "carried" | "fetched" | undefined;
  readonly inflate?: InflateFunction | undefined;
}

/** Verify a status list's signature and shape, and decode it. Offline. */
export async function verifyStatusList(envelope: DsseEnvelope, opts: VerifyStatusListOptions): Promise<StatusListReport> {
  const source = opts.source ?? "carried";
  if (!isPlainObject(envelope) || typeof envelope.payloadType !== "string" || !Array.isArray(envelope.signatures)) {
    return failedList("MALFORMED_STATUS_LIST", "not a DSSE envelope", source);
  }
  if (envelope.payloadType !== DST_STATUS_LIST) {
    return failedList("STATUS_LIST_TYPE_MISMATCH", `payloadType is ${JSON.stringify(envelope.payloadType)}`, source);
  }
  const p = decodeEnvelopePayload(envelope);
  if (
    !isPlainObject(p) ||
    p.format !== STATUS_LIST_FORMAT ||
    p.type !== "BitstringStatusList" ||
    typeof p.id !== "string" ||
    typeof p.issuer !== "string" ||
    (p.statusPurpose !== "revocation" && p.statusPurpose !== "suspension") ||
    typeof p.encodedList !== "string" ||
    typeof p.issuedAtUnix !== "number" ||
    (p.validUntilUnix !== null && typeof p.validUntilUnix !== "number")
  ) {
    return failedList("MALFORMED_STATUS_LIST", "payload is not a kashscript-status-list/1 document", source);
  }
  const partial: Partial<StatusListReport> = {
    id: p.id,
    issuer: p.issuer,
    statusPurpose: p.statusPurpose,
    issuedAtUnix: p.issuedAtUnix,
    validUntilUnix: p.validUntilUnix as number | null,
  };
  const key = opts.resolveKey(p.issuer);
  let signed = false;
  try {
    const res = await verifyEnvelope(envelope, (kid) => (kid === p.issuer && key !== null ? keyOfResolved(key) : null));
    signed = res.verifiedKeyids.includes(p.issuer);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    signed = false;
  }
  if (!signed) {
    return failedList("STATUS_LIST_SIGNATURE_INVALID", "not signed by its named issuer (or the issuer's key is unknown)", source, partial);
  }
  let bits: Uint8Array;
  try {
    bits = await decodeStatusList(p.encodedList, { inflate: opts.inflate });
  } catch {
    return failedList("STATUS_LIST_UNDECODABLE", "encodedList does not decode as multibase base64url GZIP", source, partial);
  }
  const entries = bits.length * 8;
  if (entries < STATUS_LIST_MIN_ENTRIES) {
    return failedList(
      "STATUS_LIST_TOO_SMALL",
      `${entries} entries — below the ${STATUS_LIST_MIN_ENTRIES} floor, so an index could stand out`,
      source,
      { ...partial, entries },
    );
  }
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const current = p.validUntilUnix === null || now <= (p.validUntilUnix as number);
  const notes: string[] = ["the list's time is the issuer's own claim"];
  if (!current) notes.push("past its validUntil — it decides nothing until a fresh list is presented");
  return {
    ok: true,
    ...partial,
    issuerKeySource: key?.source ?? null,
    current,
    entries,
    bits,
    source,
    reason: null,
    notes,
  } as StatusListReport;
}

const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(".000Z", "Z");

/**
 * The status of one record, from lists already verified. Never touches the
 * network. `lists` may mix carried and fetched lists; the verdict names which.
 */
export function checkStatus(entry: StatusListEntry | null, lists: readonly StatusListReport[]): StatusVerdict {
  if (entry === null) {
    return {
      state: "no-status-entry",
      asOfUnix: null,
      source: null,
      listId: null,
      text: "no status entry in the signed record — it can be withdrawn only by expiry or a presented revocation",
    };
  }
  const list = lists.find((l) => l.ok && l.id === entry.statusListCredential && l.statusPurpose === entry.statusPurpose);
  if (list === undefined) {
    return {
      state: "unknown",
      asOfUnix: null,
      source: null,
      listId: entry.statusListCredential,
      text: `status not checked — the list ${entry.statusListCredential} was not presented (fetching it is the one networked check)`,
    };
  }
  if (!list.current || list.bits === null) {
    return {
      state: "unknown",
      asOfUnix: list.issuedAtUnix,
      source: list.source,
      listId: list.id,
      text: `status unknown — the presented list is past its validUntil`,
    };
  }
  const index = Number(entry.statusListIndex);
  if (!Number.isSafeInteger(index) || index >= list.entries) {
    return { state: "unknown", asOfUnix: list.issuedAtUnix, source: list.source, listId: list.id, text: "status unknown — the index is outside the list" };
  }
  const asOf = list.issuedAtUnix as number;
  const how = list.source === "fetched" ? "fetched from the issuer" : "carried with the record, nothing fetched";
  if (getStatusBit(list.bits, index)) {
    const state = entry.statusPurpose === "suspension" ? "suspended" : "revoked";
    return { state, asOfUnix: asOf, source: list.source, listId: list.id, text: `${state} as of ${iso(asOf)} (${how})` };
  }
  return {
    state: "not-revoked",
    asOfUnix: asOf,
    source: list.source,
    listId: list.id,
    text: `valid unless revoked, as of ${iso(asOf)} (${how})`,
  };
}

/* ── the one networked function ────────────────────────────────────────── */

export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface FetchedStatusList {
  readonly url: string;
  readonly envelope: DsseEnvelope | null;
  readonly error: string | null;
}

/**
 * Fetch each distinct list URL once. **The only networked function in attest**,
 * and it takes `fetch` explicitly so every call site shows it. The fetch reveals
 * to the list's host that someone is checking *that list* — never which index,
 * which is why lists are large and shared.
 */
export async function fetchStatusLists(urls: readonly string[], fetchImpl: FetchLike): Promise<readonly FetchedStatusList[]> {
  const out: FetchedStatusList[] = [];
  for (const url of [...new Set(urls)]) {
    if (!/^https:\/\//.test(url)) {
      out.push({ url, envelope: null, error: "only https:// status lists are fetched" });
      continue;
    }
    try {
      const res = await fetchImpl(url);
      if (!res.ok) {
        out.push({ url, envelope: null, error: `HTTP ${res.status}` });
        continue;
      }
      out.push({ url, envelope: (await res.json()) as DsseEnvelope, error: null });
    } catch (e) {
      out.push({ url, envelope: null, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

/** Sign a status list (the issuer's side). Refuses a list below the size floor. */
export async function signStatusList(payload: StatusListPayload, signer: DsseSigner): Promise<DsseEnvelope> {
  if (payload.format !== STATUS_LIST_FORMAT || payload.type !== "BitstringStatusList") {
    throw new AttestError("INVALID_INPUT", "format must be kashscript-status-list/1, type BitstringStatusList");
  }
  if (signer.keyid !== payload.issuer) throw new AttestError("INVALID_INPUT", "the signer must be the named issuer");
  const bits = await decodeStatusList(payload.encodedList);
  if (bits.length * 8 < STATUS_LIST_MIN_ENTRIES) {
    throw new AttestError("INVALID_INPUT", `a status list needs at least ${STATUS_LIST_MIN_ENTRIES} entries`);
  }
  return signEnvelope(payload, DST_STATUS_LIST, signer, { canonical: true });
}
