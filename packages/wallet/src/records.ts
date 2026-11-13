/**
 * Hold: records exactly as their issuers signed them, each beside the holding
 * manifest the wallet writes (holder contract §2). Nothing is re-wrapped or
 * re-signed. The manifest is built from what attest computes from the bytes,
 * then checked by attest before anything is stored — so a manifest this wallet
 * writes always passes `verifyHeldRecord`, and an export always verifies.
 *
 * Expiry is real (d27.5): a record goes at the earlier of the expiry signed
 * into it and the retention its issuer declared, and `sweep` crypto-shreds it.
 */

import { lookupDst, type DstFamily } from "@kashscript/attest/dst";
import { decodeJws, isSdJwt, parseSdJwt } from "@kashscript/attest/sd-jwt";
import { isSessionReceipt, verifySessionReceipt } from "@kashscript/attest/exchange";
import { isCountersignBundle } from "@kashscript/attest/countersign";
import { parseIndusToken } from "@kashscript/attest/compat";
import {
  decodeEnvelopePayload,
  statusEntryOf,
  verifyHeldRecord,
  type ArtifactKind,
  type HeldArtifact,
  type HeldRecord,
  type HeldRecordContext,
  type HeldRecordReport,
  type HoldingManifest,
  type RetentionSource,
} from "@kashscript/attest/holder";
import { base64ToBytes, utf8Decode } from "./crypto/bytes";
import type { Clock } from "./platform";
import type { TrustStore } from "./trust";
import type { Vault } from "./vault";

/** Wallet-private notes about a record. Never exported, never sent. */
export interface RecordLocal {
  /** The place it came from. */
  readonly counterparty: string | null;
  /** The key it is bound to: the copy key in its `cnf`, or the relationship key it was received under. */
  readonly boundKey: string | null;
  /** Copies of one yes share a group. */
  readonly copyGroup: string | null;
  /** The one verifier this copy has been shown to (presentation §4). */
  readonly assignedVerifier: string | null;
}

export interface HeldEntry {
  readonly slot: string;
  readonly manifest: HoldingManifest;
  readonly artifact: HeldArtifact;
  readonly local: RecordLocal;
}

export type BuildResult =
  | { readonly status: "ready"; readonly record: HeldRecord }
  | { readonly status: "needs-keep-choice"; readonly record: HeldRecord; readonly issuer: string }
  | { readonly status: "refused"; readonly reasons: readonly string[] };

/* ── reading an artifact ───────────────────────────────────────────────── */

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

/** Which of the holder contract's kinds this value is, or null. */
export function detectKind(value: unknown): ArtifactKind | null {
  if (typeof value === "string") {
    const text = value.trim();
    if (isSdJwt(text)) return "sd-jwt";
    try {
      parseIndusToken(text);
      return "indus-token";
    } catch {
      return null;
    }
  }
  if (!isPlainObject(value)) return null;
  if (isSessionReceipt(value)) return "session-receipt";
  if (isCountersignBundle(value)) return "countersign-bundle";
  if (typeof value.payloadType === "string" && typeof value.payload === "string" && Array.isArray(value.signatures)) return "dsse";
  if (isPlainObject(value.header) && isPlainObject(value.body) && isPlainObject(value.signature)) return "kash-event";
  return null;
}

/** The payload the issuer signed, as attest reads it for each kind. */
export function signedPayloadOf(artifact: HeldArtifact): unknown {
  const v = artifact.value;
  try {
    switch (artifact.kind) {
      case "dsse":
        return decodeEnvelopePayload(v);
      case "kash-event":
        return isPlainObject(v) ? v.body : null;
      case "countersign-bundle": {
        const subject = isPlainObject(v) && isPlainObject(v.subject) ? v.subject : null;
        return subject !== null && typeof subject.payload === "string" ? JSON.parse(utf8Decode(base64ToBytes(subject.payload)) ?? "null") : null;
      }
      case "indus-token":
        return typeof v === "string" ? parseIndusToken(v.trim()).body : null;
      case "sd-jwt": {
        const p = typeof v === "string" ? parseSdJwt(v) : null;
        return p === null ? null : decodeJws(p.issuerJwt)?.payload ?? null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** The expiry signed into the record — attest's ceiling on retention. */
async function signedExpiryOf(artifact: HeldArtifact, payload: unknown, nowSec: number): Promise<number | null> {
  if (artifact.kind === "session-receipt") return (await verifySessionReceipt(artifact.value, { nowSec })).expiresAtUnix;
  if (artifact.kind === "indus-token") return null; // a scan window, not a retention
  if (!isPlainObject(payload)) return null;
  if (artifact.kind === "sd-jwt") return isInt(payload.exp) ? payload.exp : null;
  if (isInt(payload.expiresAtUnix)) return payload.expiresAtUnix;
  if (typeof payload.expiresAt === "string") {
    const ms = Date.parse(payload.expiresAt);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return null;
}

function familyOf(kind: ArtifactKind, tag: string): DstFamily {
  const registered = lookupDst(tag)?.family;
  switch (kind) {
    case "indus-token":
      return "indus";
    case "session-receipt":
      return "dsse-type";
    case "kash-event":
      return registered ?? "kash-event";
    case "sd-jwt":
      return registered ?? "sd-jwt-vct";
    default:
      return registered ?? "dsse-type";
  }
}

const HARD_FAILURES = new Set(["MALFORMED_ARTIFACT", "KEY_UNRESOLVED", "SIGNATURE_INVALID"]);

/** attest's reading of an artifact on its own, with no manifest to compare. */
export async function probeArtifact(artifact: HeldArtifact, ctx: HeldRecordContext): Promise<HeldRecordReport> {
  const probe: HoldingManifest = {
    recordId: "",
    issuer: "",
    relationship: null,
    type: { tag: "", family: "dsse-type", attestation: "issuer-signed" },
    receivedAtUnix: ctx.nowSec,
    expiresAtUnix: null,
    retentionSource: "none-declared",
    status: null,
    listing: "unlisted",
    keptUnlistedAtUnix: ctx.nowSec,
  };
  return verifyHeldRecord({ manifest: probe, artifact }, ctx);
}

export function hardFailures(report: HeldRecordReport): readonly string[] {
  return report.reasons.filter((r) => HARD_FAILURES.has(r));
}

export interface BuildOptions {
  /** The holder's identifier this record is held under — never a global id. */
  readonly relationship: string | null;
  /** `kash_retention_until` from the handoff, if the issuer declared one. */
  readonly declaredRetention: number | null;
  /** The holder chose to keep a record from an issuer no pinned list names. */
  readonly keepUnlisted: boolean;
}

/* ── the store ─────────────────────────────────────────────────────────── */

export class Records {
  constructor(
    private readonly vault: Vault,
    private readonly trust: TrustStore,
    private readonly now: Clock,
  ) {}

  /** Write the manifest for an artifact, and have attest agree with it. Stores nothing. */
  async build(artifact: HeldArtifact, opts: BuildOptions): Promise<BuildResult> {
    const ctx = await this.trust.context();
    const probe = await probeArtifact(artifact, ctx);
    const hard = hardFailures(probe);
    if (hard.length > 0 || probe.tag === null || probe.attestation === null || probe.issuer === null || probe.kind === null) {
      return { status: "refused", reasons: hard.length > 0 ? hard : ["MALFORMED_ARTIFACT"] };
    }
    const payload = signedPayloadOf(artifact);
    const recordExpiry = await signedExpiryOf(artifact, payload, ctx.nowSec);
    let expiresAtUnix: number | null = null;
    let retentionSource: RetentionSource = "none-declared";
    if (recordExpiry !== null) {
      const declaredEarlier = opts.declaredRetention !== null && opts.declaredRetention < recordExpiry;
      expiresAtUnix = declaredEarlier ? opts.declaredRetention : recordExpiry;
      retentionSource = declaredEarlier ? "issuer-declared" : "record";
    } else if (opts.declaredRetention !== null) {
      expiresAtUnix = opts.declaredRetention;
      retentionSource = "issuer-declared";
    }
    if (expiresAtUnix !== null && expiresAtUnix <= ctx.nowSec) return { status: "refused", reasons: ["RECORD_PAST_RETENTION"] };

    const listed = probe.listing.evidence === "pinned-list";
    const deviceAsserted = probe.attestation === "device-asserted";
    const manifest: HoldingManifest = {
      recordId: probe.recordId,
      issuer: probe.issuer,
      relationship: opts.relationship,
      type: { tag: probe.tag, family: familyOf(probe.kind, probe.tag), attestation: probe.attestation },
      receivedAtUnix: ctx.nowSec,
      expiresAtUnix,
      retentionSource,
      status: statusEntryOf(payload),
      listing: listed ? "listed" : "unlisted",
      keptUnlistedAtUnix: listed || deviceAsserted || !opts.keepUnlisted ? null : ctx.nowSec,
    };
    const record: HeldRecord = { manifest, artifact };
    if (!listed && !deviceAsserted && !opts.keepUnlisted) return { status: "needs-keep-choice", record, issuer: probe.issuer };
    const final = await verifyHeldRecord(record, ctx);
    if (!final.ok) return { status: "refused", reasons: final.reasons };
    return { status: "ready", record };
  }

  /** Store a built record. Holding the same record twice keeps one copy. */
  async hold(record: HeldRecord, local: RecordLocal): Promise<string> {
    for (const e of await this.list()) if (e.manifest.recordId === record.manifest.recordId) return e.slot;
    const slot = await this.vault.newSlot();
    await this.vault.putRecord(slot, { manifest: record.manifest, artifact: record.artifact, local });
    return slot;
  }

  async list(): Promise<readonly HeldEntry[]> {
    const out: HeldEntry[] = [];
    for (const slot of await this.vault.recordSlots()) {
      const v = await this.vault.getRecord<Omit<HeldEntry, "slot">>(slot);
      if (v !== null) out.push({ slot, ...v });
    }
    return out;
  }

  async get(slot: string): Promise<HeldEntry | null> {
    const v = await this.vault.getRecord<Omit<HeldEntry, "slot">>(slot);
    return v === null ? null : { slot, ...v };
  }

  async updateLocal(slot: string, local: RecordLocal): Promise<void> {
    const e = await this.get(slot);
    if (e === null) return;
    await this.vault.putRecord(slot, { manifest: e.manifest, artifact: e.artifact, local });
  }

  /** The holder's own deletion, and expiry's: the record's key first, then its bytes. */
  async remove(slot: string): Promise<void> {
    await this.vault.shredRecord(slot);
  }

  /** Crypto-shred every record past its retention. Returns how many went. */
  async sweep(): Promise<number> {
    const now = this.now();
    let n = 0;
    for (const e of await this.list()) {
      if (e.manifest.expiresAtUnix !== null && e.manifest.expiresAtUnix <= now) {
        await this.remove(e.slot);
        n++;
      }
    }
    return n;
  }
}
