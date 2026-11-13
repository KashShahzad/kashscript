/**
 * The holder's export bundle and the holding manifest
 * (specs/holder-contract.md §2).
 *
 * **Records stay what they are.** A wallet holds each artifact exactly as its
 * issuer signed it, beside a small holding manifest the wallet writes itself.
 * Nothing is re-wrapped or re-signed. The manifest is unsigned and trusted for
 * nothing: every claim in it is either recomputed here from the artifact and
 * compared, or reported as the holder's own assertion.
 *
 * The export is one JSON file, written as RFC 8785 (JCS) canonical JSON with
 * records sorted by `recordId`, so the same holdings always produce the same
 * bytes. That is safe for every artifact in use, because each signature covers
 * base64 payload bytes (DSSE), canonical bytes (Kash-Event, countersign) or a
 * verbatim string (Indus tokens) — never the JSON text around it.
 *
 * Verification here never touches the network. Status lists are checked only
 * if they are carried in the file or passed in by a caller that fetched them.
 */

import { canonicalize, isAlgorithmUnsupported, verifyEventForKey, type SignedKashEvent } from "@kashscript/identity-core";
import { base64ToBytes, base64UrlToBytes } from "../ed25519";
import { contentIdOf, recordIdOf } from "./record-id";
import { verifyEnvelope, type DsseEnvelope } from "../dsse";
import { isRegisteredDst, lookupDst, type DstFamily } from "../dst";
import { verifyCountersignBundle, type CountersignBundle } from "../countersign";
import {
  verifyHelperSet,
  verifySuccessionSet,
  type CountersignKeyClaimReport,
  type HelperSetReport,
  type KeyClaim,
  type SignedHelperSet,
  type SuccessionConflict,
} from "../succession";
import { parseIndusToken, verifyIndusToken } from "../compat/indus-token";
import { findMarkRevocation, INDUS_MARK_DST } from "../compat/indus-mark";
import { verifySdJwt } from "../sd-jwt/sd-jwt";
import { verifySessionReceipt, type SessionReceiptReport } from "../exchange/session";
import { SESSION_EVENT_DST } from "../exchange/constants";
import { validatePresentationLog, type PresentationLogEntry } from "../exchange/presentation-log";
import { keyIdentityOf, keyOfResolved, makeKeyResolver, stripFragment, typedKeyOf, type KeyResolver, type KeySource, type PublicKeyEntry } from "./keys";
import type { KashPublicKey } from "../signing";
import { findListing, trustListKeyMap, verifyTrustList, type ListingMatch, type TrustListReport } from "./trust-list";
import { checkStatus, statusEntryOf, verifyStatusList, type StatusListEntry, type StatusListReport, type StatusVerdict } from "./status-list";
import type { InflateFunction } from "./gzip";

export const HOLDER_EXPORT_FORMAT = "kashscript-holder-export/1" as const;

/** Records whose only signer is the holder's own device or browser: Indusland's
 *  ambient IGEO1 check-in, and Indorania's practice receipts (signed with the
 *  visitor's own browser key). They never pass as countersigned and never earn
 *  a thank-you (ECOSYSTEM d49 rule 5). */
export const DEVICE_ASSERTED_DSTS: readonly string[] = [
  "indus.poe.v1.geo",
  "application/vnd.indorania.visa+json",
  "application/vnd.indorania.day+json",
];

/** `sd-jwt` and `session-receipt` added in holder contract v1.1 (PL-3). */
export type ArtifactKind = "dsse" | "countersign-bundle" | "kash-event" | "indus-token" | "sd-jwt" | "session-receipt";
export type AttestationClass = "countersigned" | "issuer-signed" | "device-asserted";
export type RetentionSource = "record" | "issuer-declared" | "none-declared";

export interface HeldArtifact {
  readonly kind: ArtifactKind;
  /** The artifact exactly as issued: a JSON object, or the token string. */
  readonly value: unknown;
}

/** What the wallet writes beside a record. Unsigned; every field is checked or labelled. */
export interface HoldingManifest {
  /** SHA-256 hex over JCS(value), or over the UTF-8 of a token string. Local to the wallet. */
  readonly recordId: string;
  /** The signer the record is attributed to (issuer DID, keyid, or token kid). */
  readonly issuer: string;
  /** The holder's relationship identifier for this issuer — never a global id. */
  readonly relationship: string | null;
  readonly type: {
    readonly tag: string;
    readonly family: DstFamily;
    readonly attestation: AttestationClass;
  };
  readonly receivedAtUnix: number;
  /** When the wallet deletes it. Never later than an expiry the issuer signed into the record. */
  readonly expiresAtUnix: number | null;
  readonly retentionSource: RetentionSource;
  /** A copy of the record's own signed `credentialStatus`, or null. */
  readonly status: StatusListEntry | null;
  readonly listing: "listed" | "unlisted";
  /** When the holder chose to keep a record from an unlisted issuer (d47(e)). */
  readonly keptUnlistedAtUnix: number | null;
}

export interface HeldRecord {
  readonly manifest: HoldingManifest;
  readonly artifact: HeldArtifact;
}

/** A public key the holder kept for a signer that is not self-certifying. */
export interface HeldKey extends PublicKeyEntry {
  readonly note: string;
}

/** JWE flattened JSON serialization (RFC 7516 §7.2.2). Only ever present because the holder asked. */
export interface EncryptedKeyBackup {
  readonly protected: string;
  readonly encrypted_key: string;
  readonly iv: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export interface HolderExport {
  readonly formatVersion: typeof HOLDER_EXPORT_FORMAT;
  readonly exportedAtUnix: number;
  readonly records: readonly HeldRecord[];
  /** `kash-key-claim-v1` claims, either path: prior-key pairs, or (v1.3) helper-quorum claims. */
  readonly keySuccession: readonly KeyClaim[];
  readonly trustLists: readonly DsseEnvelope[];
  readonly statusLists: readonly DsseEnvelope[];
  /** Presented revocations (today: `indus.mark.revoke.v1`). */
  readonly revocations: readonly SignedKashEvent[];
  readonly heldKeys: readonly HeldKey[];
  readonly encryptedKeyBackup: EncryptedKeyBackup | null;
  /** v1.1: the holder's own presentation log. Exported with the wallet, never sent anywhere. */
  readonly presentationLog?: readonly PresentationLogEntry[];
  /** v1.3: the helper sets the holder's keys signed in advance (specs/recovery.md) — what a
   *  new phone recovers from. Absent when there are none, so older exports are unchanged. */
  readonly recoveryHelpers?: readonly RecoveryHelpersEntry[];
}

/**
 * v1.3: one relationship key's helper set, with the holder's own label for
 * where that key is used. The label is unsigned and local — the holder's
 * assertion, like a manifest's `relationship` — so a new phone knows which
 * place to show the succession to. **It never goes to a helper:** a recovery
 * request carries the signed set alone.
 */
export interface RecoveryHelpersEntry {
  /** The place, as the wallet names it (an https origin, or the place's identifier), or null. */
  readonly counterparty: string | null;
  readonly helperSet: SignedHelperSet;
}

export type HeldRecordFailureReason =
  | "MALFORMED_ARTIFACT"
  | "MALFORMED_MANIFEST"
  | "RECORD_ID_MISMATCH"
  | "KEY_UNRESOLVED"
  | "SIGNATURE_INVALID"
  | "MANIFEST_TYPE_MISMATCH"
  | "MANIFEST_CLASS_MISMATCH"
  | "MANIFEST_ISSUER_MISMATCH"
  | "MANIFEST_STATUS_MISMATCH"
  | "RETENTION_EXTENDED"
  | "RETENTION_SOURCE_UNSUPPORTED"
  | "RECORD_PAST_RETENTION"
  | "LISTING_CLAIM_UNSUPPORTED"
  | "UNLISTED_WITHOUT_CHOICE";

export interface HeldRecordReport {
  readonly ok: boolean;
  readonly recordId: string;
  readonly kind: ArtifactKind | null;
  readonly tag: string | null;
  readonly registered: boolean;
  /** Computed from the bytes, never taken from the manifest. */
  readonly attestation: AttestationClass | null;
  readonly issuer: string | null;
  readonly signatureOk: boolean;
  readonly keySources: readonly { readonly keyid: string; readonly source: KeySource | "unresolved" }[];
  /** `pinned-list` is the only evidence that makes a record listed. */
  readonly listing: {
    readonly evidence: "pinned-list" | "unpinned-list" | "none";
    readonly listId: string | null;
    readonly version: number | null;
    readonly label: string | null;
  };
  /** True only when a pinned trust list lists this issuer for this tag. */
  readonly trusted: boolean;
  readonly status: StatusVerdict;
  readonly retention: {
    readonly expiresAtUnix: number | null;
    readonly source: RetentionSource | null;
    readonly pastNow: boolean;
  };
  readonly reasons: readonly HeldRecordFailureReason[];
  readonly notes: readonly string[];
}

export interface HeldRecordContext {
  readonly resolveKey: KeyResolver;
  readonly trustLists: readonly TrustListReport[];
  readonly statusLists: readonly StatusListReport[];
  readonly revocations: readonly unknown[];
  readonly nowSec: number;
  /** The export's own time, for the resurrection check. Null at handoff. */
  readonly exportedAtUnix: number | null;
}

/* ── helpers ───────────────────────────────────────────────────────────── */

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(".000Z", "Z");

export { contentIdOf, recordIdOf };

/** An expiry the issuer signed into the record — the ceiling on the wallet's retention. */
function signedExpiryOf(payload: unknown): number | null {
  if (!isPlainObject(payload)) return null;
  if (isInt(payload.expiresAtUnix)) return payload.expiresAtUnix;
  if (typeof payload.expiresAt === "string") {
    const ms = Date.parse(payload.expiresAt);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return null;
}

interface Analysis {
  tag: string | null;
  family: DstFamily | null;
  signer: string | null;
  signerCandidates: string[];
  signatureOk: boolean;
  keySources: { keyid: string; source: KeySource | "unresolved" }[];
  attestation: AttestationClass | null;
  signedPayload: unknown;
  recordExpiryUnix: number | null;
  presentedStatus: StatusVerdict | null;
  notes: string[];
  failure: HeldRecordFailureReason | null;
}

function emptyAnalysis(failure: HeldRecordFailureReason | null, note?: string): Analysis {
  return {
    tag: null,
    family: null,
    signer: null,
    signerCandidates: [],
    signatureOk: false,
    keySources: [],
    attestation: null,
    signedPayload: null,
    recordExpiryUnix: null,
    presentedStatus: null,
    notes: note ? [note] : [],
    failure,
  };
}

/* ── per kind, each delegating to the existing verifier unchanged ──────── */

async function analyseDsse(value: unknown, ctx: HeldRecordContext): Promise<Analysis> {
  if (!isPlainObject(value) || typeof value.payloadType !== "string" || !Array.isArray(value.signatures)) {
    return emptyAnalysis("MALFORMED_ARTIFACT", "not a DSSE envelope");
  }
  const env = value as unknown as DsseEnvelope;
  const keySources = env.signatures.map((s) => {
    const r = typeof s?.keyid === "string" ? ctx.resolveKey(s.keyid) : null;
    return { keyid: typeof s?.keyid === "string" ? s.keyid : "", source: r?.source ?? ("unresolved" as const) };
  });
  let verified: string[];
  let payload: unknown;
  try {
    // Each signer's algorithm comes from its resolved key's type.
    const res = await verifyEnvelope(env, (kid) => {
      const r = ctx.resolveKey(kid);
      return r === null ? null : keyOfResolved(r);
    });
    verified = [...new Set(res.verifiedKeyids)];
    payload = res.payloadJson;
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    return { ...emptyAnalysis("MALFORMED_ARTIFACT", "the envelope does not parse"), tag: env.payloadType };
  }
  // A record is JSON. Bytes that are not are malformed here, however well they are signed (AU-3, A7-04).
  if (payload === undefined) return { ...emptyAnalysis("MALFORMED_ARTIFACT", "the envelope's payload is not JSON"), tag: env.payloadType };
  const notes: string[] = [];
  // "Two signatures" means two keys — never one key under two spellings (AU-3, A7-02).
  const distinctKeys = new Set(
    verified.map((k) => {
      const r = ctx.resolveKey(k);
      return r === null ? k : keyIdentityOf(r);
    }),
  ).size;
  if (distinctKeys >= 2) {
    notes.push("two signatures but no countersign context — held as a countersign bundle, it would count as countersigned");
  }
  const deviceAsserted = DEVICE_ASSERTED_DSTS.includes(env.payloadType);
  if (deviceAsserted) notes.push("device-asserted: signed by the holder's own device or browser, never by a counterparty");
  const unresolved = keySources.every((k) => k.source === "unresolved");
  return {
    tag: env.payloadType,
    family: lookupDst(env.payloadType)?.family ?? "dsse-type",
    signer: verified[0] ?? env.signatures[0]?.keyid ?? null,
    signerCandidates: verified,
    signatureOk: verified.length > 0,
    keySources,
    attestation: deviceAsserted ? "device-asserted" : "issuer-signed",
    signedPayload: payload,
    recordExpiryUnix: signedExpiryOf(payload),
    presentedStatus: null,
    notes,
    failure: verified.length > 0 ? null : unresolved ? "KEY_UNRESOLVED" : "SIGNATURE_INVALID",
  };
}

async function analyseCountersign(value: unknown): Promise<Analysis> {
  const report = await verifyCountersignBundle(value as CountersignBundle);
  if (report.reason === "MALFORMED_BUNDLE") return emptyAnalysis("MALFORMED_ARTIFACT", report.notes[0]);
  // A withdrawal presented from before the signing is the countersign
  // mechanic's own revocation: the signatures still verify, and the status
  // says withdrawn. Nothing about the bundle's verifier changes.
  const withdrawn = report.reason === "WITHDRAWN_BEFORE_SIGNING";
  const signatureOk = report.ok || withdrawn;
  const notes: string[] = [...report.notes];
  if (report.withdrawalPresented && !report.withdrawnBeforeSigning && report.withdrawalSignatureOk) {
    notes.push("a withdrawal of the request was presented, dated after the signing — it does not withdraw this record");
  }
  let payload: unknown = null;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64ToBytes((value as CountersignBundle).subject.payload)));
  } catch {
    // A record is JSON: a subject that is not is malformed here, whatever the bundle's signatures say (AU-3, A7-04).
    return { ...emptyAnalysis("MALFORMED_ARTIFACT", "the subject's payload is not JSON"), tag: report.subjectPayloadType };
  }
  return {
    tag: report.subjectPayloadType,
    family: report.subjectPayloadType === null ? null : lookupDst(report.subjectPayloadType)?.family ?? "dsse-type",
    signer: report.requesterDid,
    signerCandidates: report.requesterDid === null ? [] : [report.requesterDid],
    signatureOk,
    keySources: report.subjectVerifiedKeyids.map((k) => ({ keyid: k, source: "self-certifying" as const })),
    attestation: signatureOk && report.twoSignatureProof ? "countersigned" : "issuer-signed",
    signedPayload: payload,
    recordExpiryUnix: signedExpiryOf(payload),
    presentedStatus: withdrawn
      ? {
          state: "withdrawn",
          asOfUnix: null,
          source: "presented",
          listId: null,
          text: "withdrawn — the requester's signed withdrawal predates the countersignature",
        }
      : null,
    notes,
    failure: signatureOk ? null : "SIGNATURE_INVALID",
  };
}

async function analyseKashEvent(value: unknown, ctx: HeldRecordContext): Promise<Analysis> {
  if (!isPlainObject(value) || !isPlainObject(value.header) || !isPlainObject(value.body) || !isPlainObject(value.signature)) {
    return emptyAnalysis("MALFORMED_ARTIFACT", "not a Kash-Event {header, body, signature}");
  }
  const event = value as unknown as SignedKashEvent;
  const tag = typeof event.signature.dst === "string" ? event.signature.dst : null;
  if (tag === null) return emptyAnalysis("MALFORMED_ARTIFACT", "the signature names no DST");
  const header = value.header as Record<string, unknown>;
  const rawSigner =
    typeof header.iss === "string" ? header.iss : typeof event.signature.kid === "string" ? event.signature.kid : null;
  const signer = rawSigner === null ? null : stripFragment(rawSigner);
  const key = signer === null ? null : ctx.resolveKey(signer);
  let ok = false;
  if (key !== null) {
    try {
      ok = await verifyEventForKey(event, keyOfResolved(key));
    } catch (err) {
      if (isAlgorithmUnsupported(err)) throw err;
      ok = false;
    }
  }
  const presented = tag === INDUS_MARK_DST ? await findMarkRevocation(event, ctx.revocations) : null;
  const revokedUnix = presented === null ? null : Math.floor(Date.parse(presented.revokedAt) / 1000);
  return {
    tag,
    family: lookupDst(tag)?.family ?? "kash-event",
    signer,
    signerCandidates: signer === null ? [] : [signer],
    signatureOk: ok,
    keySources: signer === null ? [] : [{ keyid: signer, source: key?.source ?? "unresolved" }],
    attestation: "issuer-signed",
    signedPayload: value.body,
    recordExpiryUnix: signedExpiryOf(value.body),
    presentedStatus:
      presented === null
        ? null
        : {
            state: "revoked",
            asOfUnix: Number.isFinite(revokedUnix) ? revokedUnix : null,
            source: "presented",
            listId: null,
            text: `revoked as of ${presented.revokedAt} (the issuer's signed revocation was presented)`,
          },
    notes: [],
    failure: ok ? null : key === null ? "KEY_UNRESOLVED" : "SIGNATURE_INVALID",
  };
}

async function analyseIndusToken(value: unknown, ctx: HeldRecordContext): Promise<Analysis> {
  if (typeof value !== "string") return emptyAnalysis("MALFORMED_ARTIFACT", "an Indus token is a string");
  let parsed: ReturnType<typeof parseIndusToken>;
  try {
    parsed = parseIndusToken(value);
  } catch (e) {
    return emptyAnalysis("MALFORMED_ARTIFACT", e instanceof Error ? e.message : "unparseable token");
  }
  const kid = typeof parsed.header.kid === "string" ? parsed.header.kid : null;
  const key = kid === null ? null : ctx.resolveKey(kid);
  const iat = isInt(parsed.body.iat) ? parsed.body.iat : null;
  const exp = isInt(parsed.body.exp) ? parsed.body.exp : null;
  let signatureOk = false;
  if (key !== null) {
    // Checked at the token's own issue time: a held token proves it was issued;
    // whether its scan window is still open is a different question, reported below.
    const r = await verifyIndusToken(value, key.publicKey, { nowSec: iat ?? ctx.nowSec });
    signatureOk = r.signatureOk && r.certIdOk !== false;
  }
  const notes: string[] = [];
  if (exp !== null) {
    notes.push(
      `token window ${iat !== null ? iso(iat) : "?"} → ${iso(exp)}` +
        (exp < ctx.nowSec ? " (closed — a held token proves it was issued, not that it is open)" : ""),
    );
  }
  const deviceAsserted = DEVICE_ASSERTED_DSTS.includes(parsed.dst);
  if (deviceAsserted) notes.push("device-asserted: signed by the holder's own device, never by a counterparty");
  return {
    tag: parsed.dst,
    family: "indus",
    signer: kid,
    signerCandidates: kid === null ? [] : [kid],
    signatureOk,
    keySources: kid === null ? [] : [{ keyid: kid, source: key?.source ?? "unresolved" }],
    attestation: deviceAsserted ? "device-asserted" : "issuer-signed",
    signedPayload: parsed.body,
    // An Indus token's `exp` is a scan window, not a retention the issuer set.
    recordExpiryUnix: null,
    presentedStatus: null,
    notes,
    failure: signatureOk ? null : key === null ? "KEY_UNRESOLVED" : "SIGNATURE_INVALID",
  };
}

async function analyseSdJwt(value: unknown, ctx: HeldRecordContext): Promise<Analysis> {
  if (typeof value !== "string") return emptyAnalysis("MALFORMED_ARTIFACT", "an SD-JWT is a string");
  // A held credential: no key binding. Its `exp` is judged below as the
  // retention the issuer signed, so it is not also judged here as a failure.
  const r = await verifySdJwt(value, { resolveKey: ctx.resolveKey, requireKeyBinding: false, nowSec: 0 });
  if (r.reason === "MALFORMED_SD_JWT") return emptyAnalysis("MALFORMED_ARTIFACT", "not an SD-JWT");
  const signer = r.issuer === null ? null : stripFragment(r.issuer);
  const exp = r.claims !== null && isInt(r.claims.exp) ? r.claims.exp : null;
  return {
    tag: r.vct,
    family: r.vct === null ? null : lookupDst(r.vct)?.family ?? "sd-jwt-vct",
    signer,
    signerCandidates: signer === null ? [] : [signer],
    signatureOk: r.ok,
    keySources: signer === null ? [] : [{ keyid: signer, source: r.issuerKeySource ?? "unresolved" }],
    attestation: "issuer-signed",
    signedPayload: r.claims,
    recordExpiryUnix: exp,
    presentedStatus: null,
    notes: [],
    failure: r.ok ? null : r.reason === "ISSUER_KEY_UNRESOLVED" ? "KEY_UNRESOLVED" : "SIGNATURE_INVALID",
  };
}

async function analyseSession(value: unknown, ctx: HeldRecordContext): Promise<Analysis> {
  const r = await verifySessionReceipt(value, { nowSec: ctx.nowSec });
  if (r.faults.some((f) => f.fault === "MALFORMED_RECEIPT")) return emptyAnalysis("MALFORMED_ARTIFACT", "not a session receipt");
  const parties = r.parties === null ? [] : [r.parties.establishment, r.parties.person];
  return {
    tag: SESSION_EVENT_DST,
    family: "dsse-type",
    signer: r.parties?.establishment ?? null,
    signerCandidates: parties,
    signatureOk: r.ok,
    keySources: parties.map((k) => ({ keyid: k, source: "self-certifying" as const })),
    // Complete is proof; a pending session is one side's claim.
    attestation: r.proof ? "countersigned" : "issuer-signed",
    signedPayload: null,
    recordExpiryUnix: r.expiresAtUnix,
    presentedStatus: null,
    notes: [...(r.state === "pending" ? ["a pending session — one signature is never proof"] : []), ...sessionAnchorNote(r)],
    failure: r.ok ? null : "SIGNATURE_INVALID",
  };
}

/** What the anchor proves, in one note: a place in a batch proved by its own path, or the limit of an anchor without one. */
function sessionAnchorNote(r: SessionReceiptReport): string[] {
  const a = r.anchor;
  if (a === null) return [];
  const inc = a.inclusion;
  if (inc === undefined) {
    return a.matches
      ? ["anchored without an inclusion proof this verifier reads — its place in a batch is not checked"]
      : ["its anchor's head does not match the line it names (ANCHOR_MISMATCH)"];
  }
  // `matches` is the anchor as a whole: its head, its path and its witness's root together.
  if (a.matches && inc.included && inc.witnessNamesRoot !== false) {
    const behind =
      a.backend === "none"
        ? "no public log witnessed that root"
        : inc.witnessNamesRoot === null
          ? `its ${a.backend} receipt names no root, so that a log witnessed it is not checked`
          : `its ${a.backend} receipt names that root; the log itself is not checked here`;
    return [`its anchor's own path leads from this record's head, as leaf index ${inc.leafIndex} in a batch of ${inc.treeSize}, to the root the anchor names — ${behind}`];
  }
  return ["its anchor does not prove its place in a batch (ANCHOR_MISMATCH)"];
}

/* ── one record ────────────────────────────────────────────────────────── */

function manifestIsWellFormed(m: unknown): m is HoldingManifest {
  if (!isPlainObject(m) || !isPlainObject(m.type)) return false;
  return (
    typeof m.recordId === "string" &&
    typeof m.issuer === "string" &&
    (m.relationship === null || typeof m.relationship === "string") &&
    typeof m.type.tag === "string" &&
    typeof m.type.family === "string" &&
    typeof m.type.attestation === "string" &&
    isInt(m.receivedAtUnix) &&
    (m.expiresAtUnix === null || isInt(m.expiresAtUnix)) &&
    (m.retentionSource === "record" || m.retentionSource === "issuer-declared" || m.retentionSource === "none-declared") &&
    (m.status === null || isPlainObject(m.status)) &&
    (m.listing === "listed" || m.listing === "unlisted") &&
    (m.keptUnlistedAtUnix === null || isInt(m.keptUnlistedAtUnix))
  );
}

/**
 * Verify one held record against its manifest. Used at handoff (before the
 * wallet stores a record) and for every record in an export. Offline.
 */
async function analyse(artifact: HeldArtifact | null, ctx: HeldRecordContext): Promise<Analysis> {
  const kind = artifact?.kind;
  if (artifact === null) return emptyAnalysis("MALFORMED_ARTIFACT", "no artifact");
  if (kind === "dsse") return analyseDsse(artifact.value, ctx);
  if (kind === "countersign-bundle") return analyseCountersign(artifact.value);
  if (kind === "kash-event") return analyseKashEvent(artifact.value, ctx);
  if (kind === "indus-token") return analyseIndusToken(artifact.value, ctx);
  if (kind === "sd-jwt") return analyseSdJwt(artifact.value, ctx);
  if (kind === "session-receipt") return analyseSession(artifact.value, ctx);
  return emptyAnalysis("MALFORMED_ARTIFACT", `unknown artifact kind ${JSON.stringify(kind)}`);
}

export async function verifyHeldRecord(record: HeldRecord, ctx: HeldRecordContext): Promise<HeldRecordReport> {
  const reasons: HeldRecordFailureReason[] = [];
  const artifact = isPlainObject(record) && isPlainObject(record.artifact) ? (record.artifact as unknown as HeldArtifact) : null;
  const kind = artifact?.kind;
  let a: Analysis;
  try {
    a = await analyse(artifact, ctx);
  } catch (err) {
    // One record anyone could have mangled never stops the rest of a wallet from being judged (AU-3, A7-04).
    if (isAlgorithmUnsupported(err)) throw err;
    a = emptyAnalysis("MALFORMED_ARTIFACT", `the artifact could not be read: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (a.failure !== null) reasons.push(a.failure);

  const computedId = artifact === null ? "" : await recordIdOf(artifact);
  const m = isPlainObject(record) ? record.manifest : null;
  const notes = [...a.notes];
  const signedEntry = statusEntryOf(a.signedPayload);

  // Listing: which issuer does a presented, current trust list vouch for?
  let match: ListingMatch | null = null;
  for (const s of a.signerCandidates) {
    const found = a.tag === null ? null : findListing(s, a.tag, ctx.trustLists, ctx.nowSec);
    if (found !== null && (match === null || (!match.pinned && found.pinned))) match = found;
  }
  const evidence = match === null ? "none" : match.pinned ? "pinned-list" : "unpinned-list";
  if (match !== null && !match.pinned) notes.push(`listed by ${match.publisher}, a publisher not pinned here — shown as unlisted`);

  let retentionSource: RetentionSource | null = null;
  let expiresAtUnix: number | null = null;
  if (!manifestIsWellFormed(m)) {
    reasons.push("MALFORMED_MANIFEST");
  } else {
    retentionSource = m.retentionSource;
    expiresAtUnix = m.expiresAtUnix;
    if (m.recordId !== computedId) reasons.push("RECORD_ID_MISMATCH");
    if (m.type.tag !== a.tag || m.type.family !== a.family) reasons.push("MANIFEST_TYPE_MISMATCH");
    // The class comes from the bytes. Editing the manifest cannot make an IGEO1
    // check-in countersigned, or anything else stronger than it is.
    if (a.attestation !== null && m.type.attestation !== a.attestation) reasons.push("MANIFEST_CLASS_MISMATCH");
    // The manifest's issuer must be a signer the bytes name (either party, for a session).
    const named = a.signerCandidates.length > 0 ? a.signerCandidates : a.signer === null ? [] : [a.signer];
    if (named.length > 0 && !named.map(stripFragment).includes(stripFragment(m.issuer))) reasons.push("MANIFEST_ISSUER_MISMATCH");
    if (canonicalize(m.status) !== canonicalize(signedEntry)) reasons.push("MANIFEST_STATUS_MISMATCH");

    if (a.recordExpiryUnix !== null) {
      if (m.expiresAtUnix === null || m.expiresAtUnix > a.recordExpiryUnix) reasons.push("RETENTION_EXTENDED");
    } else if (m.retentionSource === "record") {
      reasons.push("RETENTION_SOURCE_UNSUPPORTED");
    }
    if (m.retentionSource === "issuer-declared") notes.push("retention as the issuer declared it at handoff (recorded by the wallet)");
    if (m.retentionSource === "none-declared") notes.push("the issuer declared no retention — the holder decides when it goes");
    // An export made later never resurrects a record past its retention.
    if (ctx.exportedAtUnix !== null && m.expiresAtUnix !== null && m.expiresAtUnix <= ctx.exportedAtUnix) {
      reasons.push("RECORD_PAST_RETENTION");
    }

    if (m.listing === "listed" && evidence === "none") reasons.push("LISTING_CLAIM_UNSUPPORTED");
    if (m.listing === "unlisted" && a.attestation !== "device-asserted" && m.keptUnlistedAtUnix === null) {
      reasons.push("UNLISTED_WITHOUT_CHOICE");
    }
  }

  const pastNow = expiresAtUnix !== null && ctx.nowSec >= expiresAtUnix;
  if (pastNow && !reasons.includes("RECORD_PAST_RETENTION")) {
    notes.push("past its retention now — a wallet importing this file drops it");
  }
  if (a.tag !== null && !isRegisteredDst(a.tag)) {
    notes.push("its type is not in the DST registry — a stranger's verifier cannot know what it is reading");
  }

  return {
    ok: reasons.length === 0,
    recordId: computedId,
    kind:
      kind === "dsse" || kind === "countersign-bundle" || kind === "kash-event" || kind === "indus-token" || kind === "sd-jwt" || kind === "session-receipt"
        ? kind
        : null,
    tag: a.tag,
    registered: a.tag !== null && isRegisteredDst(a.tag),
    attestation: a.attestation,
    issuer: a.signer,
    signatureOk: a.signatureOk,
    keySources: a.keySources,
    listing: {
      evidence,
      listId: match?.listId ?? null,
      version: match?.version ?? null,
      label: match?.label ?? null,
    },
    trusted: evidence === "pinned-list",
    status: a.presentedStatus ?? checkStatus(signedEntry, ctx.statusLists),
    retention: { expiresAtUnix, source: retentionSource, pastNow },
    reasons,
    notes,
  };
}

/* ── the whole export ──────────────────────────────────────────────────── */

export type HolderExportFailureReason =
  | "MALFORMED_EXPORT"
  | "PLAINTEXT_PRIVATE_KEY"
  | "HELD_KEY_INVALID"
  | "TRUST_LIST_INVALID"
  | "STATUS_LIST_INVALID"
  | "KEY_CLAIM_INVALID"
  | "DUPLICATE_RECORD"
  | "MALFORMED_BACKUP"
  | "RECORD_INVALID"
  | "PRESENTATION_LOG_INVALID"
  /** v1.3: a recovery helper set does not verify. */
  | "HELPER_SET_INVALID"
  /** v1.3: two successors claimed for one key, or a claim resting on a superseded helper set. */
  | "KEY_SUCCESSION_CONFLICT"
  /** This runtime cannot run a key's algorithm (older browsers lack Ed25519). Nothing was judged. */
  | "RUNTIME_CANNOT_CHECK";

export interface HolderExportReport {
  readonly ok: boolean;
  readonly formatVersion: string;
  readonly exportedAtUnix: number | null;
  /** The file's bytes are exactly {@link serializeHolderExport} of its content. Null when no bytes were given. */
  readonly canonical: boolean | null;
  readonly records: readonly HeldRecordReport[];
  readonly trustLists: readonly TrustListReport[];
  readonly statusLists: readonly StatusListReport[];
  readonly keySuccession: readonly CountersignKeyClaimReport[];
  /** v1.3: the recovery helper sets, and any succession conflicts across the claims. */
  readonly recoveryHelpers: readonly HelperSetReport[];
  readonly successionConflicts: readonly SuccessionConflict[];
  readonly encryptedKeyBackup: "absent" | "present" | "malformed";
  /** What touched the network. `none` for every offline check. */
  readonly network: string;
  readonly reasons: readonly HolderExportFailureReason[];
  readonly notes: readonly string[];
}

export interface VerifyHolderExportOptions {
  /** Trust-list publishers pinned out of band. attest ships none. */
  readonly pinnedPublishers?: readonly string[] | undefined;
  readonly nowSec?: number | undefined;
  /** The file's exact text, to report byte-stability. */
  readonly rawText?: string | undefined;
  /** Status-list envelopes a caller fetched (the one networked path). */
  readonly fetchedStatusLists?: readonly DsseEnvelope[] | undefined;
  readonly inflate?: InflateFunction | undefined;
}

/** Field names that may only ever appear inside the encrypted backup. */
const PRIVATE_KEY_FIELDS = new Set(["privateKey", "privateKeyHex", "privateKeyB64", "privateSeed", "secretKey", "seed", "masterSeed"]);

function findPlaintextKey(value: unknown, path: string): string | null {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = findPlaintextKey(value[i], `${path}[${i}]`);
      if (hit !== null) return hit;
    }
    return null;
  }
  if (!isPlainObject(value)) return null;
  // A JWK with its private parameter.
  if (typeof value.kty === "string" && value.d !== undefined) return `${path}.d`;
  for (const [k, v] of Object.entries(value)) {
    if (path === "$" && k === "encryptedKeyBackup") continue;
    if (PRIVATE_KEY_FIELDS.has(k) && v !== null && v !== undefined) return `${path}.${k}`;
    const hit = findPlaintextKey(v, `${path}.${k}`);
    if (hit !== null) return hit;
  }
  return null;
}

const B64U = /^[A-Za-z0-9_-]*$/;
function backupShape(b: unknown): "absent" | "present" | "malformed" {
  if (b === null || b === undefined) return "absent";
  if (!isPlainObject(b)) return "malformed";
  for (const f of ["protected", "encrypted_key", "iv", "ciphertext", "tag"]) {
    if (typeof b[f] !== "string" || !B64U.test(b[f] as string)) return "malformed";
  }
  try {
    const hdr = JSON.parse(new TextDecoder().decode(base64UrlToBytes(b.protected as string)));
    if (!isPlainObject(hdr) || typeof hdr.alg !== "string" || typeof hdr.enc !== "string") return "malformed";
  } catch {
    return "malformed";
  }
  return "present";
}

/** Records sorted by id, then RFC 8785 canonical JSON: the byte-stable form. */
export function serializeHolderExport(e: HolderExport): string {
  const records = [...e.records].sort((x, y) => (x.manifest.recordId < y.manifest.recordId ? -1 : x.manifest.recordId > y.manifest.recordId ? 1 : 0));
  return canonicalize({ ...e, records });
}

export function isHolderExport(value: unknown): value is HolderExport {
  return isPlainObject(value) && value.formatVersion === HOLDER_EXPORT_FORMAT;
}

/**
 * Verify a holder export end to end, **offline**. Every key comes from a
 * self-certifying identifier, a trust list in the file, or a public key the
 * holder kept; every status comes from a list carried in the file or passed in
 * by a caller that fetched it. Structurally junk input returns a report.
 */
export async function verifyHolderExport(value: unknown, opts: VerifyHolderExportOptions = {}): Promise<HolderExportReport> {
  try {
    return await verifyHolderExportInner(value, opts);
  } catch (err) {
    if (!isAlgorithmUnsupported(err)) throw err;
    return {
      ok: false,
      formatVersion: HOLDER_EXPORT_FORMAT,
      exportedAtUnix: null,
      canonical: null,
      records: [],
      trustLists: [],
      statusLists: [],
      keySuccession: [],
      recoveryHelpers: [],
      successionConflicts: [],
      encryptedKeyBackup: "absent",
      network: "none",
      reasons: ["RUNTIME_CANNOT_CHECK"],
      notes: ["this runtime cannot run a signature algorithm this export needs (Ed25519 arrived late in some browsers) — nothing was judged; check it in Node 22+ or a current browser"],
    };
  }
}

async function verifyHolderExportInner(value: unknown, opts: VerifyHolderExportOptions): Promise<HolderExportReport> {
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const reasons: HolderExportFailureReason[] = [];
  const notes: string[] = [];
  const base = {
    formatVersion: HOLDER_EXPORT_FORMAT,
    exportedAtUnix: null,
    canonical: null,
    records: [],
    trustLists: [],
    statusLists: [],
    keySuccession: [],
    recoveryHelpers: [],
    successionConflicts: [],
    encryptedKeyBackup: "absent" as const,
    network: "none",
  };
  if (
    !isHolderExport(value) ||
    !isInt(value.exportedAtUnix) ||
    !Array.isArray(value.records) ||
    !Array.isArray(value.keySuccession) ||
    !Array.isArray(value.trustLists) ||
    !Array.isArray(value.statusLists) ||
    !Array.isArray(value.revocations) ||
    !Array.isArray(value.heldKeys) ||
    value.encryptedKeyBackup === undefined
  ) {
    return { ...base, ok: false, reasons: ["MALFORMED_EXPORT"], notes: ["not a kashscript-holder-export/1 file"] };
  }

  const leak = findPlaintextKey(value, "$");
  if (leak !== null) {
    reasons.push("PLAINTEXT_PRIVATE_KEY");
    notes.push(`private key material outside the encrypted backup, at ${leak}`);
  }

  const trustReports: TrustListReport[] = [];
  for (const t of value.trustLists) trustReports.push(await verifyTrustList(t, { pinnedPublishers: opts.pinnedPublishers ?? [], nowSec }));
  if (trustReports.some((r) => !r.ok)) reasons.push("TRUST_LIST_INVALID");

  const held = new Map<string, KashPublicKey>();
  for (const k of value.heldKeys) {
    const key = isPlainObject(k) && typeof k.keyid === "string" ? typedKeyOf(k as unknown as PublicKeyEntry) : null;
    if (key === null) {
      reasons.push("HELD_KEY_INVALID");
      continue;
    }
    held.set(k.keyid, key);
  }
  const resolveKey = makeKeyResolver(trustListKeyMap(trustReports), held);

  const statusReports: StatusListReport[] = [];
  for (const s of value.statusLists) statusReports.push(await verifyStatusList(s, { resolveKey, nowSec, source: "carried", inflate: opts.inflate }));
  for (const s of opts.fetchedStatusLists ?? []) statusReports.push(await verifyStatusList(s, { resolveKey, nowSec, source: "fetched", inflate: opts.inflate }));
  if (statusReports.some((r) => !r.ok)) reasons.push("STATUS_LIST_INVALID");

  // v1.3: recovery helper sets, and the succession across every claim together.
  const entries: readonly unknown[] = Array.isArray(value.recoveryHelpers) ? value.recoveryHelpers : [];
  if (value.recoveryHelpers !== undefined && !Array.isArray(value.recoveryHelpers)) reasons.push("HELPER_SET_INVALID");
  const helperSets: SignedHelperSet[] = [];
  const helperReports: HelperSetReport[] = [];
  for (const e of entries) {
    const ok = isPlainObject(e) && (e.counterparty === null || typeof e.counterparty === "string") && isPlainObject(e.helperSet);
    const report = await verifyHelperSet(ok ? e.helperSet : e);
    helperReports.push(ok ? report : { ...report, ok: false, reason: report.reason ?? "MALFORMED_HELPER_SET" });
    if (ok) helperSets.push(e.helperSet as SignedHelperSet);
  }
  if (helperReports.some((r) => r.reason === "RUNTIME_CANNOT_CHECK")) reasons.push("RUNTIME_CANNOT_CHECK");
  else if (helperReports.some((r) => !r.ok)) reasons.push("HELPER_SET_INVALID");
  const succession = await verifySuccessionSet(value.keySuccession, helperSets);
  const claimReports: CountersignKeyClaimReport[] = [...succession.claims];
  if (claimReports.some((r) => r.reason === "RUNTIME_CANNOT_CHECK")) reasons.push("RUNTIME_CANNOT_CHECK");
  else if (claimReports.some((r) => !r.ok)) reasons.push("KEY_CLAIM_INVALID");
  if (succession.conflicts.length > 0 || succession.superseded.length > 0) {
    reasons.push("KEY_SUCCESSION_CONFLICT");
    notes.push(...succession.notes.slice(0, -1));
  }

  const ctx: HeldRecordContext = {
    resolveKey,
    trustLists: trustReports,
    statusLists: statusReports,
    revocations: value.revocations,
    nowSec,
    exportedAtUnix: value.exportedAtUnix,
  };
  const recordReports: HeldRecordReport[] = [];
  for (const r of value.records) recordReports.push(await verifyHeldRecord(r, ctx));
  if (recordReports.some((r) => !r.ok)) reasons.push("RECORD_INVALID");
  if (value.presentationLog !== undefined && !validatePresentationLog(value.presentationLog).ok) {
    reasons.push("PRESENTATION_LOG_INVALID");
  }
  const ids = recordReports.map((r) => r.recordId);
  if (new Set(ids).size !== ids.length) reasons.push("DUPLICATE_RECORD");

  const backup = backupShape(value.encryptedKeyBackup);
  if (backup === "malformed") reasons.push("MALFORMED_BACKUP");
  if (backup === "present") notes.push("an encrypted key backup is present — made because the holder asked; never inspected here");

  let canonical: boolean | null = null;
  if (opts.rawText !== undefined) {
    try {
      canonical = opts.rawText === serializeHolderExport(value);
    } catch {
      canonical = false;
    }
    if (!canonical) notes.push("the bytes are not the canonical form — a conforming writer emits sorted RFC 8785 JSON");
  }

  const fetched = statusReports.filter((s) => s.source === "fetched").length;
  const network = fetched === 0 ? "none" : `${fetched} status list(s) fetched from their issuers — the one networked check`;
  if (trustReports.length > 0 && !trustReports.some((t) => t.pinned)) {
    notes.push("no trust-list publisher is pinned — every record shows as unlisted (pin one with --trust-publisher)");
  }

  return {
    ok: reasons.length === 0,
    formatVersion: HOLDER_EXPORT_FORMAT,
    exportedAtUnix: value.exportedAtUnix,
    canonical,
    records: recordReports,
    trustLists: trustReports,
    statusLists: statusReports,
    keySuccession: claimReports,
    recoveryHelpers: helperReports,
    successionConflicts: succession.conflicts,
    encryptedKeyBackup: backup,
    network,
    reasons,
    notes,
  };
}
