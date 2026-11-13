/**
 * Receipts, read once: every held artifact or presentation becomes one view —
 * its format, type, issuer, attestation class, the payload its issuer signed,
 * its expiry and its status — so the DCQL matcher and the conditions read one
 * shape whatever the receipt was.
 *
 * attest does every check (`verifySdJwt`, `verifyHeldRecord`); nothing here
 * verifies a signature by itself. A receipt counts only if it verifies offline,
 * is unexpired at the evaluation time (d27.5), is not revoked or suspended on a
 * list the caller carries, and is not a stopped work record (d43 §4.6).
 */

import { sha256Hex } from "@kashscript/attest/chain";
import { isCountersignBundle, verifyCountersignBundle, type CountersignBundle } from "@kashscript/attest/countersign";
import { isAlgorithmUnsupported } from "@kashscript/identity-core";
import {
  checkStatus,
  contentIdOf,
  decodeEnvelopePayload,
  makeKeyResolver,
  recordIdOf,
  statusEntryOf,
  verifyHeldRecord,
  type ArtifactKind,
  type AttestationClass,
  type HoldingManifest,
  type KeyResolver,
  type StatusListReport,
  type StatusState,
  type TrustListReport,
} from "@kashscript/attest/holder";
import { parseSdJwt, verifySdJwt, type SdJwtReport } from "@kashscript/attest/sd-jwt";
import { KASH_ARTIFACT_FORMAT, SD_JWT_FORMAT } from "./constants";

export interface ReadContext {
  /** Issuer keys: self-certifying DIDs resolve without one; trust lists add listed keys. */
  readonly resolveKey?: KeyResolver;
  readonly trustLists?: readonly TrustListReport[];
  readonly statusLists?: readonly StatusListReport[];
  /** The evaluation time, unix seconds. Nothing here reads a clock. */
  readonly nowSec: number;
}

/** A receipt as the holder keeps it, or as a packet carries it. `ref` is the caller's own handle — never sent. */
export interface HeldReceipt {
  readonly ref: string;
  readonly value: unknown;
}

export interface ReceiptView {
  readonly ref: string;
  /** SHA-256 hex a decision relies on: an SD-JWT's issuer-signed JWT, or an artifact's record id. Never the content. */
  readonly id: string;
  /**
   * The identity a count is made by (AU-3, A7-03): what the issuer signed, never the
   * wrapping — attest's `contentIdOf`. A record re-wrapped with an extra field or a junk
   * signature entry, or shown once bare and once countersigned, has one `contentId` and
   * counts once. For an SD-JWT it is the `id`.
   */
  readonly contentId: string;
  readonly format: typeof SD_JWT_FORMAT | typeof KASH_ARTIFACT_FORMAT;
  readonly kind: ArtifactKind;
  /** The `vct`, or the artifact's registered tag. */
  readonly type: string | null;
  readonly issuer: string | null;
  readonly attestation: AttestationClass | null;
  /** The payload its issuer signed. For an SD-JWT: its visible claims plus what is disclosed. */
  readonly claims: unknown;
  /** An SD-JWT's holder key (`cnf`), as a DID. Never set for an artifact: its holder is the query's to name (`artifactHolderOf`). */
  readonly holder: string | null;
  /**
   * A countersign bundle's countersigners, as attest verified them (KS-Q11): the
   * canonical DID of every acceptance whose own report is `ok` and `independent` —
   * its signature, its binding to this request and these bytes, its window, that
   * key's signature on the subject, no earlier withdrawal, and a key that is not
   * the requester's under any spelling (AU-3, A7-02) — distinct. Empty for every
   * other kind. Nothing unsigned is read.
   */
  readonly countersigners: readonly string[];
  readonly expiresAtUnix: number | null;
  readonly status: StatusState;
  /** Checks offline, unexpired, not revoked or suspended, not a stopped record. */
  readonly counts: boolean;
  readonly problems: readonly string[];
  /** attest's SD-JWT report, when it is one (the packet check reads its key binding). */
  readonly sdJwt: SdJwtReport | null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const enc = new TextEncoder();

export function artifactKindOf(value: unknown): ArtifactKind | null {
  if (!isPlainObject(value)) return null;
  if (isCountersignBundle(value)) return "countersign-bundle";
  if (typeof value.payloadType === "string" && typeof value.payload === "string" && Array.isArray(value.signatures)) return "dsse";
  if (isPlainObject(value.header) && isPlainObject(value.body) && isPlainObject(value.signature)) return "kash-event";
  return null;
}

/** The payload an artifact's issuer signed, as attest reads each kind. */
export function signedPayloadOf(kind: ArtifactKind, value: unknown): unknown {
  try {
    switch (kind) {
      case "dsse":
        return decodeEnvelopePayload(value);
      case "countersign-bundle":
        return isPlainObject(value) ? decodeEnvelopePayload(value.subject) : null;
      case "kash-event":
        return isPlainObject(value) ? value.body : null;
      default:
        return null;
    }
  } catch {
    return null;
  }
}

function expiryOf(payload: unknown): number | null {
  if (!isPlainObject(payload)) return null;
  if (typeof payload.exp === "number" && Number.isInteger(payload.exp)) return payload.exp;
  if (typeof payload.expiresAtUnix === "number" && Number.isInteger(payload.expiresAtUnix)) return payload.expiresAtUnix;
  if (typeof payload.expiresAt === "string") {
    const ms = Date.parse(payload.expiresAt);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return null;
}

/** d43 §4.6: a halt is protected — a stopped record never enters the evidence. */
function isStopped(payload: unknown): boolean {
  return isPlainObject(payload) && payload.status === "stopped";
}

const HARD = new Set(["MALFORMED_ARTIFACT", "KEY_UNRESOLVED", "SIGNATURE_INVALID"]);

function judge(status: StatusState, expiresAtUnix: number | null, nowSec: number, payload: unknown, problems: string[]): boolean {
  let counts = problems.length === 0;
  if (expiresAtUnix !== null && expiresAtUnix <= nowSec) {
    problems.push("expired — an expired record never counts");
    counts = false;
  }
  if (status === "revoked" || status === "suspended") {
    problems.push(`${status} on its issuer's status list`);
    counts = false;
  }
  if (isStopped(payload)) {
    problems.push("a stopped record — a halt never counts for or against anyone");
    counts = false;
  }
  return counts;
}

export interface ReadOptions {
  /** Read it as a presentation to this verifier: the KB-JWT must bind this audience and nonce. */
  readonly presentedTo?: { readonly audience: string; readonly nonce: string };
  /** With `presentedTo`: a KB-JWT whose `iat` is further than this from `nowSec` is stale (AU-3, A7-08). */
  readonly maxKbAgeSec?: number;
}

/**
 * Read one receipt. Junk returns a view that does not count, or null for what is
 * not a receipt at all — never a throw (AU-3, A7-04). The one exception is
 * identity-core's `ALG_UNAVAILABLE`: a runtime that cannot run a key's algorithm
 * judged nothing, and says so upward.
 */
export async function readReceipt(h: HeldReceipt, ctx: ReadContext, opts: ReadOptions = {}): Promise<ReceiptView | null> {
  try {
    return await readReceiptInner(h, ctx, opts);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    return null;
  }
}

async function readReceiptInner(h: HeldReceipt, ctx: ReadContext, opts: ReadOptions): Promise<ReceiptView | null> {
  const resolveKey = ctx.resolveKey ?? makeKeyResolver(new Map(), new Map());
  const statusLists = ctx.statusLists ?? [];
  if (typeof h.value === "string") {
    const parsed = parseSdJwt(h.value);
    if (parsed === null) return null;
    const pres = opts.presentedTo;
    const sd = await verifySdJwt(h.value, {
      resolveKey,
      requireKeyBinding: pres !== undefined,
      nowSec: ctx.nowSec,
      ...(pres !== undefined ? { audience: pres.audience, nonce: pres.nonce } : {}),
      ...(pres !== undefined && opts.maxKbAgeSec !== undefined ? { maxKbAgeSec: opts.maxKbAgeSec } : {}),
    });
    const claims = sd.claims;
    const problems: string[] = [];
    if (!sd.ok && sd.reason !== "CREDENTIAL_EXPIRED") problems.push(`does not check (${sd.reason})`);
    const status = checkStatus(statusEntryOf(claims), statusLists).state;
    const expiresAtUnix = expiryOf(claims);
    const counts = judge(status, expiresAtUnix, ctx.nowSec, claims, problems);
    const id = await sha256Hex(enc.encode(parsed.issuerJwt));
    return {
      ref: h.ref,
      id,
      contentId: id,
      format: SD_JWT_FORMAT,
      kind: "sd-jwt",
      type: sd.vct,
      issuer: sd.issuer,
      attestation: "issuer-signed",
      claims,
      holder: sd.holder,
      countersigners: [],
      expiresAtUnix,
      status,
      counts,
      problems,
      sdJwt: sd,
    };
  }
  const kind = artifactKindOf(h.value);
  if (kind === null) return null;
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
  const report = await verifyHeldRecord(
    { manifest: probe, artifact: { kind, value: h.value } },
    { resolveKey, trustLists: ctx.trustLists ?? [], statusLists, revocations: [], nowSec: ctx.nowSec, exportedAtUnix: null },
  );
  const payload = signedPayloadOf(kind, h.value);
  const problems: string[] = [];
  const hard = report.reasons.filter((r) => HARD.has(r));
  if (hard.length > 0 || !report.signatureOk) problems.push(`does not check (${hard.join(", ") || "SIGNATURE_INVALID"})`);
  const expiresAtUnix = expiryOf(payload) ?? report.retention.expiresAtUnix;
  const counts = judge(report.status.state, expiresAtUnix, ctx.nowSec, payload, problems);
  return {
    ref: h.ref,
    id: await recordIdOf({ kind, value: h.value }),
    contentId: await contentIdOf({ kind, value: h.value }),
    format: KASH_ARTIFACT_FORMAT,
    kind,
    type: report.tag,
    issuer: report.issuer,
    attestation: report.attestation,
    claims: payload,
    holder: null,
    countersigners: kind === "countersign-bundle" ? await verifiedCountersigners(h.value) : [],
    expiresAtUnix,
    status: report.status.state,
    counts,
    problems,
    sdJwt: null,
  };
}

/** The countersigners attest verified — `ok` and `independent`, in canonical form — `ReceiptView.countersigners`. */
async function verifiedCountersigners(value: unknown): Promise<string[]> {
  const report = await verifyCountersignBundle(value as CountersignBundle);
  const out = new Set<string>();
  for (const a of report.acceptances) {
    if (a.ok && a.independent && a.countersignerDid !== "") out.add(a.countersignerDid);
  }
  return [...out];
}

export async function readReceipts(held: readonly HeldReceipt[], ctx: ReadContext): Promise<ReceiptView[]> {
  const out: ReceiptView[] = [];
  for (const h of held) {
    const v = await readReceipt(h, ctx);
    if (v !== null) out.push(v);
  }
  return out;
}
