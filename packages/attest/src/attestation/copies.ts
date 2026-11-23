/**
 * The copies of the records already in use, and what opens their reference (RW-15;
 * `specs/attestation/README.md` §2.4a–§2.4b).
 *
 * RW-14's `copyClaimsOf` copies the attestation record of truth. The records the engines already sign — a
 * countersigned work record (Client Sign-off, `booking.delivered/1`, a chain consent), read through the
 * algebra's §1.9 mapping as *receipt · accepted* — had no copy form: they travelled raw, and a raw record
 * joins by its own bytes wherever it is shown. `copyClaimsOfCountersigned` gives them the same copy, under
 * the same `vct`: what every holder of the kind shares is visible, and **the artefact reference** — the
 * SHA-256 of the subject's payload bytes, the very digest the acceptance bound — is selectively disclosable,
 * so each copy commits to it under its own fresh salt and two copies share nothing to join on (§3 G1).
 *
 * `openRecordCommitment` is the arithmetic a checker runs: which disclosures the issuer's `_sd` commits to,
 * and whether the opened `record` names an artefact. `shownOnPage` is the page's rule — **the artefact is
 * shown only to the holder of the disclosure** — over a copy and the artefacts a page holds; the seal that
 * keeps the artefact from anyone else is `./page`.
 *
 * Pure and offline. Never the counterparty, its key or its custody.
 */

import { sha256Hex } from "../chain";
import { isCountersignBundle, verifyCountersignBundle, type CountersignBundle, type CountersignVerifyReport } from "../countersign";
import type { DsseEnvelope } from "../dsse";
import { base64ToBytes } from "../ed25519";
import { AttestError } from "../errors";
import { makeKeyResolver, type KeyResolver } from "../holder/keys";
import { jwkOf } from "../sd-jwt/jws";
import { decodeDisclosure, verifySdJwt } from "../sd-jwt/sd-jwt";
import { canonicalSignerOf, type VerifyKey } from "../signing";
import { statementProblem } from "./faults";
import { ATTESTATION_DST, ATTESTATION_VCT, COPY_LIFETIME_DAYS, COPY_SD_SLOTS, payloadSha256, verifyAttestationRecord, viewOfCopy, type AttestationView, type CopyClaims } from "./forms";
import { PROFILE_PATTERN, type Reference } from "./lexicon";

const DAY = 86_400;
const HEX64 = /^[0-9a-f]{64}$/;
const dayOf = (unix: number): number => unix - (unix % DAY);
const isoOf = (unix: number): string => new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const isPlainObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const nameOf = (keyid: string): string => canonicalSignerOf(keyid) ?? keyid.split("#")[0]!;

/* ── 1. a countersigned record, read through the algebra ───────────── */

export interface CountersignedReading {
  readonly report: CountersignVerifyReport;
  /** The subject's payload, when it is JSON. */
  readonly payload: Record<string, unknown> | null;
  /** SHA-256 hex of the subject's payload bytes — the artefact reference the acceptance bound (`subjectDigestSha256`). Null when the payload is not base64. */
  readonly record: string | null;
  /**
   * Who may issue a copy — the parties to the record, never the counterparty: a verified subject signer that is
   * not an independent countersigner, and the requester whose signature on the request checks (an organisation
   * may ask for an acceptance on its doer's record). Canonical `did:kash`.
   */
  readonly eligibleIssuers: readonly string[];
  /** The independent countersigners whose acceptances verify — the other side. Canonical. */
  readonly countersigners: readonly string[];
  /** The earliest verifying independent acceptance's own claim of when it signed. */
  readonly acceptedAtUnix: number | null;
}

/** attest's verdict on a bundle, with what the copy and the page read out of it. Never throws. */
export async function readCountersigned(bundle: CountersignBundle): Promise<CountersignedReading> {
  const report = await verifyCountersignBundle(bundle);
  let payload: Record<string, unknown> | null = null;
  let record: string | null = null;
  try {
    const bytes = base64ToBytes(bundle.subject.payload);
    record = await sha256Hex(bytes);
    const json: unknown = JSON.parse(new TextDecoder().decode(bytes));
    payload = isPlainObject(json) ? json : null;
  } catch {
    // not base64, or not JSON — the report says what it judged
  }
  const made = report.acceptances.filter((a) => a.ok && a.independent && a.countersignerDid !== "");
  const countersigners = [...new Set(made.map((a) => a.countersignerDid))];
  const eligible = new Set(report.subjectVerifiedKeyids.filter((k) => !countersigners.includes(k)));
  if (report.requestSignatureOk && report.requesterDid !== null && !countersigners.includes(report.requesterDid)) eligible.add(report.requesterDid);
  return {
    report,
    payload,
    record,
    eligibleIssuers: [...eligible],
    countersigners,
    acceptedAtUnix: made.length === 0 ? null : Math.min(...made.map((a) => a.signedAtUnix)),
  };
}

/* ── 2. the copy ───────────────────────────────────────────────────── */

export interface CountersignedCopyInput {
  /** The issuer, whose key signs the copy and whose DID is `iss`: a party to the record (`eligibleIssuers`), never the counterparty. */
  readonly issuer: string;
  /** The holder's key for this verifier alone (d62(d)3) — the copy's `cnf`. Absent on a page copy, which carries no key and so can never be presented: it is only ever shown (§2.4b). */
  readonly holderKey?: VerifyKey;
  readonly iatUnix: number;
  /** Default {@link COPY_LIFETIME_DAYS}. */
  readonly lifetimeDays?: number;
  /** The job, as `name/version` (`client-signoff/1`). Default: the payload's `meta.profile`, when it is one. */
  readonly profile?: string;
  /** The counterparty's ceremony grade, as the issuer's flow ran it (d91(d)). The kernel bundle carries the key's custody, not a grade — the issuer states it. */
  readonly grade?: 0 | 1 | 2 | 3;
  /** Default: the payload's own `practice` or `meta.practice`. */
  readonly practice?: boolean;
}

function expiryOf(payload: Record<string, unknown> | null): number | null {
  if (payload === null) return null;
  if (typeof payload.expiresAtUnix === "number" && Number.isInteger(payload.expiresAtUnix)) return payload.expiresAtUnix;
  if (typeof payload.exp === "number" && Number.isInteger(payload.exp)) return payload.exp;
  if (typeof payload.expiresAt === "string") {
    const ms = Date.parse(payload.expiresAt);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return null;
}

/** The words a copy may carry about the work: the record's own summary, else the request's statement — plain, at most 280 characters, free of a link, an identifier and a contact (§2.2). */
function statementOf(payload: Record<string, unknown> | null, bundle: CountersignBundle): string | null {
  const action = payload !== null && isPlainObject(payload.action) ? payload.action : null;
  const request = isPlainObject(bundle.request) && isPlainObject(bundle.request.body) ? bundle.request.body : null;
  for (const words of [action?.summary, request?.statement]) {
    if (typeof words === "string" && words.length >= 1 && words.length <= 280 && statementProblem(words) === null) return words;
  }
  return null;
}

/**
 * The claims of one copy of a countersigned record that checks, for attest's `issueSdJwt` — the same shape
 * `copyClaimsOf` gives an attestation record of truth, under the same `vct` (§2.4a).
 *
 * **Only from a record that checks:** the bundle's two-signature proof, or no copy — so a one-signature claim
 * can never be copied as accepted. A stopped record gets no copy (d43 §4.6: a halt is never shown for or
 * against anyone), and a record that ends before the copy's lifetime would gets none (RW-14's rule).
 *
 * **Visible** (the class): the issuer, the copy's own day and lifetime, the vct, the holder's key when there is
 * one, and `attestation: {kind: "receipt", outcome: "accepted", profile?, grade?, practice?}`.
 * **Selectively disclosable, each under its own fresh salt:** `record` — the SHA-256 of the subject's payload
 * bytes, the digest the acceptance bound — `reference` when the record names a SHA-256 agreement, the record's
 * own words, and the exact time of acceptance. `_sd` is padded to {@link COPY_SD_SLOTS}. Never the
 * counterparty, its key or its custody.
 */
export async function copyClaimsOfCountersigned(bundle: CountersignBundle, copy: CountersignedCopyInput): Promise<CopyClaims> {
  if (!isCountersignBundle(bundle)) throw new AttestError("INVALID_INPUT", "a copy of a countersigned record is made from a kashscript-countersign/1 bundle");
  const r = await readCountersigned(bundle);
  if (!r.report.ok || !r.report.twoSignatureProof || r.record === null) {
    throw new AttestError("INVALID_INPUT", `a copy is made only from a record that checks: ${r.report.reason ?? "no two-signature proof"}`);
  }
  const issuer = nameOf(copy.issuer);
  if (!r.eligibleIssuers.includes(issuer)) {
    throw new AttestError("INVALID_INPUT", "a copy is issued by the record's issuer — a party who signed it or asked for its acceptance, never the counterparty (d41; §2.4a)");
  }
  const payload = r.payload;
  if (payload !== null && payload.status === "stopped") throw new AttestError("INVALID_INPUT", "a stopped record gets no copy — a halt is never shown for or against anyone (d43 §4.6)");
  const iat = dayOf(copy.iatUnix);
  const exp = iat + (copy.lifetimeDays ?? COPY_LIFETIME_DAYS) * DAY;
  if (!(exp > iat)) throw new AttestError("INVALID_INPUT", "a copy lives at least a day");
  const ends = expiryOf(payload);
  if (ends !== null && ends < exp) throw new AttestError("INVALID_INPUT", "the record ends before a copy's lifetime would: a shorter copy would carry the record's end, so none is made");
  const meta = payload !== null && isPlainObject(payload.meta) ? payload.meta : null;
  const profile = copy.profile ?? (typeof meta?.profile === "string" ? meta.profile : undefined);
  if (profile !== undefined && !PROFILE_PATTERN.test(profile)) throw new AttestError("INVALID_INPUT", `a profile is a job as name/version, not ${JSON.stringify(profile)}`);
  const practice = copy.practice === true || payload?.practice === true || meta?.practice === true;
  if (copy.grade === 0 && !practice) throw new AttestError("INVALID_INPUT", "grade 0 — a one-time key — is practice only, never a customer's record (d91(d)); say practice");

  const head: Record<string, unknown> = { kind: "receipt", outcome: "accepted" };
  if (profile !== undefined) head.profile = profile;
  if (copy.grade !== undefined) head.grade = copy.grade;
  if (practice) head.practice = true;
  const claims: Record<string, unknown> = { iss: issuer, iat, exp, vct: ATTESTATION_VCT };
  if (copy.holderKey !== undefined) claims.cnf = { jwk: jwkOf(copy.holderKey) };
  claims.attestation = head;

  const sd: Record<string, unknown> = {};
  const ref = meta?.reference;
  if (typeof ref === "string" && HEX64.test(ref)) sd.reference = { kind: "agreement", sha256: ref } satisfies Reference;
  const statement = statementOf(payload, bundle);
  if (statement !== null) sd.statement = statement;
  if (r.acceptedAtUnix !== null) sd.claimedAt = isoOf(r.acceptedAtUnix);
  sd.record = r.record;
  return { claims, sdProperties: sd, decoys: COPY_SD_SLOTS - Object.keys(sd).length };
}

/* ── 3. the commitment, and what opens it ──────────────────────────── */

/** The hash a copy's `record` names: a countersign bundle's subject payload, or a DSSE envelope's payload. Null for anything else. */
export async function recordHashOf(artefact: unknown): Promise<string | null> {
  try {
    if (isCountersignBundle(artefact)) return await sha256Hex(base64ToBytes(artefact.subject.payload));
    if (isPlainObject(artefact) && typeof artefact.payloadType === "string" && typeof artefact.payload === "string" && Array.isArray(artefact.signatures)) {
      return await payloadSha256(artefact as unknown as DsseEnvelope);
    }
  } catch {
    // not base64: no payload bytes to name
  }
  return null;
}

export interface CommitmentInput {
  /** The copy's `_sd` — the digests the issuer signed. */
  readonly sd: readonly string[];
  /** The disclosures the holder presents, as the SD-JWT carries them (base64url). */
  readonly disclosures: readonly string[];
  /** The artefact's hash ({@link recordHashOf}), when one is offered. */
  readonly artefactSha256?: string;
}

export interface CommitmentOpening {
  /** The disclosures whose digests the issuer signed, by claim name. */
  readonly committed: readonly string[];
  /** Disclosures no signed digest names: not this copy's. */
  readonly uncommitted: readonly string[];
  /** The record hash a committed `record` disclosure opens to. */
  readonly record: string | null;
  /** With an artefact: whether the opened record names it. Null when no record was opened or no artefact was given. */
  readonly opens: boolean | null;
}

/**
 * The salted commitment, opened: a disclosure's digest — `b64u(SHA-256(ASCII(disclosure)))`, the SD-JWT rule —
 * is in the copy's `_sd`, or it is not this copy's; a committed `record` opens to its hash; and the hash names
 * an artefact or does not. Pure hashing, the reference for `specs/attestation/tck/attestation-copy@1`.
 */
export async function openRecordCommitment(input: CommitmentInput): Promise<CommitmentOpening> {
  const committed: string[] = [];
  const uncommitted: string[] = [];
  let record: string | null = null;
  for (const d of input.disclosures) {
    const decoded = await decodeDisclosure(d);
    const label = decoded === null ? "(unreadable)" : (decoded.name ?? "(array element)");
    if (decoded === null || !input.sd.includes(decoded.digest)) {
      uncommitted.push(label);
      continue;
    }
    committed.push(label);
    if (decoded.name === "record" && typeof decoded.value === "string" && HEX64.test(decoded.value)) record = decoded.value;
  }
  const opens = record === null || input.artefactSha256 === undefined ? null : record === input.artefactSha256;
  return { committed, uncommitted, record, opens };
}

/* ── 4. the page's rule ────────────────────────────────────────────── */

export interface PageOptions {
  readonly resolveKey?: KeyResolver;
  readonly nowSec?: number;
}

export interface PageView {
  /** The copy verifies as held and is an attestation copy. */
  readonly ok: boolean;
  readonly reason: string | null;
  readonly view: AttestationView | null;
  /** The one artefact the disclosed record names, when it checks. */
  readonly shown: { readonly index: number; readonly artefact: unknown } | null;
  /** One sentence: shown, or why not. */
  readonly why: string;
}

export const NOT_DISCLOSED = "the record was not disclosed — a page shows the artefact only to the holder of the disclosure" as const;

async function artefactProblem(artefact: unknown, issuer: string): Promise<string | null> {
  if (isCountersignBundle(artefact)) {
    const r = await readCountersigned(artefact);
    if (!r.report.ok || !r.report.twoSignatureProof) return `the disclosed record names an artefact that does not check (${r.report.reason ?? "no two-signature proof"})`;
    if (!r.eligibleIssuers.includes(nameOf(issuer))) return "the disclosed record names an artefact whose issuer is not the copy's";
    return null;
  }
  if (isPlainObject(artefact) && artefact.payloadType === ATTESTATION_DST) {
    const rc = await verifyAttestationRecord(artefact as unknown as DsseEnvelope);
    if (!rc.ok || rc.body === null) return `the disclosed record names an artefact that does not check (${rc.problems.map((p) => p.code).join(", ")})`;
    if (nameOf(rc.body.issuer) !== nameOf(issuer)) return "the disclosed record names an artefact whose issuer is not the copy's";
    return null;
  }
  return "the disclosed record names bytes that are not a countersigned record or an attestation record of truth — one signature is a request, not a record (d41)";
}

/**
 * What a page shows of a copy: its class to anyone, and the artefact only to the holder of the disclosure. The
 * copy is checked as held (its issuer's signature, every disclosure against a signed digest); with no `record`
 * disclosed nothing is shown; with one, the one artefact whose hash it names, whose issuer side is the copy's
 * issuer, and which itself checks — a countersigned record's two-signature proof, or an attestation record of
 * truth. Offline; every miss is said in `why`.
 */
export async function shownOnPage(copy: string, artefacts: readonly unknown[], opts: PageOptions = {}): Promise<PageView> {
  const resolveKey = opts.resolveKey ?? makeKeyResolver(new Map(), new Map());
  const sd = await verifySdJwt(copy, { resolveKey, requireKeyBinding: false, ...(opts.nowSec !== undefined ? { nowSec: opts.nowSec } : {}) });
  if (!sd.ok || sd.claims === null) return { ok: false, reason: sd.reason ?? "MALFORMED_SD_JWT", view: null, shown: null, why: `the copy does not check (${sd.reason ?? "malformed"})` };
  if (sd.vct !== ATTESTATION_VCT) return { ok: false, reason: "NOT_AN_ATTESTATION_COPY", view: null, shown: null, why: `not an attestation copy (${sd.vct ?? "no vct"})` };
  const view = viewOfCopy(sd.claims);
  if (view.record === undefined) return { ok: true, reason: null, view, shown: null, why: NOT_DISCLOSED };
  let why = "the disclosed record names no artefact here";
  for (const [index, artefact] of artefacts.entries()) {
    if ((await recordHashOf(artefact)) !== view.record) continue;
    const problem = await artefactProblem(artefact, view.issuer);
    if (problem === null) return { ok: true, reason: null, view, shown: { index, artefact }, why: "shown — the disclosed record names this artefact, and it checks" };
    why = problem;
  }
  return { ok: true, reason: null, view, shown: null, why };
}
