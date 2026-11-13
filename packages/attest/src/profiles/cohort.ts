/**
 * The cohort profile — station zero's record of a finished cohort
 * (`specs/cohort-profile.md`; ECOSYSTEM d43, d54(g), d59, d62(d)1–3, d63(b)–(c)).
 *
 * ── A profile, not a tag ────────────────────────────────────────────────────
 * The record is an ordinary Oreoasis work record — payloadType
 * `application/vnd.oreoasis.work-record+json`, claim `oreoasis.work-record/1` —
 * with its open slots pinned and `meta` given four named fields. d59(e):
 * reusing a registered type through a profile is preferred over adding a tag,
 * and a work record already names a doer, a rule at a version and a status.
 *
 * ── Who signs ───────────────────────────────────────────────────────────────
 * Two organisations, each as itself (d62(d)2), and nobody else:
 *
 *   • the teacher's organisation REQUESTS the countersignatures and accepts its
 *     own request. A wallet names a held bundle's issuer from the request's
 *     signer (`../holder/export`), so this is the key a trust list lists;
 *   • the station accepts, with the DID its charter names — so a published rule
 *     can later recognise "countersigned by a chartered station" (d53, d62(c)5).
 *
 * The subject starts unsigned and ends with exactly their two signatures, each
 * beside an acceptance that states its time and its key's custody.
 *
 * **The holder signs no part of it.** The record NAMES the holder's key — the
 * relationship key their wallet made for this issuer alone (d41, d47(g)) — and
 * the holder signs the key proofs that bind it at enrolment and redeem the
 * record at the end. A wallet receives only through OpenID4VCI and has no path
 * to sign a subject for an issuer; a holder-signed subject would also make a
 * wallet name the learner's own key as the record's issuer.
 *
 * ── What it never carries ───────────────────────────────────────────────────
 * No grade, score, rank or skill level (d43, d51: nothing scores a person); no
 * payer or sponsor (d55(e): sponsored seats are Duedale's); no capstone, which
 * is its own Accepted record, so a client's decline leaves no trace (d49); no
 * `prev`, which would chain one learner's record to the next one's; and no
 * record at all for a cohort that was not finished. The shape is closed, so
 * anything it does not name is refused.
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import {
  isCountersignBundle,
  verifyCountersignBundle,
  type CountersignBundle,
  type CountersignVerifyReport,
} from "../countersign";
import type { DsseEnvelope } from "../dsse";
import { base64ToBytes, bytesToBase64 } from "../ed25519";
import { AttestError } from "../errors";
import { isUlid, ulid } from "../ids";
import { resolveDidKey } from "../signing";

/* ── The type it rides on, and the profile ─────────────────────────────── */

/** The work record's payloadType, registered in `../dst`. Oreoasis owns the claim. */
export const DST_WORK_RECORD = "application/vnd.oreoasis.work-record+json" as const;

/** The claim's own spec string, exactly as Oreoasis's SDK writes it. */
export const WORK_RECORD_SPEC = "oreoasis.work-record/1" as const;

/** The profile, named in the claim's `meta.profile`. */
export const COHORT_PROFILE = "kashscript-cohort/1" as const;

/** Pinned, so the record carries no free text a grade could hide in. */
export const COHORT_ACTION = {
  type: "cohort.complete",
  summary: "Finished a cohort under the syllabus and version named in this record.",
} as const;

/* ── The claim ─────────────────────────────────────────────────────────── */

/** The published syllabus — the rule the cohort followed — by version (d43: every predicate names its rule version). */
export interface CohortSyllabus {
  /** Where it is published. Opaque here; the spec recommends the teacher's organisation's DID plus a path. */
  readonly id: string;
  readonly version: string;
  /** SHA-256, lowercase hex, of the syllabus document's exact published bytes. */
  readonly hash: string;
}

/** A work-record claim in the cohort profile — the DSSE payload. */
export interface CohortClaim {
  readonly spec: typeof WORK_RECORD_SPEC;
  readonly receiptId: string;
  /** The issuer's own label for itself (Oreoasis writes its slug). Never checked against anything. */
  readonly org?: string;
  /** Who learned: the holder, named only by the relationship key their wallet made for this issuer. */
  readonly actor: { readonly class: "person"; readonly id: string };
  readonly shape: "followed";
  readonly rule: CohortSyllabus;
  readonly action: typeof COHORT_ACTION;
  readonly inputs: readonly [];
  readonly outputs: readonly [];
  readonly status: "completed";
  /** When the cohort finished. ISO-8601, UTC. */
  readonly timestamp: string;
  readonly meta: {
    readonly profile: typeof COHORT_PROFILE;
    /** The teacher's organisation: an organisation's own DID, never a person's. */
    readonly teacherOrg: string;
    /** The station, with the DID its charter names. */
    readonly station: string;
    /** After it the record no longer attests (d27). ISO-8601, UTC. */
    readonly expiresAt: string;
  };
}

/** What `buildCohortClaim` needs. There is no status: a record exists only for a cohort that was finished. */
export interface CohortClaimInput {
  /** The DID the binding gave — the `kid` of the holder's key proof at enrolment. */
  readonly holderDid: string;
  readonly teacherOrgDid: string;
  readonly stationDid: string;
  readonly syllabus: CohortSyllabus;
  /** ISO-8601, UTC. */
  readonly finishedAt: string;
  /** ISO-8601, UTC, after `finishedAt`. */
  readonly expiresAt: string;
  readonly org?: string;
  readonly receiptId?: string;
}

/* ── Violations ────────────────────────────────────────────────────────── */

export type CohortViolationCode =
  /** Not a work record in this profile at all. */
  | "NOT_A_COHORT_RECORD"
  | "WRONG_SPEC"
  | "MISSING_FIELD"
  /** The shape is closed: a key it does not name. */
  | "UNKNOWN_FIELD"
  /** A grade, score or rank (d43, d51), or a payer or sponsor (d55(e)), wherever it sits. */
  | "FORBIDDEN_FIELD"
  | "BAD_VALUE"
  /** Any status but `completed`. An unfinished cohort yields no record, and there is no "failed" one. */
  | "NOT_FINISHED"
  /** The signed bytes are not RFC 8785 JCS, so two parsers could read two different records. */
  | "NOT_CANONICAL"
  /** The request was not signed by the teacher's organisation, so a wallet would name someone else as the issuer. */
  | "WRONG_ISSUER"
  | "MISSING_COUNTERSIGNATURE"
  /** A signature or acceptance from anyone but the two organisations, or a second one from either. */
  | "UNEXPECTED_SIGNER"
  /** An organisation signed with a key someone else minted for it. */
  | "DELEGATED_KEY"
  | "COUNTERSIGNED_BEFORE_FINISH"
  /** The record names another key than the holder the caller expected. */
  | "NOT_THIS_HOLDER";

export interface CohortViolation {
  readonly code: CohortViolationCode;
  /** A JSON path into the claim (`$…`), or a place in the bundle (`request…`, `acceptances[i]`, `subject…`). */
  readonly path: string;
  readonly message: string;
}

export interface CohortClaimCheck {
  readonly ok: boolean;
  /** The claim, typed — only when it follows the profile. */
  readonly claim: CohortClaim | null;
  readonly violations: readonly CohortViolation[];
}

/* ── The words a cohort record never uses for a field ──────────────────── */

/** d43, d51: nothing scores a person, ranks people or measures how hard they worked. */
const JUDGEMENT_WORDS: ReadonlySet<string> = new Set([
  "grade", "grades", "graded", "grading", "score", "scores", "scored", "scoring",
  "rank", "ranks", "ranked", "ranking", "rankings", "rating", "ratings", "rated",
  "mark", "marks", "marking", "percentile", "percentage", "percent", "gpa", "cgpa",
  "points", "level", "levels", "result", "results", "merit", "distinction", "honours", "honors",
  "pass", "passed", "fail", "failed", "failure", "attendance", "performance", "standing",
]);

/** d55(e): who paid for a seat is Duedale's to prove, never this record's to say. */
const PAYER_WORDS: ReadonlySet<string> = new Set([
  "sponsor", "sponsors", "sponsored", "sponsorship", "payer", "paid", "payment", "fee", "fees",
  "price", "amount", "cost", "scholarship", "funder", "funded", "invoice", "discount", "waiver",
]);

const FORBIDDEN_MESSAGE = {
  judgement: "a cohort record carries no grade, score or rank — it says the cohort was finished, never how well (d43, d51)",
  payer: "a cohort record never names who paid for a seat — sponsored seats are Duedale's (d55(e))",
} as const;

/** A key's words, whatever its casing — so `finalGrade`, `GPAScore` and `score_out_of_100` are caught and `passport` is not. */
function wordsOf(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 0);
}

function forbiddenKind(key: string): keyof typeof FORBIDDEN_MESSAGE | null {
  const words = wordsOf(key);
  if (words.some((w) => JUDGEMENT_WORDS.has(w))) return "judgement";
  if (words.some((w) => PAYER_WORDS.has(w))) return "payer";
  return null;
}

/* ── Small checks ──────────────────────────────────────────────────────── */

type Add = (code: CohortViolationCode, path: string, message: string) => void;

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Unix seconds for an ISO-8601 UTC string, or null. A date that rolls over (30 February) is refused. */
function isoUnix(v: unknown): number | null {
  if (typeof v !== "string" || !ISO_UTC.test(v)) return null;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== v.slice(0, 19)) return null;
  return Math.floor(ms / 1000);
}

function boundedText(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= max && v.trim() === v && !CONTROL.test(v);
}

/** A bare, self-certifying `did:kash` — no fragment, so it compares exactly with a countersigner's DID. */
function isBareDidKash(v: unknown): v is string {
  return typeof v === "string" && v.startsWith("did:kash:") && !v.includes("#") && resolveDidKey(v) !== null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Every key, at any depth, against the two forbidden families. Flagged paths are not reported again as unknown. */
function scanForbidden(value: unknown, path: string, add: Add, flagged: Set<string>): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => scanForbidden(v, `${path}[${i}]`, add, flagged));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [k, v] of Object.entries(value)) {
    const p = `${path}.${k}`;
    const kind = forbiddenKind(k);
    if (kind !== null) {
      add("FORBIDDEN_FIELD", p, FORBIDDEN_MESSAGE[kind]);
      flagged.add(p);
      continue;
    }
    scanForbidden(v, p, add, flagged);
  }
}

/** The shape is closed: any key not named here is refused. */
function closed(obj: Record<string, unknown>, path: string, allowed: readonly string[], add: Add, flagged: ReadonlySet<string>): void {
  for (const k of Object.keys(obj)) {
    const p = `${path}.${k}`;
    if (allowed.includes(k) || flagged.has(p)) continue;
    const message =
      k === "prev"
        ? "a cohort record never points at another record — `prev` would chain one learner's record to the next one's"
        : k === "authority"
          ? "a cohort record is not a licence, certification or delegation"
          : "not part of the cohort profile, whose shape is closed";
    add("UNKNOWN_FIELD", p, message);
  }
}

const TOP_KEYS = ["spec", "receiptId", "org", "actor", "shape", "rule", "action", "inputs", "outputs", "status", "timestamp", "meta"] as const;

/* ── Validating a claim ────────────────────────────────────────────────── */

/**
 * Check a decoded payload against the profile. Pure and offline: it judges the
 * claim's shape only. Who signed it is `verifyCohortRecord`'s question.
 *
 * A payload that does not name the profile in `meta.profile` is reported as
 * `NOT_A_COHORT_RECORD` and nothing else — it may be a perfectly good work
 * record of another kind.
 */
export function validateCohortClaim(value: unknown): CohortClaimCheck {
  const violations: CohortViolation[] = [];
  const add: Add = (code, path, message) => {
    violations.push({ code, path, message });
  };
  const done = (): CohortClaimCheck => {
    const ok = violations.length === 0;
    return { ok, claim: ok ? (value as CohortClaim) : null, violations };
  };

  if (!isPlainObject(value)) {
    add("NOT_A_COHORT_RECORD", "$", "the payload is not a JSON object");
    return done();
  }
  const meta = value.meta;
  if (!isPlainObject(meta) || meta.profile !== COHORT_PROFILE) {
    add("NOT_A_COHORT_RECORD", "$.meta.profile", `not in the cohort profile: meta.profile is not "${COHORT_PROFILE}"`);
    return done();
  }

  const flagged = new Set<string>();
  scanForbidden(value, "$", add, flagged);
  closed(value, "$", TOP_KEYS, add, flagged);

  if (value.spec === undefined) add("MISSING_FIELD", "$.spec", `must be "${WORK_RECORD_SPEC}"`);
  else if (value.spec !== WORK_RECORD_SPEC) add("WRONG_SPEC", "$.spec", `must be "${WORK_RECORD_SPEC}"`);

  if (value.receiptId === undefined) add("MISSING_FIELD", "$.receiptId", "a ULID");
  else if (typeof value.receiptId !== "string" || !isUlid(value.receiptId)) add("BAD_VALUE", "$.receiptId", "must be a ULID");

  if (value.org !== undefined && !boundedText(value.org, 200)) {
    add("BAD_VALUE", "$.org", "the issuer's own label: 1–200 characters, no control characters");
  }

  // Who learned — the holder, by the key the binding gave and nothing else.
  const actor = value.actor;
  if (actor === undefined) add("MISSING_FIELD", "$.actor", "who learned: { class: \"person\", id: <the holder's relationship key> }");
  else if (!isPlainObject(actor)) add("BAD_VALUE", "$.actor", "must be an object");
  else {
    closed(actor, "$.actor", ["class", "id"], add, flagged);
    if (actor.class !== "person") add(actor.class === undefined ? "MISSING_FIELD" : "BAD_VALUE", "$.actor.class", "the learner is a person: \"person\"");
    if (actor.id === undefined) add("MISSING_FIELD", "$.actor.id", "the holder's relationship key, a did:kash");
    else if (!isBareDidKash(actor.id)) {
      add("BAD_VALUE", "$.actor.id", "must be the holder's relationship key — a bare did:kash, never a name or an issuer's own id for the person");
    }
  }

  if (value.shape === undefined) add("MISSING_FIELD", "$.shape", "\"followed\"");
  else if (value.shape !== "followed") add("BAD_VALUE", "$.shape", "\"followed\" — the learner followed the syllabus in force");

  // What process — the published syllabus, by version.
  const rule = value.rule;
  if (rule === undefined) add("MISSING_FIELD", "$.rule", "the syllabus: { id, version, hash }");
  else if (!isPlainObject(rule)) add("BAD_VALUE", "$.rule", "must be an object");
  else {
    closed(rule, "$.rule", ["id", "version", "hash"], add, flagged);
    if (rule.id === undefined) add("MISSING_FIELD", "$.rule.id", "where the syllabus is published");
    else if (!boundedText(rule.id, 200)) add("BAD_VALUE", "$.rule.id", "1–200 characters, no control characters");
    if (rule.version === undefined) add("MISSING_FIELD", "$.rule.version", "every predicate names its rule version (d43)");
    else if (!boundedText(rule.version, 64)) add("BAD_VALUE", "$.rule.version", "1–64 characters, no control characters");
    if (rule.hash === undefined) add("MISSING_FIELD", "$.rule.hash", "the SHA-256 of the published syllabus");
    else if (typeof rule.hash !== "string" || !HEX64.test(rule.hash)) add("BAD_VALUE", "$.rule.hash", "64 lowercase hex characters: the SHA-256 of the published syllabus");
  }

  const action = value.action;
  if (action === undefined) add("MISSING_FIELD", "$.action", "the pinned cohort action");
  else if (!isPlainObject(action)) add("BAD_VALUE", "$.action", "must be an object");
  else {
    closed(action, "$.action", ["type", "summary"], add, flagged);
    if (action.type !== COHORT_ACTION.type) add("BAD_VALUE", "$.action.type", `pinned: "${COHORT_ACTION.type}"`);
    if (action.summary !== COHORT_ACTION.summary) add("BAD_VALUE", "$.action.summary", "pinned — the record carries no free text");
  }

  for (const k of ["inputs", "outputs"] as const) {
    const v = value[k];
    if (v === undefined) add("MISSING_FIELD", `$.${k}`, "[]");
    else if (!Array.isArray(v) || v.length > 0) {
      add("BAD_VALUE", `$.${k}`, "must be empty — work products, the capstone among them, are their own records");
    }
  }

  if (value.status === undefined) add("MISSING_FIELD", "$.status", "\"completed\"");
  else if (value.status !== "completed") {
    add("NOT_FINISHED", "$.status", "only a finished cohort yields a record — there is no failed or stopped one, and a learner's stop is protected (d43)");
  }

  const finished = isoUnix(value.timestamp);
  if (value.timestamp === undefined) add("MISSING_FIELD", "$.timestamp", "when the cohort finished, ISO-8601 in UTC");
  else if (finished === null) add("BAD_VALUE", "$.timestamp", "ISO-8601 in UTC, for example 2026-12-18T00:00:00.000Z");

  // Who countersigns, and until when.
  closed(meta, "$.meta", ["profile", "teacherOrg", "station", "expiresAt"], add, flagged);
  for (const [k, who] of [["teacherOrg", "the teacher's organisation"], ["station", "the station"]] as const) {
    if (meta[k] === undefined) add("MISSING_FIELD", `$.meta.${k}`, `${who}'s own DID`);
    else if (!isBareDidKash(meta[k])) add("BAD_VALUE", `$.meta.${k}`, `${who}'s own DID — a bare did:kash, never a per-ceremony key (d62(d)2)`);
  }
  const expires = isoUnix(meta.expiresAt);
  if (meta.expiresAt === undefined) add("MISSING_FIELD", "$.meta.expiresAt", "records expire (d27): ISO-8601 in UTC");
  else if (expires === null) add("BAD_VALUE", "$.meta.expiresAt", "ISO-8601 in UTC");
  else if (finished !== null && expires <= finished) add("BAD_VALUE", "$.meta.expiresAt", "the expiry must come after the finish");

  // Three parties, three keys.
  const holder = isPlainObject(actor) && isBareDidKash(actor.id) ? actor.id : null;
  const teacher = isBareDidKash(meta.teacherOrg) ? meta.teacherOrg : null;
  const station = isBareDidKash(meta.station) ? meta.station : null;
  if (teacher !== null && teacher === station) {
    add("BAD_VALUE", "$.meta.station", "the station and the teacher's organisation must be two organisations — one cannot countersign itself (d26)");
  }
  if (holder !== null && (holder === teacher || holder === station)) {
    add("BAD_VALUE", "$.actor.id", "the holder's key cannot be an organisation's");
  }

  return done();
}

/* ── Building one ──────────────────────────────────────────────────────── */

/**
 * Build a claim in the profile, with every pinned field filled in. Throws
 * `INVALID_INPUT` naming each violation, so an issuer cannot build a record the
 * profile would refuse.
 */
export function buildCohortClaim(input: CohortClaimInput): CohortClaim {
  if (!isPlainObject(input) || !isPlainObject(input.syllabus)) {
    throw new AttestError("INVALID_INPUT", "buildCohortClaim needs the holder, both organisations, the syllabus, the finish and the expiry");
  }
  const claim = {
    spec: WORK_RECORD_SPEC,
    receiptId: input.receiptId ?? ulid(),
    ...(input.org !== undefined ? { org: input.org } : {}),
    actor: { class: "person", id: input.holderDid },
    shape: "followed",
    rule: { id: input.syllabus.id, version: input.syllabus.version, hash: input.syllabus.hash },
    action: { type: COHORT_ACTION.type, summary: COHORT_ACTION.summary },
    inputs: [],
    outputs: [],
    status: "completed",
    timestamp: input.finishedAt,
    meta: { profile: COHORT_PROFILE, teacherOrg: input.teacherOrgDid, station: input.stationDid, expiresAt: input.expiresAt },
  };
  const check = validateCohortClaim(claim);
  if (check.claim === null) {
    throw new AttestError("INVALID_INPUT", `not a cohort record: ${check.violations.map((v) => `${v.path} ${v.code}`).join("; ")}`);
  }
  return check.claim;
}

/**
 * The subject the teacher's organisation asks both organisations to
 * countersign: a DSSE envelope over the claim's RFC 8785 bytes, with no
 * signature yet. identity-server's ceremony appends each countersignature over
 * these exact bytes, so the finished envelope carries the two organisations'
 * signatures and nobody else's.
 */
export function cohortSubject(claim: CohortClaim): DsseEnvelope {
  const check = validateCohortClaim(claim);
  if (check.claim === null) {
    throw new AttestError("INVALID_INPUT", `not a cohort record: ${check.violations.map((v) => `${v.path} ${v.code}`).join("; ")}`);
  }
  return { payloadType: DST_WORK_RECORD, payload: bytesToBase64(canonicalizeBytes(check.claim)), signatures: [] };
}

/* ── Verifying the held record ─────────────────────────────────────────── */

function decodeSubject(subject: unknown): { readonly bytes: Uint8Array; readonly json: unknown } | null {
  if (!isPlainObject(subject) || typeof subject.payload !== "string") return null;
  try {
    const bytes = base64ToBytes(subject.payload);
    return { bytes, json: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown };
  } catch {
    return null;
  }
}

/**
 * Structural guard: a countersign bundle whose subject is a work record naming
 * this profile. The CLI uses it to route; it says nothing about validity.
 */
export function isCohortRecord(value: unknown): value is CountersignBundle {
  if (!isCountersignBundle(value) || !isPlainObject(value.subject) || value.subject.payloadType !== DST_WORK_RECORD) return false;
  const decoded = decodeSubject(value.subject);
  return decoded !== null && isPlainObject(decoded.json) && isPlainObject(decoded.json.meta) && decoded.json.meta.profile === COHORT_PROFILE;
}

export interface CohortRecordReport {
  /** The bundle verifies, its claim follows the profile, and exactly the two organisations it names countersigned. */
  readonly ok: boolean;
  /** The countersign verifier's own report, unchanged. */
  readonly countersign: CountersignVerifyReport;
  /** The claim, typed — only when it follows the profile. */
  readonly claim: CohortClaim | null;
  /** What the file says, read even when it breaks the profile — for display, never for trust. */
  readonly holderDid: string | null;
  readonly teacherOrgDid: string | null;
  readonly stationDid: string | null;
  readonly syllabus: { readonly id: string | null; readonly version: string | null; readonly hash: string | null } | null;
  readonly finishedAt: string | null;
  readonly expiresAtUnix: number | null;
  /** Past `meta.expiresAt`: the record no longer attests (d27). Integrity is reported apart, so `ok` can stand. */
  readonly expired: boolean;
  readonly violations: readonly CohortViolation[];
  /** Plain-language facts a reader must not have to infer. Always non-empty. */
  readonly notes: readonly string[];
}

export interface VerifyCohortRecordOptions {
  readonly nowSec?: number;
  /**
   * The holder the caller expects — the issuer before it releases the record to
   * a key proof, or a wallet checking the record names its own relationship key.
   */
  readonly holderDid?: string;
}

/**
 * Verify a held cohort record end to end, offline: everything
 * `verifyCountersignBundle` checks, then the profile, then who signed against
 * who the record says signs. No network, no registry, no key material passed
 * in. Structurally junk input returns a report rather than throwing.
 */
export async function verifyCohortRecord(bundle: unknown, opts: VerifyCohortRecordOptions = {}): Promise<CohortRecordReport> {
  const countersign = await verifyCountersignBundle(bundle as CountersignBundle);
  const violations: CohortViolation[] = [];
  const add: Add = (code, path, message) => {
    violations.push({ code, path, message });
  };

  const subject = isCountersignBundle(bundle) && isPlainObject(bundle.subject) ? bundle.subject : null;
  const decoded = subject === null || subject.payloadType !== DST_WORK_RECORD ? null : decodeSubject(subject);
  let claim: CohortClaim | null = null;
  let read: Record<string, unknown> = {};

  if (decoded === null) {
    add("NOT_A_COHORT_RECORD", "subject", "not a countersigned work record");
  } else {
    let canonical = false;
    try {
      canonical = bytesEqual(canonicalizeBytes(decoded.json), decoded.bytes);
    } catch {
      canonical = false;
    }
    if (!canonical) add("NOT_CANONICAL", "subject.payload", "the signed bytes are not RFC 8785 JCS — two parsers could read two different records");
    const check = validateCohortClaim(decoded.json);
    violations.push(...check.violations);
    claim = check.claim;
    if (isPlainObject(decoded.json)) read = decoded.json;
  }

  // Who signed, judged only against a claim that follows the profile.
  if (claim !== null) {
    const { teacherOrg, station } = claim.meta;
    const finished = isoUnix(claim.timestamp);
    if (countersign.requesterDid !== teacherOrg) {
      add("WRONG_ISSUER", "request.body.requesterDid", "the teacher's organisation asks for the countersignatures — a wallet names the request's signer as the record's issuer");
    }
    for (const [path, did, who] of [["$.meta.teacherOrg", teacherOrg, "the teacher's organisation"], ["$.meta.station", station, "the station"]] as const) {
      const mine = countersign.acceptances.filter((a) => a.countersignerDid === did);
      if (mine.length === 0) {
        add("MISSING_COUNTERSIGNATURE", path, `${who} has not countersigned`);
        continue;
      }
      if (mine.length > 1) add("UNEXPECTED_SIGNER", path, `${who} countersigned more than once`);
      for (const a of mine) {
        if (!a.subjectHeldKey) add("DELEGATED_KEY", path, `${who} signed with a key someone else minted — an organisation signs with its own (d62(d)2)`);
        if (finished !== null && a.signedAtUnix < finished) add("COUNTERSIGNED_BEFORE_FINISH", path, `${who} countersigned before the cohort finished`);
      }
    }
    const parties = new Set<string>([teacherOrg, station]);
    countersign.acceptances.forEach((a, i) => {
      if (!parties.has(a.countersignerDid)) add("UNEXPECTED_SIGNER", `acceptances[${i}]`, "only the teacher's organisation and the station countersign a cohort record");
    });
    for (const k of countersign.subjectVerifiedKeyids) {
      if (!parties.has(k)) add("UNEXPECTED_SIGNER", "subject.signatures", `${k} signed the record — only the two organisations sign it, and the holder is named, not a signer`);
    }
    if (opts.holderDid !== undefined && claim.actor.id !== opts.holderDid) {
      add("NOT_THIS_HOLDER", "$.actor.id", "the record names another key than this holder's");
    }
  }

  // The request's disclosures travel with the record for as long as it is held.
  const request = isCountersignBundle(bundle) && isPlainObject(bundle.request) ? bundle.request : null;
  const disclosures = request !== null && isPlainObject(request.body) && Array.isArray(request.body.disclosures) ? request.body.disclosures : [];
  disclosures.forEach((d: unknown, i: number) => {
    const kind = isPlainObject(d) && typeof d.label === "string" ? forbiddenKind(d.label) : null;
    if (kind !== null) add("FORBIDDEN_FIELD", `request.body.disclosures[${i}].label`, FORBIDDEN_MESSAGE[kind]);
  });

  const meta = isPlainObject(read.meta) ? read.meta : {};
  const actor = isPlainObject(read.actor) ? read.actor : {};
  const rule = isPlainObject(read.rule) ? read.rule : null;
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  const expiresAtUnix = isoUnix(meta.expiresAt);
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const expired = expiresAtUnix !== null && nowSec > expiresAtUnix;

  const notes = [
    "it says the cohort was finished under this syllabus version — not how well: it carries no grade, score or rank, and proves no skill level",
    "the holder is named by a key their wallet made for this issuer alone; every verifier shown this record sees that key and these bytes, so two verifiers can tell it is one person — nothing here protects against that yet",
    "that these keys are this teacher's organisation and this station is for a charter, or a trust list you pinned, to say — not this file",
  ];
  if (expired) notes.push("past its expiry — it no longer attests, and a wallet deletes it");

  return {
    ok: countersign.ok && violations.length === 0,
    countersign,
    claim,
    holderDid: str(actor.id),
    teacherOrgDid: str(meta.teacherOrg),
    stationDid: str(meta.station),
    syllabus: rule === null ? null : { id: str(rule.id), version: str(rule.version), hash: str(rule.hash) },
    finishedAt: str(read.timestamp),
    expiresAtUnix,
    expired,
    violations,
    notes,
  };
}
