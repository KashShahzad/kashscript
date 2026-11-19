/**
 * One record, three forms (RW-14; `specs/attestation/README.md` §2.3–§2.5):
 *
 *   1. **the record of truth** — a DSSE envelope, payloadType `application/vnd.kash.attestation+json`,
 *      payload the body in RFC 8785 canonical form. It is made when the counterparty answers: the
 *      counterparty signs, then the issuer (or a delegate under a cited mandate) signs the same bytes. Held by
 *      its parties. `verifyAttestationRecord` is the stranger's check of it. Citations name the SHA-256 of its
 *      payload bytes.
 *   2. **the presentation** — an SD-JWT VC, `vct https://kashscript.com/vct/attestation/1`, issued by the
 *      issuer's own key from a record of truth that checks, one copy per verifier. What every holder of the
 *      kind shares is visible; what could join two copies is selectively disclosable, so each copy commits to
 *      it under its own fresh salt. A copy is the issuer's word.
 *   3. **the W3C VC 2.0 projection** — a deterministic, unsecured credential for software that speaks VC 2.0,
 *      made from whatever form the viewer was given. It proves nothing by itself.
 *
 * Pure and offline: nothing here fetches. Issuing copies at scale, serving proof pages and checking a chain
 * of mandates are the engine's (RW-15, RW-24).
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import { toJsonSchema, type JsonSchema } from "@kashscript/lexicons/json-schema";
import { S, type ObjectSchema } from "@kashscript/lexicons/schema";
import { hexToBytes, sha256Hex } from "../chain";
import { base64ToBytes, bytesToBase64, bytesToBase64Url } from "../ed25519";
import { verifyEnvelope, type DsseEnvelope } from "../dsse";
import { AttestError } from "../errors";
import { jwkOf } from "../sd-jwt/jws";
import { canonicalSignerOf, resolveVerificationKey, type VerifyKey } from "../signing";
import type { StatusListEntry } from "../holder/status-list";
import { checkAttestation, checkMandate } from "./faults";
import {
  ATTESTATION_KINDS,
  ATTESTATION_OUTCOMES,
  MANDATE_CITATION_SCHEMA,
  PARTY_DID_PATTERN,
  PROFILE_PATTERN,
  REFERENCE_SCHEMA,
  STATUS_ENTRY_SCHEMA,
  isPublicReference,
  type AttestationBody,
  type AttestationKind,
  type AttestationOutcome,
  type MandateBody,
  type MandateCitation,
  type Reference,
} from "./lexicon";

/** The record of truth's payloadType. Registered in `../dst`. */
export const ATTESTATION_DST = "application/vnd.kash.attestation+json" as const;
/** A mandate's payloadType. Registered in `../dst`. */
export const MANDATE_DST = "application/vnd.kash.mandate+json" as const;
/** The presentation's `vct`. Registered in `../dst` (family `sd-jwt-vct`). */
export const ATTESTATION_VCT = "https://kashscript.com/vct/attestation/1" as const;
/** The one context the projection uses; its issuer-dependent `@vocab` names the rest, so nothing needs hosting. */
export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2" as const;
/** How long a copy lives, from the day it is issued (§2.4). A copy is cheap to issue again; a long life only lets a stale one linger. The issuer's policy, the same for every copy of a kind. */
export const COPY_LIFETIME_DAYS = 90;
/**
 * How many selectively disclosable slots every copy's `_sd` holds, real or decoy: one for each claim a copy can
 * hide (a private reference, the statement, the exact time, the record id, a mandate, a supersession, a contested
 * decision, the reasons). Padded to it, the array's length says nothing about which a record carries (§3 G1).
 */
export const COPY_SD_SLOTS = 8;

const DAY = 86_400;
const dayOf = (unix: number): number => unix - (unix % DAY);
const isoOf = (unix: number): string => new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const unixOf = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

/* ── 1. the record of truth ────────────────────────────────────────── */

/**
 * SHA-256 hex of a DSSE envelope's signed payload bytes — what `supersedes`, a mandate citation and a copy's
 * `record` name, as a rule's hash is named (rule.md §6).
 */
export async function payloadSha256(envelope: DsseEnvelope): Promise<string> {
  return sha256Hex(base64ToBytes(envelope.payload));
}

export type RecordProblemCode =
  | "WRONG_TYPE"
  | "MALFORMED"
  | "NOT_CANONICAL"
  | "ATTESTATION_INVALID"
  | "ISSUER_SIGNATURE"
  | "COUNTERPARTY_SIGNATURE"
  | "MANDATE_MISSING"
  | "MANDATE_INVALID"
  | "SUPERSESSION";

export interface RecordProblem {
  readonly code: RecordProblemCode;
  readonly message: string;
}

export interface RecordCheckOptions {
  /** Keys by keyid. Default: self-certifying `did:kash` and `did:key` only — a `did:web` signer's key comes from a pinned trust list or a held key, passed here. */
  readonly resolveKey?: (keyid: string) => VerifyKey | null;
  /** The mandate the body's `mandate` cites, presented beside the record. */
  readonly mandate?: DsseEnvelope;
  /** The mandate the body's `counterpartyMandate` cites. */
  readonly counterpartyMandate?: DsseEnvelope;
  /** The record the body's `supersedes` cites, when the checker holds it. */
  readonly superseded?: DsseEnvelope;
}

export interface RecordCheck {
  readonly ok: boolean;
  readonly body: AttestationBody | null;
  /** SHA-256 hex of the payload bytes. */
  readonly contentId: string | null;
  readonly problems: readonly RecordProblem[];
  /** What this check could not decide, said in words — never a pass by silence. */
  readonly notChecked: readonly string[];
}

const nameOf = (keyid: string): string => canonicalSignerOf(keyid) ?? keyid.split("#")[0]!;

function readPayload(envelope: DsseEnvelope): { bytes: Uint8Array; json: unknown } | null {
  try {
    const bytes = base64ToBytes(envelope.payload);
    return { bytes, json: JSON.parse(new TextDecoder().decode(bytes)) };
  } catch {
    return null;
  }
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** Whether a mandate's scope covers this record: every bound it names holds. */
function scopeProblems(m: MandateBody, body: AttestationBody): string[] {
  const s = m.scope;
  const out: string[] = [];
  if (s.kinds !== undefined && !s.kinds.includes(body.kind)) out.push(`its scope's kinds do not include ${body.kind}`);
  if (s.outcomes !== undefined && !s.outcomes.includes(body.outcome)) out.push(`its scope's outcomes do not include ${body.outcome}`);
  if (s.dsts !== undefined && !s.dsts.includes(ATTESTATION_DST)) out.push(`its scope's tags do not include ${ATTESTATION_DST}`);
  if (s.profiles !== undefined && (body.profile === undefined || !s.profiles.includes(body.profile))) out.push("its scope's profiles do not include this record's");
  if (s.references !== undefined && !s.references.some((r) => r.kind === body.reference.kind && r.sha256 === body.reference.sha256)) out.push("its scope's references do not include this record's");
  return out;
}

/** One link: the cited mandate is the principal's, to a key that signed this record, covering it. */
async function mandateProblems(
  envelope: DsseEnvelope | undefined,
  citation: MandateCitation,
  principal: string,
  body: AttestationBody,
  signers: ReadonlySet<string>,
  resolveKey: (keyid: string) => VerifyKey | null,
): Promise<{ problems: string[]; delegate: string | null }> {
  if (envelope === undefined) return { problems: ["the cited mandate was not presented"], delegate: null };
  const problems: string[] = [];
  if (envelope.payloadType !== MANDATE_DST) problems.push(`it is not a ${MANDATE_DST} envelope`);
  const p = readPayload(envelope);
  const m = p === null ? null : checkMandate(p.json);
  if (p === null || m === null || !m.ok || m.body === null) return { problems: [...problems, `it does not check${m !== null ? `: ${m.faults.map((f) => f.code).join(", ")}` : ""}`], delegate: null };
  const mb = m.body;
  if (!sameBytes(p.bytes, canonicalizeBytes(mb))) problems.push("its payload is not canonical");
  if (mb.id !== citation.id || (await payloadSha256(envelope)) !== citation.hash) problems.push("it is not the mandate the record cites — its id or its hash differs");
  if (mb.principal !== principal) problems.push(`its principal is not ${principal}`);
  const v = await verifyEnvelope(envelope, resolveKey);
  if (!v.verifiedKeyids.some((k) => nameOf(k) === nameOf(principal))) problems.push("its principal's signature does not check");
  const delegate = nameOf(mb.delegate.key);
  if (!signers.has(delegate)) problems.push("its delegate's key did not sign this record");
  problems.push(...scopeProblems(mb, body));
  const at = Date.parse(body.claimedAt);
  if (!(at >= Date.parse(mb.dates.from) && at < Date.parse(mb.dates.until))) problems.push("the record's claimed time is outside its dates");
  return { problems, delegate };
}

/**
 * The stranger's check of a record of truth (§2.3), offline: the tag; a canonical payload that passes
 * `checkAttestation`; the issuer's signature, or a delegate's under the cited mandate presented beside it; the
 * counterparty's signature, or its delegate's under its mandate; and a supersession's authority when the
 * superseded record is held. Its time is the witness's and its status the issuer's list — both named in
 * `notChecked`, never passed by silence.
 */
export async function verifyAttestationRecord(record: DsseEnvelope, opts: RecordCheckOptions = {}): Promise<RecordCheck> {
  const resolveKey = opts.resolveKey ?? resolveVerificationKey;
  const problems: RecordProblem[] = [];
  const notChecked: string[] = [
    "the witnessed time — claimedAt is the signer's claim; the trust log decides when it existed (§1.7)",
    "status — the issuer's status list, read with attest's holder checks",
    "whether the counterparty is independent of the issuer — a signature shows a key, not who holds it (d26; d91(d))",
  ];
  const fail = (code: RecordProblemCode, message: string): RecordCheck => ({ ok: false, body: null, contentId: null, problems: [...problems, { code, message }], notChecked });
  if (record === null || typeof record !== "object" || typeof record.payload !== "string" || !Array.isArray(record.signatures)) return fail("MALFORMED", "not a DSSE envelope");
  if (record.payloadType !== ATTESTATION_DST) return fail("WRONG_TYPE", `the payloadType is not ${ATTESTATION_DST}`);
  const p = readPayload(record);
  if (p === null) return fail("MALFORMED", "the payload is not JSON");
  const checked = checkAttestation(p.json);
  if (!checked.ok || checked.body === null) return fail("ATTESTATION_INVALID", checked.faults.map((f) => `${f.code}: ${f.message}`).join("; "));
  const body = checked.body;
  if (!sameBytes(p.bytes, canonicalizeBytes(body))) problems.push({ code: "NOT_CANONICAL", message: "the payload is not the body's RFC 8785 canonical form" });
  const contentId = await payloadSha256(record);

  let verified: readonly string[] = [];
  try {
    verified = (await verifyEnvelope(record, resolveKey)).verifiedKeyids;
  } catch (e) {
    problems.push({ code: "MALFORMED", message: (e as Error).message });
  }
  const signers = new Set(verified.map(nameOf));

  if (body.mandate === undefined) {
    if (!signers.has(nameOf(body.issuer))) problems.push({ code: "ISSUER_SIGNATURE", message: "the issuer's signature does not check" });
  } else {
    const m = await mandateProblems(opts.mandate, body.mandate, body.issuer, body, signers, resolveKey);
    for (const x of m.problems) problems.push({ code: opts.mandate === undefined ? "MANDATE_MISSING" : "MANDATE_INVALID", message: `the issuer's mandate: ${x}` });
  }
  if (body.counterparty !== undefined) {
    if (body.counterpartyMandate === undefined) {
      if (!signers.has(nameOf(body.counterparty))) problems.push({ code: "COUNTERPARTY_SIGNATURE", message: "the counterparty's signature does not check — one signature is a request, not a record (d41)" });
    } else {
      const m = await mandateProblems(opts.counterpartyMandate, body.counterpartyMandate, body.counterparty, body, signers, resolveKey);
      for (const x of m.problems) problems.push({ code: opts.counterpartyMandate === undefined ? "MANDATE_MISSING" : "MANDATE_INVALID", message: `the counterparty's mandate: ${x}` });
    }
  }
  if (body.supersedes !== undefined) {
    if (opts.superseded === undefined) notChecked.push("the supersession's authority — the superseded record was not presented");
    else {
      const old = readPayload(opts.superseded);
      const ob = old === null ? null : (old.json as Partial<AttestationBody>);
      if ((await payloadSha256(opts.superseded)) !== body.supersedes) problems.push({ code: "SUPERSESSION", message: "the presented record is not the one `supersedes` cites" });
      else if (ob === null || ob.issuer !== body.issuer || ob.kind !== body.kind || ob.counterparty !== body.counterparty) {
        problems.push({ code: "SUPERSESSION", message: "only the same issuer, about the same kind, with the same counterparty, supersedes a record (d91(a))" });
      }
    }
  }
  return { ok: problems.length === 0, body, contentId, problems, notChecked };
}

/* ── 2. the presentation ───────────────────────────────────────────── */

/** What one copy adds: the verifier's relationship key and the day it is issued. */
export interface CopyInput {
  /** The holder's key for this verifier alone (d62(d)3) — the copy's `cnf`. */
  readonly holderKey: VerifyKey;
  readonly iatUnix: number;
  /**
   * Not recommended (§2.4, §3 G1): a status bit on a copy can be set only by an issuer that keeps which index
   * belongs to which record — the copy material G1 asks it not to keep — and a verifier fetching the list tells
   * the issuer who checked, and when. A copy's short life is its bound instead. Never the record's own entry.
   */
  readonly credentialStatus?: StatusListEntry;
  /** Default {@link COPY_LIFETIME_DAYS}. */
  readonly lifetimeDays?: number;
}

/** Arguments for attest's `issueSdJwt`: what every verifier sees, what the holder may disclose, and the decoys that pad `_sd` to {@link COPY_SD_SLOTS}. */
export interface CopyClaims {
  readonly claims: Readonly<Record<string, unknown>>;
  readonly sdProperties: Readonly<Record<string, unknown>>;
  /** Pass to `issueSdJwt` as `decoys`, so every copy's `_sd` holds exactly {@link COPY_SD_SLOTS} digests. */
  readonly decoys: number;
}

/**
 * The claims of one copy of a record of truth that checks — `verifyAttestationRecord` runs first, and a record
 * that does not check gets no copy, so an unanswered request can never be copied as accepted.
 *
 * Visible: what every holder of the same kind shares — the issuer, the kind, the outcome, the profile, the
 * grade, a public reference — and the copy's own key, status entry and dates. Always selectively disclosable:
 * a private reference, the statement, the exact time, the record's id, a mandate, a supersession, a contested
 * decision and the reasons. Never in a copy: the counterparty and its mandate, which would join every copy
 * (d62(d)3).
 *
 * **Both dates are the copy's own.** `iat` is the day it is issued and `exp` that day plus its lifetime, so no copy
 * carries anything of its record's dates, and two copies of one record issued on different days share no date.
 * A record that ends before a copy's lifetime would gets no copy: a shorter one would carry the record's end.
 *
 * **Its `_sd` is padded** to {@link COPY_SD_SLOTS} digests with decoys (`decoys`, for `issueSdJwt`), so the
 * array's length does not tell a record with a supersession, a mandate or reasons from one without.
 *
 * **A copy is the issuer's word** that the record exists with its signatures. Where the issuer is also the
 * holder — an agency showing its own sign-offs — a copy is self-attestation (d26): a door that needs the other
 * side's acceptance reads the record of truth, never a copy (§2.4). The format cannot see who holds a copy.
 */
export async function copyClaimsOf(record: DsseEnvelope, copy: CopyInput, opts: RecordCheckOptions = {}): Promise<CopyClaims> {
  const checked = await verifyAttestationRecord(record, opts);
  if (!checked.ok || checked.body === null || checked.contentId === null) {
    throw new AttestError("INVALID_INPUT", `a copy is made only from a record of truth that checks: ${checked.problems.map((p) => p.code).join(", ")}`);
  }
  const body = checked.body;
  const iat = dayOf(copy.iatUnix);
  const exp = iat + (copy.lifetimeDays ?? COPY_LIFETIME_DAYS) * DAY;
  if (!(exp > iat)) throw new AttestError("INVALID_INPUT", "a copy lives at least a day");
  if (unixOf(body.expiresAt) < exp) throw new AttestError("INVALID_INPUT", "the record ends before a copy's lifetime would: a shorter copy would carry the record's end, so none is made");

  const head: Record<string, unknown> = { kind: body.kind, outcome: body.outcome };
  if (body.profile !== undefined) head.profile = body.profile;
  if (body.grade !== undefined) head.grade = body.grade;
  if (body.practice === true) head.practice = true;
  const pub = isPublicReference(body.reference.kind);
  const claims: Record<string, unknown> = {
    iss: body.issuer,
    iat,
    exp,
    vct: ATTESTATION_VCT,
    cnf: { jwk: jwkOf(copy.holderKey) },
    attestation: head,
  };
  if (pub) claims.reference = body.reference;
  if (copy.credentialStatus !== undefined) claims.credentialStatus = copy.credentialStatus;
  const sd: Record<string, unknown> = {};
  if (!pub) sd.reference = body.reference;
  sd.statement = body.statement;
  sd.claimedAt = body.claimedAt;
  sd.record = checked.contentId;
  if (body.mandate !== undefined) sd.mandate = body.mandate;
  if (body.supersedes !== undefined) sd.supersedes = body.supersedes;
  if (body.contests !== undefined) sd.contests = body.contests;
  if (body.reasons !== undefined) sd.reasons = body.reasons;
  return { claims, sdProperties: sd, decoys: COPY_SD_SLOTS - Object.keys(sd).length };
}

/* ── 3. the projection ─────────────────────────────────────────────── */

/** What a viewer holds of an attestation, whichever form it came in. Never the counterparty. */
export interface AttestationView {
  readonly issuer: string;
  readonly kind: AttestationKind;
  readonly outcome: AttestationOutcome;
  readonly profile?: string;
  readonly grade?: 0 | 1 | 2 | 3;
  readonly practice?: boolean;
  readonly reference?: Reference;
  readonly statement?: string;
  readonly claimedAt?: string;
  /** A copy's day of issue, when its exact time was not disclosed. */
  readonly issuedAt?: string;
  readonly expiresAt: string;
  readonly mandate?: MandateCitation;
  readonly supersedes?: string;
  readonly contests?: string;
  readonly reasons?: readonly string[];
  /** SHA-256 hex of the record of truth's payload. */
  readonly record?: string;
  readonly credentialStatus?: StatusListEntry;
}

/** A viewer's view of a copy: the claims a verifier sees (attest's `verifySdJwt` report `claims`). */
export function viewOfCopy(claims: Readonly<Record<string, unknown>>): AttestationView {
  const head = (claims.attestation ?? {}) as Record<string, unknown>;
  const view: Record<string, unknown> = {
    issuer: claims.iss,
    kind: head.kind,
    outcome: head.outcome,
    expiresAt: isoOf(Number(claims.exp)),
  };
  if (head.profile !== undefined) view.profile = head.profile;
  if (head.grade !== undefined) view.grade = head.grade;
  if (head.practice === true) view.practice = true;
  for (const k of ["reference", "statement", "claimedAt", "mandate", "supersedes", "contests", "reasons", "record", "credentialStatus"]) {
    if (claims[k] !== undefined) view[k] = claims[k];
  }
  if (view.claimedAt === undefined && typeof claims.iat === "number") view.issuedAt = isoOf(claims.iat);
  return view as unknown as AttestationView;
}

/** RFC 6920 named information: `ni:///sha-256;<base64url digest>` — a standard content address, no namespace of ours. */
export const niUriOf = (sha256HexDigest: string): string => `ni:///sha-256;${bytesToBase64Url(hexToBytes(sha256HexDigest))}`;
/** W3C Subresource Integrity form, as VC 2.0's `digestSRI` takes it. */
export const sriOf = (sha256HexDigest: string): string => `sha256-${bytesToBase64(hexToBytes(sha256HexDigest))}`;

/**
 * The W3C VC 2.0 projection of a view: an **unsecured** credential in the VC 2.0 data model. Deterministic; it
 * carries what the view carries and nothing more, never the counterparty, and proves nothing by itself — a
 * verifier checks the copy, or the record of truth that `relatedResource` names: the resource is the record's
 * payload bytes, and the digest covers those bytes, not the envelope around them.
 */
export function projectVc(view: AttestationView): Record<string, unknown> {
  const subject: Record<string, unknown> = { kind: view.kind, outcome: view.outcome };
  if (view.profile !== undefined) subject.profile = view.profile;
  if (view.grade !== undefined) subject.grade = view.grade;
  if (view.practice === true) subject.practice = true;
  if (view.reference !== undefined) subject.reference = view.reference;
  if (view.statement !== undefined) subject.statement = view.statement;
  if (view.reasons !== undefined) subject.reasons = view.reasons;
  if (view.mandate !== undefined) subject.mandate = view.mandate;
  if (view.supersedes !== undefined) subject.supersedes = view.supersedes;
  if (view.contests !== undefined) subject.contests = view.contests;
  const vc: Record<string, unknown> = {
    "@context": [VC_CONTEXT_V2],
    type: ["VerifiableCredential", "KashAttestation"],
    issuer: view.issuer,
  };
  const from = view.claimedAt ?? view.issuedAt;
  if (from !== undefined) vc.validFrom = from;
  vc.validUntil = view.expiresAt;
  vc.credentialSubject = subject;
  if (view.credentialStatus !== undefined) vc.credentialStatus = view.credentialStatus;
  if (view.record !== undefined) vc.relatedResource = [{ id: niUriOf(view.record), digestSRI: sriOf(view.record) }];
  return vc;
}

const HEX64_STRING = S.string({ pattern: /^[0-9a-f]{64}$/ });

/** The projection's shape — what `projectVc` can produce. */
export const ATTESTATION_VC_SCHEMA: ObjectSchema = S.object(
  {
    "@context": S.array(S.literal(VC_CONTEXT_V2), { minItems: 1, maxItems: 1 }),
    type: S.array(S.enum("VerifiableCredential", "KashAttestation"), { minItems: 2, maxItems: 2 }),
    issuer: S.string({ pattern: PARTY_DID_PATTERN }),
    validFrom: S.optional(S.string({ format: "iso8601" })),
    validUntil: S.string({ format: "iso8601" }),
    credentialSubject: S.object(
      {
        kind: S.enum(...ATTESTATION_KINDS),
        outcome: S.enum(...ATTESTATION_OUTCOMES),
        profile: S.optional(S.string({ pattern: PROFILE_PATTERN })),
        grade: S.optional(S.enum(0, 1, 2, 3)),
        practice: S.optional(S.boolean()),
        reference: S.optional(REFERENCE_SCHEMA),
        statement: S.optional(S.string({ minLength: 1, maxLength: 280 })),
        reasons: S.optional(S.array(S.string({ pattern: /^[a-z0-9][a-z0-9-]{0,62}$/ }), { minItems: 1, maxItems: 16 })),
        mandate: S.optional(MANDATE_CITATION_SCHEMA),
        supersedes: S.optional(HEX64_STRING),
        contests: S.optional(HEX64_STRING),
      },
      ["kind", "outcome"],
    ),
    credentialStatus: S.optional(STATUS_ENTRY_SCHEMA),
    relatedResource: S.optional(
      S.array(S.object({ id: S.string({ pattern: /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/ }), digestSRI: S.string({ pattern: /^sha256-[A-Za-z0-9+/]{43}=$/ }) }, ["id", "digestSRI"]), { minItems: 1, maxItems: 1 }),
    ),
  },
  ["@context", "type", "issuer", "validUntil", "credentialSubject"],
);

/** The projection's published JSON Schema (`specs/schemas/attestation-vc.schema.json`). */
export function attestationVcJsonSchema(): JsonSchema {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://kashscript.com/schemas/attestation-vc/1.json",
    title: "The W3C VC 2.0 projection of an attestation",
    description:
      "What @kashscript/attest/attestation's projectVc produces: an unsecured credential in the VC 2.0 data model, using only the base context, never naming the counterparty, whose relatedResource names the record of truth's payload bytes by RFC 6920 named information. It proves nothing by itself.",
    ...toJsonSchema(ATTESTATION_VC_SCHEMA),
  } as JsonSchema;
}
