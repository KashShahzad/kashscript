// ============================================================================
// The cohort profile (specs/cohort-profile.md) — station zero's record.
//
// Bundles here are built with attest and identity-core only, the path a
// stranger has, so a pass proves the format rather than our ceremony code;
// identity-server's own suite runs the real ceremony into the same verifier.
// Three tests are constitutional rather than functional: the record carries no
// grade, score or rank (d43, d51), never names who paid (d55(e)), and exists
// only for a finished cohort. A regression in any of them is a breach.
// Everything here is a simulation (d11): no real person, station or teacher.
// ============================================================================

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeBytes, deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";

import { sha256Hex } from "../src/chain";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  countersignRequestDigest,
  type CountersignBundle,
  type KeyCustody,
  type SignedCountersignAcceptance,
} from "../src/countersign";
import { pae, type DsseEnvelope, type DsseSignature } from "../src/dsse";
import { base64ToBytes, bytesToBase64, signRaw } from "../src/ed25519";
import { AttestError } from "../src/errors";
import { sha256HexOf } from "../src/ids";
import {
  COHORT_ACTION,
  COHORT_PROFILE,
  DST_WORK_RECORD,
  WORK_RECORD_SPEC,
  buildCohortClaim,
  cohortSubject,
  isCohortRecord,
  validateCohortClaim,
  verifyCohortRecord,
  type CohortClaim,
  type CohortClaimInput,
  type CohortViolationCode,
} from "../src/profiles";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";

const FINISHED = "2026-09-25T12:00:00.000Z";
const FINISHED_UNIX = Date.parse(FINISHED) / 1000;
const EXPIRES = "2029-09-25T12:00:00.000Z";
const NOW = FINISHED_UNIX + 86_400;

interface Party extends KashKeyPair {
  readonly did: string;
}
async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

/** A learner's relationship key, a teacher's organisation and a station — three keys, three parties. */
interface World {
  readonly holder: Party;
  readonly teacher: Party;
  readonly station: Party;
  readonly syllabusHash: string;
}
async function world(): Promise<World> {
  return {
    holder: await party(),
    teacher: await party(),
    station: await party(),
    syllabusHash: await sha256HexOf("Web foundations — syllabus, version 1.0 (simulation)"),
  };
}

function input(w: World, over: Partial<CohortClaimInput> = {}): CohortClaimInput {
  return {
    holderDid: w.holder.did,
    teacherOrgDid: w.teacher.did,
    stationDid: w.station.did,
    syllabus: { id: `${w.teacher.did}/syllabus/web-foundations`, version: "1.0", hash: w.syllabusHash },
    finishedAt: FINISHED,
    expiresAt: EXPIRES,
    ...over,
  };
}

/** A plain copy of a built claim, to bend in ways the builder would refuse. */
function loose(c: CohortClaim): Record<string, any> {
  return JSON.parse(JSON.stringify(c)) as Record<string, any>;
}

/** An unsigned envelope over any value's JCS bytes — no validation, so a test can sign what the profile refuses. */
function subjectOf(value: unknown): DsseEnvelope {
  return { payloadType: DST_WORK_RECORD, payload: bytesToBase64(canonicalizeBytes(value)), signatures: [] };
}

function subjectOfText(json: string): DsseEnvelope {
  return { payloadType: DST_WORK_RECORD, payload: bytesToBase64(new TextEncoder().encode(json)), signatures: [] };
}

interface Signing {
  readonly by: Party;
  readonly custody?: KeyCustody;
  readonly atUnix?: number;
}

/**
 * The ceremony by hand: the requester signs a request over the subject, then
 * each signer appends a signature over the same PAE bytes and signs its
 * acceptance — what identity-server's `acceptCountersignRequest` does.
 */
async function countersigned(
  subject: DsseEnvelope,
  requester: Party,
  signers: readonly Signing[],
  opts: { readonly disclosures?: readonly { label: string; value: string }[]; readonly issuedAtUnix?: number } = {},
): Promise<CountersignBundle> {
  const payloadBytes = base64ToBytes(subject.payload);
  const subjectDigestSha256 = await sha256Hex(payloadBytes);
  const issuedAtUnix = opts.issuedAtUnix ?? FINISHED_UNIX + 3_600;
  const body = {
    requestId: `csr_${"c0".repeat(16)}`,
    requesterDid: requester.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256,
    statement: "Countersign that the holder of the key named in this record finished the cohort under this syllabus version.",
    disclosures: opts.disclosures ?? [{ label: "Syllabus", value: "web-foundations, version 1.0" }],
    nonceB64: bytesToBase64(new Uint8Array(32).fill(7)),
    issuedAtUnix,
    expiresAtUnix: issuedAtUnix + 14 * 86_400,
    relationshipContext: "cohort-demo",
    withdrawalFeed: null,
  };
  const header = { typ: "countersign-request", v: 1 };
  const request = { header, body, signature: await signEvent(header, body, requester.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
  const requestDigestSha256 = await countersignRequestDigest(request);

  const signatures: DsseSignature[] = [...subject.signatures];
  const acceptances: SignedCountersignAcceptance[] = [];
  for (const s of signers) {
    const sig = await signRaw(pae(subject.payloadType, payloadBytes), s.by.privateKey, s.by.publicKey);
    signatures.push({ keyid: s.by.did, sig: bytesToBase64(sig) });
    const acceptanceBody = {
      act: "countersign" as const,
      requestId: body.requestId,
      requestDigestSha256,
      subjectPayloadType: subject.payloadType,
      subjectDigestSha256,
      countersignerDid: s.by.did,
      keyCustody: s.custody ?? ("subject-generated" as const),
      signedAtUnix: s.atUnix ?? issuedAtUnix + 60,
    };
    const acceptanceHeader = { typ: "countersign", v: 1 };
    acceptances.push({
      header: acceptanceHeader,
      body: acceptanceBody,
      signature: await signEvent(acceptanceHeader, acceptanceBody, s.by.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }),
    });
  }
  return { formatVersion: COUNTERSIGN_BUNDLE_FORMAT, subject: { ...subject, signatures }, request, acceptances, withdrawal: null };
}

/** The record as station zero issues it: the teacher's organisation asks, and both organisations countersign. */
async function issued(w: World, claim: CohortClaim = buildCohortClaim(input(w))): Promise<CountersignBundle> {
  return countersigned(cohortSubject(claim), w.teacher, [{ by: w.teacher }, { by: w.station }]);
}

function has(violations: readonly { code: string; path: string }[], code: CohortViolationCode, path?: string): boolean {
  return violations.some((v) => v.code === code && (path === undefined || v.path === path));
}

/* ── The claim ─────────────────────────────────────────────────────────── */

describe("cohort profile — the claim", () => {
  it("a built claim follows the profile, with every pinned field in place", async () => {
    const w = await world();
    const claim = buildCohortClaim(input(w));
    const check = validateCohortClaim(claim);
    expect(check.violations).toEqual([]);
    expect(check.ok).toBe(true);
    expect(claim.spec).toBe(WORK_RECORD_SPEC);
    expect(claim.actor).toEqual({ class: "person", id: w.holder.did });
    expect(claim.shape).toBe("followed");
    expect(claim.rule).toEqual({ id: `${w.teacher.did}/syllabus/web-foundations`, version: "1.0", hash: w.syllabusHash });
    expect(claim.action).toEqual(COHORT_ACTION);
    expect(claim.inputs).toEqual([]);
    expect(claim.outputs).toEqual([]);
    expect(claim.status).toBe("completed");
    expect(claim.meta).toEqual({ profile: COHORT_PROFILE, teacherOrg: w.teacher.did, station: w.station.did, expiresAt: EXPIRES });
  });

  it("CONSTITUTIONAL — rejects any score or grade field, wherever it sits (d43, d51)", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const cases: readonly [string, Record<string, any>][] = [
      ["$.grade", { ...c, grade: "A" }],
      ["$.score", { ...c, score: 97 }],
      ["$.meta.finalGrade", { ...c, meta: { ...c.meta, finalGrade: "B+" } }],
      ["$.meta.score", { ...c, meta: { ...c.meta, score: 88 } }],
      ["$.meta.GPA", { ...c, meta: { ...c.meta, GPA: 3.7 } }],
      ["$.actor.rank", { ...c, actor: { ...c.actor, rank: 1 } }],
      ["$.rule.passMark", { ...c, rule: { ...c.rule, passMark: 50 } }],
      ["$.action.rating", { ...c, action: { ...c.action, rating: 5 } }],
      ["$.meta.skill_level", { ...c, meta: { ...c.meta, skill_level: "advanced" } }],
      ["$.meta.extra.score_out_of_100", { ...c, meta: { ...c.meta, extra: { score_out_of_100: 88 } } }],
      ["$.outputs[0].grade", { ...c, outputs: [{ name: "capstone", grade: "A" }] }],
    ];
    for (const [path, claim] of cases) {
      const check = validateCohortClaim(claim);
      expect(check.ok).toBe(false);
      expect(check.claim).toBeNull();
      const v = check.violations.find((x) => x.path === path);
      expect(v?.code).toBe("FORBIDDEN_FIELD");
      expect(v?.message).toContain("no grade, score or rank");
    }
  });

  it("CONSTITUTIONAL — never names who paid for a seat: sponsored seats are Duedale's (d55(e))", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const cases: readonly [string, Record<string, any>][] = [
      ["$.meta.sponsor", { ...c, meta: { ...c.meta, sponsor: "did:kash:z6Mk-sponsor" } }],
      ["$.meta.paidBy", { ...c, meta: { ...c.meta, paidBy: "a foundation" } }],
      ["$.sponsoredBy", { ...c, sponsoredBy: "a foundation" }],
      ["$.meta.fee", { ...c, meta: { ...c.meta, fee: "PKR 30,000" } }],
      ["$.meta.scholarship", { ...c, meta: { ...c.meta, scholarship: true } }],
    ];
    for (const [path, claim] of cases) {
      const check = validateCohortClaim(claim);
      const v = check.violations.find((x) => x.path === path);
      expect(check.ok).toBe(false);
      expect(v?.code).toBe("FORBIDDEN_FIELD");
      expect(v?.message).toContain("Duedale");
    }
  });

  it("matches field names word by word — a passport is not a pass mark", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const check = validateCohortClaim({ ...c, meta: { ...c.meta, passport: "x" } });
    expect(has(check.violations, "UNKNOWN_FIELD", "$.meta.passport")).toBe(true);
    expect(has(check.violations, "FORBIDDEN_FIELD")).toBe(false);
  });

  it("CONSTITUTIONAL — a cohort not finished yields no record: there is no failed one", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    for (const status of ["failed", "stopped", "escalated"]) {
      const check = validateCohortClaim({ ...c, status });
      expect(check.ok).toBe(false);
      expect(has(check.violations, "NOT_FINISHED", "$.status")).toBe(true);
    }
    // The builder has no way to say anything else.
    const sneaky = { ...input(await world()), status: "failed" } as unknown as CohortClaimInput;
    expect(buildCohortClaim(sneaky).status).toBe("completed");
  });

  it("is closed: prev, authority, agent fields and unnamed keys are refused", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const prev = validateCohortClaim({ ...c, prev: "a".repeat(64) });
    expect(prev.violations.find((v) => v.path === "$.prev")?.message).toContain("next one's");
    const authority = validateCohortClaim({ ...c, actor: { ...c.actor, authority: { kind: "certification", ref: "X-1", expires: EXPIRES } } });
    expect(authority.violations.find((v) => v.path === "$.actor.authority")?.message).toContain("not a licence");
    expect(has(validateCohortClaim({ ...c, actor: { ...c.actor, model: "m" } }).violations, "UNKNOWN_FIELD", "$.actor.model")).toBe(true);
    expect(has(validateCohortClaim({ ...c, actor: { ...c.actor, class: "agent" } }).violations, "BAD_VALUE", "$.actor.class")).toBe(true);
    expect(has(validateCohortClaim({ ...c, meta: { ...c.meta, name: "Ayesha" } }).violations, "UNKNOWN_FIELD", "$.meta.name")).toBe(true);
    expect(has(validateCohortClaim({ ...c, holderEmail: "a@b.c" }).violations, "UNKNOWN_FIELD", "$.holderEmail")).toBe(true);
  });

  it("names the holder only by a relationship key — Oreoasis's own work record is not a cohort record", async () => {
    const vector = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "holder", "source", "oreoasis-work-record.json"), "utf8"));
    const oreoasis = JSON.parse(new TextDecoder().decode(base64ToBytes(vector.envelope.payload)));
    const plain = validateCohortClaim(oreoasis);
    expect(plain.violations.map((v) => v.code)).toEqual(["NOT_A_COHORT_RECORD"]);

    // Claim the profile on it, and its establishment-scoped id is refused as a holder.
    const w = await world();
    const claimed = validateCohortClaim({ ...oreoasis, meta: { profile: COHORT_PROFILE, teacherOrg: w.teacher.did, station: w.station.did, expiresAt: EXPIRES } });
    expect(has(claimed.violations, "BAD_VALUE", "$.actor.id")).toBe(true);
    expect(has(claimed.violations, "UNKNOWN_FIELD", "$.actor.authority")).toBe(true);
    expect(has(claimed.violations, "NOT_FINISHED", "$.status")).toBe(true);

    // A key with a fragment does not compare exactly with a countersigner's DID.
    const c = loose(buildCohortClaim(input(w)));
    expect(has(validateCohortClaim({ ...c, actor: { ...c.actor, id: `${w.holder.did}#key-1` } }).violations, "BAD_VALUE", "$.actor.id")).toBe(true);
  });

  it("three parties, three keys: the station is not the teacher's organisation, and neither is the holder", async () => {
    const w = await world();
    const c = loose(buildCohortClaim(input(w)));
    expect(has(validateCohortClaim({ ...c, meta: { ...c.meta, station: w.teacher.did } }).violations, "BAD_VALUE", "$.meta.station")).toBe(true);
    expect(has(validateCohortClaim({ ...c, actor: { ...c.actor, id: w.station.did } }).violations, "BAD_VALUE", "$.actor.id")).toBe(true);
    expect(has(validateCohortClaim({ ...c, meta: { ...c.meta, teacherOrg: "KashScript" } }).violations, "BAD_VALUE", "$.meta.teacherOrg")).toBe(true);
  });

  it("names the syllabus by version and by the hash of what was published (d43)", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const { version: _v, ...noVersion } = c.rule;
    expect(has(validateCohortClaim({ ...c, rule: noVersion }).violations, "MISSING_FIELD", "$.rule.version")).toBe(true);
    expect(has(validateCohortClaim({ ...c, rule: { ...c.rule, hash: c.rule.hash.toUpperCase() } }).violations, "BAD_VALUE", "$.rule.hash")).toBe(true);
    expect(has(validateCohortClaim({ ...c, rule: { ...c.rule, hash: "abc" } }).violations, "BAD_VALUE", "$.rule.hash")).toBe(true);
    expect(has(validateCohortClaim({ ...c, rule: { ...c.rule, id: "line one\nline two" } }).violations, "BAD_VALUE", "$.rule.id")).toBe(true);
  });

  it("expires, and only after it finished (d27)", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    const { expiresAt: _e, ...noExpiry } = c.meta;
    expect(has(validateCohortClaim({ ...c, meta: noExpiry }).violations, "MISSING_FIELD", "$.meta.expiresAt")).toBe(true);
    expect(has(validateCohortClaim({ ...c, meta: { ...c.meta, expiresAt: FINISHED } }).violations, "BAD_VALUE", "$.meta.expiresAt")).toBe(true);
    expect(has(validateCohortClaim({ ...c, meta: { ...c.meta, expiresAt: "2029-02-30T00:00:00Z" } }).violations, "BAD_VALUE", "$.meta.expiresAt")).toBe(true);
    expect(has(validateCohortClaim({ ...c, timestamp: "2026-09-25 12:00" }).violations, "BAD_VALUE", "$.timestamp")).toBe(true);
  });

  it("pins the action and empties the work products, so no free text or capstone rides along", async () => {
    const c = loose(buildCohortClaim(input(await world())));
    expect(has(validateCohortClaim({ ...c, action: { ...c.action, summary: "Top of the class" } }).violations, "BAD_VALUE", "$.action.summary")).toBe(true);
    expect(has(validateCohortClaim({ ...c, outputs: [{ name: "capstone", sha256: "a".repeat(64) }] }).violations, "BAD_VALUE", "$.outputs")).toBe(true);
    expect(has(validateCohortClaim({ ...c, shape: "accepted" }).violations, "BAD_VALUE", "$.shape")).toBe(true);
  });

  it("buildCohortClaim refuses what the profile would refuse", async () => {
    const w = await world();
    expect(() => buildCohortClaim(input(w, { holderDid: "Ayesha" }))).toThrow(AttestError);
    expect(() => buildCohortClaim(input(w, { stationDid: w.teacher.did }))).toThrow(/INVALID_INPUT/);
    expect(() => buildCohortClaim(input(w, { expiresAt: FINISHED }))).toThrow(/meta\.expiresAt/);
  });

  it("cohortSubject is an unsigned envelope over the claim's RFC 8785 bytes", async () => {
    const claim = buildCohortClaim(input(await world()));
    const subject = cohortSubject(claim);
    expect(subject.payloadType).toBe(DST_WORK_RECORD);
    expect(subject.signatures).toEqual([]);
    expect(base64ToBytes(subject.payload)).toEqual(canonicalizeBytes(claim));
  });
});

/* ── The countersigned record ──────────────────────────────────────────── */

describe("cohort profile — the countersigned record", () => {
  it("verifies when the teacher's organisation asks and both organisations countersign", async () => {
    const w = await world();
    const bundle = await issued(w);
    expect(isCohortRecord(bundle)).toBe(true);
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.violations).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.countersign.twoSignatureProof).toBe(true);
    expect(r.countersign.requesterDid).toBe(w.teacher.did);
    expect(r.claim?.actor.id).toBe(w.holder.did);
    expect([r.holderDid, r.teacherOrgDid, r.stationDid]).toEqual([w.holder.did, w.teacher.did, w.station.did]);
    expect(r.syllabus).toEqual({ id: `${w.teacher.did}/syllabus/web-foundations`, version: "1.0", hash: w.syllabusHash });
    expect(r.expired).toBe(false);
    expect(r.notes.join("\n")).toContain("no grade, score or rank");
    expect(r.notes.join("\n")).toContain("two verifiers can tell it is one person");
  });

  it("needs both organisations — without the station's countersignature there is nothing to offer", async () => {
    const w = await world();
    const bundle = await countersigned(cohortSubject(buildCohortClaim(input(w))), w.teacher, [{ by: w.teacher }]);
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.ok).toBe(false);
    // AU-3 (A7-02): the only acceptance is the requester's own — a signature over its own claim, named as such.
    expect(r.countersign.reason).toBe("COUNTERSIGNER_IS_REQUESTER");
    expect(r.countersign.twoSignatureProof).toBe(false);
    expect(has(r.violations, "MISSING_COUNTERSIGNATURE", "$.meta.station")).toBe(true);
  });

  it("the teacher's organisation asks — it is the issuer a wallet names", async () => {
    const w = await world();
    const bundle = await countersigned(cohortSubject(buildCohortClaim(input(w))), w.station, [{ by: w.teacher }, { by: w.station }]);
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.countersign.ok).toBe(true);
    expect(r.ok).toBe(false);
    expect(has(r.violations, "WRONG_ISSUER")).toBe(true);
  });

  it("nobody else signs — not the holder, not a third organisation", async () => {
    const w = await world();
    const claim = buildCohortClaim(input(w));
    const third = await countersigned(cohortSubject(claim), w.teacher, [{ by: w.teacher }, { by: w.station }, { by: w.holder }]);
    const r = await verifyCohortRecord(third, { nowSec: NOW });
    expect(r.ok).toBe(false);
    expect(has(r.violations, "UNEXPECTED_SIGNER", "acceptances[2]")).toBe(true);
    expect(has(r.violations, "UNEXPECTED_SIGNER", "subject.signatures")).toBe(true);

    // A holder's signature already on the subject, without an acceptance, is refused too.
    const payload = base64ToBytes(cohortSubject(claim).payload);
    const holderSig = await signRaw(pae(DST_WORK_RECORD, payload), w.holder.privateKey, w.holder.publicKey);
    const preSigned = { ...cohortSubject(claim), signatures: [{ keyid: w.holder.did, sig: bytesToBase64(holderSig) }] };
    const r2 = await verifyCohortRecord(await countersigned(preSigned, w.teacher, [{ by: w.teacher }, { by: w.station }]), { nowSec: NOW });
    expect(r2.ok).toBe(false);
    expect(has(r2.violations, "UNEXPECTED_SIGNER", "subject.signatures")).toBe(true);
  });

  it("organisations sign as themselves — a key someone else minted is refused (d62(d)2)", async () => {
    const w = await world();
    const bundle = await countersigned(cohortSubject(buildCohortClaim(input(w))), w.teacher, [{ by: w.teacher }, { by: w.station, custody: "delegated-mint" }]);
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.ok).toBe(false);
    expect(has(r.violations, "DELEGATED_KEY", "$.meta.station")).toBe(true);
  });

  it("no countersignature before the cohort finished", async () => {
    const w = await world();
    const early = FINISHED_UNIX - 3_600;
    const bundle = await countersigned(cohortSubject(buildCohortClaim(input(w))), w.teacher, [{ by: w.teacher }, { by: w.station, atUnix: early }], {
      issuedAtUnix: early - 60,
    });
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.countersign.ok).toBe(true);
    expect(has(r.violations, "COUNTERSIGNED_BEFORE_FINISH", "$.meta.station")).toBe(true);
  });

  it("refuses signed bytes that are not canonical — two parsers must read one record", async () => {
    const w = await world();
    const claim = buildCohortClaim(input(w));
    const jcs = new TextDecoder().decode(canonicalizeBytes(claim));

    // A duplicate key: JSON.parse keeps the last value, and another parser could keep the first.
    const twoStatuses = jcs.replace('"status":"completed"', '"status":"failed","status":"completed"');
    expect(twoStatuses).not.toBe(jcs);
    const dup = await verifyCohortRecord(await countersigned(subjectOfText(twoStatuses), w.teacher, [{ by: w.teacher }, { by: w.station }]), { nowSec: NOW });
    expect(dup.countersign.ok).toBe(true);
    expect(dup.ok).toBe(false);
    expect(has(dup.violations, "NOT_CANONICAL")).toBe(true);

    const pretty = await verifyCohortRecord(await countersigned(subjectOfText(JSON.stringify(claim, null, 2)), w.teacher, [{ by: w.teacher }, { by: w.station }]), { nowSec: NOW });
    expect(has(pretty.violations, "NOT_CANONICAL")).toBe(true);
  });

  it("a disclosure travels with the record, so it cannot carry a grade either", async () => {
    const w = await world();
    const bundle = await countersigned(cohortSubject(buildCohortClaim(input(w))), w.teacher, [{ by: w.teacher }, { by: w.station }], {
      disclosures: [{ label: "Syllabus", value: "web-foundations, version 1.0" }, { label: "Final grade", value: "A" }],
    });
    const r = await verifyCohortRecord(bundle, { nowSec: NOW });
    expect(r.ok).toBe(false);
    expect(has(r.violations, "FORBIDDEN_FIELD", "request.body.disclosures[1].label")).toBe(true);
  });

  it("a record that is signed well but carries a grade is refused, even with both countersignatures", async () => {
    const w = await world();
    const graded = loose(buildCohortClaim(input(w)));
    graded.meta.grade = "A";
    const r = await verifyCohortRecord(await countersigned(subjectOf(graded), w.teacher, [{ by: w.teacher }, { by: w.station }]), { nowSec: NOW });
    expect(r.countersign.ok).toBe(true);
    expect(r.ok).toBe(false);
    expect(has(r.violations, "FORBIDDEN_FIELD", "$.meta.grade")).toBe(true);
  });

  it("a tampered copy fails", async () => {
    const w = await world();
    const bundle = await issued(w);
    const claim = JSON.parse(new TextDecoder().decode(base64ToBytes(bundle.subject.payload)));
    claim.rule.version = "2.0";
    const tampered = { ...bundle, subject: { ...bundle.subject, payload: bytesToBase64(canonicalizeBytes(claim)) } };
    const r = await verifyCohortRecord(tampered, { nowSec: NOW });
    expect(r.ok).toBe(false);
    expect(r.countersign.ok).toBe(false);
    expect(r.countersign.reason).toBe("SUBJECT_SIGNATURE_INVALID");
  });

  it("an expired record still verifies as signed, and says it no longer attests (d27)", async () => {
    const bundle = await issued(await world());
    const r = await verifyCohortRecord(bundle, { nowSec: Date.parse(EXPIRES) / 1000 + 1 });
    expect(r.ok).toBe(true);
    expect(r.expired).toBe(true);
    expect(r.notes.join("\n")).toContain("no longer attests");
  });

  it("checks the holder it is shown to — an issuer before it releases, a wallet on receipt", async () => {
    const w = await world();
    const bundle = await issued(w);
    expect((await verifyCohortRecord(bundle, { nowSec: NOW, holderDid: w.holder.did })).ok).toBe(true);
    const another = await party();
    const r = await verifyCohortRecord(bundle, { nowSec: NOW, holderDid: another.did });
    expect(r.ok).toBe(false);
    expect(has(r.violations, "NOT_THIS_HOLDER", "$.actor.id")).toBe(true);
  });

  it("a plain countersign bundle is not a cohort record", async () => {
    const plain = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "countersign-bundle.json"), "utf8"));
    expect(isCohortRecord(plain)).toBe(false);
    const r = await verifyCohortRecord(plain);
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.code)).toEqual(["NOT_A_COHORT_RECORD"]);
  });

  it("returns a report for junk, and never throws", async () => {
    for (const junk of [null, "x", {}, { formatVersion: COUNTERSIGN_BUNDLE_FORMAT }]) {
      const r = await verifyCohortRecord(junk);
      expect(r.ok).toBe(false);
      expect(has(r.violations, "NOT_A_COHORT_RECORD")).toBe(true);
    }
  });
});

/* ── The published binary, under plain Node, with the network off ──────── */

describe("cohort profile — attest verify, offline", () => {
  const GUARD = "./test/offline-guard.cjs";
  let dir = "";

  beforeAll(() => {
    const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
    if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
    dir = mkdtempSync(join(tmpdir(), "attest-cohort-"));
  });
  afterAll(() => {
    if (dir !== "") rmSync(dir, { recursive: true, force: true });
  });

  function verify(name: string, value: unknown): { status: number | null; stdout: string; stderr: string } {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(value, null, 2));
    // Relative bin from the package directory: the repo path has a space, which `shell: true` would split on Windows.
    const r = spawnSync("node", ["--require", GUARD, "dist/bin/attest.js", "verify", path], { cwd: PKG, encoding: "utf8", shell: WIN });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  }

  it("a cohort record passes, and says what it does not prove", async () => {
    const w = await world();
    const r = verify("cohort.json", await issued(w));
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("two-signature proof: yes");
    expect(r.stdout).toContain(`Cohort record (${COHORT_PROFILE})`);
    expect(r.stdout).toContain(`holder             : ${w.holder.did}`);
    expect(r.stdout).toContain(`teacher's org      : ${w.teacher.did} — countersigned`);
    expect(r.stdout).toContain(`station            : ${w.station.did} — countersigned`);
    expect(r.stdout).toContain("profile            : every rule holds");
    expect(r.stdout).toContain("does not prove     : how well anyone learned");
    expect(r.stdout.trimEnd().split("\n").pop()).toMatch(/^RESULT: PASS/);
  });

  it("a tampered copy fails (exit 1)", async () => {
    const bundle = await issued(await world());
    const claim = JSON.parse(new TextDecoder().decode(base64ToBytes(bundle.subject.payload)));
    claim.rule.version = "2.0";
    const r = verify("tampered.json", { ...bundle, subject: { ...bundle.subject, payload: bytesToBase64(canonicalizeBytes(claim)) } });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("— NOT countersigned");
    expect(r.stdout).toContain("profile            : the claim follows the profile, but the signatures above do not verify");
    expect(r.stdout).not.toContain("every rule holds");
    expect(r.stdout).toContain("RESULT: FAIL");
  });

  it("a record both organisations signed but that carries a grade fails (exit 1)", async () => {
    const w = await world();
    const graded = loose(buildCohortClaim(input(w)));
    graded.meta.grade = "A";
    const r = verify("graded.json", await countersigned(subjectOf(graded), w.teacher, [{ by: w.teacher }, { by: w.station }]));
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("two-signature proof: yes");
    expect(r.stdout).toContain("profile            : FORBIDDEN_FIELD at $.meta.grade");
    expect(r.stdout).toContain("RESULT: FAIL");
  });

  it("a plain countersign bundle prints as before — no cohort section", () => {
    const plain = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "countersign-bundle.json"), "utf8"));
    const r = verify("plain.json", plain);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain("Cohort record");
    expect(r.stdout).toContain("RESULT: PASS");
  });
});
