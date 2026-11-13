/**
 * Station zero's record through the real ceremony (specs/cohort-profile.md).
 *
 * The round trip KS-R1 asks for: issue → countersign with this package's
 * ceremony → verify offline with attest's published binary (exit 0) → a
 * tampered copy (exit 1). Delivery into a wallet is the online issuer's
 * (OA-S1 at Oreoasis, or KS-R2b); here it shrinks to the two key proofs the
 * wallet signs with its relationship key — the binding at enrolment and the
 * redemption at the end — because those are all this profile depends on.
 * Everything here is a simulation (d11): no real learner, station or teacher.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeBytes, deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import {
  base64ToBytes,
  buildCohortClaim,
  bytesToBase64,
  cohortSubject,
  decodeJws,
  resolveDidKey,
  sha256HexOf,
  signJws,
  verifyCohortRecord,
  verifyJws,
  type CountersignBundle,
} from "@kashscript/attest";

import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  createCountersignRequest,
  decodeCompactCountersignRequest,
  declineCountersignRequest,
  type RelationshipSigningKey,
} from "../src/countersign";

const ATTEST = join(import.meta.dir, "..", "..", "attest");
const WIN = process.platform === "win32";

const ISSUER = "https://issuer.example/cohorts/demo";
const FINISHED = "2026-09-25T12:00:00.000Z";
const FINISHED_UNIX = Date.parse(FINISHED) / 1000;
const EXPIRES = "2029-09-25T12:00:00.000Z";
const PROOF_TYP = "openid4vci-proof+jwt";

/**
 * An organisation's own key, from its own keystore (KS-R2's `station init`) —
 * the DID its charter or records name. Never `generateOneTimeSigningKey`, which
 * is a fresh key per ceremony: no rule could recognise it later (d62(d)2).
 */
async function organisation(): Promise<RelationshipSigningKey> {
  const kp = await generateKeyPair();
  return { did: deriveDid(kp.publicKey), publicKey: kp.publicKey, privateKey: kp.privateKey, custody: "subject-generated" };
}

/** The learner's wallet key for this issuer alone (d41, d47(g)). Chakor makes it at the first redemption. */
async function relationshipKey(): Promise<KashKeyPair & { readonly did: string }> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

/** The wallet's OpenID4VCI key proof, signed by the relationship key over the issuer's nonce (holder contract §1). */
function keyProof(key: KashKeyPair & { readonly did: string }, nonce: string, iat: number): Promise<string> {
  return signJws({ typ: PROOF_TYP, kid: key.did }, { aud: ISSUER, iat, nonce }, { privateKey: key.privateKey, publicKey: key.publicKey });
}

/** What the issuer does with a key proof: check it, and read the key it names. */
async function provenKey(proof: string, nonce: string): Promise<string | null> {
  const jws = decodeJws(proof);
  if (jws === null || jws.header.typ !== PROOF_TYP || jws.payload.aud !== ISSUER || jws.payload.nonce !== nonce) return null;
  const kid = typeof jws.header.kid === "string" ? jws.header.kid : null;
  const key = kid === null ? null : resolveDidKey(kid);
  return key !== null && (await verifyJws(jws, key)) ? kid : null;
}

/** The completion record, bound to the key the binding proved. */
async function completionRecord(holderDid: string, teacher: RelationshipSigningKey, station: RelationshipSigningKey) {
  const syllabusHash = await sha256HexOf("Web foundations — syllabus, version 1.0 (simulation)");
  return buildCohortClaim({
    holderDid,
    teacherOrgDid: teacher.did,
    stationDid: station.did,
    syllabus: { id: `${teacher.did}/syllabus/web-foundations`, version: "1.0", hash: syllabusHash },
    finishedAt: FINISHED,
    expiresAt: EXPIRES,
  });
}

describe("cohort record — station zero's loop, through the ceremony and the published binary", () => {
  let dir = "";

  beforeAll(() => {
    const build = spawnSync("bun", ["run", "build:bin"], { cwd: ATTEST, encoding: "utf8", shell: WIN });
    if (build.status !== 0) throw new Error(`attest build:bin failed (${build.status}):\n${build.stderr || build.stdout}`);
    dir = mkdtempSync(join(tmpdir(), "cohort-ceremony-"));
  });
  afterAll(() => {
    if (dir !== "") rmSync(dir, { recursive: true, force: true });
  });

  /** attest's published binary, under plain Node with the network switched off. */
  function verify(name: string, bundle: unknown): { status: number | null; stdout: string; stderr: string } {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(bundle, null, 2));
    // Run from the attest package with a relative bin path: the repo path
    // contains a space, which `shell: true` would split on Windows.
    const r = spawnSync("node", ["--require", "./test/offline-guard.cjs", "dist/bin/attest.js", "verify", path], {
      cwd: ATTEST,
      encoding: "utf8",
      shell: WIN,
    });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  }

  it("binding → issue → both countersign → verify offline (exit 0) → a tampered copy fails (exit 1)", async () => {
    const teacher = await organisation();
    const station = await organisation();
    const learner = await relationshipKey();

    // 1. Binding first: at enrolment the wallet's key proof names its relationship key with this issuer.
    const bound = await provenKey(await keyProof(learner, "nonce-enrolment", FINISHED_UNIX - 90 * 86_400), "nonce-enrolment");
    expect(bound).toBe(learner.did);

    // 2. The completion record, bound to that key: built and checked against the profile, still unsigned.
    const subject = cohortSubject(await completionRecord(bound as string, teacher, station));
    expect(subject.signatures).toEqual([]);

    // 3. Both countersignatures. The teacher's organisation asks, and accepts its own request where it stands…
    const created = await createCountersignRequest({
      subject,
      requesterDid: teacher.did,
      requesterPrivateKey: teacher.privateKey,
      statement: "Countersign that the holder of the key named in this record finished the cohort under this syllabus version.",
      disclosures: [{ label: "Syllabus", value: "web-foundations, version 1.0" }],
      relationshipContext: "cohort-demo",
      nowSec: FINISHED_UNIX + 3_600,
    });
    const byTeacher = await acceptCountersignRequest({ request: created.request, subject, signingKey: teacher, nowSec: FINISHED_UNIX + 3_660 });
    if (!byTeacher.ok) throw new Error(`the teacher's organisation could not accept: ${byTeacher.reason}`);
    // …and the station opens the carried rendering: the request as bytes, no server anywhere (the path `kash countersign` takes).
    const carried = decodeCompactCountersignRequest(created.compactB64u);
    const byStation = await acceptCountersignRequest({ request: carried, subject: byTeacher.envelope, signingKey: station, nowSec: FINISHED_UNIX + 7_200 });
    if (!byStation.ok) throw new Error(`the station could not accept: ${byStation.reason}`);
    const bundle: CountersignBundle = assembleCountersignBundle({
      subject: byStation.envelope,
      request: created.request,
      acceptances: [byTeacher.acceptance, byStation.acceptance],
    });
    expect(bundle.subject.signatures.map((s) => s.keyid)).toEqual([teacher.did, station.did]);

    // 4. The offer: the issuer checks what it is about to release, and releases it only to the key the record names.
    const asOf = FINISHED_UNIX + 86_400;
    const redeemedBy = await provenKey(await keyProof(learner, "nonce-redeem", asOf), "nonce-redeem");
    const report = await verifyCohortRecord(bundle, { holderDid: redeemedBy as string, nowSec: asOf });
    expect(report.violations).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.countersign.requesterDid).toBe(teacher.did);
    const someoneElse = await relationshipKey();
    const notTheirs = await provenKey(await keyProof(someoneElse, "nonce-redeem", asOf), "nonce-redeem");
    expect((await verifyCohortRecord(bundle, { holderDid: notTheirs as string, nowSec: asOf })).ok).toBe(false);

    // 5. Anyone checks it offline: a file, a command, no key material, no service.
    const pass = verify("cohort-record.json", bundle);
    expect(pass.stderr).not.toContain("offline-guard");
    expect(pass.stdout).toContain("two-signature proof: yes");
    expect(pass.stdout).toContain("Cohort record (kashscript-cohort/1)");
    expect(pass.stdout).toContain(`teacher's org      : ${teacher.did} — countersigned`);
    expect(pass.stdout).toContain(`station            : ${station.did} — countersigned`);
    expect(pass.stdout).toContain("profile            : every rule holds");
    expect(pass.stdout).toContain("RESULT: PASS");
    expect(pass.status).toBe(0);

    // 6. A tampered copy fails: the syllabus version changed after both organisations signed.
    const claim = JSON.parse(new TextDecoder().decode(base64ToBytes(bundle.subject.payload)));
    claim.rule.version = "2.0";
    const fail = verify("cohort-record-tampered.json", { ...bundle, subject: { ...bundle.subject, payload: bytesToBase64(canonicalizeBytes(claim)) } });
    expect(fail.stdout).toContain("RESULT: FAIL");
    expect(fail.status).toBe(1);
  });

  it("a station that declines leaves no trace, and the issuer is left with nothing it may offer", async () => {
    const teacher = await organisation();
    const station = await organisation();
    const learner = await relationshipKey();
    const subject = cohortSubject(await completionRecord(learner.did, teacher, station));
    const created = await createCountersignRequest({
      subject,
      requesterDid: teacher.did,
      requesterPrivateKey: teacher.privateKey,
      statement: "Countersign that the holder of the key named in this record finished the cohort under this syllabus version.",
      nowSec: FINISHED_UNIX + 3_600,
    });
    const byTeacher = await acceptCountersignRequest({ request: created.request, subject, signingKey: teacher, nowSec: FINISHED_UNIX + 3_660 });
    if (!byTeacher.ok) throw new Error(byTeacher.reason);

    expect(declineCountersignRequest()).toEqual({ ok: true, recorded: false });

    const pending = assembleCountersignBundle({ subject: byTeacher.envelope, request: created.request, acceptances: [byTeacher.acceptance] });
    const report = await verifyCohortRecord(pending, { nowSec: FINISHED_UNIX + 86_400 });
    expect(report.ok).toBe(false);
    expect(report.countersign.twoSignatureProof).toBe(false);
    expect(report.violations.some((v) => v.code === "MISSING_COUNTERSIGNATURE" && v.path === "$.meta.station")).toBe(true);
  });
});
