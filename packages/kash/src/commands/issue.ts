/**
 * `kash issue cohort` — the teacher's organisation writes a cohort record as a file.
 *
 * Station zero's record (specs/cohort-profile.md). This is the teacher's side:
 *
 *   claim (buildCohortClaim) → unsigned subject (cohortSubject) → a countersign
 *   request signed by the teacher's organisation → the teacher's own acceptance.
 *
 * The result is a *pending* record: one of the two signatures it needs. The
 * station adds the other with `kash countersign`; until then `kash verify` says
 * so (exit 1, MISSING_COUNTERSIGNATURE). Nothing here is sent anywhere, and the
 * file is not delivered into a wallet — that is an online issuer's job (OA-S1,
 * KS-R2b), because the wallet receives only through OpenID4VCI from the issuer's
 * own HTTPS origin (d62(d)1). Paper is the floor.
 *
 * Organisations sign as themselves (d62(d)2): the key is the teacher's own,
 * made with `kash station init --name teacher`, never one made per ceremony.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AttestError, buildCohortClaim, cohortSubject, sha256HexOf } from "@kashscript/attest";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  createCountersignRequest,
} from "@kashscript/identity-server";

import { COUNTERSIGN_STATEMENT, printCaveats } from "../cohort";
import { KashCliError } from "../errors";
import { loadKey } from "../keystore/store";
import { writeOutput } from "../utils/files";
import { banner, c, info, step, success } from "../utils/output";

export interface IssueCohortOptions {
  /** The relationship key the learner's wallet made for this issuer, bound at enrolment. */
  readonly holder: string;
  /** The station's DID — public; its key is not needed here. */
  readonly station: string;
  readonly syllabusId: string;
  readonly syllabusVersion: string;
  /** The syllabus exactly as published. kash hashes its bytes. */
  readonly syllabusFile: string;
  /** ISO-8601 UTC. */
  readonly finished: string;
  /** ISO-8601 UTC, after `finished`. The founder's to set; there is no default. */
  readonly expires: string;
  readonly org?: string;
  /** How long the station has to countersign. 14 by default, 90 at most. */
  readonly ttlDays?: number;
  readonly key?: string;
  readonly keystore?: string;
  readonly out?: string;
}

const DEFAULT_OUT = "cohort-record.pending.json";
const MAX_TTL_DAYS = 90;

/** The cohort profile's own pattern (attest, profiles/cohort.ts): ISO-8601, UTC, "Z", at most three fractional digits. */
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/** Milliseconds for a time written exactly as the profile writes it — the same string goes into the claim, so what is checked is what is signed. */
function isoUtcMs(flag: string, value: string): number {
  const ms = ISO_UTC.test(value) ? Date.parse(value) : Number.NaN;
  // Date.parse rolls 2026-02-31 over to March; the round trip catches it.
  if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new KashCliError(`${flag} ${JSON.stringify(value)} is not an ISO-8601 UTC time (for example 2026-09-25T12:00:00.000Z).`, "INVALID_INPUT");
  }
  return ms;
}

export async function runIssueCohort(opts: IssueCohortOptions): Promise<void> {
  banner("kash · issue cohort");

  const ttlDays = opts.ttlDays ?? 14;
  if (!Number.isFinite(ttlDays) || ttlDays <= 0 || ttlDays > MAX_TTL_DAYS) {
    throw new KashCliError(`--ttl-days must be a number above 0 and at most ${MAX_TTL_DAYS} (fractions are fine).`, "INVALID_INPUT");
  }
  const finishedMs = isoUtcMs("--finished", opts.finished);
  const expiresMs = isoUtcMs("--expires", opts.expires);
  if (finishedMs > Date.now()) {
    throw new KashCliError("--finished is in the future. A record exists only for a cohort that was finished.", "INVALID_INPUT");
  }
  if (expiresMs <= finishedMs) {
    throw new KashCliError("--expires must be after --finished.", "INVALID_INPUT");
  }
  if (expiresMs <= Date.now()) {
    throw new KashCliError("--expires is already in the past, so the record would not attest from the moment it was made.", "INVALID_INPUT");
  }

  const teacher = await loadKey(opts.key ?? "teacher", opts.keystore);

  let syllabusBytes: Uint8Array;
  try {
    syllabusBytes = readFileSync(resolve(opts.syllabusFile));
  } catch (err) {
    throw new KashCliError(`Cannot read the syllabus at ${resolve(opts.syllabusFile)}: ${(err as Error).message}`, "INVALID_INPUT", err);
  }
  const hash = await sha256HexOf(syllabusBytes);

  let subject;
  try {
    const claim = buildCohortClaim({
      holderDid: opts.holder,
      teacherOrgDid: teacher.did,
      stationDid: opts.station,
      syllabus: { id: opts.syllabusId, version: opts.syllabusVersion, hash },
      finishedAt: opts.finished,
      expiresAt: opts.expires,
      ...(opts.org !== undefined ? { org: opts.org } : {}),
    });
    subject = cohortSubject(claim);
  } catch (err) {
    if (err instanceof AttestError) throw new KashCliError(err.message, "RECORD_INVALID", err);
    throw err;
  }

  const signingKey = { did: teacher.did, publicKey: teacher.publicKey, privateKey: teacher.privateKey, custody: "subject-generated" } as const;

  const created = await createCountersignRequest({
    subject,
    requesterDid: teacher.did,
    requesterPrivateKey: teacher.privateKey,
    statement: COUNTERSIGN_STATEMENT,
    disclosures: [{ label: "Syllabus", value: `${opts.syllabusId}, version ${opts.syllabusVersion}` }],
    relationshipContext: "cohort",
    ttlSeconds: Math.round(ttlDays * 86_400),
  });
  const byTeacher = await acceptCountersignRequest({ request: created.request, subject, signingKey });
  if (!byTeacher.ok) {
    throw new KashCliError(`The teacher's organisation could not accept its own request: ${byTeacher.reason}.`, "RECORD_INVALID");
  }
  const pending = assembleCountersignBundle({
    subject: byTeacher.envelope,
    request: created.request,
    acceptances: [byTeacher.acceptance],
  });

  const out = writeOutput(opts.out ?? DEFAULT_OUT, JSON.stringify(pending, null, 2) + "\n");

  success(`Wrote the pending record: ${c.bold(out)}`);
  process.stdout.write(`  teacher's organisation : ${teacher.did}  (signed)\n`);
  process.stdout.write(`  station                : ${opts.station}  (has not signed)\n`);
  process.stdout.write(`  holder                 : ${opts.holder}  (a key, not a person)\n`);
  process.stdout.write(`  syllabus               : ${opts.syllabusId}, version ${opts.syllabusVersion}\n`);
  process.stdout.write(`  syllabus sha-256       : ${hash}\n`);
  process.stdout.write(`  finished / expires     : ${opts.finished} / ${opts.expires}\n`);
  process.stdout.write(`  station has until      : ${new Date(created.request.body.expiresAtUnix * 1000).toISOString()}\n`);

  process.stdout.write(`\n${c.bold("Carried link")} (the countersign request as bytes — no server):\n${created.compactB64u}\n`);
  info("Give the station this link and the pending file. They run:");
  process.stdout.write(`  kash countersign <link> --record ${out} --key station --out cohort-record.json\n`);
  step("The file is not a finished record yet: `kash verify` on it exits 1 until the station has signed.");
  step("Nothing was uploaded, and nothing was delivered into a wallet — an online issuer does that (the wallet receives only over OpenID4VCI).");
  printCaveats();
}
