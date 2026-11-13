/**
 * What `issue cohort` and `countersign` share: the one sentence the station is
 * asked to sign, the plain reading of the claim, and the caveats a record must
 * not travel without (specs/cohort-profile.md — "What the record does not prove").
 */

import {
  base64ToBytes,
  isCountersignBundle,
  validateCohortClaim,
  type CohortClaim,
  type CohortViolation,
  type CountersignBundle,
} from "@kashscript/attest";

import { KashCliError } from "./errors";
import { c, step } from "./utils/output";

/** The whole of what the station is told it is signing, so it carries the meaning (specs/countersign.md). */
export const COUNTERSIGN_STATEMENT =
  "Countersign that the holder of the key named in this record finished the cohort under this syllabus version.";

/** What the record does not prove — printed wherever one is made or signed. */
export const DOES_NOT_PROVE: readonly string[] = [
  "How well anyone learned. It carries no grade, score or rank, and proves no skill level.",
  "Who the holder is. It names a key their wallet made for this issuer alone, and a key is not a person.",
  "That these keys belong to those organisations. A charter, or a trust list the verifier pinned, says that — not this file.",
  "Who paid, or whether a seat was sponsored. That is never in the record.",
  "That a capstone exists or that a client accepted it. That is its own record.",
  "Attendance, effort or deviations.",
  "That it has not been withdrawn. Absence of a withdrawal cannot be proven offline.",
  "When it was signed. Signing times are the signers' own claims.",
];

/** What it does not protect (d62(d)3). */
export const DOES_NOT_PROTECT =
  "Showing it links its holder: every verifier shown this record sees the same bytes and the same holder key, so two verifiers can tell it is one person. Show it only where being recognised as its holder is fine.";

export function printCaveats(): void {
  process.stdout.write(`\n${c.bold("What this record does not prove")}\n`);
  for (const line of DOES_NOT_PROVE) step(line);
  step(DOES_NOT_PROTECT);
}

export interface PendingRecord {
  readonly bundle: CountersignBundle;
  readonly claim: CohortClaim;
}

/** A countersign bundle whose subject follows the cohort profile, or the reason it does not. */
export function readPendingRecord(value: unknown, where: string): PendingRecord {
  if (!isCountersignBundle(value)) {
    throw new KashCliError(`${where} is not a kashscript-countersign/1 bundle.`, "RECORD_INVALID");
  }
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64ToBytes(value.subject.payload)));
  } catch (err) {
    throw new KashCliError(`${where}: the subject payload is not readable JSON.`, "RECORD_INVALID", err);
  }
  const check = validateCohortClaim(json);
  if (check.claim === null) {
    throw new KashCliError(`${where} is not a cohort record: ${describeViolations(check.violations)}`, "RECORD_INVALID");
  }
  return { bundle: value, claim: check.claim };
}

export function describeViolations(violations: readonly CohortViolation[]): string {
  return violations.map((v) => `${v.code} at ${v.path} (${v.message})`).join("; ");
}
