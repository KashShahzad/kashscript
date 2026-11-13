/**
 * `kash countersign <link>` — the station countersigns a pending cohort record.
 *
 * Uses the ceremony's *carried* rendering (specs/countersign.md): the whole
 * request travels as bytes, so no server is involved. It signs with the
 * station's own key from `kash station init` — the DID a charter will name —
 * never a key made for the occasion (d62(d)2).
 *
 * What it will not do:
 *   - sign without showing what it is signing and getting a yes. A no writes
 *     nothing (d49: a decline leaves no trace);
 *   - sign a record that names a different station than the key it was given;
 *   - write a record that fails `verifyCohortRecord`.
 */

import { existsSync } from "node:fs";
import { createInterface } from "node:readline";

import { canonicalize } from "@kashscript/identity-core";
import { verifyCohortRecord } from "@kashscript/attest";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  decodeCompactCountersignRequest,
} from "@kashscript/identity-server";

import { describeViolations, printCaveats, readPendingRecord } from "../cohort";
import { KashCliError } from "../errors";
import { loadKey } from "../keystore/store";
import { readJsonFile, writeOutput } from "../utils/files";
import { banner, c, info, step, success, warn } from "../utils/output";

export interface CountersignOptions {
  /** The carried link, or the path of the pending record itself. */
  readonly link: string;
  /** The pending record, when `link` is the carried request. */
  readonly record?: string;
  readonly key?: string;
  readonly keystore?: string;
  readonly out?: string;
  /** Answer yes without asking. A script's way of saying the person already decided. */
  readonly yes?: boolean;
  /** How to ask, when there is a person to ask. Defaults to the terminal. A test's way to say no. */
  readonly prompt?: (question: string) => Promise<string>;
}

const DEFAULT_OUT = "cohort-record.json";
const BASE64URL = /^[A-Za-z0-9_-]+$/;

const REFUSALS: Record<string, string> = {
  REQUEST_EXPIRED: "The request has expired. The teacher's organisation needs to issue a new one.",
  REQUEST_NOT_YET_VALID: "The request is dated in the future by this machine's clock. Check the clock.",
  SUBJECT_MISMATCH: "The request does not describe this record.",
  ALREADY_COUNTERSIGNED: "This key has already signed this record. One organisation cannot countersign itself (d26).",
};

async function confirm(question: string, opts: CountersignOptions): Promise<boolean> {
  if (opts.yes === true) return true;
  let ask = opts.prompt;
  if (ask === undefined) {
    if (!process.stdin.isTTY) {
      throw new KashCliError("Not a terminal, so there is no one to ask. Pass --yes once a person has decided.", "INVALID_INPUT");
    }
    ask = (q) =>
      new Promise<string>((resolve) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        // Input that closes before an answer (a piped or hung-up stdin) is a no, not a hang.
        rl.once("close", () => resolve(""));
        rl.question(`${q} [y/N] `, (answer) => {
          resolve(answer);
          rl.close();
        });
      });
  }
  const answer = (await ask(question)).trim().toLowerCase();
  return answer === "y" || answer === "yes";
}

export async function runCountersign(opts: CountersignOptions): Promise<void> {
  banner("kash · countersign");

  // 1. The pending record, and the request it carries. A signing command does not guess its mode:
  //    a carried link is base64url (letters, digits, "-" and "_" — no dot, slash or backslash), and
  //    anything else is a path. A name that is both a valid link and a file that exists is the file.
  const isCarriedLink = BASE64URL.test(opts.link.trim()) && !existsSync(opts.link);
  let recordPath: string;
  if (isCarriedLink) {
    if (opts.record === undefined) {
      throw new KashCliError("A carried link describes the request, not the record. Pass the pending file too: --record <file>.", "INVALID_INPUT");
    }
    recordPath = opts.record;
  } else {
    if (!existsSync(opts.link)) {
      throw new KashCliError(`No file at ${opts.link}. Give the pending record's path, or the carried link with --record.`, "INVALID_INPUT");
    }
    if (opts.record !== undefined) {
      throw new KashCliError("<link> is already the pending record, so --record would be ignored. Give one or the other.", "INVALID_INPUT");
    }
    recordPath = opts.link;
  }
  const { bundle, claim } = readPendingRecord(readJsonFile(recordPath, "the pending record"), recordPath);

  if (isCarriedLink) {
    let carried;
    try {
      carried = decodeCompactCountersignRequest(opts.link.trim());
    } catch (err) {
      throw new KashCliError("That does not decode as a carried countersign request (and it is not a file that exists).", "LINK_INVALID", err);
    }
    if (canonicalize(carried) !== canonicalize(bundle.request)) {
      throw new KashCliError("That link is not the request inside this record. They were not made together.", "LINK_INVALID");
    }
  }

  // 2. Is this key the station the record names?
  const station = await loadKey(opts.key ?? "station", opts.keystore);
  if (claim.meta.station !== station.did) {
    throw new KashCliError(
      `This record names the station ${claim.meta.station}, but the key offered is ${station.did}. Nothing was signed.`,
      "WRONG_STATION",
    );
  }
  if (claim.meta.teacherOrg === station.did) {
    throw new KashCliError("The teacher's organisation and the station are the same key. One organisation cannot countersign itself (d26).", "WRONG_STATION");
  }

  // 2b. Not worth asking a person to sign what can no longer be signed.
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec > bundle.request.body.expiresAtUnix) {
    throw new KashCliError(REFUSALS["REQUEST_EXPIRED"] as string, "RECORD_INVALID");
  }

  // 3. Show what is being signed, and ask.
  info("You are about to countersign, as the station:");
  process.stdout.write(`  station (you)          : ${station.did}\n`);
  process.stdout.write(`  teacher's organisation : ${claim.meta.teacherOrg}  (already signed)\n`);
  process.stdout.write(`  holder                 : ${claim.actor.id}  (a key, not a person)\n`);
  process.stdout.write(`  syllabus               : ${claim.rule.id}, version ${claim.rule.version}\n`);
  process.stdout.write(`  syllabus sha-256       : ${claim.rule.hash}\n`);
  process.stdout.write(`  finished / expires     : ${claim.timestamp} / ${claim.meta.expiresAt}\n`);
  process.stdout.write(`  the request says       : ${bundle.request.body.statement}\n`);
  step("Your signature says the cohort was finished under this syllabus version — nothing about how well.");
  if (!(await confirm(`Countersign as ${c.bold(station.name)}?`, opts))) {
    info("Declined. Nothing was signed or written.");
    return;
  }

  // 4. Sign, assemble, and check what is about to be released.
  const accepted = await acceptCountersignRequest({
    request: bundle.request,
    subject: bundle.subject,
    signingKey: { did: station.did, publicKey: station.publicKey, privateKey: station.privateKey, custody: "subject-generated" },
  });
  if (!accepted.ok) {
    throw new KashCliError(REFUSALS[accepted.reason] ?? `Could not countersign: ${accepted.reason}.`, "RECORD_INVALID");
  }
  const finished = assembleCountersignBundle({
    subject: accepted.envelope,
    request: bundle.request,
    acceptances: [...bundle.acceptances, accepted.acceptance],
  });
  const report = await verifyCohortRecord(finished);
  if (!report.ok) {
    throw new KashCliError(
      `The finished record does not verify, so it was not written: ${describeViolations(report.violations) || "the signatures do not check out"}.`,
      "RECORD_INVALID",
    );
  }

  const out = writeOutput(opts.out ?? DEFAULT_OUT, JSON.stringify(finished, null, 2) + "\n");
  success(`Wrote the finished record: ${c.bold(out)}`);
  step(`Anyone checks it offline, with no key and no service: kash verify ${out}`);
  if (report.expired) warn("It is already past its expiry, so it no longer attests.");
  step("Nothing was uploaded. Delivery into a wallet is an online issuer's job (OpenID4VCI), not this command's.");
  printCaveats();
}
