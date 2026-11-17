#!/usr/bin/env node

/**
 * `kash` — the station kit (d59).
 *
 * Makes a station's own keys, issues a cohort record as a file, countersigns it
 * as the station, checks any record offline, signs a trust list with the
 * publisher key, and keeps the trust log. Local files only: no server, no
 * upload, no delivery into a wallet (the wallet receives only over OpenID4VCI,
 * from an issuer's own origin). Two commands go online, to public witnesses
 * only, and say so first: `log witness` and `log upgrade` (KS-Q4).
 *
 *   kash station init [--name station]        make a key in the keystore; print its DID
 *   kash issue cohort ...                     the teacher's organisation writes a pending record
 *   kash countersign <link>                   the station countersigns it → the finished record
 *   kash verify <file>                        attest's verifier, exit 0 / 1 / 2, never the network
 *   kash trust sign <file>                    sign a trust or status list with the publisher key
 *   kash log init|add|checkpoint|proof        the trust log, a folder any host mirrors
 *   kash log witness|upgrade                  ONLINE — a head's hash to OpenTimestamps / RFC 3161
 *   kash status | doctor                      the keystore · integration checks
 *   kash add <product> | rollback             the older project-integration commands
 */

import { Command } from "commander";

import { runAdd }      from "../commands/add";
import { runCountersign } from "../commands/countersign";
import { runDoctor }   from "../commands/doctor";
import { runIssueCohort } from "../commands/issue";
import { runLogAdd, runLogCheckpoint, runLogInit, runLogProof, runLogUpgrade, runLogWitness } from "../commands/log";
import { runRollback } from "../commands/rollback";
import { runStationInit } from "../commands/station";
import { runStatus }   from "../commands/status";
import { runTrustSign } from "../commands/trust";
import { runVerify }   from "../commands/verify";
import { KashCliError } from "../errors";
import { c, fail } from "../utils/output";
import { VERSION } from "../version";

const collect = (value: string, previous: string[]): string[] => [...previous, value];

async function main(): Promise<void> {
  const program = new Command();

  program
    .name("kash")
    .description("The station kit: a station's own keys, cohort records as files, offline verification, signed trust lists and the trust log. Local files only — no server, no upload; only `log witness` and `log upgrade` go online, to public witnesses.")
    .version(VERSION);

  /* ── station ──────────────────────────────────────────────────── */

  const station = program.command("station").description("A station's own keys.");
  station
    .command("init")
    .description("Make a key in your own keystore and print its DID. Never overwrites a key.")
    .option("--name <name>", "the key's name (default: station; use teacher, publisher, ...)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .action(async (opts: { name?: string; keystore?: string }) => {
      await runStationInit({
        ...(opts.name !== undefined ? { name: opts.name } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
      });
    });

  /* ── issue ────────────────────────────────────────────────────── */

  const issue = program.command("issue").description("Write a record as a file.");
  issue
    .command("cohort")
    .description("The teacher's organisation writes a pending cohort record (one of two signatures) and a carried countersign link.")
    .requiredOption("--holder <did>", "the relationship key the learner's wallet made for this issuer, bound at enrolment")
    .requiredOption("--station <did>", "the station's DID (public; its key is not needed here)")
    .requiredOption("--syllabus-id <id>", "where the syllabus is published (the teacher's organisation DID plus a path is recommended)")
    .requiredOption("--syllabus-version <version>", "the syllabus version the cohort followed")
    .requiredOption("--syllabus-file <path>", "the syllabus exactly as published; kash records the SHA-256 of its bytes")
    .requiredOption("--finished <iso>", "when the cohort finished, ISO-8601 UTC")
    .requiredOption("--expires <iso>", "when the record stops attesting, ISO-8601 UTC, after --finished (no default: it is yours to set)")
    .option("--org <label>", "the issuer's own label for itself")
    .option("--ttl-days <n>", "days the station has to countersign (default 14, at most 90; fractions allowed)", (v) => Number(v))
    .option("--key <name|path>", "the teacher's organisation's key (default: teacher)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .option("--out <file>", "where to write the pending record (default: cohort-record.pending.json)")
    .action(async (opts: {
      holder: string; station: string; syllabusId: string; syllabusVersion: string; syllabusFile: string;
      finished: string; expires: string; org?: string; ttlDays?: number; key?: string; keystore?: string; out?: string;
    }) => {
      await runIssueCohort({
        holder: opts.holder,
        station: opts.station,
        syllabusId: opts.syllabusId,
        syllabusVersion: opts.syllabusVersion,
        syllabusFile: opts.syllabusFile,
        finished: opts.finished,
        expires: opts.expires,
        ...(opts.org !== undefined ? { org: opts.org } : {}),
        ...(opts.ttlDays !== undefined ? { ttlDays: opts.ttlDays } : {}),
        ...(opts.key !== undefined ? { key: opts.key } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
        ...(opts.out !== undefined ? { out: opts.out } : {}),
      });
    });

  /* ── countersign ──────────────────────────────────────────────── */

  program
    .command("countersign <link>")
    .description("The station countersigns a pending cohort record with its own key. <link> is the carried link (with --record) or the pending file.")
    .option("--record <file>", "the pending record, when <link> is the carried link")
    .option("--key <name|path>", "the station's key (default: station)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .option("--out <file>", "where to write the finished record (default: cohort-record.json)")
    .option("--yes", "do not ask; a person has already decided")
    .action(async (link: string, opts: { record?: string; key?: string; keystore?: string; out?: string; yes?: boolean }) => {
      await runCountersign({
        link,
        ...(opts.record !== undefined ? { record: opts.record } : {}),
        ...(opts.key !== undefined ? { key: opts.key } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
        ...(opts.out !== undefined ? { out: opts.out } : {}),
        ...(opts.yes === true ? { yes: true } : {}),
      });
    });

  /* ── verify ───────────────────────────────────────────────────── */

  program
    .command("verify <file>")
    .description("Check a record, bundle, trust list or status list with attest's verifier. Offline; exit 0 PASS · 1 FAILED · 2 usage/IO.")
    .option("--trust-publisher <did>", "pin a publisher DID when the file is a trust list (repeatable)", collect, [] as string[])
    .option("--status-list <file>", "hand in a status list, offline (repeatable)", collect, [] as string[])
    // Usage errors exit 2, as attest's own CLI does (commander's default is 1).
    .exitOverride((err) => {
      process.exit(err.exitCode === 0 ? 0 : 2);
    })
    .action((file: string, opts: { trustPublisher: string[]; statusList: string[] }) => {
      runVerify({ file, trustPublishers: opts.trustPublisher, statusLists: opts.statusList });
    });

  /* ── trust ────────────────────────────────────────────────────── */

  const trust = program.command("trust").description("Trust and status lists.");
  trust
    .command("sign <file>")
    .description("Sign a trust list or status list with the publisher key; prints the signed file. Uploads nothing.")
    .option("--key <name|path>", "the publisher key (default: publisher — never the station's)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .option("--out <file>", "also write the signed file here")
    .action(async (file: string, opts: { key?: string; keystore?: string; out?: string }) => {
      await runTrustSign(file, {
        ...(opts.key !== undefined ? { key: opts.key } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
        ...(opts.out !== undefined ? { out: opts.out } : {}),
      });
    });

  /* ── log ──────────────────────────────────────────────────────── */

  const log = program
    .command("log")
    .description("The trust log: issuers and lists, and attestations by salted hash, in a folder any host serves and mirrors. Never a person or a record. Only witness and upgrade go online.");
  log
    .command("init <dir>")
    .description("Start a log whose key is the publisher key: writes log.json and the empty folders.")
    .requiredOption("--name <slug>", "the log's short name; its id is <publisher did>/log/<slug>")
    .option("--max-batch-delay <seconds>", "how long an entry may wait for its first witnessed head before its claimed time is not supported (default 86400)")
    .option("--origin <https-url>", "where you will serve the folder (or put it in log.json later)")
    .option("--key <name|path>", "the log's key (default: publisher — never the station's)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .action(async (dir: string, opts: { name: string; maxBatchDelay?: string; origin?: string; key?: string; keystore?: string }) => {
      await runLogInit(dir, {
        name: opts.name,
        ...(opts.maxBatchDelay !== undefined ? { maxBatchDelay: opts.maxBatchDelay } : {}),
        ...(opts.origin !== undefined ? { origin: opts.origin } : {}),
        ...(opts.key !== undefined ? { key: opts.key } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
      });
    });
  log
    .command("add <dir> <files...>")
    .description("Append a signed trust list's version and its key changes, a signed status list's version, or attestation entries (JSON or .jsonl). Checks the whole batch before writing any of it.")
    .option("--previous <file>", "the signed version of a trust list the log already holds, so the key changes to the next are logged (repeatable)", collect, [] as string[])
    .option("--trust-list <file>", "a signed trust list whose keys check a status list's signature (repeatable)", collect, [] as string[])
    .action(async (dir: string, files: string[], opts: { previous: string[]; trustList: string[] }) => {
      await runLogAdd(dir, files, { previous: opts.previous, trustList: opts.trustList });
    });
  log
    .command("checkpoint <dir>")
    .description("Sign the log's head with the publisher key. Its time is the log's own claim until a public witness stamps it.")
    .option("--key <name|path>", "the log's key (default: publisher)")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .action(async (dir: string, opts: { key?: string; keystore?: string }) => {
      await runLogCheckpoint(dir, {
        ...(opts.key !== undefined ? { key: opts.key } : {}),
        ...(opts.keystore !== undefined ? { keystore: opts.keystore } : {}),
      });
    });
  log
    .command("witness <dir>")
    .description("GOES ONLINE: send the newest head's 32-byte hash to public witnesses and keep their proofs in witness/.")
    .option("--size <n>", "witness the head of this size instead of the newest")
    .option("--no-ots", "skip OpenTimestamps, which runs by default")
    .option("--calendar <url>", "an OpenTimestamps calendar to submit to (repeatable; default the four public pools)", collect, [] as string[])
    .option("--tsa [url]", "also an RFC 3161 time-stamp authority: a second witness that fails differently (default http://timestamp.digicert.com)")
    .option("--tsa-root <pem>", "keep the authority's token only if its signature verifies against this root (needs openssl)")
    .action(async (dir: string, opts: { size?: string; ots?: boolean; calendar: string[]; tsa?: string | boolean; tsaRoot?: string }) => {
      await runLogWitness(dir, {
        ...(opts.size !== undefined ? { size: opts.size } : {}),
        ...(opts.ots === false ? { ots: false } : {}),
        calendar: opts.calendar,
        ...(opts.tsa === true ? { tsa: true as const } : typeof opts.tsa === "string" ? { tsa: opts.tsa } : {}),
        ...(opts.tsaRoot !== undefined ? { tsaRoot: opts.tsaRoot } : {}),
      });
    });
  log
    .command("upgrade <dir>")
    .description("GOES ONLINE: ask the calendars for the Bitcoin attestation each pending OpenTimestamps proof waits for.")
    .option("--calendar <url>", "a calendar a pending proof may be upgraded from (repeatable; default the four known)", collect, [] as string[])
    .action(async (dir: string, opts: { calendar: string[] }) => {
      await runLogUpgrade(dir, { calendar: opts.calendar });
    });
  log
    .command("proof <dir> <index>")
    .description("Print the inclusion proof for entry <index>: its path to the first head that held it, that head, and the head's witnesses. Offline.")
    .option("--size <n>", "prove against the head of this size instead")
    .option("--out <file>", "also write the proof here")
    .action(async (dir: string, index: string, opts: { size?: string; out?: string }) => {
      await runLogProof(dir, index, {
        ...(opts.size !== undefined ? { size: opts.size } : {}),
        ...(opts.out !== undefined ? { out: opts.out } : {}),
      });
    });

  /* ── status · doctor ──────────────────────────────────────────── */

  program
    .command("status")
    .description("Show the keystore (each key's DID and whether its file is still private to you) and the environment fingerprint.")
    .option("--keystore <dir>", "keystore folder (default: $KASH_KEYSTORE, else ~/.kash/keys)")
    .action(async (opts: { keystore?: string }) => {
      await runStatus(opts.keystore !== undefined ? { keystore: opts.keystore } : {});
    });

  program
    .command("doctor [product]")
    .description("Verify that one (or every) product is correctly integrated.")
    .option("--target <name>", "monorepo target workspace")
    .action(async (product: string | undefined, opts: { target?: string }) => {
      await runDoctor({
        ...(product !== undefined ? { product } : {}),
        ...(opts.target !== undefined ? { target: opts.target } : {}),
      });
    });

  /* ── add · rollback (older) ── */

  program
    .command("add <product>")
    .description("Install a product (identity | terms | muffler | whiffin). Dry-run by default.")
    .option("--apply",            "actually write changes (otherwise: dry run)")
    .option("--force",             "overwrite user-edited scaffold files AND replace non-object JSON intermediates (F1 escape hatch)")
    .option("--target <name>",     "monorepo target workspace (e.g., apps/kashscript) or 'shared'")
    .option("--skip-install",      "skip dependency install (still patches JSON)")
    .option("--create-tsconfig",   "opt in to auto-creating tsconfig.json when the project doesn't have one")
    .option("--verify",            "post-apply, run the project's typecheck/build; offer rollback on failure (F4)")
    .option("--manager <name>",    "force a specific package manager (bun | pnpm | yarn | npm); default: detected from lockfile")
    .action(async (product: string, opts: {
      apply?: boolean;
      force?: boolean;
      target?: string;
      skipInstall?: boolean;
      createTsconfig?: boolean;
      verify?: boolean;
      manager?: string;
    }) => {
      const manager = parseManager(opts.manager);
      await runAdd(product, {
        ...(opts.apply       === true ? { apply: true } : {}),
        ...(opts.force       === true ? { force: true } : {}),
        ...(opts.skipInstall === true ? { skipInstall: true } : {}),
        ...(opts.createTsconfig === true ? { createTsconfig: true } : {}),
        ...(opts.verify === true ? { verifyBuild: true } : {}),
        ...(manager !== undefined ? { manager } : {}),
        ...(opts.target !== undefined ? { target: opts.target } : {}),
      });
    });

  program
    .command("rollback [match]")
    .description("Restore files from the backup store. `kash rollback list` lists; pass <match> to restore.")
    .option("--list",                "list available backups (default when no args)")
    .option("--all-since <iso>",     "restore every backup taken at or after this ISO-8601 timestamp")
    .option("--yes",                 "confirm the restore (otherwise: dry-run preview)")
    .action(async (match: string | undefined, opts: { list?: boolean; allSince?: string; yes?: boolean }) => {
      const mode: "list" | "restore" = (opts.list || (!match && !opts.allSince)) ? "list" : "restore";
      await runRollback({
        mode,
        ...(match !== undefined ? { match } : {}),
        ...(opts.allSince !== undefined ? { allSince: opts.allSince } : {}),
        ...(opts.yes === true ? { yes: true } : {}),
      });
    });

  await program.parseAsync(process.argv);
}

function parseManager(raw: string | undefined): "bun" | "pnpm" | "yarn" | "npm" | undefined {
  if (raw === undefined) return undefined;
  const lower = raw.toLowerCase();
  if (lower === "bun" || lower === "pnpm" || lower === "yarn" || lower === "npm") return lower;
  throw new KashCliError(
    `Unknown --manager ${JSON.stringify(raw)}. Choose one of: bun, pnpm, yarn, npm.`,
    "INVALID_INPUT",
  );
}

main().catch((err) => {
  if (err instanceof KashCliError) {
    fail(`${err.message} ${c.gray(`(${err.code})`)}`);
    process.exit(1);
  }
  fail(`Unexpected error: ${(err as Error)?.stack ?? String(err)}`);
  process.exit(1);
});
