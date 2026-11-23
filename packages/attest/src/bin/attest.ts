#!/usr/bin/env node
/**
 * attest — the KashScript evidence-commons verifier CLI.
 *
 *   attest verify <file> [--key <hex|host-key.txt|jwks.json>] [--signer-did <did>] [--offline]
 *                        [--trust-publisher <did>]... [--check-status]
 *
 * Auto-detects and verifies OFFLINE: a countersign bundle (two signatures over
 * the same bytes — needs no --key at all) and a cohort record, which is one
 * checked against its profile as well, a holder export, a trust list, a
 * status list, a DSSE audit bundle (Oreoasis), an Every-Rupee report (Duedale),
 * an Indus token (IPOE1/IVFC1/IBPS1/IGEO1), and the trust log's checkpoint,
 * inclusion proof and consistency proof (KS-Q4). `attest log verify <dir>`
 * audits a whole log from its files. `--check-status` is the one flag that
 * touches the network: it fetches the status lists a holder export points at
 * and did not carry. Exit codes: 0 = PASS · 1 = verification FAILED (tamper) ·
 * 2 = usage/IO error · 3 = INTEGRITY ONLY (the file is consistent with itself,
 * but its only key came from inside it — pass --key; AU-3, A7-06). An RFC 3161
 * token's signature is openssl's, against the root `--tsa-root` names.
 */

import { readFileSync } from "node:fs";
import { isLogConsistencyProof, isLogInclusionProof, verifyCheckpoint, verifyLogConsistency, verifyLogInclusion, auditLog, DEFAULT_MAX_BATCH_DELAY_SEC, DST_LOG_CHECKPOINT, type CheckpointReport, type LogAuditReport, type LogConsistencyReport, type LogInclusionReport } from "../log";
import { readLogDirectory } from "../log/files";
import type { BitcoinHeader, WitnessVerdict } from "../witness/verdict";
import { opensslAvailable, opensslRfc3161Check, type OpensslCheck } from "./openssl";
import { hexToBytes } from "../chain";
import { TamperError } from "../errors";
import { verifyAuditBundle, type AuditBundleVerifyReport } from "../bundle";
import type { DsseEnvelope } from "../dsse";
import {
  verifyDuedaleReport,
  type DuedaleReportVerifyReport,
  type SignedReport,
} from "../compat/duedale-report";
import {
  verifyIndusToken,
  verifyIndusTokenWithJwks,
  type IndusVerifyResult,
  type Jwks,
} from "../compat/indus-token";
import {
  isCountersignBundle,
  verifyCountersignBundle,
  type CountersignVerifyReport,
} from "../countersign";
import {
  DST_STATUS_LIST,
  DST_TRUST_LIST,
  fetchStatusLists,
  isHolderExport,
  makeKeyResolver,
  verifyHolderExport,
  verifyStatusList,
  verifyTrustList,
  type FetchLike,
  type HolderExportReport,
  type StatusListReport,
  type TrustListReport,
} from "../holder";
import { isSdJwt, verifySdJwt, type SdJwtReport } from "../sd-jwt";
import { ATTESTATION_VCT, NOT_DISCLOSED, shownOnPage, viewOfCopy, type PageView } from "../attestation";
import { COHORT_PROFILE, isCohortRecord, verifyCohortRecord, type CohortRecordReport } from "../profiles";
import {
  ASK_FORMAT,
  PREDICATE_VCT,
  THANK_YOU_VCT,
  isSessionReceipt,
  validateAsk,
  verifyPredicatePresentation,
  verifyRedemption,
  verifySessionReceipt,
  verifyThankYou,
  type AskViolation,
  type PredicatePresentationReport,
  type SessionReceiptReport,
  type ThankYouReport,
} from "../exchange";
import { statusEntryOf } from "../holder/status-list";
import {
  plainAsk,
  plainBundle,
  plainCheckpoint,
  plainCohort,
  plainCountersign,
  plainHolderExport,
  plainIndus,
  plainLines,
  plainLogAudit,
  plainLogConsistency,
  plainLogInclusion,
  plainPredicate,
  plainReport,
  plainSdJwt,
  plainSession,
  plainStatusList,
  plainTamper,
  plainThankYou,
  plainTrustList,
  plainAttestationCopy,
  type PlainLayer,
} from "./plain";

const USAGE = `attest — the KashScript evidence-commons verifier

Usage:
  attest verify <file> [--key <hex|host-key.txt|jwks.json>] [--signer-did <did>] [--offline]
                       [--trust-publisher <did>]... [--check-status]
                       [--audience <id>] [--nonce <n>] [--at <unix>] [--max-age <s>]
                       [--status-list <file>]... [--artifact <file>]
                       [--header <file>]... [--tsa-root <pem>] [--max-batch-delay <s>]
  attest log verify <dir> [--mirror <dir>] [--header <file>]... [--tsa-root <pem>]

A presentation is made to one verifier: check it with --audience and --nonce,
the identifier you are and the nonce you sent. Its binding must be no further
than --max-age seconds (default 600) from now, or from --at, the time you
received it, for a file you check later.

An attestation copy (a receipt's copy: held, presented, or a page's) prints its
class and what its holder disclosed. --artifact hands in the record it is a copy
of — the countersigned record, or the attestation record of truth. The artefact
is shown only when the copy discloses its record and that record names the
file: the page's rule (RW-15). Without the disclosure it is simply not shown.

The trust log (KS-Q4): a checkpoint, an inclusion proof and a consistency
proof are auto-detected. --header hands in a Bitcoin block header for an
OpenTimestamps witness ({height, header}, as A-List's anchors/headers/ keep
them). --tsa-root names the root an RFC 3161 witness must chain to; openssl
checks the signature, and its fingerprint is printed. --max-batch-delay is the
log's allowance between a claimed time and its first witness (default 86400;
the log's log.json states its own).

Auto-detected, verified offline:
  - Countersign bundle  (two signatures over the same bytes; needs NO --key,
                         every public key is inside the did:kash identifiers)
  - Cohort record       (a countersign bundle whose work record names the cohort
                         profile; checked against the profile too)
  - Holder export       (a wallet's records, manifests, key succession, trust
                         and status lists; needs NO --key)
  - Trust list          (who a wallet admits; pin its publisher with --trust-publisher)
  - Status list         (an issuer's revocation bitstring)
  - SD-JWT              (a predicate or thank-you, held or presented; check a
                         presentation against the --audience and --nonce you sent)
  - Attestation copy    (a receipt's copy; with --artifact, whether the disclosed
                         record names the file — shown to the holder of the disclosure)
  - Session receipt     (both parties' signatures on every line; pending or complete)
  - Ask                 (the eight rules and the forbidden needs)
  - Log checkpoint      (the trust log's signed head)
  - Inclusion proof     (one entry in a signed head, its witnesses, its time)
  - Consistency proof   (a later head keeps every entry of an earlier one)
  - DSSE audit bundle   (Oreoasis: { payloadType, payload, signatures })
  - Every-Rupee report  (Duedale:  { report, signature, operatorPublicKeyHex })
  - Indus token         (IPOE1/IVFC1/IBPS1/IGEO1 - requires --key)

--check-status is the only flag that touches the network: it fetches the status
lists an export or a credential points at but did not carry. --status-list hands
one in instead, offline.

Every verdict is followed, just before RESULT, by three plain lines: who signed,
what was checked, and what this does not prove. A PASS is never read alone.

Exit: 0 = PASS | 1 = verification FAILED (tamper) | 2 = usage/IO error
      3 = INTEGRITY ONLY — a DSSE audit bundle or Every-Rupee report checked with no
          --key: consistent with itself, but its only key came from inside the file`;

/** One line under a key claim: which authority moved the key, and across which algorithms (PL-2). */
function printClaimDetail(c: {
  readonly path?: string;
  readonly priorKeyType?: string | null;
  readonly successorKeyType?: string | null;
  readonly helpers?: { readonly need: number; readonly of: number; readonly counted: number } | null;
  readonly reason?: string | null;
}): void {
  const by = c.path === "helpers" && c.helpers ? `helpers, ${c.helpers.counted} of ${c.helpers.of} signed (need ${c.helpers.need})` : "the prior key";
  const algs = `${c.priorKeyType ?? "?"} → ${c.successorKeyType ?? "?"}`;
  out(`    by               : ${by} · ${algs}${c.reason ? ` · ${c.reason}` : ""}`);
}

function out(line: string): void {
  process.stdout.write(line + "\n");
}
/** The checker's plain layer (law 9): who signed, what was checked, what this does not prove. Always just before RESULT. */
function printPlain(layer: PlainLayer, ok: boolean): void {
  for (const l of plainLines(layer, ok)) out(l);
}
function die(code: number, msg: string): never {
  process.stderr.write(msg + "\n");
  process.exit(code);
}

const HEX64 = /^[0-9a-fA-F]{64}$/;
function readKeyBytes(key: string): Uint8Array {
  const txt = HEX64.test(key) ? key : readFileSync(key, "utf8").trim().split(/\s+/).pop()!;
  return hexToBytes(txt.toLowerCase());
}

interface Args {
  /** `verify <file>`, or `log verify <dir>`. */
  readonly command: "verify" | "log-verify";
  readonly file: string;
  readonly key?: string;
  readonly signerDid?: string;
  readonly trustPublishers: readonly string[];
  readonly checkStatus: boolean;
  readonly audience?: string;
  readonly nonce?: string;
  readonly statusListFiles: readonly string[];
  /** Check as of this unix time — for a presentation checked after it was received. */
  readonly at?: number;
  /** A presentation's binding window, seconds. */
  readonly maxAge?: number;
  /** The record an attestation copy is a copy of — shown only to the holder of its disclosure (RW-15). */
  readonly artifact?: string;
  readonly headerFiles: readonly string[];
  readonly tsaRoot?: string;
  readonly maxBatchDelay?: number;
  readonly mirror?: string;
}
function parseArgs(argv: readonly string[]): Args {
  let command: Args["command"];
  let file: string;
  let start: number;
  if (argv[0] === "verify" && argv[1] !== undefined) {
    command = "verify";
    file = argv[1];
    start = 2;
  } else if (argv[0] === "log" && argv[1] === "verify" && argv[2] !== undefined) {
    command = "log-verify";
    file = argv[2];
    start = 3;
  } else {
    die(2, USAGE);
  }
  let key: string | undefined;
  let signerDid: string | undefined;
  let audience: string | undefined;
  let nonce: string | undefined;
  let at: number | undefined;
  let maxAge: number | undefined;
  let tsaRoot: string | undefined;
  let maxBatchDelay: number | undefined;
  let mirror: string | undefined;
  let artifact: string | undefined;
  const trustPublishers: string[] = [];
  const statusListFiles: string[] = [];
  const headerFiles: string[] = [];
  let checkStatus = false;
  const need = (flag: string, v: string | undefined): string => (v === undefined ? die(2, `${flag} needs a value\n\n${USAGE}`) : v);
  const seconds = (flag: string, v: string | undefined): number => {
    const n = Number(need(flag, v));
    return Number.isSafeInteger(n) && n >= 0 ? n : die(2, `${flag} takes a whole number of seconds\n\n${USAGE}`);
  };
  for (let i = start; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--key") key = argv[++i];
    else if (a === "--signer-did") signerDid = argv[++i];
    else if (a === "--trust-publisher") trustPublishers.push(need(a, argv[++i]));
    else if (a === "--audience") audience = need(a, argv[++i]);
    else if (a === "--nonce") nonce = need(a, argv[++i]);
    else if (a === "--status-list") statusListFiles.push(need(a, argv[++i]));
    else if (a === "--check-status") checkStatus = true;
    else if (a === "--at") at = seconds(a, argv[++i]);
    else if (a === "--max-age") maxAge = seconds(a, argv[++i]);
    else if (a === "--header") headerFiles.push(need(a, argv[++i]));
    else if (a === "--tsa-root") tsaRoot = need(a, argv[++i]);
    else if (a === "--max-batch-delay") maxBatchDelay = seconds(a, argv[++i]);
    else if (a === "--mirror") mirror = need(a, argv[++i]);
    else if (a === "--artifact") artifact = need(a, argv[++i]);
    else if (a === "--offline") continue; // verify never touches the network unless --check-status asks
    else die(2, `unknown argument: ${a}\n\n${USAGE}`);
  }
  return {
    command,
    file,
    ...(key !== undefined ? { key } : {}),
    ...(signerDid !== undefined ? { signerDid } : {}),
    ...(audience !== undefined ? { audience } : {}),
    ...(nonce !== undefined ? { nonce } : {}),
    ...(at !== undefined ? { at } : {}),
    ...(maxAge !== undefined ? { maxAge } : {}),
    ...(artifact !== undefined ? { artifact } : {}),
    ...(tsaRoot !== undefined ? { tsaRoot } : {}),
    ...(maxBatchDelay !== undefined ? { maxBatchDelay } : {}),
    ...(mirror !== undefined ? { mirror } : {}),
    trustPublishers,
    checkStatus,
    statusListFiles,
    headerFiles,
  };
}

/** Bitcoin block headers from files shaped as A-List's anchors/headers/<height>.json: {height, header}, or a list of them. */
function loadHeaders(files: readonly string[]): BitcoinHeader[] {
  const out: BitcoinHeader[] = [];
  for (const f of files) {
    let j: unknown;
    try {
      j = JSON.parse(readFileSync(f, "utf8"));
    } catch (e) {
      die(2, `cannot read ${f}: ${(e as Error).message}`);
    }
    for (const h of Array.isArray(j) ? j : [j]) {
      const r = h as { height?: unknown; header?: unknown };
      if (typeof r.height !== "number" || typeof r.header !== "string") die(2, `${f}: a header file is {height, header}, or a list of them`);
      out.push({ height: r.height, headerHex: r.header.toLowerCase() });
    }
  }
  return out;
}

/** The RFC 3161 signature check `--tsa-root` asks for, or null; says plainly when openssl is missing. */
function rfc3161CheckFor(args: Args): OpensslCheck | null {
  if (args.tsaRoot === undefined) return null;
  if (!opensslAvailable()) {
    out("note               : --tsa-root was given but openssl is not on this machine — RFC 3161 signatures stay unchecked");
    return null;
  }
  try {
    return opensslRfc3161Check(args.tsaRoot);
  } catch (e) {
    die(2, `--tsa-root: ${(e as Error).message}`);
  }
}

function printWitness(w: WitnessVerdict): void {
  out(`  witness            : ${w.kind} — ${w.state}${w.timeUnix !== null ? `, ${iso(w.timeUnix)}` : ""} — ${w.by}`);
  out(`    detail           : ${w.detail}`);
}

function printCheckpoint(r: CheckpointReport): void {
  out(`Trust log checkpoint`);
  out(`  log                : ${r.logId ?? "unknown"}`);
  out(`  signature          : ${r.ok ? "ok" : `FAIL (${r.reason})`} — by ${r.key ?? "unknown"}, the key inside the log id`);
  out(`  tree size          : ${r.treeSize ?? "?"}`);
  out(`  root               : ${r.rootHash ?? "?"}`);
  out(`  log's own time     : ${iso(r.timestampUnix)} — a claim until a public witness stamps it`);
  out(`  previous head      : ${r.previous === null ? "none — the first" : `${r.previous.treeSize} entries, ${r.previous.rootHash}`}`);
  out(`  witness digest     : ${r.payloadSha256 ?? "?"} — what a public witness stamps`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainCheckpoint(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printLogInclusion(r: LogInclusionReport, rfc: OpensslCheck | null, allowance: number): void {
  out(`Trust log inclusion proof`);
  out(`  log                : ${r.logId ?? "unknown"}`);
  out(`  entry              : ${r.entry?.kind ?? "?"} — leaf ${r.leafIndex ?? "?"} of ${r.treeSize ?? "?"}`);
  out(`  in the log         : ${r.included ? "yes — its own path reaches the root the log's key signed" : "NO"}`);
  out(`  checkpoint         : ${r.checkpoint === null ? "not read" : r.checkpoint.ok ? "signed by the log's own key" : `FAIL (${r.checkpoint.reason})`}`);
  for (const w of r.witnesses) printWitness(w);
  if (rfc !== null) out(`  tsa root           : sha256 ${rfc.rootSha256} — compare it with the authority's published fingerprint`);
  if (r.time !== null) {
    out(`  claimed            : ${iso(r.time.claimedAtUnix)}${r.time.backfilled ? " (backfilled — logged after the log began, about something before it)" : r.time.backfillRefused ? " (marked backfilled, but the log had begun by then — judged as any other entry)" : ""}`);
    out(`  attested           : ${r.time.attestedAtUnix === null ? `none — ${r.time.state}` : `existed by ${iso(r.time.attestedAtUnix)}, ${r.time.by}`}`);
    out(`  first head         : ${r.time.firstHead ? "yes — its witness is the entry's first" : "no — a later head; the claimed time is not judged"}`);
    out(`  allowance          : ${allowance} s between a claimed time and its first witness`);
    if (r.time.fault !== null) out(`  time               : ${r.time.fault} — the claimed time is not supported; the attested time stands`);
  }
  if (r.reason !== null) out(`  reason             : ${r.reason}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainLogInclusion(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printLogConsistency(r: LogConsistencyReport): void {
  out(`Trust log consistency proof`);
  out(`  log                : ${r.logId ?? "unknown"}`);
  out(`  heads              : ${r.first?.treeSize ?? "?"} → ${r.second?.treeSize ?? "?"}`);
  out(`  consistent         : ${r.consistent ? "yes — the later head keeps every entry of the earlier one, in order" : "NO"}`);
  if (r.reason !== null) out(`  reason             : ${r.reason}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainLogConsistency(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printLogAudit(r: LogAuditReport, rfc: OpensslCheck | null): void {
  out(`Trust log (${r.entries} entries)`);
  out(`  log                : ${r.logId ?? "unknown"}`);
  out(`  key                : ${r.key ?? "unknown"}`);
  for (const c of r.checkpoints) {
    out(`  head ${String(c.treeSize).padEnd(14)}: root ${c.rootMatches ? "rebuilt from the entries" : "DOES NOT MATCH the entries"}; ${c.consistentWithPrevious === null ? "the first held" : c.consistentWithPrevious ? "extends the head before it" : "DOES NOT extend the head before it"}; log's time ${iso(c.timestampUnix)}; attested ${c.attestedAtUnix === null ? "—" : iso(c.attestedAtUnix)}`);
    for (const w of c.witnesses) printWitness(w);
  }
  if (rfc !== null) out(`  tsa root           : sha256 ${rfc.rootSha256} — compare it with the authority's published fingerprint`);
  for (const f of r.faults) out(`  fault              : ${f.code}${f.at !== null ? ` at ${f.at}` : ""} — ${f.detail}`);
  for (const t of r.timeFindings) out(`  time               : entry ${t.index} (${t.kind}) — ${t.fault}: ${t.text}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainLogAudit(r), r.ok);
  out(`RESULT: ${r.ok ? (r.timeFindings.length === 0 ? "PASS" : `PASS — the log is whole; ${r.timeFindings.length} entr${r.timeFindings.length === 1 ? "y's" : "ies'"} claimed time not supported`) : "FAIL"}`);
}

const iso = (unix: number | null): string => (unix === null ? "never" : new Date(unix * 1000).toISOString().replace(".000Z", "Z"));

function printTrustList(r: TrustListReport, heading = true): void {
  if (heading) out(`Trust list`);
  out(`  list               : ${r.listId ?? "unknown"} v${r.version ?? "?"}`);
  out(`  publisher          : ${r.publisher ?? "unknown"} — ${r.pinned ? "pinned" : "NOT pinned: lists nobody here"}`);
  out(`  signature          : ${r.ok ? "ok" : `FAIL (${r.reason})`}`);
  out(`  window             : ${r.current ? "current" : "not current"} (until ${iso(r.validUntilUnix)})`);
  if (r.ok) out(`  issuers            : ${r.issuers.length}`);
  for (const n of r.notes) out(`  note               : ${n}`);
}

function printStatusList(r: StatusListReport, heading = true): void {
  if (heading) out(`Status list`);
  out(`  list               : ${r.id ?? "unknown"} (${r.statusPurpose ?? "?"}, ${r.source})`);
  out(`  issuer             : ${r.issuer ?? "unknown"}${r.issuerKeySource ? ` via ${r.issuerKeySource}` : ""}`);
  out(`  signature          : ${r.ok ? "ok" : `FAIL (${r.reason})`}`);
  if (r.ok) out(`  entries            : ${r.entries}, as of ${iso(r.issuedAtUnix)}`);
  for (const n of r.notes) out(`  note               : ${n}`);
}

function printHolderExport(r: HolderExportReport): void {
  out(`Holder export (${r.records.length} record(s), exported ${iso(r.exportedAtUnix)})`);
  out(`  canonical bytes    : ${r.canonical === null ? "not checked" : r.canonical ? "yes" : "no"}`);
  out(`  network            : ${r.network}`);
  for (const t of r.trustLists) printTrustList(t, false);
  for (const s of r.statusLists) printStatusList(s, false);
  for (const c of r.keySuccession) {
    out(`  key succession     : ${c.priorDid} → ${c.successorDid} (${c.ok ? "ok" : "FAIL"})`);
    printClaimDetail(c);
  }
  for (const h of r.recoveryHelpers ?? []) {
    out(`  recovery helpers   : ${h.subjectDid ?? "?"} — ${h.need ?? "?"} of ${h.of ?? "?"}, sequence ${h.sequence ?? "?"} (${h.ok ? "ok" : `FAIL ${h.reason}`})`);
  }
  for (const c of r.successionConflicts ?? []) {
    out(`  CONFLICT           : ${c.priorDid} → ${c.successors.join(" | ")} — neither is trusted`);
  }
  out(`  encrypted backup   : ${r.encryptedKeyBackup}`);
  for (const rec of r.records) {
    out(`  record ${rec.recordId.slice(0, 12)}  ${(rec.tag ?? "unknown").replace(/\n$/, "\\n")}`);
    const via = rec.keySources.map((k) => k.source).join(", ") || "no key";
    out(`    signature        : ${rec.signatureOk ? "ok" : "FAIL"} (${via})`);
    out(
      `    kind             : ${rec.attestation ?? "unknown"}` +
        (rec.attestation === "device-asserted" ? " — the holder's own device; never countersigned" : ""),
    );
    // "Listed" is printed only for a pinned list. An unlisted issuer is never shown as trusted.
    out(
      `    issuer           : ${rec.issuer ?? "unknown"} — ` +
        (rec.trusted ? `listed (${rec.listing.label}, ${rec.listing.listId} v${rec.listing.version})` : "UNLISTED"),
    );
    out(`    status           : ${rec.status.text}`);
    out(`    kept until       : ${iso(rec.retention.expiresAtUnix)} (${rec.retention.source ?? "?"})`);
    for (const reason of rec.reasons) out(`    reason           : ${reason}`);
    for (const n of rec.notes) out(`    note             : ${n}`);
  }
  for (const reason of r.reasons) out(`  reason             : ${reason}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainHolderExport(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printKeyBinding(sd: SdJwtReport): void {
  const kb = sd.keyBinding;
  if (!kb.present) {
    out(`  holder binding     : none — a held credential proves nothing about who shows it`);
    return;
  }
  out(`  holder binding     : ${kb.signatureOk && kb.sdHashOk ? "ok" : "FAIL"} (relationship ${sd.holder ?? "unknown"})`);
  out(`  audience           : ${kb.audience ?? "none"}${kb.audienceOk === null ? " (not checked — pass --audience)" : kb.audienceOk ? " — matches" : " — DOES NOT MATCH"}`);
  out(`  nonce              : ${kb.nonceOk === null ? "not checked — pass --nonce" : kb.nonceOk ? "matches" : "DOES NOT MATCH"}`);
}

function printPredicate(r: PredicatePresentationReport): void {
  out(`Predicate presentation`);
  out(`  issuer             : ${r.issuer ?? "unknown"}${r.sdJwt.issuerKeySource ? ` via ${r.sdJwt.issuerKeySource}` : ""} — ${r.trusted ? "listed" : "UNLISTED"}`);
  printKeyBinding(r.sdJwt);
  if (r.predicate !== null) {
    out(`  answer             : ${r.predicate.answer ? "yes" : "no"} — ${r.predicate.kind}`);
    out(`  judged against     : rule ${r.predicate.rule.id} version ${r.predicate.rule.version}`);
    out(`  window             : ${r.predicate.window.from} → ${r.predicate.window.to}`);
  }
  out(`  record hashes      : ${r.disclosedRecordHashes.length === 0 ? "none disclosed" : `${r.disclosedRecordHashes.length} disclosed by the holder`}`);
  for (const a of r.attachments) out(`  attached record    : ${a.recordId.slice(0, 12)} — ${a.bound ? "one the answer rests on" : "NOT one the answer rests on"}`);
  out(`  status             : ${r.status.text}`);
  if (r.reason !== null) out(`  reason             : ${r.reason}${r.sdJwt.reason ? ` (${r.sdJwt.reason})` : ""}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainPredicate(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printThankYou(r: ThankYouReport, presented: boolean): void {
  out(presented ? `Thank-you redemption` : `Thank-you`);
  out(`  given by           : ${r.issuer ?? "unknown"}`);
  out(`  for                : ${r.for === null ? "unknown" : r.for.act === "answered-ask" ? `answering ${r.for.ask}` : `confirming ${r.for.session}`} — never the answer`);
  out(`  value              : ${r.value ?? "unknown"}`);
  out(`  redeemed at        : ${r.redeemAt ?? "unknown"}`);
  out(`  bound to           : ${r.holder ?? "nobody"} — cannot be passed on`);
  if (presented) {
    const kb = r.sdJwt.keyBinding;
    out(`  holder binding     : ${kb.signatureOk && kb.sdHashOk ? "ok — signed by the holder's key" : "FAIL"}`);
    out(`  presented to       : ${kb.audience ?? "nobody"} — ${kb.audience !== null && kb.audience === r.issuer ? "its own issuer" : "NOT its issuer"}`);
    out(`  nonce              : ${kb.nonceOk === null ? "not checked — pass --nonce" : kb.nonceOk ? "matches" : "DOES NOT MATCH"}`);
  }
  out(`  status             : ${r.status.text}`);
  out(`  expires            : ${iso(r.expiresAtUnix)}`);
  if (r.reason !== null) out(`  reason             : ${r.reason}${r.sdJwt.reason ? ` (${r.sdJwt.reason})` : ""}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainThankYou(r, presented), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

/** An attestation copy: its class, what the holder disclosed, and — with --artifact — the page's rule applied (RW-15). */
function printAttestationCopy(r: SdJwtReport, page: PageView | null, ok: boolean): void {
  out(`Attestation copy (${r.vct ?? "unknown type"})`);
  out(`  issuer             : ${r.issuer ?? "unknown"}${r.issuerKeySource ? ` via ${r.issuerKeySource}` : ""}`);
  printKeyBinding(r);
  if (r.claims !== null) {
    const v = viewOfCopy(r.claims);
    out(`  attests            : ${v.kind} — ${v.outcome}${v.profile !== undefined ? `, ${v.profile}` : ""}${v.grade !== undefined ? `, grade ${v.grade}` : ""}${v.practice === true ? " (practice)" : ""}`);
    out(`  issued             : ${typeof r.claims.iat === "number" ? iso(r.claims.iat) : "unknown"} — the copy's own day, not the record's`);
    out(`  expires            : ${v.expiresAt}`);
    const disclosed = r.disclosed.map((d) => String(d.path[0]));
    out(`  disclosed          : ${disclosed.length === 0 ? "nothing beyond the class" : [...new Set(disclosed)].join(", ")}`);
    out(`  record             : ${v.record !== undefined ? `${v.record.slice(0, 12)}… (disclosed by the holder)` : "not disclosed"}`);
  }
  if (page !== null) {
    out(`  artefact           : ${page.shown !== null ? page.why : page.view?.record === undefined ? `not shown — ${NOT_DISCLOSED}` : `DOES NOT MATCH — ${page.why}`}`);
  }
  if (r.reason !== null) out(`  reason             : ${r.reason}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainAttestationCopy(r, page), ok);
  out(`RESULT: ${ok ? "PASS" : "FAIL"}`);
}

function printSdJwt(r: SdJwtReport): void {
  out(`SD-JWT (${r.vct ?? "unknown type"})`);
  out(`  issuer             : ${r.issuer ?? "unknown"}${r.issuerKeySource ? ` via ${r.issuerKeySource}` : ""}`);
  printKeyBinding(r);
  if (r.reason !== null) out(`  reason             : ${r.reason}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainSdJwt(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

function printSession(r: SessionReceiptReport): void {
  out(`Session receipt (${r.profile ?? "unknown profile"}, ${r.events.length} line(s))`);
  out(`  state              : ${r.state === "complete" ? "complete — every line signed by both" : "PENDING — not proof"}`);
  if (r.parties !== null) {
    out(`  establishment      : ${r.parties.establishment}`);
    out(`  person             : ${r.parties.person}`);
  }
  for (const e of r.events) {
    out(`  line ${String(e.seq).padEnd(3)}           : ${e.kind ?? "?"} by ${e.by ?? "?"} — ${e.bothSigned ? "both signed" : `signed by ${e.signers.join(", ") || "nobody"} only`}`);
  }
  out(`  total              : ${r.total === null ? "not closed" : `${r.total.amount} ${r.total.currency} over ${r.lineItemCount} hashed line item(s)`}`);
  out(`  anchor             : ${r.anchor === null ? "none" : `${r.anchor.backend}, covers lines 0–${r.anchor.coversSeq} — ${r.anchor.matches ? "matches" : "DOES NOT MATCH"}`}`);
  if (r.anchor !== null) out(`  batch              : ${batchLine(r.anchor)}`);
  out(`  expires            : ${iso(r.expiresAtUnix)}`);
  for (const f of r.faults) out(`  fault              : ${f.fault}${f.seq !== null ? ` at line ${f.seq}` : ""}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainSession(r), r.ok);
  out(`RESULT: ${r.ok ? (r.proof ? "PASS" : "PASS (pending — not proof)") : "FAIL"}`);
}

/**
 * A session anchor's place in its batch (GP-6). The path is checked against the root the anchor itself
 * names, so the line says what stands behind that root: no witness, a witness naming it, or one naming nothing.
 */
function batchLine(a: NonNullable<SessionReceiptReport["anchor"]>): string {
  const inc = a.inclusion;
  if (inc === undefined) return "not checked — the anchor carries no inclusion proof this verifier reads";
  if (inc.treeSize === null || inc.leafIndex === null || inc.root === null) return "an inclusion proof that cannot be read — DOES NOT MATCH";
  const claim = `leaf index ${inc.leafIndex} in a batch of ${inc.treeSize}`;
  if (!inc.included) return `claims ${claim} — its path DOES NOT reach the root this anchor names`;
  if (inc.witnessNamesRoot === false) return `${claim} — the witness receipt names a DIFFERENT root`;
  const behind =
    a.backend === "none"
      ? "no public log witnessed that root"
      : inc.witnessNamesRoot === null
        ? `its ${a.backend} receipt names no root, so that a log witnessed it is not checked`
        : `its ${a.backend} receipt names that root; the log itself is not checked here`;
  return `${claim} — its own path reaches the root this anchor names; ${behind}; this file holds no other session's id, head or lines`;
}

function printAsk(key: unknown, violations: readonly AskViolation[]): void {
  out(`Ask (${typeof key === "string" ? key : "no key"})`);
  if (violations.length === 0) out(`  rules              : all eight hold; no forbidden need`);
  for (const v of violations) out(`  ${v.rule.padEnd(19)}: ${v.path} — ${v.message}`);
  printPlain(plainAsk(), violations.length === 0);
  out(`RESULT: ${violations.length === 0 ? "PASS" : "FAIL"}`);
}

function printBundle(r: AuditBundleVerifyReport, keyGiven: boolean): void {
  out(`DSSE audit bundle`);
  out(`  dsse signature     : ${r.dsseOk ? "ok" : "FAIL"} (signers: ${r.dsseVerifiedKeyids.join(", ") || "none"})`);
  out(`  required signer    : ${r.requiredSignerVerified ? "ok" : "FAIL"}`);
  out(`  hash-chain         : ok (${r.forensic.rowCount} row(s))`);
  out(`  anchor             : ${r.anchorPresent ? `present — root ${r.anchorRootMatches ? "ok" : "FAIL"}, binds-chain ${r.anchorBindsChain ? "ok" : "FAIL"}` : "none (locally tamper-evident only)"}`);
  const w = r.anchor?.witness;
  if (w) out(`  witness            : ${w.backend}${w.backend !== "none" ? " — confirm with rekor-cli / ots verify" : ""}`);
  // A key from inside the file names a claimant, not a signer: the plain layer says "claims signed by".
  printPlain(plainBundle(r, keyGiven), r.ok && !r.selfAsserted);
  out(`RESULT: ${r.ok ? (r.selfAsserted ? INTEGRITY_ONLY : "PASS") : "FAIL"}`);
}

/** AU-3 (A7-06): a file whose only key came from inside itself is consistent with itself — and that is all the exit code may say. */
const INTEGRITY_ONLY = "INTEGRITY ONLY — the signer's key came from the file; pass --key <did> <hex> (or --key <hex>) to check who signed";
const exitFor = (ok: boolean, selfAsserted: boolean): number => (ok ? (selfAsserted ? 3 : 0) : 1);

function printReport(r: DuedaleReportVerifyReport, keyGiven: boolean): void {
  out(`Every-Rupee report (${r.reportId})`);
  out(`  envelope signature : ${r.signatureOk ? "ok" : "FAIL"}`);
  out(`  hash-chain         : ${r.chain.ok ? "ok" : "FAIL"} (${r.chain.transitionCount} transition(s))`);
  out(`  operator key       : ${r.operatorPublicKeyHex.slice(0, 16)}… (confirm out of band)`);
  printPlain(plainReport(r, keyGiven), r.ok && keyGiven);
  out(`RESULT: ${r.ok ? (keyGiven ? "PASS" : INTEGRITY_ONLY) : "FAIL"}`);
}

function printCountersignLines(r: CountersignVerifyReport): void {
  out(`Countersign bundle (${r.requestId ?? "no request id"})`);
  out(`  request signature  : ${r.requestSignatureOk ? "ok" : "FAIL"} (requester: ${r.requesterDid ?? "unknown"})`);
  out(`  subject            : ${r.subjectPayloadType ?? "unknown"}`);
  out(`  signatures on it   : ${r.independentSignatureCount} distinct key(s) over the same bytes`);
  out(`  two-signature proof: ${r.twoSignatureProof ? "yes" : "NO — one-sided claim, not proof"}`);
  for (const a of r.acceptances) {
    out(`  countersigned by   : ${a.countersignerDid}${a.independent ? "" : "  (the requester's own key — a signature, not a countersignature)"}`);
    out(`    signature        : ${a.acceptanceSignatureOk && a.countersignedSubject ? "ok" : "FAIL"}`);
    out(`    binds request    : ${a.bindingOk ? "ok" : "FAIL"}`);
    out(`    within window    : ${a.inWindow ? "ok" : "FAIL"}`);
    out(`    key custody      : ${a.keyCustody}${a.subjectHeldKey ? "" : "  ← NOT subject-held"}`);
    if (a.reason !== null) out(`    reason           : ${a.reason}`);
  }
  out(`  withdrawal         : ${r.withdrawalPresented ? (r.withdrawnBeforeSigning ? "PRESENTED — predates the signing" : "presented") : "none presented"}`);
  for (const c of r.keyClaims) {
    out(`  key claim          : ${c.priorDid} → ${c.successorDid} (${c.ok ? "ok" : "FAIL"})`);
    printClaimDetail(c);
  }
  for (const n of r.notes) out(`  note               : ${n}`);
}

function printCountersign(r: CountersignVerifyReport): void {
  printCountersignLines(r);
  printPlain(plainCountersign(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

/** A cohort record: the countersign lines unchanged, then what the profile says and whether it holds (specs/cohort-profile.md). */
function printCohort(r: CohortRecordReport): void {
  printCountersignLines(r.countersign);
  const countersigned = (did: string | null): string =>
    did !== null && r.countersign.acceptances.some((a) => a.countersignerDid === did && a.ok) ? "countersigned" : "NOT countersigned";
  out(`Cohort record (${COHORT_PROFILE})`);
  out(`  holder             : ${r.holderDid ?? "unknown"} — a key made for this issuer alone, not a person`);
  out(`  syllabus           : ${r.syllabus?.id ?? "unknown"}, version ${r.syllabus?.version ?? "?"}`);
  out(`  syllabus sha-256   : ${r.syllabus?.hash ?? "unknown"}`);
  out(`  teacher's org      : ${r.teacherOrgDid ?? "unknown"} — ${countersigned(r.teacherOrgDid)}`);
  out(`  station            : ${r.stationDid ?? "unknown"} — ${countersigned(r.stationDid)}`);
  out(`  finished           : ${r.finishedAt ?? "unknown"}`);
  out(`  expires            : ${r.expiresAtUnix === null ? "unknown" : iso(r.expiresAtUnix)}${r.expired ? " — EXPIRED, it no longer attests" : ""}`);
  if (r.violations.length === 0) {
    out(`  profile            : ${r.countersign.ok ? "every rule holds" : "the claim follows the profile, but the signatures above do not verify"}`);
  }
  for (const v of r.violations) out(`  profile            : ${v.code} at ${v.path} — ${v.message}`);
  for (const n of r.notes) out(`  note               : ${n}`);
  printPlain(plainCohort(r), r.ok);
  out(`RESULT: ${r.ok ? (r.expired ? "PASS (expired — it no longer attests)" : "PASS") : "FAIL"}`);
}

function printIndus(r: IndusVerifyResult): void {
  out(`Indus ${r.prefix} token (${r.dst})`);
  out(`  signature          : ${r.signatureOk ? "ok" : "FAIL"}`);
  out(`  time window        : ${r.timeOk ? "ok" : "FAIL"}`);
  if (r.certIdOk !== null) out(`  certId derivation  : ${r.certIdOk ? "ok" : "FAIL"}`);
  if (r.reason) out(`  reason             : ${r.reason}`);
  printPlain(plainIndus(r), r.ok);
  out(`RESULT: ${r.ok ? "PASS" : "FAIL"}`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  // `attest log verify <dir>`: the whole log, from its files alone (KS-Q4).
  if (args.command === "log-verify") {
    const headers = loadHeaders(args.headerFiles);
    const rfc = rfc3161CheckFor(args);
    let files: ReturnType<typeof readLogDirectory>;
    let mirror: ReturnType<typeof readLogDirectory> | undefined;
    try {
      files = readLogDirectory(args.file);
      mirror = args.mirror === undefined ? undefined : readLogDirectory(args.mirror);
    } catch (e) {
      die(2, `cannot read the log: ${(e as Error).message}`);
    }
    const report = await auditLog(files, {
      headers,
      ...(mirror !== undefined ? { mirror } : {}),
      ...(rfc !== null ? { verifyRfc3161Signature: rfc.check } : {}),
    });
    printLogAudit(report, rfc);
    process.exit(report.ok ? 0 : 1);
  }

  let raw: string;
  try {
    raw = readFileSync(args.file, "utf8");
  } catch (e) {
    die(2, `cannot read ${args.file}: ${(e as Error).message}`);
  }
  const trimmed = raw.trim();

  // 1. Indus token — a bare `PREFIX.h.b.s` string.
  if (/^(IPOE1|IVFC1|IBPS1|IGEO1)\./.test(trimmed)) {
    if (args.key === undefined) die(2, "indus token verification requires --key <hex|jwks.json>");
    const token = trimmed.split(/\s/)[0]!;
    const result = args.key.endsWith(".json")
      ? await verifyIndusTokenWithJwks(token, JSON.parse(readFileSync(args.key, "utf8")) as Jwks)
      : await verifyIndusToken(token, readKeyBytes(args.key));
    printIndus(result);
    process.exit(result.ok ? 0 : 1);
  }

  // 1b. SD-JWT — a predicate or a thank-you, held or presented. The issuer's
  // key comes out of its did:kash; status comes from --status-list files, or
  // from the one networked path, --check-status.
  if (isSdJwt(trimmed)) {
    const resolveKey = makeKeyResolver(new Map(), new Map());
    // --at: the time a file is checked as of — for a presentation received earlier. Otherwise the clock.
    const asOf = args.at !== undefined ? { nowSec: args.at } : {};
    const statusLists: StatusListReport[] = [];
    for (const f of args.statusListFiles) {
      statusLists.push(await verifyStatusList(JSON.parse(readFileSync(f, "utf8")) as DsseEnvelope, { resolveKey, ...asOf }));
    }
    const first = await verifySdJwt(trimmed, { resolveKey, requireKeyBinding: false, ...asOf });
    const entry = statusEntryOf(first.claims);
    if (args.checkStatus && entry !== null && !statusLists.some((l) => l.ok && l.id === entry.statusListCredential)) {
      for (const f of await fetchStatusLists([entry.statusListCredential], globalThis.fetch as unknown as FetchLike)) {
        if (f.envelope === null) out(`status fetch ${f.url}: ${f.error}`);
        else statusLists.push(await verifyStatusList(f.envelope, { resolveKey, source: "fetched", ...asOf }));
      }
    }
    const presented = first.keyBinding.present;
    // A presentation is made to one verifier: without its audience and nonce there is nothing to check it against (KS-Q4).
    if (presented && (args.audience === undefined || args.nonce === undefined)) {
      die(
        2,
        "this is a presentation, made to one verifier: pass --audience and --nonce — the identifier you are and the nonce you sent.\n" +
          "For a file you check after you received it, add --at <unix seconds>, the time you received it.",
      );
    }
    const when = { ...asOf, ...(args.maxAge !== undefined ? { maxKbAgeSec: args.maxAge } : {}) };
    if (first.vct === PREDICATE_VCT && presented) {
      const report = await verifyPredicatePresentation(trimmed, { resolveKey, statusLists, audience: args.audience!, nonce: args.nonce!, ...when });
      printPredicate(report);
      process.exit(report.ok ? 0 : 1);
    }
    if (first.vct === THANK_YOU_VCT) {
      const report = presented
        ? await verifyRedemption(trimmed, { resolveKey, statusLists, audience: args.audience!, nonce: args.nonce!, ...when })
        : await verifyThankYou(trimmed, { resolveKey, statusLists, ...asOf });
      printThankYou(report, presented);
      process.exit(report.ok ? 0 : 1);
    }
    // An attestation copy (RW-14, RW-15): held, presented, or a page's. With --artifact, the page's rule: the
    // artefact is shown only when the copy discloses its record and that record names the file.
    if (first.vct === ATTESTATION_VCT) {
      const report = presented
        ? await verifySdJwt(trimmed, { resolveKey, requireKeyBinding: true, audience: args.audience!, nonce: args.nonce!, ...when })
        : await verifySdJwt(trimmed, { resolveKey, requireKeyBinding: false, ...asOf });
      let page: PageView | null = null;
      if (args.artifact !== undefined) {
        let artefact: unknown;
        try {
          artefact = JSON.parse(readFileSync(args.artifact, "utf8"));
        } catch (e) {
          die(2, `cannot read --artifact ${args.artifact}: ${(e as Error).message}`);
        }
        page = await shownOnPage(trimmed, [artefact], { resolveKey, ...asOf });
      }
      // A disclosed record that names no artefact handed in is a failure; a record not disclosed is simply not shown.
      const mismatch = page !== null && page.view !== null && page.view.record !== undefined && page.shown === null;
      const ok = report.ok && !mismatch;
      printAttestationCopy(report, page, ok);
      process.exit(ok ? 0 : 1);
    }
    const report = presented
      ? await verifySdJwt(trimmed, { resolveKey, requireKeyBinding: true, audience: args.audience!, nonce: args.nonce!, ...when })
      : await verifySdJwt(trimmed, { resolveKey, requireKeyBinding: false, ...asOf });
    printSdJwt(report);
    process.exit(report.ok ? 0 : 1);
  }

  // 2. JSON artifact.
  let obj: unknown;
  try {
    obj = JSON.parse(trimmed);
  } catch (e) {
    die(2, `not a JSON artifact or Indus token: ${(e as Error).message}`);
  }
  const o = obj as Record<string, unknown>;

  // 2a. Countersign bundle — checked FIRST. It has no top-level `payloadType`
  // (its subject envelope carries its own), so it cannot collide with 2b; the
  // order is for clarity, not disambiguation. Needs no --key: both public keys
  // come out of the did:kash identifiers already in the file.
  if (isCountersignBundle(obj)) {
    // A cohort record is a countersign bundle with a profile on its subject:
    // the same checks, then the profile's. Every other bundle prints as before.
    if (isCohortRecord(obj)) {
      const report = await verifyCohortRecord(obj);
      printCohort(report);
      process.exit(report.ok ? 0 : 1);
    }
    const report = await verifyCountersignBundle(obj);
    printCountersign(report);
    process.exit(report.ok ? 0 : 1);
  }

  // 2a'. Holder export — no top-level payloadType either, so no collision with 2b.
  // Every key comes from inside the file; nothing is fetched unless --check-status.
  if (isHolderExport(obj)) {
    const base = { pinnedPublishers: args.trustPublishers, rawText: raw, ...(args.at !== undefined ? { nowSec: args.at } : {}) };
    let report = await verifyHolderExport(obj, base);
    if (args.checkStatus) {
      const wanted = report.records
        .filter((rec) => rec.status.state === "unknown" && rec.status.listId !== null && rec.status.asOfUnix === null)
        .map((rec) => rec.status.listId as string);
      if (wanted.length > 0) {
        const fetched = await fetchStatusLists(wanted, globalThis.fetch as unknown as FetchLike);
        for (const f of fetched) if (f.error !== null) out(`status fetch ${f.url}: ${f.error}`);
        const envelopes = fetched.flatMap((f) => (f.envelope === null ? [] : [f.envelope]));
        report = await verifyHolderExport(obj, { ...base, fetchedStatusLists: envelopes });
      }
    }
    printHolderExport(report);
    process.exit(report.ok ? 0 : 1);
  }

  // 2a'''. A session receipt, and an ask. Neither has a top-level payloadType.
  if (isSessionReceipt(obj)) {
    const report = await verifySessionReceipt(obj);
    printSession(report);
    process.exit(report.ok ? 0 : 1);
  }
  if (o.format === ASK_FORMAT) {
    const { violations } = validateAsk(obj);
    printAsk(o.key, violations);
    process.exit(violations.length === 0 ? 0 : 1);
  }

  // 2a''''. The trust log's three artifacts (KS-Q4). The checkpoint is a DSSE envelope, so before 2b.
  if (isLogInclusionProof(obj)) {
    const rfc = rfc3161CheckFor(args);
    const allowance = args.maxBatchDelay ?? DEFAULT_MAX_BATCH_DELAY_SEC;
    const report = await verifyLogInclusion(obj, {
      maxBatchDelaySec: allowance,
      headers: loadHeaders(args.headerFiles),
      ...(rfc !== null ? { verifyRfc3161Signature: rfc.check } : {}),
    });
    printLogInclusion(report, rfc, allowance);
    process.exit(report.ok ? 0 : 1);
  }
  if (isLogConsistencyProof(obj)) {
    const report = await verifyLogConsistency(obj);
    printLogConsistency(report);
    process.exit(report.ok ? 0 : 1);
  }
  if (o.payloadType === DST_LOG_CHECKPOINT) {
    const report = await verifyCheckpoint(obj);
    printCheckpoint(report);
    process.exit(report.ok ? 0 : 1);
  }

  // 2a''. The holder contract's two signed documents. Checked before 2b, which
  // would otherwise read any DSSE envelope as an audit bundle.
  if (o.payloadType === DST_TRUST_LIST) {
    const report = await verifyTrustList(obj as DsseEnvelope, { pinnedPublishers: args.trustPublishers });
    printTrustList(report);
    printPlain(plainTrustList(report), report.ok);
    out(`RESULT: ${report.ok ? "PASS" : "FAIL"}`);
    process.exit(report.ok ? 0 : 1);
  }
  if (o.payloadType === DST_STATUS_LIST) {
    // Standalone, a status list can only be checked against a self-certifying issuer DID.
    const report = await verifyStatusList(obj as DsseEnvelope, { resolveKey: makeKeyResolver(new Map(), new Map()) });
    printStatusList(report);
    printPlain(plainStatusList(report), report.ok);
    out(`RESULT: ${report.ok ? "PASS" : "FAIL"}`);
    process.exit(report.ok ? 0 : 1);
  }

  // 2b. DSSE audit bundle.
  if (typeof o.payloadType === "string" && typeof o.payload === "string" && Array.isArray(o.signatures)) {
    const env = obj as DsseEnvelope;
    let trustedKeysByDid: ReadonlyMap<string, string> | undefined;
    let requireSignerDid = args.signerDid;
    if (args.key !== undefined) {
      const parts = (HEX64.test(args.key) ? args.key : readFileSync(args.key, "utf8").trim()).split(/\s+/);
      const did = parts.length >= 2 ? parts[0]! : env.signatures[0]?.keyid;
      const hex = parts.length >= 2 ? parts[1]! : parts[0]!;
      if (did !== undefined) {
        trustedKeysByDid = new Map([[did, hex.toLowerCase()]]);
        requireSignerDid ??= did;
      }
    }
    try {
      const report = await verifyAuditBundle(env, {
        ...(trustedKeysByDid !== undefined ? { trustedKeysByDid } : {}),
        ...(requireSignerDid !== undefined ? { requireSignerDid } : {}),
      });
      printBundle(report, args.key !== undefined);
      process.exit(exitFor(report.ok, report.selfAsserted));
    } catch (e) {
      if (e instanceof TamperError) {
        out(`DSSE audit bundle`);
        printPlain(plainTamper(), false);
        out(`RESULT: FAIL — TAMPER DETECTED (${e.tamperKind}${e.stepIndex !== null ? "@" + e.stepIndex : ""})`);
        process.exit(1);
      }
      throw e;
    }
  }

  // 2c. Every-Rupee report.
  if (o.report !== undefined && o.signature !== undefined && typeof o.operatorPublicKeyHex === "string") {
    const signed = obj as SignedReport;
    const report = await verifyDuedaleReport(signed, args.key !== undefined ? readKeyBytes(args.key) : undefined);
    printReport(report, args.key !== undefined);
    process.exit(exitFor(report.ok, args.key === undefined));
  }

  die(2, "unrecognized artifact: not a countersign bundle, holder export, trust or status list, log checkpoint or proof, DSSE bundle, Every-Rupee report, or Indus token");
}

main().catch((e: unknown) => die(2, `error: ${e instanceof Error ? e.message : String(e)}`));
