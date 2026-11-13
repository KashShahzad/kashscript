// ============================================================================
// @kashscript/whiffin/report/sign — signed reconciliation report envelope
// ----------------------------------------------------------------------------
// Signs the whole report under a `kash-report-v1` DST (distinct from
// `kash-grant-v1`, so a report signature can never verify as a grant) and runs
// the full assembly: per-grant signature verification (REAL Ed25519) → chain →
// build → sign. The report envelope `typ` + chain `genesisLabel` are OPTIONS
// (neutral defaults); passing the Duedale-branded values yields a report that
// re-verifies under attest's M1 `verifyDuedaleReport`. Ported from
// ks-adapters/report; the crypto reuses identity-core.
// ============================================================================

import { encodeHex, signEvent, verifyEvent } from "@kashscript/identity-core";
import type { KashEventSignature, SignedKashEvent } from "@kashscript/identity-core";

import { verifyGrant } from "../mandate/grant";
import type { GrantAuthorityKeyPair } from "../mandate/grant";
import type { GrantRecord, Program } from "../mandate/types";
import { buildReconciliationReport } from "./builder";
import type { BuildReportInput, ReconciliationReport } from "./builder";
import { DEFAULT_CHAIN_GENESIS_LABEL, computeChainSummary } from "./chain";

/** Report envelope DST (distinct from `kash-grant-v1\n`; in attest's DST registry). */
export const REPORT_DST = "kash-report-v1\n";
/** Default report-envelope `header.typ` (neutral). */
export const DEFAULT_REPORT_EVENT_TYPE = "kash/reconciliation-report";

export interface ReportVerifyInstructions {
  readonly spec: string;
  readonly dst: string;
  readonly steps: readonly string[];
}

export interface SignedReport {
  readonly report: ReconciliationReport;
  readonly signature: KashEventSignature;
  readonly operatorPublicKeyHex: string;
  readonly verify: ReportVerifyInstructions;
}

/** Deterministic Kash-Event header bound to the report id + envelope type.
 *  Rebuilt identically at verify time, so tampering the report fails verification. */
function reportHeader(report: ReconciliationReport, eventType: string): Readonly<Record<string, unknown>> {
  return { typ: eventType, v: 1, reportId: report.meta.reportId };
}

export interface SignReportOptions {
  /** Override the envelope `header.typ` (default DEFAULT_REPORT_EVENT_TYPE). */
  readonly eventType?: string;
}

const VERIFY_STEPS: readonly string[] = [
  "1. Reconstruct header = { typ: <eventType>, v: 1, reportId: report.meta.reportId }.",
  "2. Verify the envelope: Ed25519.verify(operatorPublicKeyHex, DST || JCS({header, body: report}), signature), DST = UTF-8('kash-report-v1\\n').",
  "3. Recompute the chain: prevHash = SHA-256(UTF-8(report.chain.genesisLabel)); for each link, rowHash = SHA-256(prevHash || JCS(link.row)) must equal link.rowHashHex + link.prevHashHex; the last rowHash equals report.chain.headHashHex.",
  "4. Each grant's own Ed25519 signature verifies independently under the operator key (kash-grant-v1 DST).",
];

/** Sign the whole report under the operator key + report DST. */
export async function signReport(
  report: ReconciliationReport,
  operatorPrivateKey: Uint8Array,
  operatorPublicKey: Uint8Array,
  options: SignReportOptions = {},
): Promise<SignedReport> {
  const eventType = options.eventType ?? DEFAULT_REPORT_EVENT_TYPE;
  const signature = await signEvent(reportHeader(report, eventType), report, operatorPrivateKey, { dst: REPORT_DST });
  return {
    report,
    signature,
    operatorPublicKeyHex: encodeHex(operatorPublicKey),
    verify: { spec: "RFC 8785 (JCS) + Ed25519", dst: REPORT_DST, steps: VERIFY_STEPS },
  };
}

/** Verify a signed report envelope against the operator public key. Pass the
 *  same `eventType` used at signing. */
export async function verifyReportSignature(
  signed: SignedReport,
  operatorPublicKey: Uint8Array,
  options: SignReportOptions = {},
): Promise<boolean> {
  const eventType = options.eventType ?? DEFAULT_REPORT_EVENT_TYPE;
  const event: SignedKashEvent = {
    header: reportHeader(signed.report, eventType),
    body: signed.report,
    signature: signed.signature,
  };
  return verifyEvent(event, operatorPublicKey);
}

export interface AssembleReportOptions {
  /** Wall-clock at render (unix seconds). Injectable for deterministic tests. */
  readonly nowUnix?: number;
  /** Envelope `header.typ` (default DEFAULT_REPORT_EVENT_TYPE). */
  readonly eventType?: string;
  /** Chain genesis label (default DEFAULT_CHAIN_GENESIS_LABEL). */
  readonly genesisLabel?: string;
  readonly simulation?: boolean;
  readonly disclaimers?: readonly string[];
}

/**
 * Assemble a signed reconciliation report from ledger records + the program.
 * Runs the REAL per-grant signature check, computes the render-time chain, calls
 * the pure builder, and signs the envelope.
 */
export async function assembleSignedReport(
  records: readonly GrantRecord[],
  program: Program,
  operatorKeyPair: GrantAuthorityKeyPair,
  options: AssembleReportOptions = {},
): Promise<SignedReport> {
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);

  const signatureValidByGrantId = new Map<string, boolean>();
  for (const record of records) {
    signatureValidByGrantId.set(
      record.signed.grant.grantId,
      await verifyGrant(record.signed, operatorKeyPair.publicKey),
    );
  }

  const chainSummary = await computeChainSummary(records, options.genesisLabel ?? DEFAULT_CHAIN_GENESIS_LABEL);

  const buildInput: BuildReportInput = {
    nowUnix,
    signatureValidByGrantId,
    chainSummary,
    ...(options.simulation !== undefined ? { simulation: options.simulation } : {}),
    ...(options.disclaimers !== undefined ? { disclaimers: options.disclaimers } : {}),
  };
  const report = buildReconciliationReport(records, program, buildInput);

  return signReport(report, operatorKeyPair.privateKey, operatorKeyPair.publicKey, {
    ...(options.eventType !== undefined ? { eventType: options.eventType } : {}),
  });
}
