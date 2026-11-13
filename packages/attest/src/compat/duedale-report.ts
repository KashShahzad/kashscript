/**
 * Compat verifier — Duedale "Every-Rupee Report" (`kash-report-v1`).
 *
 * Verifies a `SignedReport` (the artifact emitted by Duedale's `/report/report.json`)
 * OFFLINE, from the JSON alone: (1) the envelope Ed25519 signature under
 * `kash-report-v1\n`, and (2) the render-time hash-chain
 * (`rowHash_i = SHA-256( utf8(prevHashHex) ‖ JCS(row_i) )`, genesis
 * `SHA-256(utf8("duedale-every-rupee-chain-v1"))`), genesis → head.
 *
 * The per-grant `kash-grant-v1` signatures are NOT in the report envelope, so
 * they are not re-verifiable from `report.json` alone (the report's
 * `grants[].signatureValid` is a producer claim). Domain separation between
 * report and grant DSTs is exercised in the test suite.
 *
 * Ported from Duedale `packages/ks-adapters/src/report/index.ts`.
 */

import {
  canonicalizeBytes,
  verifyEvent,
  type KashEventSignature,
  type SignedKashEvent,
} from "@kashscript/identity-core";
import { hexToBytes, sha256Hex } from "../chain";

/** Report envelope DST (distinct from `kash-grant-v1\n`). */
export const REPORT_DST = "kash-report-v1\n" as const;
/** Grant DST — for domain-separation checks. */
export const GRANT_DST = "kash-grant-v1\n" as const;
/** Genesis pre-image label for the report chain. */
export const CHAIN_GENESIS_LABEL = "duedale-every-rupee-chain-v1" as const;

export interface ChainRow {
  readonly grantId: string;
  readonly toState: string;
  readonly actorDid: string;
  readonly actorClass: string;
  readonly reason: string;
  readonly code: string | null;
  readonly atUnix: number;
}
export interface ChainLink {
  readonly seq: number;
  readonly row: ChainRow;
  readonly rowHashHex: string;
  readonly prevHashHex: string;
}
export interface EveryRupeeReportChain {
  readonly genesisLabel: string;
  readonly headHashHex: string | null;
  readonly links: ReadonlyArray<ChainLink>;
}
export interface EveryRupeeReport {
  readonly meta: { readonly reportId: string };
  readonly chain: EveryRupeeReportChain;
}
export interface SignedReport {
  readonly report: EveryRupeeReport;
  readonly signature: KashEventSignature;
  readonly operatorPublicKeyHex: string;
}

/** Deterministic header — rebuilt identically at verify time (binds reportId). */
function reportHeader(report: EveryRupeeReport): Readonly<Record<string, unknown>> {
  return { typ: "duedale/every-rupee-report", v: 1, reportId: report.meta.reportId };
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Verify the report envelope signature under the operator public key. */
export async function verifyReportSignature(
  signed: SignedReport,
  operatorPublicKey: Uint8Array,
): Promise<boolean> {
  const event: SignedKashEvent = {
    header: reportHeader(signed.report),
    body: signed.report,
    signature: signed.signature,
  };
  return verifyEvent(event, operatorPublicKey);
}

export interface ReportChainResult {
  readonly ok: boolean;
  readonly transitionCount: number;
  readonly headHashHex: string | null;
  /** The `seq` where the chain broke, or null if intact. */
  readonly brokenAtSeq: number | null;
}

/** Recompute the report chain from the JSON alone (genesis → head). */
export async function verifyReportChain(report: EveryRupeeReport): Promise<ReportChainResult> {
  const links = report.chain.links;
  let prev = await sha256Hex(utf8(report.chain.genesisLabel));
  let head: string | null = null;
  for (let i = 0; i < links.length; i++) {
    const link = links[i]!;
    if (link.prevHashHex !== prev) {
      return { ok: false, transitionCount: links.length, headHashHex: head, brokenAtSeq: link.seq };
    }
    const rowHash = await sha256Hex(concat(utf8(prev), canonicalizeBytes(link.row)));
    if (rowHash !== link.rowHashHex) {
      return { ok: false, transitionCount: links.length, headHashHex: head, brokenAtSeq: link.seq };
    }
    prev = rowHash;
    head = rowHash;
  }
  const expectedHead = links.length === 0 ? null : head;
  const headOk = (report.chain.headHashHex ?? null) === expectedHead;
  return {
    ok: headOk,
    transitionCount: links.length,
    headHashHex: head,
    brokenAtSeq: headOk ? null : -1,
  };
}

export interface DuedaleReportVerifyReport {
  readonly ok: boolean;
  readonly signatureOk: boolean;
  readonly chain: ReportChainResult;
  readonly operatorPublicKeyHex: string;
  readonly reportId: string;
}

/** Verify a signed Every-Rupee report end to end (offline). If
 *  `operatorPublicKey` is omitted, the report's embedded `operatorPublicKeyHex`
 *  is used — a fresh machine should cross-check that hex against Duedale's
 *  published operator key out of band. */
export async function verifyDuedaleReport(
  signed: SignedReport,
  operatorPublicKey?: Uint8Array,
): Promise<DuedaleReportVerifyReport> {
  const pub = operatorPublicKey ?? hexToBytes(signed.operatorPublicKeyHex);
  const signatureOk = await verifyReportSignature(signed, pub);
  const chain = await verifyReportChain(signed.report);
  return {
    ok: signatureOk && chain.ok,
    signatureOk,
    chain,
    operatorPublicKeyHex: signed.operatorPublicKeyHex,
    reportId: signed.report.meta.reportId,
  };
}
