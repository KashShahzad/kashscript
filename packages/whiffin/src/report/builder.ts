// ============================================================================
// @kashscript/whiffin/report/builder — the reconciliation report (projection)
// ----------------------------------------------------------------------------
// A PURE, deterministic projection over the mandate ledger (ISSUE → DELIVER →
// REDEEM transitions): per-grant lifecycle, vendor breakdown, reconciliation
// totals, and the SHAPE of the cryptographic chain summary. NO cryptography
// here — the two crypto results (per-grant signature validity + the render-time
// hash-chain) are INJECTED (report/chain.ts + report/sign.ts).
//
// Generalized from the duedale-core every-rupee report seed (M4, ADR-0016):
// `simulation` and `disclaimers` are INJECTED via BuildReportInput (honest
// defaults) rather than hardcoded, so a real consumer reports as itself while the
// demo stays labelled SIMULATION.
//
// WHAT A REPORT IS NOT. Whiffin never moves money, so this report holds no
// figure for value paid, returned or held — 0.1.0's two totals for value paid
// out and value returned are gone. A report counts mandates and their recorded
// transitions; that value ARRIVED is proven only by a recipient's confirmation
// (two signatures, d41), which is Duedale's record and never inferred here. A
// report signed under 0.1.0 still verifies: a signature is checked over the
// report's own JSON, not against this type.
//
// HONESTY: every simulated figure is a structural field of the payload (inside
// the signed bytes), so a downloaded report can never be re-presented as
// production. Reconciliation invariant: issuedPaisa === redeemedPaisa + unspentPaisa.
// ============================================================================

import type { Cents } from "../money";
import type {
  Grant,
  GrantActorClass,
  GrantLifecycleState,
  GrantTransition,
  Program,
  UnixSeconds,
} from "../mandate/types";

/** The ledger input the builder reads (GrantRecord is structurally assignable). */
export interface ReportLedgerRecord {
  readonly signed: { readonly grant: Grant };
  readonly state: GrantLifecycleState;
  readonly transitions: readonly GrantTransition[];
}

export type ReportGrantState = GrantLifecycleState;

export interface ReportMeta {
  readonly reportId: string;
  readonly programId: string;
  readonly programName: string;
  readonly funderDid: string;
  readonly generatedAtUnix: UnixSeconds;
  /** Whether this report describes a simulation (injected; honest default true). */
  readonly simulation: boolean;
  /** Count of ledger records too malformed to project (e.g. zero transitions). */
  readonly anomalies: number;
  /** Honesty labels, rendered verbatim + inside the signed bytes. */
  readonly disclaimers: readonly string[];
}

export interface GrantReportRow {
  readonly grantId: string;
  readonly purposeTag: string;
  readonly amountPaisa: Cents;
  readonly state: ReportGrantState;
  readonly issuedAtUnix: UnixSeconds;
  readonly deliveredAtUnix: UnixSeconds | null;
  readonly redeemedAtUnix: UnixSeconds | null;
  readonly redeemedByVendorDid: string | null;
  readonly expiryUnix: UnixSeconds;
  /** Result of verifyGrant under the operator key (REAL crypto — injected). */
  readonly signatureValid: boolean;
}

export interface VendorBreakdownRow {
  readonly vendorDid: string;
  readonly redeemedCount: number;
  readonly redeemedPaisa: Cents;
}

export interface ReportTotals {
  readonly issuedCount: number;
  readonly issuedPaisa: Cents;
  readonly redeemedCount: number;
  readonly redeemedPaisa: Cents;
  readonly expiredCount: number;
  /** Declared but not redeemed (issued − redeemed). A count of mandates, not a balance anyone holds. */
  readonly unspentPaisa: Cents;
}

/** The exact transition row canonicalized + hashed (verifiable from JSON alone). */
export interface ChainRow {
  readonly grantId: string;
  readonly toState: GrantLifecycleState;
  readonly actorDid: string;
  readonly actorClass: GrantActorClass;
  readonly reason: string;
  readonly code: string | null;
  readonly atUnix: UnixSeconds;
}

export interface ChainLink {
  readonly seq: number;
  readonly row: ChainRow;
  readonly rowHashHex: string;
  readonly prevHashHex: string;
}

export interface ChainSummary {
  readonly algorithm: "sha256-jcs-linked";
  readonly genesisLabel: string;
  readonly transitionCount: number;
  readonly headHashHex: string | null;
  readonly computedAtRender: true;
  readonly durablyAnchored: false;
  readonly links: readonly ChainLink[];
}

export interface ReconciliationReport {
  readonly meta: ReportMeta;
  readonly grants: readonly GrantReportRow[];
  readonly vendors: readonly VendorBreakdownRow[];
  readonly totals: ReportTotals;
  readonly chain: ChainSummary;
}

/** Drop-in compat alias for the venture swap (the seed named it EveryRupeeReport). */
export type EveryRupeeReport = ReconciliationReport;

export interface BuildReportInput {
  /** Wall-clock at render (unix seconds). Injected → deterministic. */
  readonly nowUnix: UnixSeconds;
  /** verifyGrant result per grantId (computed behind the crypto boundary). */
  readonly signatureValidByGrantId: ReadonlyMap<string, boolean>;
  /** The render-time hash-chain summary. */
  readonly chainSummary: ChainSummary;
  /** Whether this is a simulation (default true — the honest default). */
  readonly simulation?: boolean;
  /** Honesty disclaimers (default DEFAULT_DISCLAIMERS). */
  readonly disclaimers?: readonly string[];
}

/** Neutral, honest default disclaimers. A venture may pass its own. */
export const DEFAULT_DISCLAIMERS: readonly string[] = [
  "SIMULATION — this report describes a demonstration circuit; no fiat has moved.",
  "Grant Ed25519 signatures are real and independently verifiable under the operator key.",
  "The chain summary is computed at render over the in-memory ledger; durable append-only anchoring is not yet enabled.",
  "Whiffin never moves money. A mandate and its transitions are not evidence that value arrived; arrival is proven only by the recipient's confirmation (two signatures).",
  "A grant shown EXPIRED is a projection over its stated end date; whiffin holds no value, so nothing is returned.",
  "Trust-minimized, not trustless. No blockchain — a hash-chained signed log.",
];

function firstTransition(record: ReportLedgerRecord, toState: GrantLifecycleState): GrantTransition | null {
  for (const t of record.transitions) if (t.toState === toState) return t;
  return null;
}

/** Projected report state: the recorded state, or EXPIRED if past expiry and
 *  never redeemed. Pure. */
export function deriveReportState(record: ReportLedgerRecord, nowUnix: UnixSeconds): ReportGrantState {
  const recorded = record.state;
  const neverRedeemed = recorded === "ISSUED" || recorded === "DELIVERED";
  if (neverRedeemed && nowUnix >= record.signed.grant.expiryUnix) return "EXPIRED";
  return recorded;
}

/**
 * Build the reconciliation report from ledger records + the program, given the
 * injected crypto results. PURE + SYNC. Records with zero transitions are
 * skipped and counted in `meta.anomalies` (never throws on malformed input).
 */
export function buildReconciliationReport(
  records: readonly ReportLedgerRecord[],
  program: Program,
  input: BuildReportInput,
): ReconciliationReport {
  const { nowUnix, signatureValidByGrantId, chainSummary } = input;

  const rows: GrantReportRow[] = [];
  let anomalies = 0;

  for (const record of records) {
    const issued = firstTransition(record, "ISSUED");
    if (issued === null) {
      anomalies += 1;
      continue;
    }
    const { grant } = record.signed;
    const delivered = firstTransition(record, "DELIVERED");
    const redeemed = firstTransition(record, "REDEEMED");
    rows.push({
      grantId: grant.grantId,
      purposeTag: grant.purposeTag,
      amountPaisa: grant.amountPaisa,
      state: deriveReportState(record, nowUnix),
      issuedAtUnix: issued.atUnix,
      deliveredAtUnix: delivered?.atUnix ?? null,
      redeemedAtUnix: redeemed?.atUnix ?? null,
      redeemedByVendorDid: redeemed?.actorDid ?? null,
      expiryUnix: grant.expiryUnix,
      signatureValid: signatureValidByGrantId.get(grant.grantId) ?? false,
    });
  }

  const grants = [...rows].sort(
    (a, b) => a.issuedAtUnix - b.issuedAtUnix || (a.grantId < b.grantId ? -1 : a.grantId > b.grantId ? 1 : 0),
  );

  const totals = computeTotals(grants);
  const vendors = computeVendorBreakdown(grants);

  const meta: ReportMeta = {
    reportId: `report_${program.programId}_${nowUnix}`,
    programId: program.programId,
    programName: program.displayName,
    funderDid: program.funderDid,
    generatedAtUnix: nowUnix,
    simulation: input.simulation ?? true,
    anomalies,
    disclaimers: input.disclaimers ?? DEFAULT_DISCLAIMERS,
  };

  return { meta, grants, vendors, totals, chain: chainSummary };
}

function computeTotals(grants: readonly GrantReportRow[]): ReportTotals {
  let issuedPaisa = 0;
  let redeemedCount = 0;
  let redeemedPaisa = 0;
  let expiredCount = 0;
  for (const g of grants) {
    issuedPaisa += g.amountPaisa;
    if (g.redeemedAtUnix !== null) {
      redeemedCount += 1;
      redeemedPaisa += g.amountPaisa;
    }
    if (g.state === "EXPIRED") expiredCount += 1;
  }
  return {
    issuedCount: grants.length,
    issuedPaisa,
    redeemedCount,
    redeemedPaisa,
    expiredCount,
    unspentPaisa: issuedPaisa - redeemedPaisa,
  };
}

function computeVendorBreakdown(grants: readonly GrantReportRow[]): readonly VendorBreakdownRow[] {
  const byVendor = new Map<string, { redeemedCount: number; redeemedPaisa: number }>();
  for (const g of grants) {
    if (g.redeemedAtUnix === null || g.redeemedByVendorDid === null) continue;
    const acc = byVendor.get(g.redeemedByVendorDid) ?? { redeemedCount: 0, redeemedPaisa: 0 };
    acc.redeemedCount += 1;
    acc.redeemedPaisa += g.amountPaisa;
    byVendor.set(g.redeemedByVendorDid, acc);
  }
  return [...byVendor.entries()]
    .map(([vendorDid, acc]) => ({ vendorDid, ...acc }))
    .sort((a, b) => (a.vendorDid < b.vendorDid ? -1 : a.vendorDid > b.vendorDid ? 1 : 0));
}

/** Drop-in compat alias for the venture swap (the seed named it buildEveryRupeeReport). */
export const buildEveryRupeeReport = buildReconciliationReport;
