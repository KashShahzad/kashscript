// ============================================================================
// @kashscript/whiffin/report/chain — the render-time hash-chain
// ----------------------------------------------------------------------------
// Flatten every record's transitions into a deterministic total order and
// hash-chain them: `rowHash_i = SHA-256(utf8(prevHashHex) ‖ JCS(row_i))`,
// genesis `prevHash = SHA-256(utf8(genesisLabel))`. Records order by first-ISSUED
// time then grantId; a record's transitions keep their append (causal) order.
// Each link carries its full row, so the chain verifies from the report JSON
// alone. Reuses attest's `sha256Hex` + identity-core's `canonicalizeBytes`, so a
// report generated here re-verifies under attest's M1 `verifyDuedaleReport`
// (prev-first composition, byte-for-byte). Ported from ks-adapters/report.
// ============================================================================

import { canonicalizeBytes } from "@kashscript/identity-core";
import { sha256Hex } from "@kashscript/attest";

import type { ChainLink, ChainRow, ChainSummary, ReportLedgerRecord } from "./builder";

/** Default genesis pre-image label (neutral). Pass the venture's label for
 *  wire-compat with reports already anchored under a different genesis. */
export const DEFAULT_CHAIN_GENESIS_LABEL = "kash-reconciliation-chain-v1";

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Compute the render-time hash-chain summary over a ledger's transitions. */
export async function computeChainSummary(
  records: readonly ReportLedgerRecord[],
  genesisLabel: string = DEFAULT_CHAIN_GENESIS_LABEL,
): Promise<ChainSummary> {
  const ordered = [...records].sort((a, b) => {
    const at = (r: ReportLedgerRecord): number => r.transitions.find((t) => t.toState === "ISSUED")?.atUnix ?? 0;
    const ida = a.signed.grant.grantId;
    const idb = b.signed.grant.grantId;
    return at(a) - at(b) || (ida < idb ? -1 : ida > idb ? 1 : 0);
  });

  const links: ChainLink[] = [];
  let prevHashHex = await sha256Hex(utf8(genesisLabel));
  let seq = 0;
  for (const record of ordered) {
    for (const t of record.transitions) {
      const row: ChainRow = {
        grantId: t.grantId,
        toState: t.toState,
        actorDid: t.actorDid,
        actorClass: t.actorClass,
        reason: t.reason,
        code: t.code,
        atUnix: t.atUnix,
      };
      const rowHashHex = await sha256Hex(concat(utf8(prevHashHex), canonicalizeBytes(row)));
      links.push({ seq, row, rowHashHex, prevHashHex });
      prevHashHex = rowHashHex;
      seq += 1;
    }
  }

  return {
    algorithm: "sha256-jcs-linked",
    genesisLabel,
    transitionCount: links.length,
    headHashHex: links.length === 0 ? null : links[links.length - 1]!.rowHashHex,
    computedAtRender: true,
    durablyAnchored: false,
    links,
  };
}
