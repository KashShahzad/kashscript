/**
 * DSSE audit-bundle — sign + verify a self-contained, independently-verifiable
 * ledger export end to end (the Oreoasis `AuditTrailExport` format).
 *
 * `verifyAuditBundle` checks, offline: (1) the DSSE envelope signature, (2) the
 * full Ed25519 hash-chain (`importAndVerify` → `forensicConsistencyScan`, which
 * THROWS `TamperError` on tamper), and (3) the anchor Merkle root recompute + that
 * it binds this chain's tip. Public-log inclusion/timestamp is delegated to
 * `rekor-cli` / `ots verify`.
 *
 * Ported from Oreoasis `src/delivery/audit-export.ts` (the verify path; the
 * export-side `exportAuditTrail` — which needs a live store — stays venture/hudhud).
 */

import {
  DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE,
  signEnvelope,
  verifyEnvelope,
  type DsseEnvelope,
  type DsseSigner,
} from "./dsse";
import { hexToBytes } from "./chain";
import { AttestError } from "./errors";
import {
  InMemoryDidRegistry,
  forensicConsistencyScan,
  type ForensicScanReport,
  type LedgerBlockRecord,
} from "./ledger";
import { computeAnchorMerkleRoot, type AnchorRecord } from "./witness";

/** Format id embedded in every export + DSSE payload — the stable contract. */
export const AUDIT_EXPORT_FORMAT_VERSION = "oreoasis-audit-export/1" as const;

export interface AuditTrailDidEntry {
  readonly did: string;
  /** Raw 32-byte Ed25519 public key, lower-hex (64 chars). */
  readonly publicKeyHex: string;
}

export interface AuditTrailExport {
  readonly sessionId: string;
  /** Signed ledger rows (ORIGINAL signatures + chain hashes — never re-signed). */
  readonly rows: ReadonlyArray<LedgerBlockRecord>;
  /** Every distinct actor DID's public key (+ the host DSSE signer). */
  readonly dids: ReadonlyArray<AuditTrailDidEntry>;
  readonly exportedAtIso: string;
  readonly formatVersion?: string;
  readonly anchor?: AnchorRecord | null;
}

/** Wrap an `AuditTrailExport` in a DSSE envelope signed by the host key. */
export async function signAuditBundle(
  exp: AuditTrailExport,
  signer: DsseSigner,
): Promise<DsseEnvelope> {
  return signEnvelope(exp, DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE, signer);
}

/** Rebuild a fresh DID registry from the export's keys and run the forensic scan
 *  over its rows — the offline chain re-verification. Throws `TamperError` on tamper. */
export async function importAndVerify(exp: AuditTrailExport): Promise<ForensicScanReport> {
  const didRegistry = new InMemoryDidRegistry();
  for (const entry of exp.dids) {
    didRegistry.register({
      did: entry.did,
      publicKeyBytes: hexToBytes(entry.publicKeyHex),
      algorithm: "ed25519",
    });
  }
  return forensicConsistencyScan(exp.sessionId, exp.rows, didRegistry);
}

export interface AuditBundleVerifyOptions {
  /** Out-of-band trusted keys (`did` → 64-hex). Overrides the payload-embedded key. */
  readonly trustedKeysByDid?: ReadonlyMap<string, string>;
  /** Require this DID to be among the verified DSSE signers. */
  readonly requireSignerDid?: string;
}

export interface AuditBundleVerifyReport {
  /** The envelope, the chain and the anchor are consistent with one another. */
  readonly ok: boolean;
  /**
   * No trusted key was supplied, so every key that verified came from inside the
   * file: `ok` then means the file is consistent with itself and nothing about
   * who signed it (AU-3, A7-06). Naming a `requireSignerDid` lifts nothing —
   * that string is in the file too. The CLI exits 3, INTEGRITY ONLY, on this.
   */
  readonly selfAsserted: boolean;
  readonly dsseOk: boolean;
  readonly dsseVerifiedKeyids: ReadonlyArray<string>;
  readonly requiredSignerVerified: boolean;
  readonly forensic: ForensicScanReport;
  readonly anchorPresent: boolean;
  readonly anchorRootMatches: boolean | null;
  readonly anchorBindsChain: boolean | null;
  readonly anchor: AnchorRecord | null;
}

/** Decode the (unauthenticated) payload just far enough to read `dids`. */
function decodeClaimedExport(envelope: DsseEnvelope): {
  dids?: ReadonlyArray<AuditTrailDidEntry>;
} {
  try {
    const bin = atob(envelope.payload);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return JSON.parse(new TextDecoder().decode(bytes)) as { dids?: ReadonlyArray<AuditTrailDidEntry> };
  } catch {
    return {};
  }
}

/** Verify a signed audit bundle end to end (offline). */
export async function verifyAuditBundle(
  envelope: DsseEnvelope,
  options: AuditBundleVerifyOptions = {},
): Promise<AuditBundleVerifyReport> {
  const claimed = decodeClaimedExport(envelope);
  const resolve = (keyid: string): Uint8Array | null => {
    // audit r1 F3: a malformed hex key (attacker-controlled `publicKeyHex` /
    // trusted-map entry) must make the signature UNVERIFIABLE (→ ok:false), not
    // crash the verifier with an uncaught KashCryptoError. Fail closed to null.
    try {
      const trusted = options.trustedKeysByDid?.get(keyid);
      if (trusted !== undefined) return hexToBytes(trusted);
      const entry = claimed.dids?.find((d) => d.did === keyid);
      return entry !== undefined ? hexToBytes(entry.publicKeyHex) : null;
    } catch {
      return null;
    }
  };

  const dsse = await verifyEnvelope(envelope, resolve);
  // The payload must be an export object: anything else is malformed input, said as such
  // (AU-3, A7-04 — never a TypeError out of the chain scan).
  const claimedExport = dsse.payloadJson;
  if (
    typeof claimedExport !== "object" ||
    claimedExport === null ||
    Array.isArray(claimedExport) ||
    !Array.isArray((claimedExport as { rows?: unknown }).rows) ||
    !Array.isArray((claimedExport as { dids?: unknown }).dids)
  ) {
    throw new AttestError("MALFORMED_PAYLOAD", "the audit bundle's payload is not an audit export (a JSON object with rows and dids)");
  }
  const exp = claimedExport as AuditTrailExport;
  const selfAsserted = options.trustedKeysByDid === undefined || options.trustedKeysByDid.size === 0;
  const requiredSignerVerified =
    options.requireSignerDid === undefined
      ? true
      : dsse.verifiedKeyids.includes(options.requireSignerDid);

  // Chain integrity — throws TamperError on tamper.
  const forensic = await importAndVerify(exp);

  const anchor = exp.anchor ?? null;
  let anchorRootMatches: boolean | null = null;
  let anchorBindsChain: boolean | null = null;
  if (anchor !== null) {
    anchorRootMatches = (await computeAnchorMerkleRoot(anchor.tips)) === anchor.merkleRoot;
    const tail = [...exp.rows].sort((a, b) => a.stepIndex - b.stepIndex).at(-1) ?? null;
    const tip = anchor.tips.find((t) => t.sessionId === exp.sessionId) ?? null;
    anchorBindsChain =
      tail !== null &&
      tip !== null &&
      tip.latestHash === tail.currentTransactionBlockHash &&
      tip.latestStepIndex === tail.stepIndex;
  }

  const ok =
    dsse.ok &&
    requiredSignerVerified &&
    forensic.ok &&
    (anchor === null || (anchorRootMatches === true && anchorBindsChain === true));

  return {
    ok,
    selfAsserted,
    dsseOk: dsse.ok,
    dsseVerifiedKeyids: dsse.verifiedKeyids,
    requiredSignerVerified,
    forensic,
    anchorPresent: anchor !== null,
    anchorRootMatches,
    anchorBindsChain,
    anchor,
  };
}
