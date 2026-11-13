// ============================================================================
// @kashscript/whiffin/policy — the config-driven REDEEM policy gate
// ----------------------------------------------------------------------------
// Every rule, checked in a fixed order, each rejection a NAMED neutral code
// (never a boolean). The gate reads grant + request FIELDS only — it NEVER
// branches on segmentTag or program type ("zero segment branching"). The
// venture supplies extra checks + config; whiffin ships the standard set.
//
// The single-use nonce burn (side-effecting, atomic, LAST) is NOT a pure check
// — it is handled by `redeemGrant` after this gate passes, so a failed policy
// check can never consume a beneficiary's voucher. Generalized from the inline
// ks-adapters/redeem gate (M4, ADR-0016).
// ============================================================================

import type { WhiffinPolicyCode } from "./errors";
import { verifyGrant, verifyVendorInclusion } from "./mandate/grant";
import type { MerkleInclusionProof } from "./mandate/grant";
import type { Grant, GrantRecord } from "./mandate/types";

/**
 * A vendor's request to redeem one grant.
 *
 * ⚠ d41: use this gate to bound a DELEGATE spending money that is not theirs (a
 * trustee, a treasurer, a procurement officer, an AI agent). Pointed at a
 * recipient it is "a restriction on what an individual buys with money they
 * have received", which is on d41's never-build list. A DID is an identifier,
 * not a secret, so `beneficiaryDid` alone makes the grant a bearer instrument;
 * pass a proof-of-possession check through `RedeemOptions.policy` instead.
 */
export interface RedeemRequest {
  readonly grantId: string;
  readonly vendorDid: string;
  /** DID presented by the beneficiary at the counter (binding check). */
  readonly beneficiaryDid: string;
  /** The purpose of the sale as declared by the vendor terminal. */
  readonly purposeTag: string;
  /** Merkle inclusion proof for `vendorDid` against the grant's allowlist root. */
  readonly vendorProof: MerkleInclusionProof;
}

/** The result of a successful REDEEM: the updated record (state REDEEMED). */
export interface RedeemResult {
  readonly record: GrantRecord;
}

/** Everything a policy check may read. Pure inputs — no side effects. */
export interface PolicyContext {
  readonly grant: Grant;
  readonly record: GrantRecord;
  readonly request: RedeemRequest;
  readonly operatorPublicKey: Uint8Array;
  readonly nowUnix: number;
}

export type PolicyCheckResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: WhiffinPolicyCode; readonly detail: string };

/** One named rule in the ordered gate. Pure over `ctx`; may be async (crypto). */
export interface PolicyCheck {
  readonly name: string;
  run(ctx: PolicyContext): Promise<PolicyCheckResult> | PolicyCheckResult;
}

const PASS: PolicyCheckResult = { ok: true };
const failWith = (code: WhiffinPolicyCode, detail: string): PolicyCheckResult => ({ ok: false, code, detail });

/** The operator signature must verify (tamper check over the whole grant). */
export const checkSignature: PolicyCheck = {
  name: "signature",
  async run(ctx) {
    return (await verifyGrant(ctx.record.signed, ctx.operatorPublicKey))
      ? PASS
      : failWith("SIGNATURE_INVALID", ctx.grant.grantId);
  },
};

/**
 * The presenter must be the beneficiary the grant is bound to.
 *
 * @deprecated as a security boundary: it compares two DID strings, and a DID is
 * an identifier, not a secret — anyone who learns it passes this check. Replace it
 * with proof of possession (a challenge signed under the bound key) for any real
 * use; it is kept as the default only so 0.1.0 behaviour does not change silently.
 */
export const checkBeneficiaryBinding: PolicyCheck = {
  name: "beneficiaryBinding",
  run(ctx) {
    return ctx.request.beneficiaryDid.trim() === ctx.grant.beneficiaryDid
      ? PASS
      : failWith("BENEFICIARY_BINDING_FAILED", `presenter is not the bound beneficiary of ${ctx.grant.grantId}`);
  },
};

/** The declared sale purpose must match the grant's purpose lock. */
export const checkPurposeMatch: PolicyCheck = {
  name: "purposeMatch",
  run(ctx) {
    return ctx.request.purposeTag === ctx.grant.purposeTag
      ? PASS
      : failWith(
          "PURPOSE_MISMATCH",
          `sale purpose "${ctx.request.purposeTag}" does not match grant purpose "${ctx.grant.purposeTag}"`,
        );
  },
};

/** The grant must not be past expiry. */
export const checkNotExpired: PolicyCheck = {
  name: "notExpired",
  run(ctx) {
    return ctx.nowUnix < ctx.grant.expiryUnix
      ? PASS
      : failWith("EXPIRED", `expired at ${ctx.grant.expiryUnix}, now ${ctx.nowUnix}`);
  },
};

/** The vendor must prove membership in the grant's signed allowlist root. */
export const checkVendorInclusion: PolicyCheck = {
  name: "vendorInclusion",
  async run(ctx) {
    const included = await verifyVendorInclusion(
      ctx.request.vendorDid,
      ctx.request.vendorProof,
      ctx.grant.vendorAllowlistRoot,
    );
    return included ? PASS : failWith("VENDOR_NOT_IN_ALLOWLIST", ctx.request.vendorDid);
  },
};

/**
 * The default REDEEM policy — the field-driven gate in fixed order:
 * signature → beneficiary binding → purpose → expiry → vendor inclusion.
 * Zero segment branching. The grant-exists / redeemable-state / nonce-burn
 * steps are handled by `redeemGrant` (they need the ledger + nonce store).
 */
export const DEFAULT_REDEEM_POLICY: readonly PolicyCheck[] = [
  checkSignature,
  checkBeneficiaryBinding,
  checkPurposeMatch,
  checkNotExpired,
  checkVendorInclusion,
];

/** Run an ordered policy, returning the FIRST failure or `{ ok: true }`. */
export async function runPolicy(
  policy: readonly PolicyCheck[],
  ctx: PolicyContext,
): Promise<PolicyCheckResult> {
  for (const check of policy) {
    const result = await check.run(ctx);
    if (!result.ok) return result;
  }
  return PASS;
}
