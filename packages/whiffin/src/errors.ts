// ============================================================================
// @kashscript/whiffin — provider-neutral error vocabulary
// ----------------------------------------------------------------------------
// Whiffin emits ONLY neutral codes. A consuming venture maps them to its own
// envelope at its perimeter (e.g. Duedale's ks-adapters maps
// WhiffinPolicyError.code → DD_*). That mapping stays venture-side (ADR-0016
// guard b); this package never emits a DD_* code.
// ============================================================================

/** Named rejection codes for the mandate lifecycle + policy gate. */
export type WhiffinPolicyCode =
  | "NOT_FOUND"
  | "NOT_REDEEMABLE"
  | "SIGNATURE_INVALID"
  | "BENEFICIARY_BINDING_FAILED"
  | "PURPOSE_MISMATCH"
  | "EXPIRED"
  | "VENDOR_NOT_IN_ALLOWLIST"
  | "NONCE_SPENT"
  | "VALIDATION";

/** Thrown by the issue / deliver / redeem pipeline + the policy gate. Each
 *  rejection carries a stable neutral `code`. */
export class WhiffinPolicyError extends Error {
  readonly code: WhiffinPolicyCode;
  readonly detail: string | null;

  constructor(code: WhiffinPolicyCode, message: string, detail: string | null = null) {
    super(`[${code}] ${message}`);
    this.name = "WhiffinPolicyError";
    this.code = code;
    this.detail = detail;
  }
}
