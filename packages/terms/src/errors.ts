/**
 * Typed error class for @kashscript/terms.
 *
 * Callers `instanceof TermsError` and switch on `code` to map a failure to a
 * user-facing message without parsing strings. Only codes that a module in
 * this package actually throws are listed.
 */

export type TermsErrorCode =
  /* ── State machine ──────────────────────────────────────── */
  | "WRONG_STATE"
  | "PRE_SOFT_TIMEOUT"
  | "PRE_HARD_TIMEOUT"
  | "STALE_AFTER_SOFT_TIMEOUT"
  | "PRE_DISPUTE_TIMEOUT"
  | "ALREADY_DISPUTED"
  | "ALREADY_CLAIMED"
  | "REPLAY"
  | "SIGNAL_TOO_EARLY"
  | "WRONG_PERIOD"

  /* ── Manifest ───────────────────────────────────────────── */
  | "WRONG_VERSION"
  | "UNKNOWN_BLUEPRINT"
  | "SUB_MAJORITY_QUORUM"
  | "INVALID_MANIFEST"
  | "INVALID_BLUEPRINT_PAYLOAD"

  /* ── Declared split ─────────────────────────────────────── */
  | "NO_SWEEP_LEG"
  | "DUPLICATE_SWEEP"
  | "BPS_SUM"
  | "INVARIANT_DRIFT"

  /* ── Identity + completion receipt ──────────────────────── */
  | "WRONG_DID"
  | "INVALID_RECEIPT";

export class TermsError extends Error {
  override readonly name = "TermsError";
  readonly code: TermsErrorCode;
  override readonly cause?: unknown;

  constructor(message: string, code: TermsErrorCode, cause?: unknown) {
    super(message);
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, TermsError.prototype);
  }
}

/** Convenience throwing helper. */
export function fail(code: TermsErrorCode, message: string, cause?: unknown): never {
  throw new TermsError(message, code, cause);
}
