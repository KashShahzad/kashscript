/**
 * Error types for @kashscript/attest.
 *
 * `AttestError` is a structural/usage error (malformed input). A
 * cryptographically-invalid-but-well-formed signature is NOT an error — it
 * surfaces as `ok: false` from the verifiers, mirroring identity-core's
 * `verifyEvent` posture.
 *
 * `TamperError` is the load-bearing throw of the hash-chain contract: a chain
 * whose recomputation, ordering, or signatures do not hold throws it (replacing
 * the venture-specific `SignatureVerificationException` the seeds used).
 */

export type AttestErrorCode =
  | "MALFORMED_ENVELOPE"
  | "MALFORMED_PAYLOAD"
  | "MALFORMED_SIGNATURE"
  | "MALFORMED_TOKEN"
  | "UNSUPPORTED_ALG"
  | "UNKNOWN_DST"
  | "UNKNOWN_ACTOR"
  | "INVALID_INPUT"
  /** No CSPRNG available — refuse rather than mint a weak id (see `./ids`). */
  | "CRYPTO_UNAVAILABLE"
  | "IO_ERROR";

export class AttestError extends Error {
  public readonly code: AttestErrorCode;
  constructor(code: AttestErrorCode, message: string) {
    super(`[${code}] ${message}`);
    this.name = "AttestError";
    this.code = code;
  }
}

/** The forensic-scan tamper discriminants (ported from Oreoasis ledger-writer). */
export type TamperKind =
  | "STEP_INDEX_GAP"
  | "PREVIOUS_HASH_MISMATCH"
  | "PAYLOAD_HASH_VARIANCE"
  | "SIGNATURE_VERIFY_FAILED"
  | "ROW_HASH_MISMATCH"
  | "CHAIN_HEAD_MISMATCH";

export class TamperError extends Error {
  public readonly tamperKind: TamperKind;
  /** Row index the tamper was detected at, or null for whole-chain checks. */
  public readonly stepIndex: number | null;
  constructor(tamperKind: TamperKind, stepIndex: number | null, message: string) {
    super(
      `[TAMPER:${tamperKind}${stepIndex === null ? "" : "@" + stepIndex}] ${message}`,
    );
    this.name = "TamperError";
    this.tamperKind = tamperKind;
    this.stepIndex = stepIndex;
  }
}
