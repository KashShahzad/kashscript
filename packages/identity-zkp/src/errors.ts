/**
 * Single typed error for the ZKP package. Crypto-tier failures from
 * @kashscript/identity-core continue to surface as `KashCryptoError`.
 */

export type KashZkpErrorCode =
  /** Input body is empty, malformed, or contains non-canonicalisable values. */
  | "INVALID_BODY"
  /** A revealed field's claimed value does not hash to the committed leaf. */
  | "DISCLOSURE_LEAF_MISMATCH"
  /** A redacted field's path does not reconstruct the committed root. */
  | "DISCLOSURE_PATH_MISMATCH"
  /** Salt collection is missing required entries or is the wrong shape. */
  | "DISCLOSURE_SALT_MISMATCH"
  /** Header.cid is absent or not a valid 32-byte hex / base16 root. */
  | "DISCLOSURE_INVALID_ROOT"
  /** Recovered root from the disclosure does not match `header.cid`. */
  | "DISCLOSURE_ROOT_MISMATCH"
  /** Verifier-bound wrapper's audience / bindingHash does not validate. */
  | "DISCLOSURE_BINDING_MISMATCH"
  /** Verifier-bound wrapper has elapsed its `expiresAt`. */
  | "DISCLOSURE_BINDING_EXPIRED"
  /** Caller built a self-attestable range-proof witness without acknowledging the limitation (F1). */
  | "UNSAFE_WITNESS"
  /** Prover request was aborted via AbortSignal before completion. */
  | "PROVE_ABORTED"
  /** snarkjs (or compatible peer dep) is not installed or could not be loaded. */
  | "SNARKJS_UNAVAILABLE"
  /** WebWorker construction or messaging failed in the host environment. */
  | "WORKER_UNAVAILABLE"
  /** Worker reported a runtime error during prove / verify. */
  | "WORKER_FAILED"
  /** Circuit specification is missing required artifacts (wasm / zkey / vk). */
  | "INVALID_CIRCUIT_SPEC"
  /** Witness inputs do not match the declared circuit shape. */
  | "INVALID_WITNESS"
  /** Verification key is malformed or does not match the proof system. */
  | "INVALID_VERIFICATION_KEY"
  /** Proof object is malformed or wrong shape for the declared proof system. */
  | "INVALID_PROOF"
  /** Generic argument validation failure. */
  | "INVALID_INPUT";

export class KashZkpError extends Error {
  override readonly name = "KashZkpError";
  readonly code: KashZkpErrorCode;
  override readonly cause?: unknown;

  constructor(message: string, code: KashZkpErrorCode, cause?: unknown) {
    super(message);
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, KashZkpError.prototype);
  }
}
