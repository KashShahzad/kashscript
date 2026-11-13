/**
 * CLI-tier error class. Crypto errors from `@kashscript/identity-core` and
 * `@kashscript/attest` bubble through as their own classes — `instanceof` either
 * when distinguishing.
 */

export type KashCliErrorCode =
  /** Could not locate a package.json by walking up from cwd. */
  | "PROJECT_NOT_FOUND"
  /** A file operation would mutate state without a backup. */
  | "UNSAFE_WRITE"
  /** Generic argument validation. */
  | "INVALID_INPUT"
  /** `station init` would overwrite a key that already exists. */
  | "KEY_EXISTS"
  /** The named key is not in the keystore, or the path does not exist. */
  | "KEY_NOT_FOUND"
  /** A key file is malformed, or its DID is not the one its key derives. */
  | "KEY_INVALID"
  /** A key file is readable by someone other than its owner (POSIX). */
  | "KEY_UNPROTECTED"
  /** A record or request failed the checks made before anything was written. */
  | "RECORD_INVALID"
  /** The carried link does not decode, or does not match the record it came with. */
  | "LINK_INVALID"
  /** The record names a different station than the key offered to countersign it. */
  | "WRONG_STATION"
  /** `verify` could not find attest's verifier to run. */
  | "VERIFIER_NOT_FOUND";

export class KashCliError extends Error {
  override readonly name = "KashCliError";
  readonly code: KashCliErrorCode;
  override readonly cause?: unknown;

  constructor(message: string, code: KashCliErrorCode, cause?: unknown) {
    super(message);
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, KashCliError.prototype);
  }
}
