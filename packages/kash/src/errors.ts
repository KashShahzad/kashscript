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
  | "VERIFIER_NOT_FOUND"
  /** A public witness (`kash log witness` / `upgrade`) could not be reached, or did not take the hash. */
  | "WITNESS_FAILED"
  /** `@kashscript/floor` (RW-17) is not installed or could not load. */
  | "FLOOR_UNAVAILABLE"
  /** A `kashscript-pack/1` folder is missing a required file or violates the closed pack schema. */
  | "PACK_INVALID"
  /** A pack contains a price, fee, currency figure, or percentage. */
  | "PRICE_IN_PACK"
  /** A pack contains one of the three internal arm words (`studio`, `foundry`, `workshop`). */
  | "INTERNAL_WORD_IN_PACK"
  /** A pack contains a customer-copy never-word. */
  | "COPY_VIOLATION"
  /** A pack's open `kash.rule` failed `@kashscript/predicate` validation or drifted from `rule.md`. */
  | "RULE_INVALID"
  /** A pack failed `@kashscript/floor` (`undeclared-route`, waiver, or AST/manifest rule). */
  | "FLOOR_FAILED"
  /** `kash pack install` refused a server that is not running practice dev-echo mode. */
  | "NOT_PRACTICE_HOST"
  /** A step of `kash pack install` failed against the practice host. */
  | "INSTALL_FAILED"
  /** Offline verification of an approved practice record failed. */
  | "VERIFY_FAILED";

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
