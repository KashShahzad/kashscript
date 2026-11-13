/**
 * Single typed error class for every failure in this package.
 *
 * Callers should `instanceof KashCryptoError` and switch on `code` to handle
 * specific failure classes without parsing error messages.
 */

export type KashCryptoErrorCode =
  /** crypto.subtle.generateKey or the underlying RNG failed. */
  | "KEY_GENERATION_FAILED"
  /** JWK / raw input was syntactically valid but could not be imported. */
  | "KEY_IMPORT_FAILED"
  /** Export operation rejected the input (e.g., bytes wrong length). */
  | "KEY_EXPORT_FAILED"
  /** Underlying crypto.subtle.sign rejected the input or threw at runtime. */
  | "SIGN_FAILED"
  /** Key bytes are malformed (wrong length, non-Ed25519, mismatched seed/public). */
  | "INVALID_KEY_BYTES"
  /** JWK or other serialised form has wrong shape (missing fields, wrong kty/crv). */
  | "INVALID_KEY_FORMAT"
  /** Input string is not a well-formed did:kash. */
  | "INVALID_DID"
  /** Base58 / base64url / hex decode failed on a malformed character. */
  | "INVALID_ENCODING"
  /** Input to createDidDocument, canonicalize, or another pure formatter is malformed. */
  | "INVALID_INPUT"
  /** Signature algorithm is structurally valid but not supported by this build. */
  | "UNSUPPORTED_ALG"
  /** This RUNTIME's WebCrypto lacks the algorithm (older browsers lack Ed25519).
   *  Nothing was judged: never report this as an invalid signature. */
  | "ALG_UNAVAILABLE"
  /** DID Document does not contain a verificationMethod with the requested kid. */
  | "KID_NOT_RESOLVED";

export class KashCryptoError extends Error {
  override readonly name = "KashCryptoError";
  readonly code: KashCryptoErrorCode;
  override readonly cause?: unknown;

  constructor(message: string, code: KashCryptoErrorCode, cause?: unknown) {
    super(message);
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    // Restore prototype chain when transpiled to ES5 / commonjs.
    Object.setPrototypeOf(this, KashCryptoError.prototype);
  }
}

/** Convenience constructor used internally for guard clauses. */
export function failCrypto(
  code: KashCryptoErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new KashCryptoError(message, code, cause);
}
