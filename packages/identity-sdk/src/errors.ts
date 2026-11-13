/**
 * SDK-tier error class. Crypto-tier errors from @kashscript/identity-core
 * bubble through as their own `KashCryptoError` — callers should `instanceof`
 * either when distinguishing.
 */

export type KashSdkErrorCode =
  /** WebAuthn / Credentials API unavailable in this environment. */
  | "WEBAUTHN_UNAVAILABLE"
  /** User cancelled the biometric prompt or no matching credential. */
  | "WEBAUTHN_CANCELLED"
  /** The authenticator returned a non-public-key credential. */
  | "WEBAUTHN_UNEXPECTED_CREDENTIAL"
  /** The clientDataJSON `origin` field does not match window.location.origin. */
  | "WEBAUTHN_ORIGIN_MISMATCH"
  /** The clientDataJSON `challenge` field does not match the expected challenge. */
  | "WEBAUTHN_CHALLENGE_MISMATCH"
  /** The clientDataJSON `type` field is not the expected ceremony type. */
  | "WEBAUTHN_TYPE_MISMATCH"
  /** The clientDataJSON `crossOrigin` flag was set — ceremony ran inside an iframe. */
  | "WEBAUTHN_CROSS_ORIGIN"
  /** A registered Passkey could not be located by the authenticator (storage was cleared / device wiped). */
  | "WEBAUTHN_ORPHANED_CREDENTIAL"
  /** No active session and no usable recovery path — caller should surface the Quorum-recovery flow. */
  | "RECOVERY_REQUIRED"
  /** Storage layer (localStorage / IndexedDB) is unavailable or rejected. */
  | "STORAGE_UNAVAILABLE"
  /** A required serialised identity field is missing or malformed. */
  | "STORAGE_CORRUPT"
  /** Method was called outside the React context boundary. */
  | "PROVIDER_MISSING"
  /** Method was called before the SDK finished hydrating. */
  | "NOT_READY"
  /** Method requires an active session but none is present. */
  | "NOT_AUTHENTICATED"
  /** A previous identity already exists in storage. */
  | "ALREADY_REGISTERED"
  /** Generic argument validation failure. */
  | "INVALID_INPUT";

export class KashSdkError extends Error {
  override readonly name = "KashSdkError";
  readonly code: KashSdkErrorCode;
  override readonly cause?: unknown;

  constructor(message: string, code: KashSdkErrorCode, cause?: unknown) {
    super(message);
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, KashSdkError.prototype);
  }
}

/** True when the user cancelled or the host has no matching credential. */
export function isUserCancellation(err: unknown): boolean {
  if (err instanceof KashSdkError) return err.code === "WEBAUTHN_CANCELLED";
  if (err instanceof DOMException) {
    return err.name === "NotAllowedError" || err.name === "AbortError";
  }
  return false;
}
