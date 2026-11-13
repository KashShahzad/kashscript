// ============================================================================
// @kashscript/identity-server — Error classes
// ----------------------------------------------------------------------------
// All result-bearing operations RETURN tagged-union results (see types.ts).
// These exception classes exist for **unrecoverable** programmer errors and
// the transport-not-provisioned case.
//
// The codes are provider-neutral (`KS_IDENTITY_*`). A consuming venture maps
// them to its own error envelope at its perimeter — e.g. Duedale's ks-adapters
// bridge maps `KS_IDENTITY_NOT_IMPLEMENTED` → `DD_503_KS_IDENTITY_UNAVAILABLE`.
// That mapping stays venture-side (ADR-0016 guard b); this package never emits
// a `DD_*` code.
//
// Ported from @duedale/identity-kernel (M2 of the protocol Manifestation,
// ADR-0016) — the seed for this package. The four classes are byte-faithful so
// the venture swap is drop-in.
// ============================================================================

/** Common shape for every error this package throws. */
export interface KashscriptIdentityErrorShape {
  readonly code: string;
  readonly message: string;
  readonly cause?: unknown;
}

/**
 * Thrown when a method is invoked whose transport dependency has not been
 * provisioned — e.g. a store-backed operation reached without an injected
 * store. A consuming venture's bridge catches this and surfaces it as its own
 * "identity service unavailable" envelope.
 */
export class KashscriptIdentityNotImplementedError extends Error implements KashscriptIdentityErrorShape {
  readonly code: "KS_IDENTITY_NOT_IMPLEMENTED" = "KS_IDENTITY_NOT_IMPLEMENTED";
  readonly methodName: string;

  constructor(methodName: string, cause?: unknown) {
    super(
      `@kashscript/identity-server.${methodName} requires a transport/store dependency that was ` +
      `not provisioned. Inject a store via createIdentityServer(...) before invoking this method.`,
    );
    this.name = "KashscriptIdentityNotImplementedError";
    this.methodName = methodName;
    if (cause !== undefined) {
      Object.defineProperty(this, "cause", { value: cause, enumerable: false });
    }
  }
}

/**
 * Thrown when a caller passes a malformed DID string. Distinct from the
 * `DID_MALFORMED` result-envelope reason because programmer-supplied input
 * (e.g. a hard-coded test DID) failing format validation indicates a code
 * defect, not an authentication-failure mode.
 */
export class KashscriptIdentityMalformedDidError extends Error implements KashscriptIdentityErrorShape {
  readonly code: "KS_IDENTITY_MALFORMED_DID" = "KS_IDENTITY_MALFORMED_DID";
  readonly suppliedDid: string;

  constructor(suppliedDid: string) {
    super(
      `Supplied DID "${suppliedDid}" does not match the canonical did:kash format ` +
      `(expected "did:kash:<base58btc>" whose body decodes to a 32-byte Ed25519 public key per RFC 8032).`,
    );
    this.name = "KashscriptIdentityMalformedDidError";
    this.suppliedDid = suppliedDid;
  }
}

/** Thrown when a base64 payload supplied to a function fails decoding. */
export class KashscriptIdentityMalformedPayloadError extends Error implements KashscriptIdentityErrorShape {
  readonly code: "KS_IDENTITY_MALFORMED_PAYLOAD" = "KS_IDENTITY_MALFORMED_PAYLOAD";
  readonly fieldName: string;

  constructor(fieldName: string, cause?: unknown) {
    super(`Supplied "${fieldName}" payload could not be decoded as base64.`);
    this.name = "KashscriptIdentityMalformedPayloadError";
    this.fieldName = fieldName;
    if (cause !== undefined) {
      Object.defineProperty(this, "cause", { value: cause, enumerable: false });
    }
  }
}

/** Thrown when an algorithm not in `SignatureAlgorithm` is requested. */
export class KashscriptIdentityUnsupportedAlgorithmError extends Error implements KashscriptIdentityErrorShape {
  readonly code: "KS_IDENTITY_UNSUPPORTED_ALGORITHM" = "KS_IDENTITY_UNSUPPORTED_ALGORITHM";
  readonly suppliedAlgorithm: string;

  constructor(suppliedAlgorithm: string) {
    super(
      `Algorithm "${suppliedAlgorithm}" is not supported by @kashscript/identity-server v0.1.x. ` +
      `Supported algorithms: ed25519, ecdsa-p256.`,
    );
    this.name = "KashscriptIdentityUnsupportedAlgorithmError";
    this.suppliedAlgorithm = suppliedAlgorithm;
  }
}
