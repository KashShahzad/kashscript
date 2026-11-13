// ============================================================================
// @kashscript/identity-server — Type Definitions
// ----------------------------------------------------------------------------
// Every result-bearing call uses a tagged-union discriminated by `ok`.
// The pattern enables four-path discipline (Happy / Nil / Empty / Error) at the
// type level: callers cannot accidentally use a result without first checking
// `ok`.
//
// Ported byte-faithfully from @duedale/identity-kernel (M2, ADR-0016) so the
// venture swap onto the published package is drop-in.
// ============================================================================

/**
 * A KashScript DID string in the canonical `did:kash:<base58btc-pubkey>`
 * form, e.g. "did:kash:9qWzTMaHUuBQfZT5qLaVDCmQpjGLjk867P4Vfn31YvU6".
 *
 * The method-specific identifier is a base58btc encoding of the raw 32-byte
 * Ed25519 public key (RFC 8032). Resolution is deterministic and key-only:
 * any holder of the public key can reproduce the DID without consulting a
 * registry, and any consumer of the DID can extract the public key
 * synchronously via `@kashscript/identity-core/did.parseDid`.
 *
 * Acceptance is enforced by `isKashDid` from `@kashscript/identity-core`,
 * which both regex-matches the structural shape AND verifies that the
 * base58btc body decodes to exactly 32 bytes. The internal validator
 * `assertDidWellFormed` delegates to that helper so the acceptance rule
 * is single-sourced.
 */
export type Did = string;

/** Base64-encoded byte payload (no `data:` URI prefix, no whitespace). */
export type Base64String = string;

/** Hex-encoded SHA-256 digest (lowercase, 64 chars). */
export type Sha256Hex = string;

/** Unix seconds, integer. */
export type UnixSeconds = number;

/** Supported public-key algorithms in v0.1.x. */
export type SignatureAlgorithm = "ed25519" | "ecdsa-p256";

/** Trace identifier propagated end-to-end for cross-service correlation. */
export type TraceId = string;

// ----------------------------------------------------------------------------
// DID resolution
// ----------------------------------------------------------------------------

/**
 * Authoritative resolution of a DID's public-key material.
 *
 * For self-certifying `did:kash` DIDs the public key is intrinsic to the
 * identifier (extracted via `parseDid`); the identity metadata store supplies
 * the mutable envelope — `isGuestDid`, `expiresAtUnix`, `pdsEndpoint`, and
 * revocation status. The pubkey is NEVER sourced from client-supplied input.
 */
export interface DidPubkey {
  readonly did: Did;
  readonly algorithm: SignatureAlgorithm;
  readonly publicKeyB64: Base64String;
  readonly issuedAtUnix: UnixSeconds;
  /** Null for permanent DIDs; populated for guest and time-bound DIDs. */
  readonly expiresAtUnix: UnixSeconds | null;
  readonly isGuestDid: boolean;
  /** Optional PDS endpoint registered with this DID. */
  readonly pdsEndpoint: string | null;
}

/**
 * Result envelope for `resolveDidPubkey`.
 *
 * Path mapping:
 *   - Happy        → { ok: true, pubkey }
 *   - Nil          → { ok: false, reason: "NOT_FOUND" }
 *   - Empty        → (not applicable — resolution is single-record)
 *   - Error/Spoof  → { ok: false, reason: "REVOKED" | "UPSTREAM_UNAVAILABLE" | "DID_MALFORMED" }
 */
export type ResolveDidPubkeyResult =
  | { readonly ok: true;  readonly pubkey: DidPubkey }
  | { readonly ok: false; readonly reason: ResolveDidPubkeyFailureReason; readonly traceId: TraceId };

export type ResolveDidPubkeyFailureReason =
  | "NOT_FOUND"
  | "REVOKED"
  | "DID_MALFORMED"
  | "UPSTREAM_UNAVAILABLE";

// ----------------------------------------------------------------------------
// Handshake challenge + verification
// ----------------------------------------------------------------------------

/**
 * Server-issued challenge whose signature by the DID's private key proves
 * possession of that key. Used at session-establishment time and for PDS
 * write authorisation.
 */
export interface HandshakeChallenge {
  readonly challengeId: string;
  readonly did: Did;
  /** Random 32-byte payload, base64-encoded. */
  readonly payloadB64: Base64String;
  readonly issuedAtUnix: UnixSeconds;
  readonly expiresAtUnix: UnixSeconds;
}

/**
 * Verification outcome for `verifyHandshakeSignature`.
 *
 * `reason: null` means verification succeeded.
 * `reason: "SPOOFED_SIGNATURE"` indicates the signature parsed and the key
 *   resolved but the cryptographic verification failed — i.e. the caller
 *   does not possess the DID's private key. This is the malicious-credential
 *   path required by the doctrine.
 */
export interface SignatureVerificationResult {
  readonly ok: boolean;
  readonly reason: SignatureVerificationFailureReason | null;
  readonly verifiedAtUnix: UnixSeconds;
}

export type SignatureVerificationFailureReason =
  | "INVALID_SIGNATURE_FORMAT"
  | "EXPIRED_CHALLENGE"
  | "DID_UNKNOWN"
  | "PUBKEY_ALGORITHM_UNSUPPORTED"
  | "SPOOFED_SIGNATURE"
  | "UPSTREAM_UNAVAILABLE";

// ----------------------------------------------------------------------------
// PDS read / write
// ----------------------------------------------------------------------------

/** A PDS collection identifier — e.g. "audit.v1", "trade.otdc.v1". */
export type PdsCollection = string;

/** A canonical-JSON record persisted into a user's Personal Data Store. */
export interface PdsRecord {
  readonly collection: PdsCollection;
  /** Stable record key within the collection. */
  readonly recordKey: string;
  /** Canonical-JSON of the record body. The PDS stores this verbatim. */
  readonly contentJson: string;
  /** Caller-declared schema version for forward compatibility. */
  readonly schemaVersion: number;
  /** Optional. When provided, the PDS rejects writes that would mutate
   *  a record at a different revision. */
  readonly expectedRevision: number | null;
}

/** Successful write returns a content-addressed identifier. */
export interface PdsWriteSuccess {
  readonly ok: true;
  readonly cid: string;
  readonly revision: number;
  readonly writtenAtUnix: UnixSeconds;
}

export type PdsWriteFailureReason =
  | "PDS_UNPROVISIONED"
  | "DID_UNKNOWN"
  | "SIGNATURE_REJECTED"
  | "COLLECTION_UNKNOWN"
  | "REVISION_CONFLICT"
  | "RECORD_TOO_LARGE"
  | "UPSTREAM_UNAVAILABLE";

export type WritePdsRecordResult =
  | PdsWriteSuccess
  | { readonly ok: false; readonly reason: PdsWriteFailureReason; readonly traceId: TraceId };

/** Result envelope for read-side PDS operations. */
export type ReadPdsRecordResult =
  | { readonly ok: true;  readonly record: PdsRecord; readonly cid: string; readonly revision: number }
  | { readonly ok: false; readonly reason: "NOT_FOUND" | "PDS_UNPROVISIONED" | "DID_UNKNOWN" | "UPSTREAM_UNAVAILABLE"; readonly traceId: TraceId };

// ----------------------------------------------------------------------------
// Guest DID issuance
// ----------------------------------------------------------------------------

export interface GuestDidIssuanceRequest {
  /** Origin of the embedding page (validated against the caller's allow-list
   *  upstream of this call). */
  readonly hostOrigin: string;
  /** Hashed client fingerprint (already privacy-scrubbed by the caller). */
  readonly clientFingerprintHash: string;
  /** Hashed source IP for rate-limit attribution and forensic audit. */
  readonly sourceIpHash: string;
  /** Hashed User-Agent string. */
  readonly userAgentHash: string;
  /** BCP-47 locale code for the issued DID. */
  readonly localeCode: string;
  /** Default expiry — 7 days from issuance. Caller may shorten but not extend. */
  readonly requestedExpirySeconds: number;
}

/** Container for the server-generated keypair returned to the client.
 *  The private key is delivered ONCE over the TLS channel and NEVER
 *  persisted server-side. */
export interface GuestDidIssuance {
  readonly did: Did;
  readonly pubkey: DidPubkey;
  /** Base64-encoded private key (Ed25519 — 32 bytes raw). */
  readonly privateKeyB64: Base64String;
  readonly expiresAtUnix: UnixSeconds;
}

export type IssueGuestDidFailureReason =
  | "RATE_LIMITED_HOUR"
  | "RATE_LIMITED_DAY"
  | "DENYLISTED"
  | "CAPTCHA_REQUIRED"
  | "ORIGIN_REJECTED"
  | "UPSTREAM_UNAVAILABLE";

export type IssueGuestDidResult =
  | { readonly ok: true;  readonly issuance: GuestDidIssuance }
  | { readonly ok: false; readonly reason: IssueGuestDidFailureReason; readonly traceId: TraceId };

/** Result of explicit guest-DID revocation (used by ops or scheduled reap). */
export type RevokeGuestDidResult =
  | { readonly ok: true;  readonly revokedAtUnix: UnixSeconds }
  | { readonly ok: false; readonly reason: "NOT_FOUND" | "NOT_A_GUEST_DID" | "UPSTREAM_UNAVAILABLE"; readonly traceId: TraceId };
