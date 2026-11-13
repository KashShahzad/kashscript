// ============================================================================
// @kashscript/identity-server — Handshake challenge/response
// ----------------------------------------------------------------------------
// A server-issued challenge whose signature by the DID's private key proves
// possession of that key. `verifyHandshakeSignature` is implemented end-to-end
// against WebCrypto (no upstream call at verification time, given the DID's
// authoritative pubkey). The challenge issue/consume lifecycle is store-backed
// and lives on the IdentityServer instance (see stores.ts) — this module owns
// the pure verify logic + the pure challenge builder.
//
// Handshake signatures are DST-FREE: the signer signs the raw decoded
// `payloadB64` bytes (no domain-separation prefix). This is distinct from the
// `kash-record-v1\n` Kash-Event convention (identity-core) and the Indus
// `0x00`-prefixed token convention (attest) — kept wire-compatible with the
// @duedale/identity-kernel seed so the venture swap re-verifies byte-for-byte.
//
// Four data trajectories at the verifier perimeter:
//   - Happy : pubkey imports, signature verifies → { ok: true }.
//   - Nil   : signature / pubkey base64 blob absent or undecodable
//             → { ok: false, reason: "INVALID_SIGNATURE_FORMAT" }.
//   - Empty : challenge already expired OR decoded payload zero-length
//             → { ok: false, reason: "EXPIRED_CHALLENGE" | "INVALID_SIGNATURE_FORMAT" }.
//   - Error : unsupported algorithm → "PUBKEY_ALGORITHM_UNSUPPORTED";
//             cryptographic mismatch (wrong key / mutated payload / mutated
//             signature) → "SPOOFED_SIGNATURE".
// ============================================================================

import { KashscriptIdentityUnsupportedAlgorithmError } from "./errors";
import { asBufferSource, bytesToBase64, bytesToHex, decodeBase64Strict, nowUnix } from "./internal";
import type {
  Base64String,
  Did,
  HandshakeChallenge,
  SignatureAlgorithm,
  SignatureVerificationResult,
} from "./types";

/** Handshake challenge validity window: five minutes. */
export const HANDSHAKE_CHALLENGE_TTL_SECONDS = 300;

/** Random payload length for a handshake challenge: 32 bytes. */
const CHALLENGE_PAYLOAD_BYTES = 32;

/** Random challenge-id entropy: 16 bytes → 32 hex chars (`chal_<32hex>`). */
const CHALLENGE_ID_BYTES = 16;

// ----------------------------------------------------------------------------
// ASN.1 SPKI wrap (RFC 8410 §4) — lets WebCrypto's `importKey("spki", …)`
// accept a raw 32-byte Ed25519 public key. The 32-byte key occupies offsets
// 12..43 of the 44-byte SPKI envelope.
// ----------------------------------------------------------------------------

const ED25519_SPKI_TEMPLATE: Uint8Array = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_SPKI_LENGTH = 44;
const ED25519_RAW_PUBKEY_LENGTH = 32;

function wrapRawEd25519InSpki(rawPubkey: Uint8Array): Uint8Array {
  const out = new Uint8Array(ED25519_SPKI_LENGTH);
  out.set(ED25519_SPKI_TEMPLATE, 0);
  out.set(rawPubkey, ED25519_SPKI_TEMPLATE.length);
  return out;
}

/** WebCrypto `importKey` algorithm identifier for the supported algorithms. */
function resolveImportAlgorithm(algorithm: SignatureAlgorithm): AlgorithmIdentifier | EcKeyImportParams {
  if (algorithm === "ed25519") return { name: "Ed25519" };
  if (algorithm === "ecdsa-p256") return { name: "ECDSA", namedCurve: "P-256" };
  throw new KashscriptIdentityUnsupportedAlgorithmError(algorithm);
}

/** WebCrypto `verify` algorithm identifier. ECDSA needs a hash; Ed25519 does not. */
function resolveVerifyAlgorithm(algorithm: SignatureAlgorithm): AlgorithmIdentifier | EcdsaParams {
  if (algorithm === "ed25519") return { name: "Ed25519" };
  if (algorithm === "ecdsa-p256") return { name: "ECDSA", hash: { name: "SHA-256" } };
  throw new KashscriptIdentityUnsupportedAlgorithmError(algorithm);
}

/** Imports a public key as a WebCrypto CryptoKey suitable for `verify`. For
 *  Ed25519, accepts EITHER a 32-byte raw pubkey or a 44-byte SPKI DER. For
 *  ECDSA P-256, accepts SPKI DER only. */
async function importPublicKeyForVerification(
  algorithm: SignatureAlgorithm,
  publicKeyB64: Base64String,
): Promise<CryptoKey> {
  const raw = decodeBase64Strict(publicKeyB64, "publicKeyB64");
  const importParams = resolveImportAlgorithm(algorithm);
  if (algorithm === "ed25519") {
    const spki =
      raw.length === ED25519_RAW_PUBKEY_LENGTH
        ? wrapRawEd25519InSpki(raw)
        : raw.length === ED25519_SPKI_LENGTH
          ? raw
          : null;
    if (spki === null) {
      throw new KashscriptIdentityUnsupportedAlgorithmError("ed25519:malformed-length");
    }
    return crypto.subtle.importKey("spki", asBufferSource(spki), importParams, false, ["verify"]);
  }
  // ECDSA P-256 SPKI is variable-length (~91 bytes); defer to WebCrypto's parser.
  return crypto.subtle.importKey("spki", asBufferSource(raw), importParams, false, ["verify"]);
}

// ----------------------------------------------------------------------------
// Pure challenge construction (persisted by the IdentityServer instance)
// ----------------------------------------------------------------------------

/**
 * Builds a fresh single-use handshake challenge for `did`: a `chal_<32hex>`
 * id, 32 random payload bytes (base64), and a 300-second validity window. The
 * caller (the IdentityServer instance) persists it in a ChallengeStore and
 * atomically consumes it on verification.
 */
export function buildHandshakeChallenge(did: Did, nowSec: number = nowUnix()): HandshakeChallenge {
  const idBytes = crypto.getRandomValues(new Uint8Array(CHALLENGE_ID_BYTES));
  const payloadBytes = crypto.getRandomValues(new Uint8Array(CHALLENGE_PAYLOAD_BYTES));
  return {
    challengeId: `chal_${bytesToHex(idBytes)}`,
    did,
    payloadB64: bytesToBase64(payloadBytes),
    issuedAtUnix: nowSec,
    expiresAtUnix: nowSec + HANDSHAKE_CHALLENGE_TTL_SECONDS,
  };
}

// ----------------------------------------------------------------------------
// Verification (storeless; end-to-end WebCrypto)
// ----------------------------------------------------------------------------

/**
 * Verifies that a signature over a challenge's payload was produced by the
 * DID's private key. Callers MUST supply the DID's authoritative pubkey
 * (typically via `resolveDidPubkey`); this function never trusts a
 * self-supplied key implicitly.
 */
export async function verifyHandshakeSignature(args: {
  readonly challenge: HandshakeChallenge;
  readonly signatureB64: Base64String;
  readonly algorithm: SignatureAlgorithm;
  readonly publicKeyB64: Base64String;
}): Promise<SignatureVerificationResult> {
  const verifiedAtUnix = nowUnix();

  // -------- Empty path 1 — challenge already expired -------------------
  if (
    typeof args.challenge !== "object" ||
    args.challenge === null ||
    typeof args.challenge.expiresAtUnix !== "number" ||
    args.challenge.expiresAtUnix <= verifiedAtUnix
  ) {
    return { ok: false, reason: "EXPIRED_CHALLENGE", verifiedAtUnix };
  }

  // -------- Nil path — signature / payload base64 absent or undecodable -
  let signatureBytes: Uint8Array;
  let payloadBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Strict(args.signatureB64, "signatureB64");
    payloadBytes = decodeBase64Strict(args.challenge.payloadB64, "challenge.payloadB64");
  } catch {
    return { ok: false, reason: "INVALID_SIGNATURE_FORMAT", verifiedAtUnix };
  }

  // -------- Empty path 2 — zero-length payload / signature --------------
  if (payloadBytes.length === 0 || signatureBytes.length === 0) {
    return { ok: false, reason: "INVALID_SIGNATURE_FORMAT", verifiedAtUnix };
  }

  // -------- Error path — unsupported algorithm + key import failure -----
  let pubkey: CryptoKey;
  try {
    pubkey = await importPublicKeyForVerification(args.algorithm, args.publicKeyB64);
  } catch (err) {
    if (err instanceof KashscriptIdentityUnsupportedAlgorithmError) {
      return { ok: false, reason: "PUBKEY_ALGORITHM_UNSUPPORTED", verifiedAtUnix };
    }
    return { ok: false, reason: "INVALID_SIGNATURE_FORMAT", verifiedAtUnix };
  }

  // -------- Cryptographic verification via WebCrypto -------------------
  // `subtle.verify` returns false on any signature failure (wrong key,
  // malformed signature bytes, payload mismatch); it throws only for
  // algorithm / format mismatches at the input layer.
  let cryptographicallyValid = false;
  try {
    const verifyAlg = resolveVerifyAlgorithm(args.algorithm);
    cryptographicallyValid = await crypto.subtle.verify(
      verifyAlg,
      pubkey,
      asBufferSource(signatureBytes),
      asBufferSource(payloadBytes),
    );
  } catch {
    return { ok: false, reason: "INVALID_SIGNATURE_FORMAT", verifiedAtUnix };
  }

  if (!cryptographicallyValid) {
    return { ok: false, reason: "SPOOFED_SIGNATURE", verifiedAtUnix };
  }

  // -------- Happy path -------------------------------------------------
  return { ok: true, reason: null, verifiedAtUnix };
}

/** The public-key algorithms this package can import + verify. */
export const SUPPORTED_ALGORITHMS: readonly SignatureAlgorithm[] = Object.freeze([
  "ed25519",
  "ecdsa-p256",
]);
