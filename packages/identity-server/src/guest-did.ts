// ============================================================================
// @kashscript/identity-server — Guest-DID issuance
// ----------------------------------------------------------------------------
// Guest DIDs are NEVER self-asserted. The identity authority generates the
// Ed25519 keypair, derives a self-certifying `did:kash`, and surrenders the
// private key to the caller ONCE (custodial-at-mint). The private key is
// never persisted server-side.
//
// Ported verbatim from @duedale/identity-kernel.issueGuestDid (M2, ADR-0016).
// The keypair + DID derivation runs against `@kashscript/identity-core` (which
// itself uses `globalThis.crypto.subtle`), so this call is edge-runtime safe.
//
// Rate-limiting, denylisting, origin allow-listing, and CAPTCHA gating (the
// `IssueGuestDidFailureReason` variants) are the caller's responsibility and
// stay venture-side — this function is the pure mint step.
// ============================================================================

import { deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { KashscriptIdentityMalformedPayloadError } from "./errors";
import { bytesToBase64, nowUnix } from "./internal";
import type { GuestDidIssuanceRequest, IssueGuestDidResult } from "./types";

/** The workspace-wide guest-DID expiry cap: seven days. Callers may request a
 *  shorter window but never extend beyond this. */
export const MAX_GUEST_EXPIRY_SECONDS = 7 * 24 * 60 * 60;

/**
 * Issues a server-generated guest DID with a server-witnessed pubkey.
 *
 * State paths:
 *   - Happy → { ok: true, issuance }
 *   - The rate-limit / denylist / origin-reject failure paths are enforced by
 *     the caller before this function is reached.
 *
 * @throws KashscriptIdentityMalformedPayloadError on invalid request fields.
 */
export async function issueGuestDid(
  request: GuestDidIssuanceRequest,
): Promise<IssueGuestDidResult> {
  if (typeof request !== "object" || request === null) {
    throw new KashscriptIdentityMalformedPayloadError("request");
  }
  if (typeof request.requestedExpirySeconds !== "number" || request.requestedExpirySeconds <= 0) {
    throw new KashscriptIdentityMalformedPayloadError("requestedExpirySeconds");
  }
  if (typeof request.hostOrigin !== "string" || request.hostOrigin.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("hostOrigin");
  }

  // Generate a fresh Ed25519 keypair via @kashscript/identity-core (runs on
  // globalThis.crypto.subtle → edge-runtime safe).
  const keypair = await generateKeyPair();

  // Derive the canonical `did:kash:*` identifier directly from the public key
  // bytes. Self-sovereign — any later consumer extracts the public key
  // synchronously via `parseDid` without consulting a registry.
  const did = deriveDid(keypair.publicKey);

  // Bound the expiry at the seven-day guest cap.
  const issuedAtUnix = nowUnix();
  const cappedExpiry = Math.min(request.requestedExpirySeconds, MAX_GUEST_EXPIRY_SECONDS);
  const expiresAtUnix = issuedAtUnix + cappedExpiry;

  return {
    ok: true,
    issuance: {
      did,
      pubkey: {
        did,
        algorithm: "ed25519",
        publicKeyB64: bytesToBase64(keypair.publicKey),
        issuedAtUnix,
        expiresAtUnix,
        isGuestDid: true,
        pdsEndpoint: null,
      },
      privateKeyB64: bytesToBase64(keypair.privateKey),
      expiresAtUnix,
    },
  };
}
