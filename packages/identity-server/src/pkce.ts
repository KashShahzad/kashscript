// ============================================================================
// @kashscript/identity-server — PKCE (RFC 7636), S256 only
// ----------------------------------------------------------------------------
// Proof Key for Code Exchange. MCP authorization (OAuth 2.1) makes PKCE with
// the S256 challenge method MANDATORY and forbids the `plain` method — so this
// module implements S256 ONLY. `code_challenge = BASE64URL(SHA-256(verifier))`.
// ============================================================================

import { encodeBase64Url } from "@kashscript/identity-core";
import { KashscriptIdentityMalformedPayloadError } from "./errors";

/** The only PKCE method this package supports (OAuth 2.1 / MCP requirement). */
export const PKCE_METHOD = "S256" as const;

/** RFC 7636 §4.1 code-verifier length bounds. */
const MIN_VERIFIER_LENGTH = 43;
const MAX_VERIFIER_LENGTH = 128;

/** RFC 7636 §4.1 unreserved code-verifier charset: [A-Z a-z 0-9 - . _ ~]. */
const VERIFIER_CHARSET = /^[A-Za-z0-9\-._~]+$/;

/**
 * Generates a high-entropy code verifier: 32 random bytes → base64url (43
 * chars, within the RFC 7636 43–128 range and unreserved charset).
 */
export function generateCodeVerifier(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/** Validates a code verifier against RFC 7636 §4.1 (length + charset). */
export function assertValidCodeVerifier(verifier: string): void {
  if (
    typeof verifier !== "string" ||
    verifier.length < MIN_VERIFIER_LENGTH ||
    verifier.length > MAX_VERIFIER_LENGTH ||
    !VERIFIER_CHARSET.test(verifier)
  ) {
    throw new KashscriptIdentityMalformedPayloadError("code_verifier");
  }
}

/**
 * Computes the S256 code challenge for a verifier:
 * `BASE64URL(SHA-256(ASCII(verifier)))` (RFC 7636 §4.2).
 *
 * @throws KashscriptIdentityMalformedPayloadError on an invalid verifier.
 */
export async function codeChallengeS256(verifier: string): Promise<string> {
  assertValidCodeVerifier(verifier);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier) as unknown as BufferSource);
  return encodeBase64Url(new Uint8Array(digest));
}

/** Constant-time string comparison (avoids leaking match position via timing). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verifies that `verifier` matches the previously-issued S256 `challenge`.
 * Constant-time comparison over the derived challenge.
 */
export async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  if (typeof challenge !== "string" || challenge.length === 0) return false;
  let derived: string;
  try {
    derived = await codeChallengeS256(verifier);
  } catch {
    return false;
  }
  return timingSafeEqual(derived, challenge);
}
