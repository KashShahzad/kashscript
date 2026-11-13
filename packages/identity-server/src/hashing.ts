// ============================================================================
// @kashscript/identity-server — SHA-256 hashing helpers
// ----------------------------------------------------------------------------
// Exposed for callers that log signature / payload fingerprints without ever
// logging the secret bytes themselves. Both delegate to attest's `sha256Hex`
// (WebCrypto SHA-256 → lowercase hex), so digests are byte-identical to the
// M1 evidence-commons hashing.
// ============================================================================

import { sha256Hex } from "@kashscript/attest";
import { KashscriptIdentityMalformedPayloadError } from "./errors";
import { decodeBase64Strict, utf8Encode } from "./internal";
import type { Base64String, Sha256Hex } from "./types";

/**
 * Computes the SHA-256 hash of a base64-encoded payload, returning the
 * lowercase hex digest.
 *
 * @throws KashscriptIdentityMalformedPayloadError when `input` is not strict base64.
 */
export async function sha256HexOfBase64(input: Base64String): Promise<Sha256Hex> {
  return sha256Hex(decodeBase64Strict(input, "input"));
}

/**
 * Computes the SHA-256 hash of a UTF-8 string, returning the lowercase hex
 * digest. Exposed for canonical-JSON hashing utilities.
 *
 * @throws KashscriptIdentityMalformedPayloadError when `input` is not a string.
 */
export async function sha256HexOfUtf8(input: string): Promise<Sha256Hex> {
  if (typeof input !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("input");
  }
  return sha256Hex(utf8Encode(input));
}
