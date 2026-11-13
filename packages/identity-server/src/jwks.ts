// ============================================================================
// @kashscript/identity-server — JWKS publishing + parsing
// ----------------------------------------------------------------------------
// Publishes Ed25519 public keys as an RFC 7517 JSON Web Key Set in the exact
// wire shape the Indusland verifier route already emits:
//
//   { keys: [{ kty:"OKP", crv:"Ed25519", x, kid, use:"sig", alg:"EdDSA" }] }
//
// served with `content-type: application/jwk-set+json` and
// `cache-control: public, max-age=3600`.
//
// Hard invariant: a published JWKS is PUBLIC-ONLY. `parseJwks` REJECTS any JWK
// carrying a private scalar `d` — a JWKS must never leak private key material.
// This is the guard the Indus route enforces and identity-server single-sources.
// ============================================================================

import { decodeBase64Url, encodeBase64Url } from "@kashscript/identity-core";
import { KashscriptIdentityMalformedPayloadError } from "./errors";

/** MIME type for a JSON Web Key Set response body (RFC 7517 §8.5.1). */
export const JWKS_CONTENT_TYPE = "application/jwk-set+json";

/** Recommended cache lifetime for a published JWKS document. */
export const JWKS_CACHE_CONTROL = "public, max-age=3600";

const ED25519_PUBKEY_BYTES = 32;

/** A public-only Ed25519 JWK in the ecosystem's canonical wire shape. */
export interface Ed25519PublicJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  /** base64url of the raw 32-byte public key. */
  readonly x: string;
  readonly kid: string;
  readonly use: "sig";
  readonly alg: "EdDSA";
}

/** A JSON Web Key Set (public keys only). */
export interface Jwks {
  readonly keys: readonly Ed25519PublicJwk[];
}

/**
 * Builds a public-only Ed25519 JWK from a raw 32-byte public key.
 *
 * @throws KashscriptIdentityMalformedPayloadError on a bad key length or kid.
 */
export function jwkFromEd25519PublicKey(publicKey: Uint8Array, opts: { readonly kid: string }): Ed25519PublicJwk {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ED25519_PUBKEY_BYTES) {
    throw new KashscriptIdentityMalformedPayloadError("publicKey");
  }
  if (typeof opts?.kid !== "string" || opts.kid.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("kid");
  }
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: encodeBase64Url(publicKey),
    kid: opts.kid,
    use: "sig",
    alg: "EdDSA",
  };
}

/** Assembles a JWKS document from `(publicKey, kid)` entries. */
export function publishJwks(
  entries: readonly { readonly publicKey: Uint8Array; readonly kid: string }[],
): Jwks {
  return { keys: entries.map((e) => jwkFromEd25519PublicKey(e.publicKey, { kid: e.kid })) };
}

/**
 * Parses + validates an untrusted JWKS document. Enforces the public-only
 * invariant: throws if ANY key carries a private scalar `d`.
 *
 * @throws KashscriptIdentityMalformedPayloadError on shape violations or if a
 *         private `d` is present.
 */
export function parseJwks(input: unknown): Jwks {
  if (typeof input !== "object" || input === null || !Array.isArray((input as { keys?: unknown }).keys)) {
    throw new KashscriptIdentityMalformedPayloadError("jwks");
  }
  const rawKeys = (input as { keys: unknown[] }).keys;
  const keys: Ed25519PublicJwk[] = [];
  for (let i = 0; i < rawKeys.length; i += 1) {
    const k = rawKeys[i];
    if (typeof k !== "object" || k === null) {
      throw new KashscriptIdentityMalformedPayloadError(`jwks.keys[${i}]`);
    }
    const jwk = k as Record<string, unknown>;
    if ("d" in jwk && jwk.d !== undefined) {
      throw new KashscriptIdentityMalformedPayloadError(`jwks.keys[${i}].d (private material must never appear in a published JWKS)`);
    }
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
      throw new KashscriptIdentityMalformedPayloadError(`jwks.keys[${i}] (expected kty=OKP, crv=Ed25519)`);
    }
    if (typeof jwk.x !== "string" || jwk.x.length === 0) {
      throw new KashscriptIdentityMalformedPayloadError(`jwks.keys[${i}].x`);
    }
    if (typeof jwk.kid !== "string" || jwk.kid.length === 0) {
      throw new KashscriptIdentityMalformedPayloadError(`jwks.keys[${i}].kid`);
    }
    keys.push({
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x,
      kid: jwk.kid,
      use: "sig",
      alg: "EdDSA",
    });
  }
  return { keys };
}

/**
 * Resolves the raw 32-byte public key for `kid` from a JWKS, or null if no key
 * with that id is present.
 *
 * @throws KashscriptIdentityMalformedPayloadError if the matched key's `x` does
 *         not decode to 32 bytes.
 */
export function publicKeyFromJwks(jwks: Jwks, kid: string): Uint8Array | null {
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (jwk === undefined) return null;
  const bytes = decodeBase64Url(jwk.x);
  if (bytes.length !== ED25519_PUBKEY_BYTES) {
    throw new KashscriptIdentityMalformedPayloadError(`jwks key "${kid}" x`);
  }
  return bytes;
}
