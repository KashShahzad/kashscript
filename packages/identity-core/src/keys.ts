/**
 * Ed25519 key pair generation, export, and import.
 *
 * Implementation runs against the WebCrypto API directly — supported natively
 * by Node 20+, Bun, Deno, and modern browsers (Chrome 137+, Firefox 130+,
 * Safari 17+). Zero runtime dependencies.
 *
 * The package treats keys as raw `Uint8Array` byte buffers for in-memory work,
 * and JSON Web Keys (RFC 7517) for safe serialisation to a secure enclave.
 */

import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { KashCryptoError } from "./errors";

const ED25519_KEY_BYTES = 32;

/**
 * In-memory Ed25519 key pair. Both halves are 32-byte raw seeds.
 *
 * The private key is the seed used directly by Ed25519's signing algorithm;
 * it must be kept secret. The public key is derived deterministically from
 * the private seed.
 */
export interface KashKeyPair {
  /** 32-byte Ed25519 seed. SECRET. */
  readonly privateKey: Uint8Array;
  /** 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
}

/**
 * JSON Web Key representation of an Ed25519 key pair.
 *
 * Follows RFC 8037 (Ed25519 JWK). Includes BOTH the public (`x`) and private
 * (`d`) halves so a single object is sufficient to round-trip a key pair.
 * Suitable for storage in a secure enclave, OS keychain, or encrypted blob.
 */
export interface ExportedKey {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  /** Public key, 32 bytes, base64url-encoded. */
  readonly x: string;
  /** Private seed, 32 bytes, base64url-encoded. SECRET. */
  readonly d: string;
}

/** Generate a fresh Ed25519 key pair via WebCrypto. */
export async function generateKeyPair(): Promise<KashKeyPair> {
  if (typeof crypto === "undefined" || crypto.subtle === undefined) {
    throw new KashCryptoError(
      "WebCrypto API unavailable; @kashscript/identity-core requires globalThis.crypto.subtle (Node 20+, Bun, modern browsers).",
      "KEY_GENERATION_FAILED",
    );
  }

  let pair: CryptoKeyPair;
  try {
    pair = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
  } catch (err) {
    throw new KashCryptoError(
      "WebCrypto rejected Ed25519 key generation (host may not support Ed25519).",
      "KEY_GENERATION_FAILED",
      err,
    );
  }

  let publicKey: Uint8Array;
  let privateKey: Uint8Array;
  try {
    const publicRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
    publicKey = new Uint8Array(publicRaw);

    const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
    if (typeof privateJwk.d !== "string") {
      throw new KashCryptoError(
        "WebCrypto returned an Ed25519 private JWK without the `d` scalar.",
        "KEY_GENERATION_FAILED",
      );
    }
    privateKey = decodeBase64Url(privateJwk.d);
  } catch (err) {
    if (err instanceof KashCryptoError) throw err;
    throw new KashCryptoError(
      "Failed to export freshly generated Ed25519 key material.",
      "KEY_EXPORT_FAILED",
      err,
    );
  }

  assertKeyBytes(publicKey, "publicKey");
  assertKeyBytes(privateKey, "privateKey");
  return { privateKey, publicKey };
}

/**
 * Serialise a key pair to a JWK suitable for secure-enclave storage.
 *
 * Always includes both `d` (private) and `x` (public); the resulting object
 * is enough to reconstruct the in-memory pair via {@link importKey}.
 */
export function exportKey(keyPair: KashKeyPair): ExportedKey {
  assertKeyBytes(keyPair.privateKey, "privateKey");
  assertKeyBytes(keyPair.publicKey, "publicKey");
  return {
    kty: "OKP",
    crv: "Ed25519",
    d: encodeBase64Url(keyPair.privateKey),
    x: encodeBase64Url(keyPair.publicKey),
  };
}

/**
 * Reconstruct an in-memory key pair from a previously-exported JWK.
 *
 * Throws {@link KashCryptoError} with code `KEY_IMPORT_FAILED`,
 * `INVALID_KEY_FORMAT`, or `INVALID_KEY_BYTES` for malformed input. Includes
 * a WebCrypto smoke-test import to catch byte-level corruption that passes
 * length checks (e.g., a `d` whose seed does not lie on the curve), AND a
 * sign+verify consistency probe to catch the case where `d` and `x` are each
 * individually valid Ed25519 bytes but come from DIFFERENT keypairs (a
 * swap-attack or storage corruption that would silently produce signatures
 * that fail to verify against the DID document's published public key).
 */
export async function importKey(jwk: ExportedKey | JsonWebKey): Promise<KashKeyPair> {
  validateJwkShape(jwk);

  let privateKey: Uint8Array;
  let publicKey: Uint8Array;
  try {
    privateKey = decodeBase64Url(jwk.d as string);
    publicKey = decodeBase64Url(jwk.x as string);
  } catch (err) {
    throw new KashCryptoError(
      "Malformed base64url in imported JWK fields.",
      "INVALID_KEY_BYTES",
      err,
    );
  }

  assertKeyBytes(privateKey, "privateKey");
  assertKeyBytes(publicKey, "publicKey");

  // 1. Smoke-test import — fails iff bytes do not form a legal Ed25519 key.
  let signKey: CryptoKey;
  try {
    signKey = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", d: jwk.d, x: jwk.x } satisfies JsonWebKey,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  } catch (err) {
    throw new KashCryptoError(
      "WebCrypto rejected the imported Ed25519 JWK (key bytes do not form a valid Ed25519 keypair).",
      "KEY_IMPORT_FAILED",
      err,
    );
  }

  // 2. Consistency probe — WebCrypto imports `d` and `x` halves independently
  //    and does NOT verify they correspond. Sign a random nonce with the
  //    private key and verify with the claimed public key; mismatch means the
  //    JWK is internally inconsistent and every future signature would fail
  //    against the DID document.
  let verifyKey: CryptoKey;
  try {
    verifyKey = await crypto.subtle.importKey(
      "raw",
      publicKey as unknown as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (err) {
    throw new KashCryptoError(
      "Imported JWK has an invalid public key `x` (not a valid Ed25519 point).",
      "INVALID_KEY_BYTES",
      err,
    );
  }
  const probe = crypto.getRandomValues(new Uint8Array(32));
  let probeSig: ArrayBuffer;
  try {
    probeSig = await crypto.subtle.sign(
      { name: "Ed25519" },
      signKey,
      probe as unknown as BufferSource,
    );
  } catch (err) {
    throw new KashCryptoError(
      "Consistency probe failed: WebCrypto sign() rejected the imported private key.",
      "KEY_IMPORT_FAILED",
      err,
    );
  }
  const consistent = await crypto.subtle.verify(
    { name: "Ed25519" },
    verifyKey,
    probeSig,
    probe as unknown as BufferSource,
  );
  if (!consistent) {
    throw new KashCryptoError(
      "JWK consistency check failed: public key `x` does not correspond to private scalar `d`.",
      "INVALID_KEY_BYTES",
    );
  }

  return { privateKey, publicKey };
}

/* ── internal validators ─────────────────────────────────────────── */

function assertKeyBytes(bytes: Uint8Array, label: string): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new KashCryptoError(`${label} must be a Uint8Array.`, "INVALID_KEY_BYTES");
  }
  if (bytes.length !== ED25519_KEY_BYTES) {
    throw new KashCryptoError(
      `${label} must be ${ED25519_KEY_BYTES} bytes (got ${bytes.length}).`,
      "INVALID_KEY_BYTES",
    );
  }
}

function validateJwkShape(jwk: unknown): asserts jwk is ExportedKey {
  if (jwk === null || typeof jwk !== "object") {
    throw new KashCryptoError("Imported key must be a JWK object.", "INVALID_KEY_FORMAT");
  }
  const k = jwk as Record<string, unknown>;
  if (k.kty !== "OKP") {
    throw new KashCryptoError(`Expected kty="OKP" (got ${JSON.stringify(k.kty)}).`, "INVALID_KEY_FORMAT");
  }
  if (k.crv !== "Ed25519") {
    throw new KashCryptoError(`Expected crv="Ed25519" (got ${JSON.stringify(k.crv)}).`, "INVALID_KEY_FORMAT");
  }
  if (typeof k.d !== "string" || k.d.length === 0) {
    throw new KashCryptoError("JWK is missing private scalar `d`.", "INVALID_KEY_FORMAT");
  }
  if (typeof k.x !== "string" || k.x.length === 0) {
    throw new KashCryptoError("JWK is missing public key `x`.", "INVALID_KEY_FORMAT");
  }
}
