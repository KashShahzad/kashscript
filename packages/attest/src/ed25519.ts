/**
 * Raw Ed25519 over arbitrary bytes, via WebCrypto (native in Bun / Node 20+ /
 * browsers — zero runtime deps). `@kashscript/identity-core` only exposes the
 * `Ed25519( DST ‖ JCS({header,body}) )` shape; the DSSE/PAE and Indus-token
 * families sign different byte strings, so `attest` owns this raw layer.
 *
 * Ported from Oreoasis `apps/oreoasis-core-host/src/dsse.ts` (the base64 + key
 * import + SPKI-PEM helpers) so there is exactly one raw-Ed25519 implementation.
 */

import { ed25519Precheck, rethrowIfUnavailable } from "@kashscript/identity-core";
import { AttestError } from "./errors";

/* ── base64 (standard) + base64url ─────────────────────────────────────── */

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

export function base64ToBytes(b64: string): Uint8Array {
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new AttestError("MALFORMED_PAYLOAD", "value is not valid base64");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlToBytes(b64u: string): Uint8Array {
  const pad = b64u.length % 4 === 0 ? "" : "=".repeat(4 - (b64u.length % 4));
  return base64ToBytes(b64u.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

/* ── WebCrypto Ed25519 key import ──────────────────────────────────────────
 *
 * Private: RFC 8037 OKP JWK ({kty,crv,x,d}) — bridges the identity-core
 * 32-byte seed format directly. Public: imported "raw" (32 bytes). */

async function importSigningKey(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<CryptoKey> {
  const jwk: JsonWebKey = {
    kty: "OKP",
    crv: "Ed25519",
    x: bytesToBase64Url(publicKey),
    d: bytesToBase64Url(privateKey),
  };
  try {
    return await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
  } catch (err) {
    rethrowIfUnavailable(err, "Ed25519");
    throw err;
  }
}

async function importVerifyKey(publicKey: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "raw",
      publicKey as unknown as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (err) {
    // A runtime without Ed25519 (older browsers, some WebViews) checked
    // nothing — that is ALG_UNAVAILABLE, never an invalid signature.
    rethrowIfUnavailable(err, "Ed25519");
    throw err;
  }
}

/* ── Raw sign / verify ─────────────────────────────────────────────────── */

/** Signer material: a keyid (DID) + 32-byte Ed25519 seed and public key. */
export interface RawEd25519Signer {
  readonly keyid: string;
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** Raw Ed25519 signature over `message` → 64 raw bytes. */
export async function signRaw(
  message: Uint8Array,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  const key = await importSigningKey(privateKey, publicKey);
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    key,
    message as unknown as BufferSource,
  );
  return new Uint8Array(sig);
}

/** Raw Ed25519 signature over `message`, standard-base64-encoded (the form the
 *  Rekor witness client and DSSE envelope use). */
export async function signRawEd25519(
  message: Uint8Array,
  signer: RawEd25519Signer,
): Promise<string> {
  return bytesToBase64(await signRaw(message, signer.privateKey, signer.publicKey));
}

/** Verify a raw Ed25519 signature. Returns `false` on a well-formed non-match;
 *  never throws for a wrong-but-well-formed signature (matches verifyEvent).
 *  AU-3 (A7-07): identity-core's acceptance rule runs first — S < L, a canonical
 *  A and R, neither of small order — so every runtime that checks a record gives
 *  one verdict (test/vectors/ed25519). */
export async function verifyRaw(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  if (ed25519Precheck(publicKey, signature) !== "ok") return false;
  const key = await importVerifyKey(publicKey);
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature as unknown as BufferSource,
    message as unknown as BufferSource,
  );
}

/**
 * Encode a raw 32-byte Ed25519 public key as SPKI PEM
 * (`-----BEGIN PUBLIC KEY-----`). DER prefix `302a300506032b6570032100` is the
 * fixed RFC 8410 SubjectPublicKeyInfo header for Ed25519; Rekor + OpenSSL
 * accept this form.
 */
export function ed25519PublicKeyToSpkiPem(publicKey: Uint8Array): string {
  const derPrefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const der = new Uint8Array(derPrefix.length + publicKey.length);
  der.set(derPrefix, 0);
  der.set(publicKey, derPrefix.length);
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
