/**
 * Base64URL (RFC 4648 §5) — unpadded.
 *
 * Used for JWK field serialisation (`d`, `x`). Internal helpers; the public
 * surface of this package is byte-array based.
 */

import { KashCryptoError } from "./errors";

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64Url(input: string): Uint8Array {
  if (!B64URL_RE.test(input)) {
    throw new KashCryptoError("Malformed base64url input", "INVALID_ENCODING");
  }
  const pad = input.length % 4;
  const padded = input + (pad === 2 ? "==" : pad === 3 ? "=" : "");
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  let binary: string;
  try {
    binary = atob(base64);
  } catch (err) {
    throw new KashCryptoError("Base64url decode failed", "INVALID_ENCODING", err);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
