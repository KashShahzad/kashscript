/**
 * Lowercase hexadecimal encoding for arbitrary byte buffers.
 *
 * Pure functions. Used alongside base64url as the alternative signature
 * encoding for {@link KashEventSignature}. No I/O.
 */

import { KashCryptoError } from "./errors";

const HEX_RE = /^[0-9a-fA-F]*$/;

export function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export function decodeHex(input: string): Uint8Array {
  if (input.length % 2 !== 0) {
    throw new KashCryptoError("Hex string must have even length.", "INVALID_ENCODING");
  }
  if (!HEX_RE.test(input)) {
    throw new KashCryptoError("Hex string contains non-hex characters.", "INVALID_ENCODING");
  }
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
