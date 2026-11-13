/** Small byte helpers. Encodings come from the kernel, so there is one of each. */

export { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from "@kashscript/attest/ed25519";
export { bytesToHex, hexToBytes, sha256Hex } from "@kashscript/attest/chain";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (s: string): Uint8Array => enc.encode(s);

/** Strict UTF-8 decode; null when the bytes are not text (ciphertext, say). */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return dec.decode(bytes);
  } catch {
    return null;
  }
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Best effort: JavaScript cannot promise a copy was never made, but this one is gone. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes) bytes.fill(0);
}

/** A WebCrypto `BufferSource` from a Uint8Array (a type-only widening, as in identity-core). */
export const buf = (bytes: Uint8Array): BufferSource => bytes as unknown as BufferSource;
