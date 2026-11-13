/**
 * Bitcoin-flavoured base58 (base58btc) encoder/decoder.
 *
 * Used to encode the public key portion of a `did:kash:<...>` and to produce
 * Multibase-tagged `z`-prefixed strings inside DID Documents.
 *
 * Pure deterministic logic over a 32-byte input typical workload. No I/O.
 */

import { KashCryptoError } from "./errors";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const CHAR_TO_VALUE: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) m.set(ALPHABET[i]!, i);
  return m;
})();

/** Encode arbitrary bytes as base58btc. Empty input yields an empty string. */
export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Preserve leading-zero bytes as leading "1" characters.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Treat the remaining bytes as a big-endian unsigned integer.
  let num = 0n;
  for (let i = 0; i < bytes.length; i++) {
    num = (num << 8n) | BigInt(bytes[i]!);
  }

  // Successive division by 58 emits base-58 digits (least-significant first).
  const chars: string[] = [];
  while (num > 0n) {
    const remainder = Number(num % 58n);
    chars.push(ALPHABET[remainder]!);
    num /= 58n;
  }
  for (let i = 0; i < zeros; i++) chars.push("1");

  return chars.reverse().join("");
}

/** Decode a base58btc string. Throws {@link KashCryptoError} (`INVALID_ENCODING`) on malformed input. */
export function decodeBase58(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array();

  // Strip and record leading-"1" zero-bytes.
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros++;

  let num = 0n;
  for (let i = zeros; i < input.length; i++) {
    const ch = input[i]!;
    const v = CHAR_TO_VALUE.get(ch);
    if (v === undefined) {
      throw new KashCryptoError(
        `Invalid base58 character "${ch}" at position ${i}`,
        "INVALID_ENCODING",
      );
    }
    num = num * 58n + BigInt(v);
  }

  // Serialise the big integer to bytes (big-endian).
  const tail: number[] = [];
  while (num > 0n) {
    tail.push(Number(num & 0xffn));
    num >>= 8n;
  }
  tail.reverse();

  const out = new Uint8Array(zeros + tail.length);
  // Leading zero bytes are already zero from initialisation; just write the tail.
  out.set(tail, zeros);
  return out;
}
