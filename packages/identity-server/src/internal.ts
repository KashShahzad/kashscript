// ============================================================================
// @kashscript/identity-server — internal byte / encoding / DID helpers
// ----------------------------------------------------------------------------
// NOT part of the package's public export surface. Shared by the ported
// modules (guest-did, handshake, hashing, did). Edge-safe: relies only on
// `globalThis.btoa/atob` + WebCrypto, never Node's `Buffer` or `node:crypto`,
// so the package deploys cleanly to Vercel Edge / Cloudflare Workers.
//
// Byte helpers are ported verbatim from @duedale/identity-kernel so guest-DID
// key material and handshake payloads stay byte-identical across the swap.
// ============================================================================

import { isKashDid } from "@kashscript/identity-core";
import { encodeHex } from "@kashscript/identity-core";
import { KashscriptIdentityMalformedDidError, KashscriptIdentityMalformedPayloadError } from "./errors";
import type { TraceId, UnixSeconds } from "./types";

/** Integer Unix seconds. */
export function nowUnix(): UnixSeconds {
  return Math.floor(Date.now() / 1000);
}

/** A fresh `trace_<24hex>` correlation id for a failure envelope. */
export function newTraceId(): TraceId {
  return `trace_${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
}

/**
 * Validates the canonical KashScript DID format. Delegates to `isKashDid`
 * from `@kashscript/identity-core`, which performs both the structural regex
 * match AND the strict base58btc decode + 32-byte length check. Single-sourcing
 * the rule here guarantees a string that passes round-trips through `parseDid`
 * cleanly.
 */
export function assertDidWellFormed(did: string): void {
  if (typeof did !== "string" || !isKashDid(did)) {
    throw new KashscriptIdentityMalformedDidError(typeof did === "string" ? did : String(did));
  }
}

/**
 * Encodes a `Uint8Array` to its standard base64 representation (the wire
 * format the ecosystem uses for public + private key payloads). Edge-safe:
 * relies only on `globalThis.btoa`.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return btoa(binary);
}

/**
 * Decodes a strict base64 string into a Uint8Array. Throws
 * `KashscriptIdentityMalformedPayloadError` on malformed input. Operates
 * without Node's Buffer so the helper is edge-safe.
 */
export function decodeBase64Strict(input: string, fieldName: string): Uint8Array {
  if (typeof input !== "string" || input.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError(fieldName);
  }
  const trimmed = input.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    throw new KashscriptIdentityMalformedPayloadError(fieldName);
  }
  let binary: string;
  try {
    binary = atob(trimmed);
  } catch (err) {
    throw new KashscriptIdentityMalformedPayloadError(fieldName, err);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }
  return bytes;
}

/** Hex-encodes a Uint8Array as lowercase 2-char-per-byte string. Re-exports
 *  identity-core's `encodeHex` so hashing digests are byte-identical. */
export const bytesToHex = encodeHex;

/** UTF-8 encode a string to bytes. */
export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** A `BufferSource` view for WebCrypto calls, without widening the public API
 *  to TS 6's `Uint8Array<ArrayBuffer>` generic (matches the attest style). */
export function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}
