/**
 * Hash-chain helpers — the append-only tamper-evidence primitive shared by the
 * Oreoasis action ledger and the Duedale every-rupee chain.
 *
 * The canonical attest recipe (Oreoasis-derived) is:
 *
 *     blockHash = SHA-256( canonicalJson(payload) ‖ utf8(previousBlockHashHex) )
 *
 * `canonicalJson` here is ported verbatim from Oreoasis `chain-hash.ts` so a
 * chain hashed by the seed re-verifies byte-for-byte. `chain.test.ts` asserts it
 * agrees with identity-core's RFC-8785 `canonicalize` on a corpus — the two are
 * unified in behaviour, kept separate only to guarantee byte-faithful compat.
 *
 * Ported from Oreoasis `apps/oreoasis-core-host/src/chain-hash.ts` (the
 * `@oreoasis/ks-bridge` DID-pattern re-export dropped — attest owns its own).
 */

import { encodeHex, decodeHex } from "@kashscript/identity-core";
import { AttestError } from "./errors";

/** Hex-encode bytes (lowercase, no separator). Re-exports identity-core's
 *  `encodeHex`, which is byte-identical to the seed's `bytesToHex`. */
export const bytesToHex = encodeHex;
/** Decode lowercase hex → bytes. */
export const hexToBytes = decodeHex;

/** The 64-char hex marker used as `previousBlockHash` for stepIndex 0. */
export const GENESIS_PREV_HASH = "0".repeat(64);

/** Strict regex for the ledger Ed25519 signature wire form. */
export const ED25519_SIGNATURE_PATTERN = /^ed25519:[0-9a-f]{128}$/;

/** `did:kash:<base58btc>` — attest's own pattern (replaces the seed's ks-bridge import). */
export const KASH_DID_PATTERN = /^did:kash:[1-9A-HJ-NP-Za-km-z]+$/;

export class CanonicalJsonError extends Error {
  public readonly reason: "UNDEFINED_VALUE" | "NON_FINITE_NUMBER" | "UNSUPPORTED_TYPE";
  public readonly path: string;
  constructor(reason: CanonicalJsonError["reason"], path: string, message: string) {
    super(message);
    this.name = "CanonicalJsonError";
    this.reason = reason;
    this.path = path;
  }
}

/**
 * Deterministic JSON with sorted keys — rejects (rather than silently drops)
 * `undefined`, non-finite numbers, bigint, symbol, function. Ported exactly
 * from the seed; kept for byte-faithful chain compatibility.
 */
export function canonicalJson(value: unknown): string {
  return canonicalSerialize(value, "$");
}

function canonicalSerialize(val: unknown, path: string): string {
  if (val === undefined) {
    throw new CanonicalJsonError("UNDEFINED_VALUE", path, `canonicalJson refuses to encode undefined at ${path}`);
  }
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!Number.isFinite(val)) {
      throw new CanonicalJsonError("NON_FINITE_NUMBER", path, `canonicalJson refuses to encode non-finite number at ${path}`);
    }
    return JSON.stringify(val);
  }
  if (typeof val === "string") return JSON.stringify(val);
  if (typeof val === "bigint" || typeof val === "symbol" || typeof val === "function") {
    throw new CanonicalJsonError("UNSUPPORTED_TYPE", path, `canonicalJson refuses to encode ${typeof val} at ${path}`);
  }
  if (Array.isArray(val)) {
    const parts: string[] = [];
    for (let i = 0; i < val.length; i++) parts.push(canonicalSerialize(val[i], `${path}[${i}]`));
    return `[${parts.join(",")}]`;
  }
  const obj = val as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) parts.push(`${JSON.stringify(k)}:${canonicalSerialize(obj[k], `${path}.${k}`)}`);
  return `{${parts.join(",")}}`;
}

/**
 * SHA-256 of `bytes` → lowercase hex digest.
 *
 * Takes **bytes only, deliberately** — hashing raw content must never guess at
 * an encoding, so a string is a caller bug, not a convenience to absorb. For
 * `string | Uint8Array` input use `sha256HexOf` from `@kashscript/attest/ids`,
 * which does the UTF-8 encoding explicitly and then delegates here.
 *
 * @throws {AttestError} `INVALID_INPUT` when `bytes` is not a `Uint8Array` —
 *         previously this fell through to WebCrypto as a raw Node
 *         `ERR_INVALID_ARG_TYPE`, which named neither the contract nor the fix.
 */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  if (!(bytes instanceof Uint8Array)) {
    throw new AttestError(
      "INVALID_INPUT",
      `sha256Hex takes bytes (Uint8Array), got ${typeof bytes === "object" ? (bytes === null ? "null" : (bytes as object).constructor?.name ?? "object") : typeof bytes}. ` +
        "Pass bytes, or use sha256HexOf from @kashscript/attest/ids for string | Uint8Array input.",
    );
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Canonical attest block hash: `SHA-256( canonicalJson(payload) ‖ utf8(prevHex) )`,
 * payload first, then the previous hash as its 64-char hex TEXT bytes.
 *
 * ⚠️ Byte-faithful port of the Oreoasis seed: the composed buffer is sized with
 * `canonJson.length` (the JS **string length** = char count), while the encoder
 * writes UTF-8 **bytes**. For all-ASCII payloads these are equal and the result
 * is a clean `canonBytes ‖ prevBytes` concatenation. For a payload containing
 * non-ASCII (e.g. a "×" in a product name), the extra UTF-8 bytes extend past
 * `canon.length` and are then overwritten by the previous-hash bytes — a quirk
 * of the seed that is nonetheless the exact on-wire behaviour that produced
 * every existing Oreoasis chain hash. attest reproduces it verbatim so real
 * bundles verify (consumer-as-acceptance, ADR-0016); a future chain-format v2
 * can switch to byte-length sizing when the venture re-hashes at swap time.
 */
export async function chainBlockHash(
  payload: unknown,
  previousBlockHashHex: string,
): Promise<string> {
  if (previousBlockHashHex.length !== 64) {
    throw new CanonicalJsonError(
      "UNSUPPORTED_TYPE",
      "$",
      `chainBlockHash: previousBlockHashHex must be 64 hex chars (got ${previousBlockHashHex.length})`,
    );
  }
  const enc = new TextEncoder();
  const canon = canonicalJson(payload);
  const composed = new Uint8Array(canon.length + 64);
  composed.set(enc.encode(canon), 0);
  composed.set(enc.encode(previousBlockHashHex), canon.length);
  return sha256Hex(composed);
}
