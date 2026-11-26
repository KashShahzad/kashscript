/**
 * did:key — the standard spelling of a self-certifying key (RW-19 branch B).
 *
 * d97(h): no `did:kash` method is registered; where a stranger must resolve an
 * identifier, a standard method is used (d91(e); d71's *no format of our own*).
 * This module says what a self-certifying key is called: **`did:key`**, the
 * W3C-registered method whose identifier is `z` + base58btc(multicodec ‖ key)
 * — the same self-certifying idea as `did:kash`, under a name any stranger's
 * library already reads. The mapping is mechanical and lossless both ways:
 *
 *   • **Ed25519** — `did:kash` carries the raw 32 bytes; `did:key` the same
 *     bytes behind the `ed25519-pub` multicodec (0xed 0x01), so its body
 *     always begins `6Mk` after the `z`.
 *   • **P-256** — a `did:kash` body is already base58btc(`p256-pub` ‖ the
 *     compressed point) (ADR-0020), which is exactly the bytes `did:key`
 *     carries after its `z`: `toDidKey` literally prepends the `z`
 *     (`did:kash:Dn…` ↔ `did:key:zDn…`).
 *
 * `did:kash` is the same key's house spelling: kept for ever in records
 * already signed (d97(h)), as the kernel's internal canonical comparison form
 * (attest's `canonicalSignerOf`), and in the engines' opaque internal ids
 * (d99) — and written no more where a stranger reads. `specs/did-kash.md`
 * holds the retirement and the full mapping. Pure deterministic logic; no I/O.
 */

import { decodeBase58, encodeBase58 } from "./base58";
import {
  deriveDidForKey,
  parseDidKey,
  type KashDid,
  type KashKeyType,
  type KashPublicKey,
} from "./did";
import { KashCryptoError } from "./errors";
import { compressP256PublicKey, P256_PUBLIC_KEY_BYTES } from "./p256";

/** Branded string form of a did:key identifier (base58btc multibase, so always `z…`). */
export type DidKey = `did:key:z${string}`;

const DID_KEY_PREFIX = "did:key:z";
/** Multicodec `ed25519-pub` (0xed) as an unsigned varint. */
const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);
/** Multicodec `p256-pub` (0x1200) as an unsigned varint — the bytes a P-256 `did:kash` body already begins with. */
const P256_MULTICODEC = Uint8Array.of(0x80, 0x24);
const ED25519_KEY_BYTES = 32;

/**
 * The shape of a `did:key` this ecosystem reads or writes, as a regex source
 * for schemas (the strict reading is {@link parseDidKeyMethod}): `z` then a
 * base58btc body of an Ed25519 (34 bytes) or P-256 (35 bytes) multicodec key.
 */
export const DID_KEY_SOURCE = "did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}";

const DID_KEY_RE = new RegExp(`^${DID_KEY_SOURCE}$`);

/** Derive the `did:key` spelling of a typed public key. */
export function deriveDidKey(key: KashPublicKey): DidKey {
  if (key?.type === "Ed25519") {
    if (!(key.publicKey instanceof Uint8Array) || key.publicKey.length !== ED25519_KEY_BYTES) {
      throw new KashCryptoError(
        `an Ed25519 public key is ${ED25519_KEY_BYTES} bytes (got ${key.publicKey?.length}).`,
        "INVALID_KEY_BYTES",
      );
    }
    const body = new Uint8Array(ED25519_MULTICODEC.length + ED25519_KEY_BYTES);
    body.set(ED25519_MULTICODEC, 0);
    body.set(key.publicKey, ED25519_MULTICODEC.length);
    return `${DID_KEY_PREFIX}${encodeBase58(body)}` as DidKey;
  }
  if (key?.type === "P-256") {
    const compressed = compressP256PublicKey(key.publicKey);
    const body = new Uint8Array(P256_MULTICODEC.length + P256_PUBLIC_KEY_BYTES);
    body.set(P256_MULTICODEC, 0);
    body.set(compressed, P256_MULTICODEC.length);
    return `${DID_KEY_PREFIX}${encodeBase58(body)}` as DidKey;
  }
  throw new KashCryptoError(`Unknown key type ${JSON.stringify((key as { type?: unknown })?.type)}.`, "INVALID_KEY_FORMAT");
}

/**
 * Parse a `did:key` and return the key with the type its multicodec declares:
 * `ed25519-pub` + 32 bytes, or `p256-pub` + the 33-byte compressed point
 * (validated on the curve, as `parseDidKey` validates it for a `did:kash`).
 * Nothing else is accepted — a fragment, another multibase, another codec or
 * a wrong length all throw.
 *
 * @throws {@link KashCryptoError} (`INVALID_DID`) for malformed structure,
 *         (`INVALID_ENCODING`) when the base58 body is corrupt, or
 *         (`INVALID_KEY_BYTES` / `INVALID_KEY_FORMAT`) for a body that names
 *         no key this ecosystem reads.
 */
export function parseDidKeyMethod(did: string): KashPublicKey {
  if (typeof did !== "string") throw new KashCryptoError("DID must be a string.", "INVALID_DID");
  if (!DID_KEY_RE.test(did)) {
    throw new KashCryptoError(`Not a did:key this ecosystem reads: ${JSON.stringify(did)}.`, "INVALID_DID");
  }
  const bytes = decodeBase58(did.slice(DID_KEY_PREFIX.length));
  const hasPrefix = (p: Uint8Array): boolean => p.every((b, n) => bytes[n] === b);
  if (bytes.length === ED25519_MULTICODEC.length + ED25519_KEY_BYTES && hasPrefix(ED25519_MULTICODEC)) {
    return { type: "Ed25519", publicKey: bytes.subarray(ED25519_MULTICODEC.length) };
  }
  if (bytes.length === P256_MULTICODEC.length + P256_PUBLIC_KEY_BYTES && hasPrefix(P256_MULTICODEC)) {
    return { type: "P-256", publicKey: compressP256PublicKey(bytes.subarray(P256_MULTICODEC.length)) };
  }
  throw new KashCryptoError(
    `did:key body is neither an ed25519-pub nor a p256-pub multicodec key (got ${bytes.length} bytes).`,
    "INVALID_KEY_BYTES",
  );
}

/**
 * The `did:key` spelling of a `did:kash` — same key, standard name. For a
 * P-256 identifier the bytes already agree, so the result is the same body
 * behind `did:key:z`.
 */
export function toDidKey(did: string): DidKey {
  return deriveDidKey(parseDidKey(did));
}

/** The `did:kash` house spelling of a `did:key` — same key, two names. */
export function fromDidKey(did: string): KashDid {
  return deriveDidForKey(parseDidKeyMethod(did));
}

/**
 * Parse a self-certifying identifier of either spelling — `did:kash` or
 * `did:key` — and return the key its bytes declare. The type comes from the
 * identifier, never from whatever a signature claims about itself.
 */
export function parseAnyKeyDid(did: string): KashPublicKey {
  if (typeof did !== "string") throw new KashCryptoError("DID must be a string.", "INVALID_DID");
  return did.startsWith(DID_KEY_PREFIX) ? parseDidKeyMethod(did) : parseDidKey(did);
}

/** The key type a self-certifying identifier of either spelling declares, or null. Never throws. */
export function anyKeyDidType(value: string): KashKeyType | null {
  try {
    return parseAnyKeyDid(value).type;
  } catch {
    return null;
  }
}
