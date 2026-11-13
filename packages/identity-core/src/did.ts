/**
 * did:kash method — `did:kash:<base58-public-key>`.
 *
 * The method-specific identifier is a base58btc encoding of the public key,
 * so resolution is deterministic and key-only: any holder of the public key
 * can reproduce the DID without consulting any server. Two key types, told
 * apart by the bytes alone (ADR-0020):
 *
 *   • **Ed25519** — the raw 32-byte key, no prefix. Every identifier issued
 *     before PL-2 is this form, and it is unchanged.
 *   • **P-256** — the multicodec `p256-pub` prefix (0x80 0x24) and the 33-byte
 *     compressed point: 35 bytes, so `did:kash:Dn…`, the same bytes `did:key`
 *     carries after its `z`.
 *
 * `deriveDid` / `parseDid` / `isKashDid` keep their exact Ed25519 meaning, so a
 * P-256 identifier fails closed on every path written before it existed. Read
 * either type through {@link parseDidKey} — the key type the DID declares.
 * Pure deterministic logic; no I/O.
 */

import { decodeBase58, encodeBase58 } from "./base58";
import { KashCryptoError } from "./errors";
import { compressP256PublicKey, P256_PUBLIC_KEY_BYTES } from "./p256";

/** Branded string form of a Kash DID. */
export type KashDid = `did:kash:${string}`;

/** The key types a `did:kash` can declare. */
export type KashKeyType = "Ed25519" | "P-256";

/** A public key with the type its identifier declares. */
export interface KashPublicKey {
  readonly type: KashKeyType;
  /** 32 bytes for Ed25519; the 33-byte compressed point for P-256. */
  readonly publicKey: Uint8Array;
}

const ED25519_KEY_BYTES = 32;
/** Multicodec `p256-pub` (0x1200) as an unsigned varint. */
const P256_MULTICODEC = Uint8Array.of(0x80, 0x24);
const DID_KASH_RE = /^did:kash:([1-9A-HJ-NP-Za-km-z]+)$/;

/**
 * Derive the `did:kash:` identifier for a public key.
 *
 * @param publicKey 32-byte Ed25519 public key.
 * @returns `did:kash:<base58btc-pubkey>`.
 * @throws {@link KashCryptoError} (`INVALID_KEY_BYTES`) when `publicKey` is
 *         not exactly 32 bytes.
 */
export function deriveDid(publicKey: Uint8Array): KashDid {
  if (!(publicKey instanceof Uint8Array)) {
    throw new KashCryptoError("publicKey must be a Uint8Array.", "INVALID_KEY_BYTES");
  }
  if (publicKey.length !== ED25519_KEY_BYTES) {
    throw new KashCryptoError(
      `publicKey must be ${ED25519_KEY_BYTES} bytes (got ${publicKey.length}).`,
      "INVALID_KEY_BYTES",
    );
  }
  return `did:kash:${encodeBase58(publicKey)}` as KashDid;
}

/**
 * Parse a `did:kash:` identifier and return the embedded 32-byte public key.
 *
 * @throws {@link KashCryptoError} (`INVALID_DID`) for malformed structure,
 *         (`INVALID_ENCODING`) when the base58 body is corrupt, or
 *         (`INVALID_KEY_BYTES`) when the decoded body is not exactly 32 bytes.
 */
export function parseDid(did: string): Uint8Array {
  if (typeof did !== "string") {
    throw new KashCryptoError("DID must be a string.", "INVALID_DID");
  }
  const match = DID_KASH_RE.exec(did);
  if (!match) {
    throw new KashCryptoError(
      `Not a valid did:kash identifier: ${JSON.stringify(did)}.`,
      "INVALID_DID",
    );
  }
  const bytes = decodeBase58(match[1]!);
  if (bytes.length !== ED25519_KEY_BYTES) {
    throw new KashCryptoError(
      `did:kash public key must decode to ${ED25519_KEY_BYTES} bytes (got ${bytes.length}).`,
      "INVALID_KEY_BYTES",
    );
  }
  return bytes;
}

/** Type-guard that narrows an arbitrary string to a `KashDid` — the Ed25519
 *  form only, as before PL-2. Use {@link didKeyType} to accept either type. */
export function isKashDid(value: string): value is KashDid {
  if (!DID_KASH_RE.test(value)) return false;
  try {
    parseDid(value);
    return true;
  } catch {
    return false;
  }
}

/** The `did:kash` of a P-256 public key (33 bytes compressed, or 65 uncompressed — validated). */
export function deriveDidP256(publicKey: Uint8Array): KashDid {
  const compressed = compressP256PublicKey(publicKey);
  const body = new Uint8Array(P256_MULTICODEC.length + P256_PUBLIC_KEY_BYTES);
  body.set(P256_MULTICODEC, 0);
  body.set(compressed, P256_MULTICODEC.length);
  return `did:kash:${encodeBase58(body)}` as KashDid;
}

/** The `did:kash` of a typed key. */
export function deriveDidForKey(key: KashPublicKey): KashDid {
  if (key?.type === "Ed25519") return deriveDid(key.publicKey);
  if (key?.type === "P-256") return deriveDidP256(key.publicKey);
  throw new KashCryptoError(`Unknown key type ${JSON.stringify((key as { type?: unknown })?.type)}.`, "INVALID_KEY_FORMAT");
}

/**
 * Parse a `did:kash` of either type and return the key with the type its bytes
 * declare: 32 bytes is Ed25519; 35 bytes beginning 0x80 0x24 is P-256. Nothing
 * else is a `did:kash`. The type comes from the identifier, never from whatever
 * a signature claims about itself.
 */
export function parseDidKey(did: string): KashPublicKey {
  if (typeof did !== "string") throw new KashCryptoError("DID must be a string.", "INVALID_DID");
  const match = DID_KASH_RE.exec(did);
  if (!match) throw new KashCryptoError(`Not a valid did:kash identifier: ${JSON.stringify(did)}.`, "INVALID_DID");
  const bytes = decodeBase58(match[1]!);
  if (bytes.length === ED25519_KEY_BYTES) return { type: "Ed25519", publicKey: bytes };
  if (
    bytes.length === P256_MULTICODEC.length + P256_PUBLIC_KEY_BYTES &&
    bytes[0] === P256_MULTICODEC[0] &&
    bytes[1] === P256_MULTICODEC[1]
  ) {
    return { type: "P-256", publicKey: compressP256PublicKey(bytes.subarray(P256_MULTICODEC.length)) };
  }
  throw new KashCryptoError(
    `did:kash body is neither a 32-byte Ed25519 key nor a p256-pub multicodec key (got ${bytes.length} bytes).`,
    "INVALID_KEY_BYTES",
  );
}

/** The key type a `did:kash` declares, or null for anything that is not one. Never throws. */
export function didKeyType(value: string): KashKeyType | null {
  try {
    return parseDidKey(value).type;
  } catch {
    return null;
  }
}
