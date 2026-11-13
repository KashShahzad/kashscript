/**
 * P-256 (secp256r1) and ES256 — beside Ed25519, never instead of it
 * (ECOSYSTEM d47(g)(3)). A phone's secure chip holds P-256 only, and SD-JWT /
 * OpenID4VP ecosystems expect ES256, so the kernel signs both.
 *
 * Every private-key operation runs in WebCrypto (or in the phone's hardware,
 * through `signEventWith`). The BigInt arithmetic below touches PUBLIC values
 * only — decompressing and validating a point, and checking a signature's
 * scalars — so nothing secret depends on JavaScript's timing.
 *
 * **Malleability.** An ECDSA signature (r, s) has a twin (r, n − s) that plain
 * verification also accepts. The kernel signs only the low-S form and rejects
 * the high-S twin, so one signed thing has one signature (RFC 6979 is not
 * required: the nonce stays WebCrypto's).
 *
 * Encodings: raw `r ‖ s` (64 bytes) for Kash-Events and JWS (RFC 7518), strict
 * ASN.1 DER for DSSE (what Sigstore tooling verifies). Public keys travel as the
 * 33-byte compressed SEC1 point.
 */

import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { KashCryptoError } from "./errors";

export const P256_PUBLIC_KEY_BYTES = 33;
export const P256_UNCOMPRESSED_PUBLIC_KEY_BYTES = 65;
export const P256_PRIVATE_KEY_BYTES = 32;
export const P256_SIGNATURE_BYTES = 64;

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = P - 3n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
/** The group order n. */
export const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_ORDER = P256_ORDER >> 1n;

const ECDSA_IMPORT = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" } as const;

/** PKCS#8 header for a bare P-256 scalar (RFC 5915 ECPrivateKey, no public key). */
const PKCS8_P256_PREFIX = Uint8Array.of(
  0x30, 0x41, 0x02, 0x01, 0x00,
  0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
);

/** In-memory P-256 key pair for a SOFTWARE key. A hardware key never has one. */
export interface P256KeyPair {
  /** 32-byte scalar. SECRET. */
  readonly privateKey: Uint8Array;
  /** 33-byte compressed SEC1 point. */
  readonly publicKey: Uint8Array;
}

/** A P-256 public key as a JWK (RFC 7518 §6.2). */
export interface EcJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
}

function bufferIn(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

function toBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function toBytes(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = n;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function curveRhs(x: bigint): bigint {
  return mod(x * x * x + A * x + B, P);
}

/* ── points ────────────────────────────────────────────────────────────── */

/**
 * Validate a P-256 public key (33-byte compressed or 65-byte uncompressed SEC1)
 * and return it compressed. Throws `INVALID_KEY_BYTES` for anything that is
 * not a point on the curve — including the point at infinity.
 */
export function compressP256PublicKey(publicKey: Uint8Array): Uint8Array {
  if (!(publicKey instanceof Uint8Array)) {
    throw new KashCryptoError("A P-256 public key must be a Uint8Array.", "INVALID_KEY_BYTES");
  }
  if (publicKey.length === P256_PUBLIC_KEY_BYTES) {
    decompressP256PublicKey(publicKey); // validates
    return new Uint8Array(publicKey); // a copy, never a view of the caller's Buffer
  }
  if (publicKey.length !== P256_UNCOMPRESSED_PUBLIC_KEY_BYTES || publicKey[0] !== 0x04) {
    throw new KashCryptoError(
      `A P-256 public key is 33 bytes compressed or 65 bytes uncompressed (got ${publicKey.length}).`,
      "INVALID_KEY_BYTES",
    );
  }
  const x = toBigInt(publicKey.subarray(1, 33));
  const y = toBigInt(publicKey.subarray(33, 65));
  if (x >= P || y >= P || mod(y * y, P) !== curveRhs(x)) {
    throw new KashCryptoError("The P-256 public key is not a point on the curve.", "INVALID_KEY_BYTES");
  }
  const out = new Uint8Array(P256_PUBLIC_KEY_BYTES);
  out[0] = (y & 1n) === 1n ? 0x03 : 0x02;
  out.set(publicKey.subarray(1, 33), 1);
  return out;
}

/** Expand a 33-byte compressed point to 65 bytes (0x04 ‖ X ‖ Y), validating it. */
export function decompressP256PublicKey(compressed: Uint8Array): Uint8Array {
  if (!(compressed instanceof Uint8Array) || compressed.length !== P256_PUBLIC_KEY_BYTES) {
    throw new KashCryptoError("A compressed P-256 public key is 33 bytes.", "INVALID_KEY_BYTES");
  }
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new KashCryptoError("A compressed P-256 public key starts 0x02 or 0x03.", "INVALID_KEY_BYTES");
  }
  const x = toBigInt(compressed.subarray(1));
  if (x >= P) throw new KashCryptoError("The P-256 x-coordinate is out of range.", "INVALID_KEY_BYTES");
  const rhs = curveRhs(x);
  // p ≡ 3 (mod 4), so a square root is rhs^((p+1)/4).
  let y = modPow(rhs, (P + 1n) >> 2n, P);
  if (mod(y * y, P) !== rhs) {
    throw new KashCryptoError("The P-256 public key is not a point on the curve.", "INVALID_KEY_BYTES");
  }
  if ((y & 1n) !== BigInt(prefix & 1)) y = P - y;
  const out = new Uint8Array(P256_UNCOMPRESSED_PUBLIC_KEY_BYTES);
  out[0] = 0x04;
  out.set(compressed.subarray(1), 1);
  out.set(toBytes(y, 32), 33);
  return out;
}

/** The public JWK for a P-256 key (33 or 65 bytes). */
export function p256Jwk(publicKey: Uint8Array): EcJwk {
  const full = decompressP256PublicKey(compressP256PublicKey(publicKey));
  return { kty: "EC", crv: "P-256", x: encodeBase64Url(full.subarray(1, 33)), y: encodeBase64Url(full.subarray(33, 65)) };
}

/** The compressed key inside a P-256 public JWK, or null. Never throws. */
export function p256PublicKeyOfJwk(jwk: unknown): Uint8Array | null {
  if (typeof jwk !== "object" || jwk === null) return null;
  const k = jwk as Record<string, unknown>;
  if (k.kty !== "EC" || k.crv !== "P-256" || typeof k.x !== "string" || typeof k.y !== "string") return null;
  try {
    const x = decodeBase64Url(k.x);
    const y = decodeBase64Url(k.y);
    if (x.length !== 32 || y.length !== 32) return null;
    const full = new Uint8Array(P256_UNCOMPRESSED_PUBLIC_KEY_BYTES);
    full[0] = 0x04;
    full.set(x, 1);
    full.set(y, 33);
    return compressP256PublicKey(full);
  } catch {
    return null;
  }
}

/* ── keys ──────────────────────────────────────────────────────────────── */

function assertScalar(privateKey: Uint8Array): void {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== P256_PRIVATE_KEY_BYTES) {
    throw new KashCryptoError(`A P-256 private key is a ${P256_PRIVATE_KEY_BYTES}-byte scalar.`, "INVALID_KEY_BYTES");
  }
  const d = toBigInt(privateKey);
  if (d === 0n || d >= P256_ORDER) {
    throw new KashCryptoError("The P-256 private scalar is out of range.", "INVALID_KEY_BYTES");
  }
}

/** Generate a software P-256 key pair. A hardware key is made by the hardware, never here. */
export async function generateP256KeyPair(): Promise<P256KeyPair> {
  let pair: CryptoKeyPair;
  try {
    pair = (await crypto.subtle.generateKey(ECDSA_IMPORT, true, ["sign", "verify"])) as CryptoKeyPair;
  } catch (err) {
    throw new KashCryptoError("WebCrypto rejected P-256 key generation.", "KEY_GENERATION_FAILED", err);
  }
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  if (typeof jwk.d !== "string") throw new KashCryptoError("WebCrypto returned a P-256 JWK without `d`.", "KEY_GENERATION_FAILED");
  const publicKey = p256PublicKeyOfJwk(jwk);
  if (publicKey === null) throw new KashCryptoError("WebCrypto returned a malformed P-256 JWK.", "KEY_GENERATION_FAILED");
  // RFC 7518 §6.2.2.1 puts `d` at full length, but Bun 1.2.5 drops a leading zero byte for about 1
  // fresh key in 256 (22 of 6000 on 2026-10-03; Node 22.14: 0 of 6000). Restore it here — the one
  // place a scalar is read from a runtime. assertScalar stays strict for every scalar handed in, and
  // a `d` that is already 32 bytes (or too long) is returned exactly as the runtime gave it.
  const exported = decodeBase64Url(jwk.d);
  let privateKey = exported;
  if (exported.length < P256_PRIVATE_KEY_BYTES) {
    privateKey = new Uint8Array(P256_PRIVATE_KEY_BYTES);
    privateKey.set(exported, P256_PRIVATE_KEY_BYTES - exported.length);
  }
  return { privateKey, publicKey };
}

/**
 * The compressed public key of a P-256 scalar — for a key whose scalar came
 * from somewhere else (a seeded practice run, a vector). WebCrypto computes it.
 */
export async function p256PublicKeyFromScalar(privateKey: Uint8Array): Promise<Uint8Array> {
  assertScalar(privateKey);
  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + P256_PRIVATE_KEY_BYTES);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(privateKey, PKCS8_P256_PREFIX.length);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("pkcs8", bufferIn(pkcs8), ECDSA_IMPORT, true, ["sign"]);
  } catch (err) {
    throw new KashCryptoError("WebCrypto rejected the P-256 scalar.", "KEY_IMPORT_FAILED", err);
  }
  const publicKey = p256PublicKeyOfJwk(await crypto.subtle.exportKey("jwk", key));
  if (publicKey === null) throw new KashCryptoError("WebCrypto did not return the P-256 public key.", "KEY_EXPORT_FAILED");
  return publicKey;
}

async function importSigningKey(privateKey: Uint8Array, publicKey: Uint8Array): Promise<CryptoKey> {
  assertScalar(privateKey);
  const pub = p256Jwk(publicKey);
  try {
    return await crypto.subtle.importKey("jwk", { ...pub, d: encodeBase64Url(privateKey) }, ECDSA_IMPORT, false, ["sign"]);
  } catch (err) {
    throw new KashCryptoError("WebCrypto rejected the P-256 private key (does it match its public key?).", "KEY_IMPORT_FAILED", err);
  }
}

/* ── signatures ────────────────────────────────────────────────────────── */

function scalarsOf(raw: Uint8Array): { r: bigint; s: bigint } | null {
  if (!(raw instanceof Uint8Array) || raw.length !== P256_SIGNATURE_BYTES) return null;
  return { r: toBigInt(raw.subarray(0, 32)), s: toBigInt(raw.subarray(32)) };
}

/** True when a raw signature's s is in the low half of the group order. */
export function isLowS(raw: Uint8Array): boolean {
  const sc = scalarsOf(raw);
  return sc !== null && sc.s >= 1n && sc.s <= HALF_ORDER;
}

/** The low-S form of a raw signature (a copy; unchanged if already low). */
export function normaliseLowS(raw: Uint8Array): Uint8Array {
  const sc = scalarsOf(raw);
  if (sc === null) throw new KashCryptoError("An ES256 signature is 64 bytes (r ‖ s).", "INVALID_INPUT");
  // `new Uint8Array(raw)` copies; a Buffer's `.slice()` is a view, and `out.set` would rewrite the caller's signature.
  if (sc.s <= HALF_ORDER) return new Uint8Array(raw);
  const out = new Uint8Array(raw);
  out.set(toBytes(P256_ORDER - sc.s, 32), 32);
  return out;
}

/**
 * ES256 over `message` with a software key: SHA-256, ECDSA P-256, low-S, raw
 * `r ‖ s`. The public key is required so a mismatched pair fails at import.
 */
export async function signP256(message: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  const key = await importSigningKey(privateKey, publicKey);
  let sig: Uint8Array;
  try {
    sig = new Uint8Array(await crypto.subtle.sign(ECDSA_SHA256, key, bufferIn(message)));
  } catch (err) {
    throw new KashCryptoError("WebCrypto ECDSA sign() failed.", "SIGN_FAILED", err);
  }
  if (sig.length !== P256_SIGNATURE_BYTES) {
    throw new KashCryptoError(`ECDSA P-256 returned ${sig.length} bytes, expected ${P256_SIGNATURE_BYTES}.`, "SIGN_FAILED");
  }
  return normaliseLowS(sig);
}

/**
 * Verify a raw ES256 signature. `false` for a wrong signature, for r or s out
 * of range, and for the **high-S twin** of a valid signature — which plain
 * ECDSA would accept. Throws only for a malformed public key.
 */
export async function verifyP256(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  const sc = scalarsOf(signature);
  if (sc === null) return false;
  if (sc.r < 1n || sc.r >= P256_ORDER || sc.s < 1n || sc.s > HALF_ORDER) return false;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("jwk", p256Jwk(publicKey), ECDSA_IMPORT, false, ["verify"]);
  } catch (err) {
    if (err instanceof KashCryptoError) throw err;
    throw new KashCryptoError("WebCrypto rejected the P-256 public key.", "INVALID_KEY_BYTES", err);
  }
  return crypto.subtle.verify(ECDSA_SHA256, key, bufferIn(signature), bufferIn(message));
}

/* ── DER (strict) ──────────────────────────────────────────────────────── */

function derInteger(bytes: Uint8Array, at: number): { value: Uint8Array; next: number } {
  if (bytes[at] !== 0x02) throw new KashCryptoError("DER: expected an INTEGER.", "INVALID_ENCODING");
  const len = bytes[at + 1];
  if (len === undefined || len < 1 || len > 33) throw new KashCryptoError("DER: INTEGER length out of range.", "INVALID_ENCODING");
  const start = at + 2;
  const end = start + len;
  if (end > bytes.length) throw new KashCryptoError("DER: truncated INTEGER.", "INVALID_ENCODING");
  const value = bytes.subarray(start, end);
  // Positive and minimal: no sign bit, and a leading 0x00 only when it is needed.
  if ((value[0]! & 0x80) !== 0) throw new KashCryptoError("DER: negative INTEGER.", "INVALID_ENCODING");
  // 33 bytes can only be a 256-bit value plus its 0x00 sign byte. Any other first byte is a 257-bit
  // number, which is no P-256 r or s — and the strip below would turn it into a valid-looking one.
  if (value.length === 33 && value[0] !== 0x00) throw new KashCryptoError("DER: INTEGER wider than 256 bits.", "INVALID_ENCODING");
  if (value.length > 1 && value[0] === 0x00 && (value[1]! & 0x80) === 0) {
    throw new KashCryptoError("DER: non-minimal INTEGER.", "INVALID_ENCODING");
  }
  return { value, next: end };
}

/**
 * Strict DER `SEQUENCE { INTEGER r, INTEGER s }` → raw `r ‖ s`. Rejects every
 * non-canonical form — long-form lengths, padding, trailing bytes — so one
 * signature has one encoding. Range and low-S are checked by the verifier.
 */
export function ecdsaDerToRaw(der: Uint8Array): Uint8Array {
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > 72) {
    throw new KashCryptoError("DER: an ES256 signature is 8 to 72 bytes.", "INVALID_ENCODING");
  }
  if (der[0] !== 0x30 || der[1] !== der.length - 2) {
    throw new KashCryptoError("DER: expected one SEQUENCE spanning the whole signature.", "INVALID_ENCODING");
  }
  const r = derInteger(der, 2);
  const s = derInteger(der, r.next);
  if (s.next !== der.length) throw new KashCryptoError("DER: trailing bytes.", "INVALID_ENCODING");
  const out = new Uint8Array(P256_SIGNATURE_BYTES);
  for (const [v, offset] of [[r.value, 0], [s.value, 32]] as const) {
    const trimmed = v.length === 33 ? v.subarray(1) : v;
    if (trimmed.length > 32) throw new KashCryptoError("DER: INTEGER wider than 32 bytes.", "INVALID_ENCODING");
    out.set(trimmed, offset + 32 - trimmed.length);
  }
  return out;
}

function minimalInteger(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const body = bytes.subarray(i);
  if ((body[0]! & 0x80) === 0) return body;
  const out = new Uint8Array(body.length + 1);
  out.set(body, 1);
  return out;
}

/** Raw `r ‖ s` → minimal DER. */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (!(raw instanceof Uint8Array) || raw.length !== P256_SIGNATURE_BYTES) {
    throw new KashCryptoError("An ES256 signature is 64 bytes (r ‖ s).", "INVALID_INPUT");
  }
  const r = minimalInteger(raw.subarray(0, 32));
  const s = minimalInteger(raw.subarray(32));
  const out = new Uint8Array(6 + r.length + s.length);
  out.set([0x30, 4 + r.length + s.length, 0x02, r.length], 0);
  out.set(r, 4);
  out.set([0x02, s.length], 4 + r.length);
  out.set(s, 6 + r.length);
  return out;
}
