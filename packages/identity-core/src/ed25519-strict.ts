/**
 * The Ed25519 acceptance rule — pinned, so every runtime answers alike
 * (AU-3, A7-07; AUDIT-2026-11-11).
 *
 * WebCrypto's Ed25519 implementations agree on honest signatures and disagree
 * at the edges. BoringSSL (Bun, Chromium) accepts a public key or an `R` of
 * small order and one non-canonical key encoding that libsodium refuses;
 * OpenSSL (Node) and the other engines differ case by case. The same record is
 * checked by Bun, Node and three browser engines, so the rule is fixed here and
 * applied before WebCrypto is asked:
 *
 *   • `S < L` — RFC 8032 §5.1.7: a non-canonical `S` is rejected, never reduced;
 *   • `A` and `R` decode canonically — `y < p`, a point on the curve, and
 *     `x = 0` only with the sign bit clear (RFC 8032 §5.1.3);
 *   • neither `A` nor `R` has small order (`8·P = O`) — libsodium's rule, which
 *     keeps a signature of zeros from verifying every message under the
 *     identity key;
 *   • then WebCrypto's cofactorless equation, `[S]B = R + [k]A`, decides.
 *
 * Pure BigInt arithmetic over GF(2^255 − 19), no table, no secret: these are
 * public values. The vectors are in `packages/attest/test/vectors/ed25519`
 * (Wycheproof, ed25519-speccheck and attest's own), with one pinned verdict
 * per case, asserted under bun, node and a browser.
 */

const P = (1n << 255n) - 19n;
/** The group order of Ed25519's base point: 2^252 + 27742317777372353535851937790883648493. */
export const ED25519_ORDER_L = (1n << 252n) + 27742317777372353535851937790883648493n;
/** The curve constant d = −121665 / 121666 mod p. */
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function powMod(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

/** √−1 mod p, used when the first candidate root is off by a factor of i. */
const SQRT_M1 = powMod(2n, (P - 1n) / 4n);

/** A 32-byte little-endian integer. */
export function ed25519LittleEndianToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

/** An affine point on the twisted Edwards curve −x² + y² = 1 + d·x²·y². */
export interface Ed25519Point {
  readonly x: bigint;
  readonly y: bigint;
}

/** The scalar `S` of a signature (its last 32 bytes) is canonical when `S < L`. */
export function isCanonicalEd25519Scalar(s: Uint8Array): boolean {
  return s.length === 32 && ed25519LittleEndianToBigInt(s) < ED25519_ORDER_L;
}

/**
 * Decode a point as RFC 8032 §5.1.3 does, strictly: `y < p`, a square root
 * exists, and a zero `x` carries no sign bit. Null for every other encoding —
 * a value that is "almost" a point names no point.
 */
export function decodeEd25519Point(bytes: Uint8Array): Ed25519Point | null {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return null;
  const sign = bytes[31]! >> 7;
  // A real copy: on a Node Buffer `.slice()` is a view, and clearing the sign bit would
  // clear it in the caller's key (found during AU-3b; identity-core 0.4.0-alpha.2).
  const yBytes = new Uint8Array(bytes);
  yBytes[31]! &= 0x7f;
  const y = ed25519LittleEndianToBigInt(yBytes);
  if (y >= P) return null;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  // x = u·v³·(u·v⁷)^((p−5)/8), then corrected by √−1 when v·x² = −u.
  let x = (((u * powMod(v, 3n)) % P) * powMod((u * powMod(v, 7n)) % P, (P - 5n) / 8n)) % P;
  const vx2 = (((v * x) % P) * x) % P;
  if (vx2 === u) {
    // x is a root
  } else if (vx2 === mod(-u)) {
    x = (x * SQRT_M1) % P;
  } else {
    return null;
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { x, y };
}

/** Encode a point: `y` little-endian with the sign of `x` in the top bit. */
export function encodeEd25519Point(point: Ed25519Point): Uint8Array {
  const out = new Uint8Array(32);
  let y = point.y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(y & 0xffn);
    y >>= 8n;
  }
  if (point.x & 1n) out[31]! |= 0x80;
  return out;
}

/** Affine addition (the unified formula; valid for doubling and for the identity). */
export function addEd25519Points(a: Ed25519Point, b: Ed25519Point): Ed25519Point {
  const x1y2 = (a.x * b.y) % P;
  const x2y1 = (b.x * a.y) % P;
  const y1y2 = (a.y * b.y) % P;
  const x1x2 = (a.x * b.x) % P;
  const dxy = (((D * x1x2) % P) * y1y2) % P;
  const x3 = mod((x1y2 + x2y1) * powMod(mod(1n + dxy), P - 2n));
  const y3 = mod((y1y2 + x1x2) * powMod(mod(1n - dxy), P - 2n));
  return { x: x3, y: y3 };
}

/**
 * Does `8·P` land on the identity? Three doublings in extended coordinates
 * (dbl-2008-hwcd, a = −1), with no inversion; the identity is X = 0, Y = Z.
 * The eight torsion points — the identity, the point of order 2, two of order
 * 4 and four of order 8 — answer yes; every honest key and nonce answers no.
 */
export function isSmallOrderEd25519Point(point: Ed25519Point): boolean {
  let X = point.x;
  let Y = point.y;
  let Z = 1n;
  for (let i = 0; i < 3; i++) {
    const A = (X * X) % P;
    const B = (Y * Y) % P;
    const C = (2n * Z * Z) % P;
    const H = (A + B) % P;
    const XY = (X + Y) % P;
    const E = mod(H - (XY * XY) % P);
    const G = mod(A - B);
    const F = (C + G) % P;
    X = (E * F) % P;
    Y = (G * H) % P;
    Z = (F * G) % P;
  }
  return X === 0n && Y === Z;
}

/** Why a public key and a signature are refused before any curve equation is run, or `ok`. */
export type Ed25519Precheck = "ok" | "S_NOT_CANONICAL" | "A_INVALID" | "A_SMALL_ORDER" | "R_INVALID" | "R_SMALL_ORDER";

/**
 * The rule, applied to a 32-byte public key `A` and a 64-byte signature `R ‖ S`.
 * Callers have already checked the lengths; anything else is refused here too.
 */
export function ed25519Precheck(publicKey: Uint8Array, signature: Uint8Array): Ed25519Precheck {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return "R_INVALID";
  if (!isCanonicalEd25519Scalar(signature.subarray(32))) return "S_NOT_CANONICAL";
  const a = decodeEd25519Point(publicKey);
  if (a === null) return "A_INVALID";
  if (isSmallOrderEd25519Point(a)) return "A_SMALL_ORDER";
  const r = decodeEd25519Point(signature.subarray(0, 32));
  if (r === null) return "R_INVALID";
  if (isSmallOrderEd25519Point(r)) return "R_SMALL_ORDER";
  return "ok";
}
