/**
 * Compact JWS (RFC 7515) with EdDSA (RFC 8037) or ES256 (RFC 7518) — just what
 * SD-JWT needs. Signing input is `ASCII(b64u(header) "." b64u(payload))`,
 * verified over the received segments verbatim.
 *
 * **The algorithm comes from the key, never from the header alone (PL-2).** A
 * verifier holds a key whose type it knows; the header's `alg` must be exactly
 * the one that key implies (EdDSA for an OKP Ed25519 key, ES256 for an EC
 * P-256 key), and a header naming the other is simply false. ES256 is raw
 * `r ‖ s`, low-S.
 */

import { deriveDidForKey, p256Jwk, p256PublicKeyOfJwk, type EcJwk } from "@kashscript/identity-core";
import { base64UrlToBytes, bytesToBase64Url } from "../ed25519";
import { joseAlgOf, signBytes, signerKey, typedKey, verifyBytes, type KashPublicKey, type RawSigner, type VerifyKey } from "../signing";

/** An Ed25519 public key as a JWK (RFC 8037). */
export interface OkpJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
}

export type { EcJwk };

/** Ed25519 (`{privateKey, publicKey}`, as before), a software P-256 key, or a hardware key. */
export type JwsSigner = RawSigner;

export interface DecodedJws {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly headerB64u: string;
  readonly payloadB64u: string;
  readonly signatureB64u: string;
}

const enc = new TextEncoder();
const b64uJson = (v: unknown): string => bytesToBase64Url(enc.encode(JSON.stringify(v)));

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The public JWK of a key: a bare 32-byte key is Ed25519 (OKP); a typed P-256 key is EC. */
export function jwkOf(publicKey: VerifyKey): OkpJwk | EcJwk {
  const k = typedKey(publicKey);
  if (k.type === "P-256") return p256Jwk(k.publicKey);
  if (k.publicKey.length !== 32) throw new Error("an Ed25519 public key is 32 bytes");
  return { kty: "OKP", crv: "Ed25519", x: bytesToBase64Url(k.publicKey) };
}

/** The 32-byte key in an Ed25519 JWK, or null. Never throws. Ed25519 only — see {@link keyOfJwk}. */
export function publicKeyOfJwk(jwk: unknown): Uint8Array | null {
  if (!isPlainObject(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return null;
  try {
    const bytes = base64UrlToBytes(jwk.x);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

/** The typed key in an Ed25519 (OKP) or P-256 (EC) JWK, or null. Never throws. */
export function keyOfJwk(jwk: unknown): KashPublicKey | null {
  const ed = publicKeyOfJwk(jwk);
  if (ed !== null) return { type: "Ed25519", publicKey: ed };
  const p = p256PublicKeyOfJwk(jwk);
  return p === null ? null : { type: "P-256", publicKey: p };
}

/** The self-certifying `did:kash` of a JWK — how a relationship key is named. Either type. */
export function didOfJwk(jwk: unknown): string | null {
  const key = keyOfJwk(jwk);
  return key === null ? null : deriveDidForKey(key);
}

/** Sign a compact JWS. `alg` is set from the signer's key — EdDSA or ES256 — never by the caller. */
export async function signJws(header: Record<string, unknown>, payload: Record<string, unknown>, signer: JwsSigner): Promise<string> {
  const h = b64uJson({ ...header, alg: joseAlgOf(signerKey(signer).type) });
  const p = b64uJson(payload);
  const sig = await signBytes(signer, enc.encode(`${h}.${p}`), "raw");
  return `${h}.${p}.${bytesToBase64Url(sig)}`;
}

/** Decode a compact JWS without verifying it. Null for anything malformed. */
export function decodeJws(compact: string): DecodedJws | null {
  if (typeof compact !== "string") return null;
  const parts = compact.split(".");
  if (parts.length !== 3) return null;
  const [headerB64u, payloadB64u, signatureB64u] = parts as [string, string, string];
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64u))) as unknown;
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64u))) as unknown;
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;
    return { header, payload, headerB64u, payloadB64u, signatureB64u };
  } catch {
    return null;
  }
}

/**
 * True only when the header's `alg` is the one `key` implies and the signature
 * verifies over the received segments. A bare `Uint8Array` key is Ed25519, as
 * before PL-2.
 */
export async function verifyJws(jws: DecodedJws, key: VerifyKey): Promise<boolean> {
  const k = typedKey(key);
  if (jws.header.alg !== joseAlgOf(k.type)) return false;
  let sig: Uint8Array;
  try {
    sig = base64UrlToBytes(jws.signatureB64u);
  } catch {
    return false;
  }
  return verifyBytes(sig, enc.encode(`${jws.headerB64u}.${jws.payloadB64u}`), k, "raw");
}
