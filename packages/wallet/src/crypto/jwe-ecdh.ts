/**
 * The encrypted response of OpenID4VP 1.0's `direct_post.jwt` (§8.3, HAIP 1.0
 * §5): a compact JWE (RFC 7516) with `ECDH-ES` direct key agreement on P-256
 * (RFC 7518 §4.6, Concat KDF) and `A128GCM` or `A256GCM`, to the verifier's
 * public key from its `client_metadata.jwks`. WebCrypto only.
 *
 * The ephemeral key is made here and forgotten here: it is not a wallet key,
 * and nothing about the holder is in the header.
 */

import { base64UrlToBytes, buf, bytesToBase64Url, concat, utf8 } from "./bytes";
import type { Random } from "../platform";

export type JweEnc = "A128GCM" | "A256GCM";

export interface VerifierEncKey {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
  readonly kid?: string;
}

const KEY_BITS: Record<JweEnc, number> = { A128GCM: 128, A256GCM: 256 };

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

const lengthPrefixed = (b: Uint8Array): Uint8Array => concat(u32(b.length), b);

/** NIST SP 800-56A Concat KDF with SHA-256, as RFC 7518 §4.6.2 lays out its OtherInfo. */
export async function concatKdf(z: Uint8Array, enc: string, keyBits: number, apu: Uint8Array = new Uint8Array(0), apv: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
  const otherInfo = concat(lengthPrefixed(utf8(enc)), lengthPrefixed(apu), lengthPrefixed(apv), u32(keyBits));
  const rounds = Math.ceil(keyBits / 256);
  const out: Uint8Array[] = [];
  for (let i = 1; i <= rounds; i++) out.push(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(concat(u32(i), z, otherInfo)))));
  return concat(...out).slice(0, keyBits / 8);
}

/** A P-256 JWK this module can encrypt to, or null. */
export function asVerifierEncKey(jwk: unknown): VerifierEncKey | null {
  if (typeof jwk !== "object" || jwk === null) return null;
  const k = jwk as Record<string, unknown>;
  if (k.kty !== "EC" || k.crv !== "P-256" || typeof k.x !== "string" || typeof k.y !== "string") return null;
  if (k.use !== undefined && k.use !== "enc") return null;
  if (k.alg !== undefined && k.alg !== "ECDH-ES") return null;
  return { kty: "EC", crv: "P-256", x: k.x, y: k.y, ...(typeof k.kid === "string" ? { kid: k.kid } : {}) };
}

/** Encrypt `plaintext` to `key`. Returns the compact serialisation (its encrypted-key part is empty, as ECDH-ES direct has none). */
export async function encryptEcdhEs(plaintext: Uint8Array, key: VerifierEncKey, enc: JweEnc, random: Random): Promise<string> {
  const recipient = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: key.x, y: key.y, ext: true }, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const eph = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const epk = (await crypto.subtle.exportKey("jwk", eph.publicKey)) as JsonWebKey;
  const z = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, eph.privateKey, 256));
  const header = { alg: "ECDH-ES", enc, ...(key.kid !== undefined ? { kid: key.kid } : {}), epk: { kty: "EC", crv: "P-256", x: epk.x, y: epk.y } };
  const protectedB64 = bytesToBase64Url(utf8(JSON.stringify(header)));
  const cek = await concatKdf(z, enc, KEY_BITS[enc]);
  z.fill(0);
  const iv = await random(12);
  const aes = await crypto.subtle.importKey("raw", buf(cek), { name: "AES-GCM" }, false, ["encrypt"]);
  cek.fill(0);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(utf8(protectedB64)), tagLength: 128 }, aes, buf(plaintext)));
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  return `${protectedB64}..${bytesToBase64Url(iv)}.${bytesToBase64Url(ct)}.${bytesToBase64Url(tag)}`;
}

/** The recipient's side — for the wallet's own tests, which play the verifier. */
export async function decryptEcdhEs(compact: string, recipientPrivate: CryptoKey): Promise<Uint8Array> {
  const [p, ek, ivB, ctB, tagB] = compact.split(".");
  if (p === undefined || ek !== "" || ivB === undefined || ctB === undefined || tagB === undefined) throw new Error("not a compact ECDH-ES JWE");
  const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(p))) as { enc: JweEnc; epk: JsonWebKey };
  const epk = await crypto.subtle.importKey("jwk", { ...header.epk, ext: true }, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const z = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, recipientPrivate, 256));
  const cek = await concatKdf(z, header.enc, KEY_BITS[header.enc]);
  const aes = await crypto.subtle.importKey("raw", buf(cek), { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buf(base64UrlToBytes(ivB)), additionalData: buf(utf8(p)), tagLength: 128 },
    aes,
    buf(concat(base64UrlToBytes(ctB), base64UrlToBytes(tagB))),
  );
  return new Uint8Array(pt);
}
