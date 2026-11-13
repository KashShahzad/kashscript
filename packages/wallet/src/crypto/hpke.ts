/**
 * HPKE — RFC 9180, base mode, single shot — over WebCrypto. The one way the
 * wallet encrypts to the hardware root: sealing needs only the root's PUBLIC
 * key, and opening needs the root to agree a key with the sender's ephemeral
 * key, which happens inside the secure chip. Standards, not inventions: the
 * suite is DHKEM(P-256, HKDF-SHA256) · HKDF-SHA256 · AES-256-GCM
 * (0x0010 / 0x0001 / 0x0002), and `test/hpke.test.ts` checks this code
 * against the RFC's own P-256 test vector (appendix A.3, AES-128-GCM — the
 * same code with a 16-byte key).
 */

import { buf, concat, utf8 } from "./bytes";

const KEM_ID = 0x0010;
const KDF_ID = 0x0001;
export type HpkeAead = 0x0001 | 0x0002;
const NK: Readonly<Record<HpkeAead, number>> = { 1: 16, 2: 32 };
const NN = 12;
const N_SECRET = 32;
const HPKE_V1 = utf8("HPKE-v1");
const EMPTY = new Uint8Array(0);

function i2osp(n: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

const SUITE_KEM = concat(utf8("KEM"), i2osp(KEM_ID, 2));
const suiteHpke = (aead: HpkeAead): Uint8Array => concat(utf8("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(aead, 2));

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // RFC 5869: an absent salt is HashLen zero bytes — the same HMAC key as an empty one.
  const k = await crypto.subtle.importKey("raw", buf(key.length === 0 ? new Uint8Array(32) : key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, buf(data)));
}

async function expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const out = new Uint8Array(length);
  let t: Uint8Array = EMPTY;
  for (let i = 1, at = 0; at < length; i++) {
    t = await hmac(prk, concat(t, info, Uint8Array.of(i)));
    out.set(t.slice(0, Math.min(t.length, length - at)), at);
    at += t.length;
  }
  return out;
}

const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Promise<Uint8Array> =>
  hmac(salt, concat(HPKE_V1, suite, utf8(label), ikm));

const labeledExpand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Promise<Uint8Array> =>
  expand(prk, concat(i2osp(length, 2), HPKE_V1, suite, utf8(label), info), length);

async function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array> {
  const eaePrk = await labeledExtract(SUITE_KEM, EMPTY, "eae_prk", dh);
  return labeledExpand(SUITE_KEM, eaePrk, "shared_secret", kemContext, N_SECRET);
}

async function keySchedule(aead: HpkeAead, sharedSecret: Uint8Array, info: Uint8Array): Promise<{ key: Uint8Array; baseNonce: Uint8Array }> {
  const suite = suiteHpke(aead);
  const pskIdHash = await labeledExtract(suite, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = await labeledExtract(suite, EMPTY, "info_hash", info);
  const context = concat(Uint8Array.of(0x00), pskIdHash, infoHash);
  const secret = await labeledExtract(suite, sharedSecret, "secret", EMPTY);
  return {
    key: await labeledExpand(suite, secret, "key", context, NK[aead]),
    baseNonce: await labeledExpand(suite, secret, "base_nonce", context, NN),
  };
}

function checkPublicKey(pk: Uint8Array): void {
  if (pk.length !== 65 || pk[0] !== 0x04) throw new Error("a P-256 public key here is 65 bytes, uncompressed");
}

async function importPublic(pk: Uint8Array): Promise<CryptoKey> {
  checkPublicKey(pk);
  return crypto.subtle.importKey("raw", buf(pk), { name: "ECDH", namedCurve: "P-256" }, true, []);
}

/** An ephemeral key for tests with published vectors. Production always generates one. */
export interface HpkeEphemeral {
  readonly privateKey: CryptoKey;
  readonly publicKey: Uint8Array;
}

export interface HpkeSealed {
  /** The sender's ephemeral public key, 65 bytes. */
  readonly enc: Uint8Array;
  /** Ciphertext ‖ tag. */
  readonly ct: Uint8Array;
}

export interface HpkeOptions {
  readonly aead?: HpkeAead;
  readonly ephemeral?: HpkeEphemeral;
}

export async function hpkeSeal(pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, plaintext: Uint8Array, opts: HpkeOptions = {}): Promise<HpkeSealed> {
  const aead = opts.aead ?? 0x0002;
  let eph = opts.ephemeral;
  if (eph === undefined) {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    eph = { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
  }
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: await importPublic(pkR) }, eph.privateKey, 256));
  const sharedSecret = await extractAndExpand(dh, concat(eph.publicKey, pkR));
  const { key, baseNonce } = await keySchedule(aead, sharedSecret, info);
  const k = await crypto.subtle.importKey("raw", buf(key), { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(baseNonce), additionalData: buf(aad), tagLength: 128 }, k, buf(plaintext));
  dh.fill(0);
  sharedSecret.fill(0);
  key.fill(0);
  return { enc: eph.publicKey, ct: new Uint8Array(ct) };
}

/**
 * Open a sealed value. `decap` performs the recipient's half of the key
 * agreement — for the wallet, the hardware root's `agree`, so an error from it
 * (the person cancelled, the key is gone) propagates. Null when the sealed
 * bytes are wrong; never throws for a mismatch.
 */
export async function hpkeOpen(
  sealed: HpkeSealed,
  pkR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  decap: (enc: Uint8Array) => Promise<Uint8Array>,
  opts: { readonly aead?: HpkeAead } = {},
): Promise<Uint8Array | null> {
  const aead = opts.aead ?? 0x0002;
  if (sealed.enc.length !== 65 || sealed.enc[0] !== 0x04) return null;
  const dh = await decap(sealed.enc);
  try {
    const sharedSecret = await extractAndExpand(dh, concat(sealed.enc, pkR));
    const { key, baseNonce } = await keySchedule(aead, sharedSecret, info);
    const k = await crypto.subtle.importKey("raw", buf(key), { name: "AES-GCM" }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(baseNonce), additionalData: buf(aad), tagLength: 128 }, k, buf(sealed.ct));
    dh.fill(0);
    sharedSecret.fill(0);
    key.fill(0);
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/** The pieces the RFC vector prints, exposed for the conformance test only. */
export const hpkeInternals = { extractAndExpand, keySchedule };
