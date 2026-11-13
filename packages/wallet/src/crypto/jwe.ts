/**
 * The encrypted key backup of the holder contract (§2): JWE flattened JSON
 * (RFC 7516) with `PBES2-HS256+A128KW` key wrapping and `A256GCM` content
 * encryption (RFC 7518 §4.8, §5.3). It exists only because the holder asked,
 * and it carries relationship keys only — the hardware root cannot leave its
 * chip. Recovery by succession stays the default (d47(g)); this is the escape
 * hatch the holder chooses.
 *
 * The plaintext is the form PL-1's vector already wrote, now stated in the
 * holder contract v1.2: `{"keys":[{"keyid","alg":"Ed25519","privateKeyHex"}]}`.
 */

import type { EncryptedKeyBackup } from "@kashscript/attest/holder";
import { WalletError } from "../errors";
import type { Random } from "../platform";
import { base64UrlToBytes, buf, bytesToBase64Url, concat, utf8, utf8Decode, wipe } from "./bytes";

export const BACKUP_ALG = "PBES2-HS256+A128KW" as const;
export const BACKUP_ENC = "A256GCM" as const;
/** OWASP's floor for PBKDF2-HMAC-SHA256. Import accepts the range below. */
export const BACKUP_P2C = 600_000;
const P2C_MIN = 1_000;
const P2C_MAX = 10_000_000;
export const PASSPHRASE_MIN = 8;

export interface BackedUpKey {
  readonly keyid: string;
  readonly alg: "Ed25519";
  readonly privateKeyHex: string;
}

export interface KeyBackupPlaintext {
  readonly keys: readonly BackedUpKey[];
}

async function kekFor(passphrase: string, salt: Uint8Array, p2c: number, usage: "wrapKey" | "unwrapKey"): Promise<CryptoKey> {
  const pass = await crypto.subtle.importKey("raw", buf(utf8(passphrase)), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: buf(concat(utf8(BACKUP_ALG), Uint8Array.of(0), salt)), iterations: p2c },
    pass,
    { name: "AES-KW", length: 128 },
    false,
    [usage],
  );
}

export async function encryptKeyBackup(plain: KeyBackupPlaintext, passphrase: string, random: Random, p2c: number = BACKUP_P2C): Promise<EncryptedKeyBackup> {
  if (passphrase.length < PASSPHRASE_MIN) throw new WalletError("WEAK_PASSPHRASE");
  const salt = await random(16);
  const header = { alg: BACKUP_ALG, enc: BACKUP_ENC, p2s: bytesToBase64Url(salt), p2c, cty: "application/json" };
  const protectedB64u = bytesToBase64Url(utf8(JSON.stringify(header)));
  const kek = await kekFor(passphrase, salt, p2c, "wrapKey");
  const cekBytes = await random(32);
  const cek = await crypto.subtle.importKey("raw", buf(cekBytes), { name: "AES-GCM" }, true, ["encrypt"]);
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey("raw", cek, kek, "AES-KW"));
  const iv = await random(12);
  const body = utf8(JSON.stringify(plain));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(utf8(protectedB64u)), tagLength: 128 }, cek, buf(body)),
  );
  wipe(cekBytes);
  wipe(body);
  return {
    protected: protectedB64u,
    encrypted_key: bytesToBase64Url(wrapped),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(sealed.slice(0, sealed.length - 16)),
    tag: bytesToBase64Url(sealed.slice(sealed.length - 16)),
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export async function decryptKeyBackup(jwe: EncryptedKeyBackup, passphrase: string): Promise<KeyBackupPlaintext> {
  let header: unknown;
  let salt: Uint8Array;
  try {
    header = JSON.parse(utf8Decode(base64UrlToBytes(jwe.protected)) ?? "");
    salt = isPlainObject(header) && typeof header.p2s === "string" ? base64UrlToBytes(header.p2s) : new Uint8Array(0);
  } catch {
    throw new WalletError("BACKUP_INVALID", "the protected header does not parse");
  }
  if (!isPlainObject(header) || header.alg !== BACKUP_ALG || header.enc !== BACKUP_ENC) {
    throw new WalletError("BACKUP_INVALID", `expected ${BACKUP_ALG} / ${BACKUP_ENC}`);
  }
  const p2c = header.p2c;
  if (typeof p2c !== "number" || !Number.isInteger(p2c) || p2c < P2C_MIN || p2c > P2C_MAX) {
    throw new WalletError("BACKUP_INVALID", `p2c must be an integer from ${P2C_MIN} to ${P2C_MAX}`);
  }
  if (salt.length < 8) throw new WalletError("BACKUP_INVALID", "p2s must be at least 8 bytes");

  const kek = await kekFor(passphrase, salt, p2c, "unwrapKey");
  let cek: CryptoKey;
  try {
    cek = await crypto.subtle.unwrapKey("raw", buf(base64UrlToBytes(jwe.encrypted_key)), kek, "AES-KW", { name: "AES-GCM" }, false, ["decrypt"]);
  } catch {
    // AES Key Wrap carries its own integrity check: a wrong passphrase fails here.
    throw new WalletError("BACKUP_PASSPHRASE");
  }
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: buf(base64UrlToBytes(jwe.iv)), additionalData: buf(utf8(jwe.protected)), tagLength: 128 },
        cek,
        buf(concat(base64UrlToBytes(jwe.ciphertext), base64UrlToBytes(jwe.tag))),
      ),
    );
  } catch {
    throw new WalletError("BACKUP_INVALID", "the content does not decrypt");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(plaintext) ?? "");
  } finally {
    wipe(plaintext);
  }
  const keys = isPlainObject(parsed) ? parsed.keys : undefined;
  if (
    !Array.isArray(keys) ||
    !keys.every((k) => isPlainObject(k) && typeof k.keyid === "string" && k.alg === "Ed25519" && typeof k.privateKeyHex === "string" && /^[0-9a-f]{64}$/.test(k.privateKeyHex))
  ) {
    throw new WalletError("BACKUP_INVALID", "the plaintext is not {keys:[{keyid, alg: Ed25519, privateKeyHex}]}");
  }
  return { keys: keys as BackedUpKey[] };
}
