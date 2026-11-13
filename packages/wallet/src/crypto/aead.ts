/**
 * AES-256-GCM with associated data, over WebCrypto. A sealed value is
 * `iv (12) ‖ ciphertext ‖ tag (16)`; the IV comes from the platform's random
 * source, so one key never sees the same IV twice in any realistic lifetime.
 * The associated data binds a sealed value to the name it is stored under, so
 * a blob moved to another name fails to open.
 */

import type { Random } from "../platform";
import { buf, concat, utf8 } from "./bytes";

async function importAesKey(key: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error("an AES-256 key is 32 bytes");
  return crypto.subtle.importKey("raw", buf(key), { name: "AES-GCM" }, false, [usage]);
}

export async function sealAead(key: Uint8Array, plaintext: Uint8Array, aad: string, random: Random): Promise<Uint8Array> {
  const iv = await random(12);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: buf(iv), additionalData: buf(utf8(aad)), tagLength: 128 },
    await importAesKey(key, "encrypt"),
    buf(plaintext),
  );
  return concat(iv, new Uint8Array(ct));
}

/** Null when the key, the name or the bytes are wrong. Never throws for a mismatch. */
export async function openAead(key: Uint8Array, sealed: Uint8Array, aad: string): Promise<Uint8Array | null> {
  if (sealed.length < 12 + 16) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buf(sealed.slice(0, 12)), additionalData: buf(utf8(aad)), tagLength: 128 },
      await importAesKey(key, "decrypt"),
      buf(sealed.slice(12)),
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}
