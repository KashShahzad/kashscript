/**
 * Keys and signatures handed in as Node Buffers (identity-core 0.4.0-alpha.2).
 *
 * `Buffer.prototype.slice` returns a VIEW of the caller's memory, not a copy, and
 * a Buffer's `.buffer` can be a shared pool larger than the Buffer itself. Found
 * during AU-3b's re-pin in Oreoasis: the strict Ed25519 check (`ed25519-strict`)
 * "copied" a key with `.slice()` and cleared bit 255 of the copy — so it cleared
 * it in the caller's key, and every later check under that key failed. The same
 * pattern sat in `normaliseLowS` (it rewrote a high-S signature in place) and in
 * the licence check (it handed WebCrypto the whole pool). Each test below hands
 * the kernel a Buffer that is a view at an offset inside a larger allocation, as
 * Node's pooled Buffers are, and asserts the input is untouched and the verdict right.
 */

import { describe, expect, test } from "bun:test";
import { DEFAULT_KASH_RECORD_DST, generateKeyPair, signEvent, verifyEvent, verifyEventForKey, type SignedKashEvent } from "./index";
import { decodeBase58 } from "./base58";
import { decodeEd25519Point, ed25519Precheck } from "./ed25519-strict";
import { generateP256KeyPair, isLowS, normaliseLowS, P256_ORDER, signP256 } from "./p256";
import { canonicalizeBytes } from "./canonical";
import { encodeBase64Url } from "./base64url";
import { verifyLicense, type LicenseClaims, type SignedLicense } from "./license";

/** `bytes` as a Buffer that views offset 8 of a larger buffer — the shape Node's pool produces. */
function pooledBuffer(bytes: Uint8Array): Buffer {
  const pool = new ArrayBuffer(bytes.length + 64);
  new Uint8Array(pool).fill(0xaa);
  const view = Buffer.from(pool, 8, bytes.length);
  view.set(bytes);
  return view;
}

/** An Ed25519 key pair whose public key has bit 255 set (the sign of x) — the keys the bug broke. */
async function keyWithBit255() {
  for (;;) {
    const kp = await generateKeyPair();
    if ((kp.publicKey[31]! & 0x80) !== 0) return kp;
  }
}

describe("a Buffer key is read, never written (the AU-3b re-pin bug)", () => {
  test("the strict decoder and the pre-check leave a Buffer key's bit 255 as it was", async () => {
    const kp = await keyWithBit255();
    const key = pooledBuffer(kp.publicKey);
    const before = Buffer.from(key);
    expect(decodeEd25519Point(key)).not.toBeNull();
    expect(ed25519Precheck(key, new Uint8Array(64))).not.toBe("A_INVALID");
    expect(Buffer.compare(key, before)).toBe(0);
    expect(key[31]! & 0x80).toBe(0x80);
  });

  test("a Kash-Event verifies under a Buffer key, and again, and the key is unchanged", async () => {
    const kp = await keyWithBit255();
    const header = { typ: "x", v: 1 };
    const body = { n: 1 };
    const event: SignedKashEvent = { header, body, signature: await signEvent(header, body, kp.privateKey) };
    const key = pooledBuffer(kp.publicKey);
    const before = Buffer.from(key);
    expect(await verifyEvent(event, key)).toBe(true);
    expect(await verifyEvent(event, key)).toBe(true); // the second check failed while the first had cleared bit 255
    expect(await verifyEventForKey(event, { type: "Ed25519", publicKey: key })).toBe(true);
    expect(Buffer.compare(key, before)).toBe(0);
  });

  test("a Buffer signature passes the pre-check untouched", async () => {
    const kp = await keyWithBit255();
    const header = { typ: "x", v: 1 };
    const body = { n: 2 };
    const sig = await signEvent(header, body, kp.privateKey, { dst: DEFAULT_KASH_RECORD_DST });
    const sigBuf = pooledBuffer(decodeBase58(sig.sig.slice(1)));
    const before = Buffer.from(sigBuf);
    expect(ed25519Precheck(pooledBuffer(kp.publicKey), sigBuf)).toBe("ok");
    expect(Buffer.compare(sigBuf, before)).toBe(0);
  });
});

describe("normaliseLowS returns a copy, whatever it is handed", () => {
  test("a high-S signature in a Buffer is left as it was; the low-S form comes back separately", async () => {
    const kp = await generateP256KeyPair();
    const raw = await signP256(new TextEncoder().encode("m"), kp.privateKey, kp.publicKey);
    const s = BigInt(`0x${Buffer.from(raw.subarray(32)).toString("hex")}`);
    const high = raw.slice();
    high.set(Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"), 32);
    const input = pooledBuffer(high);
    const before = Buffer.from(input);
    const out = normaliseLowS(input);
    expect(isLowS(out)).toBe(true);
    expect(Buffer.compare(input, before)).toBe(0);
    expect(isLowS(input)).toBe(false);
  });
});

describe("the licence check reads only the bytes it is given", () => {
  test("a registry key in a pooled Buffer verifies a genuine token", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const now = Math.floor(Date.now() / 1000);
    const claims: LicenseClaims = { v: 1, did: "did:kash:9vmffxtZDbaABAB8Ry2fUDsdoAmcbPMhafEz8Ca9vqDU", tier: "paid", iat: now, exp: now + 86_400 };
    const payload = canonicalizeBytes(claims);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new Uint8Array(payload)));
    const token = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ ...claims, sig: encodeBase64Url(sig) } satisfies SignedLicense)));
    expect(await verifyLicense(token, pooledBuffer(pub))).toEqual(claims);
  });
});
