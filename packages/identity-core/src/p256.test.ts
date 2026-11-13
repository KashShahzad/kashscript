/**
 * P-256, ES256 and the P-256 did:kash (PL-2, ADR-0020).
 *
 * The external anchor is RFC 6979 §A.2.5: a published P-256 key and a
 * published ECDSA-SHA-256 signature over "sample". Its s is HIGH — so the same
 * vector proves the curve code is right (its low-S twin verifies) and that the
 * malleability rule bites (the published form, which WebCrypto accepts, does
 * not verify here).
 */

import { describe, expect, test } from "bun:test";
import { encodeBase64Url } from "./base64url";
import { decodeHex, encodeHex } from "./hex";
import { generateKeyPair } from "./keys";
import { deriveDid, deriveDidForKey, deriveDidP256, didKeyType, isKashDid, parseDid, parseDidKey } from "./did";
import { createDidDocument, decodeMultikey, verifyEventAgainstDocument } from "./document";
import {
  compressP256PublicKey,
  decompressP256PublicKey,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  generateP256KeyPair,
  isLowS,
  normaliseLowS,
  p256Jwk,
  p256PublicKeyFromScalar,
  p256PublicKeyOfJwk,
  P256_ORDER,
  signP256,
  verifyP256,
} from "./p256";
import { signEvent, signEventEs256, signEventWith, verifyEvent, verifyEventForKey, type SignedKashEvent } from "./signatures";
import { ed25519Available } from "./runtime";
import { KashCryptoError } from "./errors";

/* RFC 6979 §A.2.5 — P-256 */
const RFC6979_D = decodeHex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
const RFC6979_UX = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const RFC6979_UY = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const RFC6979_SAMPLE_SHA256 =
  "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
  "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

const enc = new TextEncoder();
const uncompressed = decodeHex(`04${RFC6979_UX}${RFC6979_UY}`);

function toHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}
function flipS(raw: Uint8Array): Uint8Array {
  const s = BigInt(`0x${encodeHex(raw.subarray(32))}`);
  const out = raw.slice();
  out.set(decodeHex(toHex(P256_ORDER - s)), 32);
  return out;
}

describe("P-256 points", () => {
  test("RFC 6979's private key yields RFC 6979's public key", async () => {
    const pub = await p256PublicKeyFromScalar(RFC6979_D);
    expect(encodeHex(decompressP256PublicKey(pub))).toBe(encodeHex(uncompressed));
  });

  test("compress ↔ decompress round-trips, against WebCrypto's own export", async () => {
    for (let i = 0; i < 8; i++) {
      const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
      const c = compressP256PublicKey(raw);
      expect(c.length).toBe(33);
      expect(encodeHex(decompressP256PublicKey(c))).toBe(encodeHex(raw));
    }
  });

  test("rejects points off the curve, bad prefixes and wrong lengths", () => {
    const off = uncompressed.slice();
    off[64] = off[64]! ^ 1;
    expect(() => compressP256PublicKey(off)).toThrow(KashCryptoError);
    const badPrefix = compressP256PublicKey(uncompressed);
    badPrefix[0] = 0x05;
    expect(() => decompressP256PublicKey(badPrefix)).toThrow(KashCryptoError);
    expect(() => compressP256PublicKey(new Uint8Array(32))).toThrow(KashCryptoError);
    // x = p is out of range
    const xp = new Uint8Array(33);
    xp[0] = 0x02;
    xp.set(decodeHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"), 1);
    expect(() => decompressP256PublicKey(xp)).toThrow(KashCryptoError);
  });

  test("JWK round-trip", () => {
    const c = compressP256PublicKey(uncompressed);
    expect(encodeHex(p256PublicKeyOfJwk(p256Jwk(c))!)).toBe(encodeHex(c));
    expect(p256PublicKeyOfJwk({ kty: "OKP", crv: "Ed25519", x: "AA" })).toBeNull();
  });
});

describe("ES256 — low-S always, high-S never", () => {
  test("RFC 6979's published signature is high-S: WebCrypto accepts it, the kernel does not, and its low-S twin verifies", async () => {
    const published = decodeHex(RFC6979_SAMPLE_SHA256);
    expect(isLowS(published)).toBe(false);
    const key = await crypto.subtle.importKey("raw", uncompressed as unknown as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, published as unknown as BufferSource, enc.encode("sample") as unknown as BufferSource)).toBe(true);
    expect(await verifyP256(published, enc.encode("sample"), uncompressed)).toBe(false);
    const twin = normaliseLowS(published);
    expect(isLowS(twin)).toBe(true);
    expect(await verifyP256(twin, enc.encode("sample"), uncompressed)).toBe(true);
  });

  test("every signature the kernel makes is low-S, and verifies", async () => {
    const kp = await generateP256KeyPair();
    for (let i = 0; i < 24; i++) {
      const msg = enc.encode(`message ${i}`);
      const sig = await signP256(msg, kp.privateKey, kp.publicKey);
      expect(isLowS(sig)).toBe(true);
      expect(await verifyP256(sig, msg, kp.publicKey)).toBe(true);
      expect(await verifyP256(flipS(sig), msg, kp.publicKey)).toBe(false);
    }
  });

  test("r or s of zero, or at least n, never verifies", async () => {
    const kp = await generateP256KeyPair();
    const msg = enc.encode("range");
    const sig = await signP256(msg, kp.privateKey, kp.publicKey);
    const zeroR = sig.slice();
    zeroR.fill(0, 0, 32);
    expect(await verifyP256(zeroR, msg, kp.publicKey)).toBe(false);
    const bigS = sig.slice();
    bigS.set(decodeHex(toHex(P256_ORDER)), 32);
    expect(await verifyP256(bigS, msg, kp.publicKey)).toBe(false);
    expect(await verifyP256(sig.subarray(0, 63), msg, kp.publicKey)).toBe(false);
  });

  test("a mismatched private/public pair fails at import", async () => {
    const a = await generateP256KeyPair();
    const b = await generateP256KeyPair();
    await expect(signP256(enc.encode("x"), a.privateKey, b.publicKey)).rejects.toThrow(KashCryptoError);
  });
});

describe("DER — strict, one encoding per signature", () => {
  test("raw → DER → raw round-trips, including short scalars", async () => {
    const kp = await generateP256KeyPair();
    for (let i = 0; i < 16; i++) {
      const raw = await signP256(enc.encode(`d${i}`), kp.privateKey, kp.publicKey);
      expect(encodeHex(ecdsaDerToRaw(ecdsaRawToDer(raw)))).toBe(encodeHex(raw));
    }
    const short = new Uint8Array(64);
    short[31] = 1;
    short[63] = 0x80;
    const der = ecdsaRawToDer(short);
    expect(encodeHex(der)).toBe("3007020101020200" + "80");
    expect(encodeHex(ecdsaDerToRaw(der))).toBe(encodeHex(short));
  });

  test("rejects padding, negatives, trailing bytes and a lying length", () => {
    expect(() => ecdsaDerToRaw(decodeHex("300802020001020200" + "80"))).toThrow(KashCryptoError); // non-minimal r
    expect(() => ecdsaDerToRaw(decodeHex("3006020180020101"))).toThrow(KashCryptoError); // negative r
    expect(() => ecdsaDerToRaw(decodeHex("3007020101020101" + "00"))).toThrow(KashCryptoError); // trailing, inside the SEQUENCE
    expect(() => ecdsaDerToRaw(decodeHex("3007020101020101"))).toThrow(KashCryptoError); // length lies
    expect(() => ecdsaDerToRaw(decodeHex("3181" + "00"))).toThrow(KashCryptoError); // long form
  });

  test("rejects a 33-byte INTEGER that does not start 0x00 — a 257-bit number the parser must not truncate into a valid r or s", async () => {
    const kp = await generateP256KeyPair();
    const msg = enc.encode("one signature, one encoding");
    const raw = await signP256(msg, kp.privateKey, kp.publicKey);
    const canonical = ecdsaRawToDer(raw);
    const rLen = canonical[3]!;
    const rTlv = canonical.slice(2, 4 + rLen);
    const sTlv = canonical.slice(4 + rLen);
    const wrap = (r: Uint8Array, s: Uint8Array) => Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
    // Rewrite r, then s, as 33 bytes with a nonzero first byte: prefix ‖ the real 32-byte scalar.
    const widen = (scalar: Uint8Array, prefix: number) => Uint8Array.of(0x02, 33, prefix, ...scalar);
    for (const prefix of [0x01, 0x02, 0x41, 0x7f]) {
      const wideR = wrap(widen(raw.subarray(0, 32), prefix), sTlv);
      const wideS = wrap(rTlv, widen(raw.subarray(32), prefix));
      for (const alt of [wideR, wideS]) {
        expect(encodeHex(alt)).not.toBe(encodeHex(canonical));
        expect(() => ecdsaDerToRaw(alt)).toThrow(KashCryptoError);
      }
    }
    // The canonical form of a value that needs its sign byte (top bit set) still has 33 bytes, starting 0x00, and still parses.
    const high = new Uint8Array(64);
    high.fill(0xff, 0, 32);
    high[63] = 1;
    const highDer = ecdsaRawToDer(high);
    expect(highDer[3]).toBe(33);
    expect(highDer[4]).toBe(0x00);
    expect(encodeHex(ecdsaDerToRaw(highDer))).toBe(encodeHex(high));
  });
});

describe("did:kash for P-256", () => {
  test("the P-256 form is did:kash:Dn…, round-trips, and declares its type", async () => {
    const kp = await generateP256KeyPair();
    const did = deriveDidP256(kp.publicKey);
    expect(did.startsWith("did:kash:Dn")).toBe(true);
    const key = parseDidKey(did);
    expect(key.type).toBe("P-256");
    expect(encodeHex(key.publicKey)).toBe(encodeHex(kp.publicKey));
    expect(didKeyType(did)).toBe("P-256");
    expect(deriveDidForKey(key)).toBe(did);
    // the uncompressed form names the same identifier
    expect(deriveDidP256(decompressP256PublicKey(kp.publicKey))).toBe(did);
  });

  test("RFC 6979's key has one fixed P-256 did:kash", async () => {
    expect(deriveDidP256(uncompressed)).toBe(deriveDidP256(await p256PublicKeyFromScalar(RFC6979_D)));
  });

  test("Ed25519 identifiers are unchanged — RFC 8032's test key keeps its did:kash", () => {
    const rfc8032 = decodeHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const did = deriveDid(rfc8032);
    expect(did).toBe("did:kash:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z");
    expect(parseDidKey(did).type).toBe("Ed25519");
    expect(encodeHex(parseDid(did))).toBe(encodeHex(rfc8032));
    expect(isKashDid(did)).toBe(true);
  });

  test("every path written before P-256 existed fails closed on a P-256 did:kash", async () => {
    const did = deriveDidP256((await generateP256KeyPair()).publicKey);
    expect(isKashDid(did)).toBe(false);
    expect(() => parseDid(did)).toThrow(KashCryptoError);
    expect(() => deriveDid(compressP256PublicKey(uncompressed))).toThrow(KashCryptoError);
  });

  test("a body that is neither type is not a did:kash", () => {
    expect(didKeyType("did:kash:2")).toBeNull();
    expect(didKeyType("did:key:zDnaeexample")).toBeNull();
    expect(() => parseDidKey("did:kash:111111111111111111111111111111111111111111111111")).toThrow(KashCryptoError);
  });

  test("the DID document carries a P-256 Multikey, and verifies an es256 event by the key's codec", async () => {
    const kp = await generateP256KeyPair();
    const did = deriveDidP256(kp.publicKey);
    const doc = createDidDocument({ did, publicKey: kp.publicKey, pdsEndpoint: "https://pds.example" });
    expect(doc.verificationMethod[0]!.publicKeyMultibase.startsWith("zDn")).toBe(true);
    expect(decodeMultikey(doc.verificationMethod[0]!.publicKeyMultibase).type).toBe("P-256");
    const signature = await signEventEs256({ t: 1 }, { b: 2 }, kp.privateKey, kp.publicKey, { kid: `${did}#sig-1` });
    expect(await verifyEventAgainstDocument({ header: { t: 1 }, body: { b: 2 }, signature }, doc)).toBe(true);
    const other = await generateP256KeyPair();
    expect(() => createDidDocument({ did, publicKey: other.publicKey, pdsEndpoint: "https://pds.example" })).toThrow(KashCryptoError);
  });
});

describe("ES256 Kash-Events — the algorithm comes from the key", () => {
  test("sign and verify; the signature is raw, low-S, multibase", async () => {
    const kp = await generateP256KeyPair();
    const signature = await signEventEs256({ h: 1 }, { b: "x" }, kp.privateKey, kp.publicKey, { dst: "kash-key-claim-v1\n" });
    expect(signature.alg).toBe("es256");
    expect(signature.sig.startsWith("z")).toBe(true);
    const ev: SignedKashEvent = { header: { h: 1 }, body: { b: "x" }, signature };
    expect(await verifyEvent(ev, kp.publicKey)).toBe(true);
    expect(await verifyEventForKey(ev, { type: "P-256", publicKey: kp.publicKey })).toBe(true);
  });

  test("an ES256 signature never verifies against an Ed25519 key, nor an Ed25519 signature against a P-256 key", async () => {
    const p = await generateP256KeyPair();
    const e = await generateKeyPair();
    const es = { header: {}, body: { n: 1 }, signature: await signEventEs256({}, { n: 1 }, p.privateKey, p.publicKey) };
    const ed = { header: {}, body: { n: 1 }, signature: await signEvent({}, { n: 1 }, e.privateKey) };
    // typed: a mismatch is simply false
    expect(await verifyEventForKey(es, { type: "Ed25519", publicKey: e.publicKey })).toBe(false);
    expect(await verifyEventForKey(ed, { type: "P-256", publicKey: p.publicKey })).toBe(false);
    // relabelled: an Ed25519 signature claiming es256 (or the reverse) under the other key
    expect(await verifyEventForKey({ ...ed, signature: { ...ed.signature, alg: "es256" } }, { type: "P-256", publicKey: p.publicKey })).toBe(false);
    expect(await verifyEventForKey({ ...es, signature: { ...es.signature, alg: "ed25519" } }, { type: "Ed25519", publicKey: e.publicKey })).toBe(false);
    // untyped: a key of the other algorithm's length is refused outright
    await expect(verifyEvent(es, e.publicKey)).rejects.toThrow(KashCryptoError);
    await expect(verifyEvent(ed, p.publicKey)).rejects.toThrow(KashCryptoError);
  });

  test("a high-S Kash-Event does not verify", async () => {
    const kp = await generateP256KeyPair();
    const signature = await signEventEs256({}, { m: 1 }, kp.privateKey, kp.publicKey, { encoding: "hex" });
    const high = encodeHex(flipS(decodeHex(signature.sig)));
    expect(await verifyEvent({ header: {}, body: { m: 1 }, signature }, kp.publicKey)).toBe(true);
    expect(await verifyEvent({ header: {}, body: { m: 1 }, signature: { ...signature, sig: high } }, kp.publicKey)).toBe(false);
  });

  test("a hardware signer returning high-S DER is normalised before it is used", async () => {
    const kp = await generateP256KeyPair();
    const signature = await signEventWith({}, { hw: true }, {
      alg: "es256",
      sign: async (payload) => ({ signature: ecdsaRawToDer(flipS(await signP256(payload, kp.privateKey, kp.publicKey))), format: "der" }),
    });
    expect(await verifyEvent({ header: {}, body: { hw: true }, signature }, kp.publicKey)).toBe(true);
  });
});

describe("a runtime without Ed25519 is 'not checked', never 'invalid'", () => {
  test("verifyEvent throws ALG_UNAVAILABLE for Ed25519, while ES256 still verifies", async () => {
    expect(await ed25519Available()).toBe(true);
    const e = await generateKeyPair();
    const p = await generateP256KeyPair();
    const ed = { header: {}, body: { r: 1 }, signature: await signEvent({}, { r: 1 }, e.privateKey) };
    const es = { header: {}, body: { r: 1 }, signature: await signEventEs256({}, { r: 1 }, p.privateKey, p.publicKey) };
    const subtle = crypto.subtle;
    const original = subtle.importKey.bind(subtle);
    (subtle as { importKey: unknown }).importKey = (format: KeyFormat, key: unknown, alg: AlgorithmIdentifier, ...rest: unknown[]) => {
      const name = typeof alg === "string" ? alg : (alg as { name: string }).name;
      if (name === "Ed25519") return Promise.reject(new DOMException("Unrecognized algorithm name", "NotSupportedError"));
      return (original as (...a: unknown[]) => Promise<CryptoKey>)(format, key, alg, ...rest);
    };
    try {
      let code = "";
      try {
        await verifyEvent(ed, e.publicKey);
      } catch (err) {
        code = err instanceof KashCryptoError ? err.code : String(err);
      }
      expect(code).toBe("ALG_UNAVAILABLE");
      expect(await verifyEvent(es, p.publicKey)).toBe(true);
    } finally {
      (subtle as { importKey: unknown }).importKey = original;
    }
  });
});

describe("generateP256KeyPair — a runtime that drops a leading zero from the JWK's d", () => {
  // Bun 1.2.5 returns a P-256 `d` shorter than 32 bytes for about 1 fresh key in 256 (22 of 6000
  // measured on 2026-10-03; Node 22.14: 0 of 6000). RFC 7518 §6.2.2.1 requires full length, so
  // the runtime is at fault. The kernel restores the length where it reads `d` from a runtime and
  // nowhere else. These stub the export so the case is deterministic rather than 1 in 256.
  const D_ONE_ZERO = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
  const D_TWO_ZEROS = "00002233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

  /** generateP256KeyPair() with the runtime's JWK export replaced by one that returns `exportedD` as `d`. */
  async function generateWithExportedD(exportedD: Uint8Array, publicKey: Uint8Array) {
    const subtle = crypto.subtle;
    const original = subtle.exportKey.bind(subtle);
    (subtle as { exportKey: unknown }).exportKey = (format: KeyFormat, key: CryptoKey) =>
      format === "jwk"
        ? Promise.resolve({ ...p256Jwk(publicKey), d: encodeBase64Url(exportedD) })
        : (original as (...a: unknown[]) => Promise<unknown>)(format, key);
    try {
      return await generateP256KeyPair();
    } finally {
      (subtle as { exportKey: unknown }).exportKey = original;
    }
  }

  test("the key that comes back is the full 32-byte scalar, and it signs and verifies under ES256", async () => {
    for (const [hex, dropped] of [[D_ONE_ZERO, 1], [D_TWO_ZEROS, 2]] as const) {
      const d = decodeHex(hex);
      const publicKey = await p256PublicKeyFromScalar(d);
      const exported = d.slice(dropped);
      expect(exported.length).toBe(32 - dropped); // the stub models the runtime's bug

      const kp = await generateWithExportedD(exported, publicKey);
      expect(kp.privateKey.length).toBe(32);
      expect(encodeHex(kp.privateKey)).toBe(hex);
      expect(encodeHex(kp.publicKey)).toBe(encodeHex(publicKey));

      const msg = enc.encode(`short d, ${dropped} byte(s) dropped`);
      const sig = await signP256(msg, kp.privateKey, kp.publicKey);
      expect(isLowS(sig)).toBe(true);
      expect(await verifyP256(sig, msg, kp.publicKey)).toBe(true);
      const ev = { header: {}, body: { r: dropped }, signature: await signEventEs256({}, { r: dropped }, kp.privateKey, kp.publicKey) };
      expect(await verifyEvent(ev, kp.publicKey)).toBe(true);
    }
  });

  test("a d that already had 32 bytes comes back byte-for-byte, leading zero or not", async () => {
    for (const d of [RFC6979_D, decodeHex(D_ONE_ZERO)]) {
      const kp = await generateWithExportedD(d.slice(), await p256PublicKeyFromScalar(d));
      expect(encodeHex(kp.privateKey)).toBe(encodeHex(d));
    }
  });

  test("a short scalar handed straight to an import is still rejected — the padding is in generation only", async () => {
    const kp = await generateP256KeyPair();
    const codeOf = async (attempt: Promise<unknown>): Promise<string> => {
      try {
        await attempt;
        return "accepted";
      } catch (err) {
        return err instanceof KashCryptoError ? err.code : String(err);
      }
    };
    for (const length of [31, 30, 33]) {
      const scalar = new Uint8Array(length).fill(0x11);
      expect(await codeOf(p256PublicKeyFromScalar(scalar))).toBe("INVALID_KEY_BYTES");
      expect(await codeOf(signP256(enc.encode("x"), scalar, kp.publicKey))).toBe("INVALID_KEY_BYTES");
    }
  });
});
