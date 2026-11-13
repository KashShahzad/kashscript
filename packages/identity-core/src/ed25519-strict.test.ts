/**
 * The Ed25519 acceptance rule (AU-3, A7-07): the points and scalars the rule
 * refuses, and the one case that shows why — a signature of zeros under the
 * identity key, which WebCrypto alone accepts for any message.
 */

import { describe, expect, test } from "bun:test";
import { decodeHex, encodeBase58 } from "./index";
import { DEFAULT_KASH_RECORD_DST, generateKeyPair, signEvent, verifyEvent, verifyEventForKey, type SignedKashEvent } from "./index";
import {
  ED25519_ORDER_L,
  addEd25519Points,
  decodeEd25519Point,
  ed25519LittleEndianToBigInt,
  ed25519Precheck,
  encodeEd25519Point,
  isCanonicalEd25519Scalar,
  isSmallOrderEd25519Point,
} from "./ed25519-strict";

/** The identity: y = 1, x = 0. */
const IDENTITY = (() => {
  const b = new Uint8Array(32);
  b[0] = 1;
  return b;
})();
/** A point of order 8 — the public key of ed25519-speccheck's case 0. */
const ORDER_8 = decodeHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");

function multibase(bytes: Uint8Array): string {
  return `z${encodeBase58(bytes)}`;
}

function littleEndian(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

describe("Ed25519 strict decoding", () => {
  test("the identity decodes to (0, 1) and is small order; its non-canonical twin y = p + 1 is no encoding", () => {
    expect(decodeEd25519Point(IDENTITY)).toEqual({ x: 0n, y: 1n });
    expect(isSmallOrderEd25519Point(decodeEd25519Point(IDENTITY)!)).toBe(true);
    const twin = new Uint8Array(32).fill(0xff);
    twin[0] = 0xee;
    twin[31] = 0x7f;
    expect(decodeEd25519Point(twin)).toBeNull();
    const identityWithSign = IDENTITY.slice();
    identityWithSign[31] = 0x80;
    expect(decodeEd25519Point(identityWithSign)).toBeNull();
  });

  test("the torsion subgroup has eight points, every one of them small order, and an honest key is not among them", async () => {
    const t = decodeEd25519Point(ORDER_8)!;
    const seen = new Set<string>();
    let p = { x: 0n, y: 1n };
    for (let k = 0; k < 8; k++) {
      expect(isSmallOrderEd25519Point(p)).toBe(true);
      seen.add(Buffer.from(encodeEd25519Point(p)).toString("hex"));
      p = addEd25519Points(p, t);
    }
    expect(seen.size).toBe(8);
    expect(p).toEqual({ x: 0n, y: 1n }); // 8·T = O
    const kp = await generateKeyPair();
    const a = decodeEd25519Point(kp.publicKey)!;
    expect(a).not.toBeNull();
    expect(isSmallOrderEd25519Point(a)).toBe(false);
    expect(encodeEd25519Point(a)).toEqual(kp.publicKey);
  });

  test("S is canonical below L and not at or above it", () => {
    expect(isCanonicalEd25519Scalar(littleEndian(ED25519_ORDER_L - 1n))).toBe(true);
    expect(isCanonicalEd25519Scalar(littleEndian(ED25519_ORDER_L))).toBe(false);
    expect(isCanonicalEd25519Scalar(littleEndian(ED25519_ORDER_L + 1n))).toBe(false);
    expect(ed25519LittleEndianToBigInt(littleEndian(12345n))).toBe(12345n);
  });

  test("the pre-check names its reason", async () => {
    const kp = await generateKeyPair();
    const zeros = new Uint8Array(64);
    zeros[0] = 1; // R = identity, S = 0
    expect(ed25519Precheck(IDENTITY, zeros)).toBe("A_SMALL_ORDER");
    expect(ed25519Precheck(ORDER_8, zeros)).toBe("A_SMALL_ORDER");
    expect(ed25519Precheck(kp.publicKey, zeros)).toBe("R_SMALL_ORDER");
    const big = new Uint8Array(64);
    big.set(littleEndian(ED25519_ORDER_L), 32);
    expect(ed25519Precheck(kp.publicKey, big)).toBe("S_NOT_CANONICAL");
    const badKey = new Uint8Array(32).fill(0xff);
    badKey[0] = 0xee;
    badKey[31] = 0x7f;
    expect(ed25519Precheck(badKey, new Uint8Array(64))).toBe("A_INVALID");
    const badR = new Uint8Array(64);
    badR.set(badKey, 0);
    expect(ed25519Precheck(kp.publicKey, badR)).toBe("R_INVALID");
    expect(ed25519Precheck(kp.publicKey, new Uint8Array(63))).toBe("R_INVALID");
  });
});

describe("Kash-Events under the rule", () => {
  test("a signature of zeros under the identity key — which WebCrypto alone accepts for any message — does not verify", async () => {
    const header = { typ: "x", v: 1 };
    const body = { any: "message at all" };
    const zeros = new Uint8Array(64);
    zeros[0] = 1;
    const forged: SignedKashEvent = { header, body, signature: { alg: "ed25519", sig: multibase(zeros), dst: DEFAULT_KASH_RECORD_DST } };
    expect(await verifyEvent(forged, IDENTITY)).toBe(false);
    expect(await verifyEventForKey(forged, { type: "Ed25519", publicKey: IDENTITY })).toBe(false);
    // the same shape under a key of order 8
    expect(await verifyEvent({ ...forged, body: { other: 1 } }, ORDER_8)).toBe(false);
  });

  test("an honest signature passes the pre-check and verifies; its S plus L is refused as non-canonical", async () => {
    const kp = await generateKeyPair();
    const header = { typ: "x", v: 1 };
    const body = { fine: true };
    const sig = await signEvent(header, body, kp.privateKey);
    const event: SignedKashEvent = { header, body, signature: sig };
    expect(await verifyEvent(event, kp.publicKey)).toBe(true);
    const { decodeBase58 } = await import("./index");
    const bytes = decodeBase58(sig.sig.slice(1));
    expect(ed25519Precheck(kp.publicKey, bytes)).toBe("ok");
    const s = ed25519LittleEndianToBigInt(bytes.subarray(32));
    const malleated = bytes.slice();
    malleated.set(littleEndian(s + ED25519_ORDER_L), 32);
    expect(ed25519Precheck(kp.publicKey, malleated)).toBe("S_NOT_CANONICAL");
    expect(await verifyEvent({ header, body, signature: { ...sig, sig: multibase(malleated) } }, kp.publicKey)).toBe(false);
  });
});
