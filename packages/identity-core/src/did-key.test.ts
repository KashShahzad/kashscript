/**
 * did:key ↔ did:kash — two spellings, one key (RW-19 branch B; d97(h)).
 *
 * The mapping must be lossless both ways, the P-256 case must be the exact
 * z-prepend ADR-0020 promised, and everything that is not an ed25519-pub or
 * p256-pub multicodec key must fail closed.
 */

import { describe, expect, test } from "bun:test";
import {
  anyKeyDidType,
  deriveDidKey,
  fromDidKey,
  parseAnyKeyDid,
  parseDidKeyMethod,
  toDidKey,
  DID_KEY_SOURCE,
} from "./did-key";
import { deriveDid, deriveDidP256, parseDid, parseDidKey } from "./did";
import { encodeBase58 } from "./base58";
import { generateKeyPair } from "./keys";
import { generateP256KeyPair, compressP256PublicKey } from "./p256";

/** The engine's live grade-1 ceremony key (founder-steps §12) — the worked example in specs/did-kash.md. */
const CEREMONY_KASH = "did:kash:DnaevFAeTBp7Ht8bShhjcHBZmnZfubu9x4YJJHqB881YpeiX";

describe("did:key · Ed25519 round-trip", () => {
  test("toDidKey and fromDidKey are inverse, byte-for-byte", async () => {
    for (let i = 0; i < 5; i++) {
      const kp = await generateKeyPair();
      const kash = deriveDid(kp.publicKey);
      const key = toDidKey(kash);
      expect(key.startsWith("did:key:z6Mk")).toBe(true); // ed25519-pub multicodec always encodes to 6Mk…
      expect(fromDidKey(key)).toBe(kash);
      expect(Array.from(parseDidKeyMethod(key).publicKey)).toEqual(Array.from(kp.publicKey));
      expect(parseDidKeyMethod(key).type).toBe("Ed25519");
    }
  });

  test("the derived spelling matches the schema source", async () => {
    const key = toDidKey(deriveDid((await generateKeyPair()).publicKey));
    expect(new RegExp(`^${DID_KEY_SOURCE}$`).test(key)).toBe(true);
  });
});

describe("did:key · P-256 is the same bytes behind the z (ADR-0020)", () => {
  test("toDidKey literally prepends z to a P-256 did:kash body", async () => {
    const kp = await generateP256KeyPair();
    const kash = deriveDidP256(kp.publicKey);
    const body = kash.slice("did:kash:".length);
    const key = toDidKey(kash);
    expect(key).toBe(`did:key:z${body}`);
    expect(key.startsWith("did:key:zDn")).toBe(true); // p256-pub multicodec always encodes to Dn…
    expect(fromDidKey(key)).toBe(kash);
  });

  test("the live ceremony key maps both ways", () => {
    const key = toDidKey(CEREMONY_KASH);
    expect(key).toBe(`did:key:z${CEREMONY_KASH.slice("did:kash:".length)}`);
    expect(fromDidKey(key)).toBe(CEREMONY_KASH);
    expect(parseDidKeyMethod(key).type).toBe("P-256");
  });

  test("deriveDidKey accepts an uncompressed point and compresses it, as deriveDidP256 does", async () => {
    const kp = await generateP256KeyPair();
    const compressed = compressP256PublicKey(kp.publicKey);
    expect(deriveDidKey({ type: "P-256", publicKey: kp.publicKey })).toBe(
      deriveDidKey({ type: "P-256", publicKey: compressed }),
    );
  });
});

describe("did:key · fails closed", () => {
  test("refuses what is not a did:key this ecosystem reads", async () => {
    const ed = (await generateKeyPair()).publicKey;
    const cases: string[] = [
      "did:key:6MkfFme3aySJZTw5WBbCXZbsdkDfXBLkSJrXBdQ1EsU6Tzvv", // no multibase z
      `did:key:z${encodeBase58(Uint8Array.of(0xec, 0x01, ...ed))}`, // x25519-pub, another codec
      `did:key:z${encodeBase58(Uint8Array.of(0xed, 0x01, ...ed, 0x00))}`, // ed25519 prefix, 33 bytes
      `did:key:z${encodeBase58(Uint8Array.of(0x80, 0x24, ...new Uint8Array(32).fill(7)))}`, // p256 prefix, 32 bytes
      `did:key:z${encodeBase58(Uint8Array.of(0x80, 0x24, 0x02, ...new Uint8Array(32).fill(0xff)))}`, // off the curve
      "did:key:zIl0O", // not base58btc
      CEREMONY_KASH, // a did:kash is not a did:key
      "did:key:z", // empty body
    ];
    for (const value of cases) {
      expect(() => parseDidKeyMethod(value)).toThrow();
      expect(anyKeyDidType(value) === null || value === CEREMONY_KASH).toBe(true);
    }
  });

  test("refuses a fragment — callers strip before parsing, as attest's resolver does", async () => {
    const key = toDidKey(deriveDid((await generateKeyPair()).publicKey));
    expect(() => parseDidKeyMethod(`${key}#sig-1`)).toThrow();
  });
});

describe("parseAnyKeyDid · either spelling, one key", () => {
  test("both spellings of one key parse to the same bytes and type", async () => {
    const kp = await generateP256KeyPair();
    const kash = deriveDidP256(kp.publicKey);
    const a = parseAnyKeyDid(kash);
    const b = parseAnyKeyDid(toDidKey(kash));
    expect(a.type).toBe(b.type);
    expect(Array.from(a.publicKey)).toEqual(Array.from(b.publicKey));
    expect(Array.from(a.publicKey)).toEqual(Array.from(parseDidKey(kash).publicKey));
  });

  test("anyKeyDidType names the type of either spelling and null for anything else", async () => {
    const kash = deriveDid((await generateKeyPair()).publicKey);
    expect(anyKeyDidType(kash)).toBe("Ed25519");
    expect(anyKeyDidType(toDidKey(kash))).toBe("Ed25519");
    expect(anyKeyDidType(CEREMONY_KASH)).toBe("P-256");
    expect(anyKeyDidType("did:web:duedale.com")).toBeNull();
    expect(anyKeyDidType("did:kash:org:acme-inc")).toBeNull(); // an engine's opaque id names no key (d99)
    expect(anyKeyDidType("")).toBeNull();
  });
});
