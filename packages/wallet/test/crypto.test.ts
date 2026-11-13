import { describe, expect, test } from "bun:test";
import { hpkeInternals, hpkeOpen, hpkeSeal } from "../src/crypto/hpke";
import { decryptKeyBackup, encryptKeyBackup } from "../src/crypto/jwe";
import { seededRandom } from "../src/crypto/drbg";
import { ed25519PublicKeyOf } from "../src/crypto/ed25519";
import { buf, bytesToBase64Url, bytesToHex, concat, utf8 } from "../src/crypto/bytes";
import { systemRandom } from "../src/platform";
import { isWalletError } from "../src/errors";
import { hex, readVector } from "./helpers";

// RFC 9180 appendix A.3.1 — DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
const A31 = {
  info: "4f6465206f6e2061204772656369616e2055726e",
  pkEm: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
  skEm: "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
  pkRm: "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
  skRm: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
  sharedSecret: "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
  key: "868c066ef58aae6dc589b6cfdd18f97e",
  baseNonce: "4e0bc5018beba4bf004cca59",
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ct: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
};

async function importP256(sk: string, pk: string): Promise<CryptoKey> {
  const p = hex(pk);
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: bytesToBase64Url(p.slice(1, 33)), y: bytesToBase64Url(p.slice(33)), d: bytesToBase64Url(hex(sk)), ext: false },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
}

describe("HPKE (RFC 9180) — the seal to the hardware root", () => {
  test("matches the RFC's P-256 base-mode vector: shared secret, key, nonce and ciphertext", async () => {
    const skE = await importP256(A31.skEm, A31.pkEm);
    const skR = await importP256(A31.skRm, A31.pkRm);
    const pkR = hex(A31.pkRm);
    const peer = await crypto.subtle.importKey("raw", buf(pkR), { name: "ECDH", namedCurve: "P-256" }, true, []);
    const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, skE, 256));
    const shared = await hpkeInternals.extractAndExpand(dh, concat(hex(A31.pkEm), pkR));
    expect(bytesToHex(shared)).toBe(A31.sharedSecret);
    const ks = await hpkeInternals.keySchedule(0x0001, shared, hex(A31.info));
    expect(bytesToHex(ks.key)).toBe(A31.key);
    expect(bytesToHex(ks.baseNonce)).toBe(A31.baseNonce);

    const sealed = await hpkeSeal(pkR, hex(A31.info), hex(A31.aad), hex(A31.pt), { aead: 0x0001, ephemeral: { privateKey: skE, publicKey: hex(A31.pkEm) } });
    expect(bytesToHex(sealed.enc)).toBe(A31.pkEm);
    expect(bytesToHex(sealed.ct)).toBe(A31.ct);

    const decap = async (enc: Uint8Array) => {
      const e = await crypto.subtle.importKey("raw", buf(enc), { name: "ECDH", namedCurve: "P-256" }, true, []);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: e }, skR, 256));
    };
    const opened = await hpkeOpen(sealed, pkR, hex(A31.info), hex(A31.aad), decap, { aead: 0x0001 });
    expect(bytesToHex(opened!)).toBe(A31.pt);
  });

  test("AES-256-GCM round trip; the wrong info, aad or bytes open nothing", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const pkR = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const decap = async (enc: Uint8Array) => {
      const e = await crypto.subtle.importKey("raw", buf(enc), { name: "ECDH", namedCurve: "P-256" }, true, []);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: e }, pair.privateKey, 256));
    };
    const sealed = await hpkeSeal(pkR, utf8("info"), utf8("aad"), utf8("the vault key"));
    expect(new TextDecoder().decode((await hpkeOpen(sealed, pkR, utf8("info"), utf8("aad"), decap))!)).toBe("the vault key");
    expect(await hpkeOpen(sealed, pkR, utf8("other"), utf8("aad"), decap)).toBeNull();
    expect(await hpkeOpen(sealed, pkR, utf8("info"), utf8("other"), decap)).toBeNull();
    const flipped = sealed.ct.slice();
    flipped[0]! ^= 1;
    expect(await hpkeOpen({ enc: sealed.enc, ct: flipped }, pkR, utf8("info"), utf8("aad"), decap)).toBeNull();
  });

  test("a refused prompt propagates instead of reading as 'wrong key'", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const pkR = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const sealed = await hpkeSeal(pkR, utf8("i"), utf8("a"), utf8("x"));
    await expect(hpkeOpen(sealed, pkR, utf8("i"), utf8("a"), async () => { throw new Error("cancelled"); })).rejects.toThrow("cancelled");
  });
});

describe("the encrypted key backup (JWE, PBES2-HS256+A128KW / A256GCM)", () => {
  test("opens PL-1's backup vector with its test passphrase — the same plaintext form", async () => {
    const file = JSON.parse(readVector("holder/holder-export-backup.v1.json"));
    const plain = await decryptKeyBackup(file.encryptedKeyBackup, "test vector only — never a real backup");
    expect(plain.keys.length).toBe(2);
    expect(plain.keys.every((k) => k.alg === "Ed25519" && /^[0-9a-f]{64}$/.test(k.privateKeyHex))).toBe(true);
    const did = plain.keys.find((k) => k.keyid.startsWith("did:kash:"))!;
    const { deriveDid } = await import("@kashscript/identity-core");
    expect(String(deriveDid(await ed25519PublicKeyOf(hex(did.privateKeyHex))))).toBe(did.keyid);
  });

  test("a wrong passphrase is told apart from a damaged file", async () => {
    const file = JSON.parse(readVector("holder/holder-export-backup.v1.json"));
    const wrong = await decryptKeyBackup(file.encryptedKeyBackup, "not the passphrase").catch((e) => e);
    expect(isWalletError(wrong, "BACKUP_PASSPHRASE")).toBe(true);
    const damaged = await decryptKeyBackup({ ...file.encryptedKeyBackup, tag: file.encryptedKeyBackup.iv }, "test vector only — never a real backup").catch((e) => e);
    expect(isWalletError(damaged, "BACKUP_INVALID")).toBe(true);
  });

  test("round trip, with the iteration count bounded both ways and short passphrases refused", async () => {
    const keys = [{ keyid: "did:kash:x", alg: "Ed25519" as const, privateKeyHex: "11".repeat(32) }];
    const jwe = await encryptKeyBackup({ keys }, "a long practice passphrase", systemRandom, 1000);
    expect((await decryptKeyBackup(jwe, "a long practice passphrase")).keys).toEqual(keys);
    expect(isWalletError(await encryptKeyBackup({ keys }, "short", systemRandom).catch((e) => e), "WEAK_PASSPHRASE")).toBe(true);
    const header = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(jwe.protected.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
    const lowered = bytesToBase64Url(utf8(JSON.stringify({ ...header, p2c: 10 })));
    expect(isWalletError(await decryptKeyBackup({ ...jwe, protected: lowered }, "a long practice passphrase").catch((e) => e), "BACKUP_INVALID")).toBe(true);
  });
});

describe("the headless random source", () => {
  test("the same seed gives the same bytes; another seed does not", async () => {
    const a = seededRandom("seed");
    const b = seededRandom("seed");
    const c = seededRandom("other");
    const [a1, a2] = [await a(40), await a(8)];
    expect(bytesToHex(await b(40))).toBe(bytesToHex(a1));
    expect(bytesToHex(await b(8))).toBe(bytesToHex(a2));
    expect(bytesToHex(await c(40))).not.toBe(bytesToHex(a1));
  });
});
