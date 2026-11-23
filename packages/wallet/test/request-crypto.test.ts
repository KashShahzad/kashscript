import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { base64UrlToBytes, buf, bytesToBase64Url, utf8 } from "../src/crypto/bytes";
import { asVerifierEncKey, concatKdf, decryptEcdhEs, encryptEcdhEs } from "../src/crypto/jwe-ecdh";
import { readLeaf, verifyEs256WithSpki } from "../src/crypto/x509";
import { makeTestVerifier } from "./x509-builder";

const random = async (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe("x509 — the leaf of a verifier's request", () => {
  test("the OpenID Foundation suite's own verifier certificate hashes to the x509_hash its request named", async () => {
    // From KS-C1's saved log (docs/conformance/2026-10-10, the HAIP VP run): the suite set
    // client_id = x509_hash:l3hP-KU_Ok3sF7e7CMwGhy0JskhLgP007Ek-e_jni3w for this certificate.
    const leaf = await readLeaf(readFileSync(join(import.meta.dir, "fixtures", "oidf-suite-verifier-leaf.b64"), "utf8").trim());
    expect(leaf.sha256).toBe("l3hP-KU_Ok3sF7e7CMwGhy0JskhLgP007Ek-e_jni3w");
    expect(leaf.dnsNames).toContain("localhost.emobix.co.uk");
    expect(leaf.notAfter).toBeGreaterThan(leaf.notBefore);
    // The key imports as P-256.
    await crypto.subtle.importKey("spki", buf(leaf.spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  });

  test("names, validity and key come out of a certificate made here", async () => {
    const v = await makeTestVerifier(["verifier.practice.invalid", "alt.practice.invalid"], { from: "260101000000Z", to: "270101000000Z" });
    const leaf = await readLeaf(v.x5c0);
    expect(leaf.dnsNames).toEqual(["verifier.practice.invalid", "alt.practice.invalid"]);
    expect(leaf.sha256).toBe(v.hash);
    expect(leaf.notBefore).toBe(Date.UTC(2026, 0, 1) / 1000);
    expect(leaf.notAfter).toBe(Date.UTC(2027, 0, 1) / 1000);
    const jws = await v.sign({}, { a: 1 });
    const [h, p, s] = jws.split(".");
    expect(await verifyEs256WithSpki(leaf.spki, utf8(`${h}.${p}`), base64UrlToBytes(s!))).toBe(true);
    expect(await verifyEs256WithSpki(leaf.spki, utf8(`${h}.${p}x`), base64UrlToBytes(s!))).toBe(false);
  });

  test("bytes that are not a certificate are refused, not guessed at", async () => {
    await expect(readLeaf("AAAA")).rejects.toThrow();
    await expect(readLeaf(btoa("not a certificate at all"))).rejects.toThrow();
  });
});

describe("ECDH-ES — direct_post.jwt", () => {
  test("Concat KDF matches RFC 7518 Appendix C", async () => {
    const alice = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps", d: "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo" },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const bob = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck" },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const z = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: bob }, alice, 256));
    const key = await concatKdf(z, "A128GCM", 128, utf8("Alice"), utf8("Bob"));
    expect(bytesToBase64Url(key)).toBe("VqqN6vgjbSBcIijNcacQGg");
  });

  test("a response encrypted to the verifier's key opens with its private key, for both encodings", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    const pub = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
    const key = asVerifierEncKey({ ...pub, kid: "v1", use: "enc", alg: "ECDH-ES" });
    expect(key).not.toBeNull();
    for (const enc of ["A128GCM", "A256GCM"] as const) {
      const jwe = await encryptEcdhEs(utf8('{"vp_token":{}}'), key!, enc, random);
      const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(jwe.split(".")[0]!)));
      expect(header).toMatchObject({ alg: "ECDH-ES", enc, kid: "v1" });
      expect(jwe.split(".")[1]).toBe("");
      expect(new TextDecoder().decode(await decryptEcdhEs(jwe, pair.privateKey))).toBe('{"vp_token":{}}');
    }
  });

  test("a signing key or another curve is not an encryption key", () => {
    expect(asVerifierEncKey({ kty: "EC", crv: "P-256", x: "a", y: "b", use: "sig" })).toBeNull();
    expect(asVerifierEncKey({ kty: "EC", crv: "P-384", x: "a", y: "b" })).toBeNull();
    expect(asVerifierEncKey({ kty: "RSA", n: "a", e: "AQAB" })).toBeNull();
  });
});
