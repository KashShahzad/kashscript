/**
 * Smoke test for the runtime license-key verifier.
 *
 * Round-trip:
 *   1. Generate a fresh registry keypair (only for this test — production
 *      uses the canonical Kash-Registry key baked into each commercial pkg).
 *   2. Mint a signed token claiming a particular DID + tier + TTL.
 *   3. Verify it. Tier ladder works. Tampering breaks it. Expiry breaks it.
 */

import { describe, expect, test } from "bun:test";
import { canonicalizeBytes } from "./canonical";
import { encodeBase64Url, decodeBase64Url } from "./base64url";
import {
  verifyLicense,
  assertLicense,
  LicenseError,
  _resetWarnedForTest,
  type LicenseClaims,
  type SignedLicense,
  type LicenseTier,
} from "./license";

/* ─────────────────────────────────────────────────────────────────
 *  Mint helper — what the kash-registry would do server-side.
 * ───────────────────────────────────────────────────────────────── */

async function generateRegistryKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as
    { privateKey: CryptoKey; publicKey: CryptoKey };
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { publicKey: pub, privateKey: kp.privateKey };
}

async function mintToken(
  privateKey: CryptoKey,
  claims: LicenseClaims,
): Promise<string> {
  const payload = canonicalizeBytes(claims);
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, payload.slice().buffer),
  );
  const signed: SignedLicense = { ...claims, sig: encodeBase64Url(sigBytes) };
  const json = new TextEncoder().encode(JSON.stringify(signed));
  return encodeBase64Url(json);
}

function freshClaims(overrides: Partial<LicenseClaims> = {}): LicenseClaims {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    did: "did:kash:9vmffxtZDbaABAB8Ry2fUDsdoAmcbPMhafEz8Ca9vqDU",
    tier: "paid",
    iat: nowSec,
    exp: nowSec + 86_400,
    ...overrides,
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  verifyLicense — happy path + tamper + expiry
 * ───────────────────────────────────────────────────────────────── */

describe("verifyLicense · happy path", () => {
  test("a freshly-minted token verifies and returns the claims", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    const claims = freshClaims();
    const token = await mintToken(privateKey, claims);

    const got = await verifyLicense(token, publicKey);
    expect(got).toEqual(claims);
  });

  test("tier values round-trip exactly", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    for (const tier of ["trial", "paid", "team", "enterprise"] as const) {
      const token = await mintToken(privateKey, freshClaims({ tier }));
      const got = await verifyLicense(token, publicKey);
      expect(got.tier).toBe(tier);
    }
  });
});

describe("verifyLicense · rejection paths", () => {
  test("wrong registry pubkey → SIGNATURE_INVALID", async () => {
    const real = await generateRegistryKeypair();
    const imposter = await generateRegistryKeypair();
    const token = await mintToken(real.privateKey, freshClaims());

    try {
      await verifyLicense(token, imposter.publicKey);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(LicenseError);
      expect((e as LicenseError).code).toBe("SIGNATURE_INVALID");
    }
  });

  test("tampered claim → SIGNATURE_INVALID", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    const token = await mintToken(privateKey, freshClaims({ tier: "trial" }));

    // Decode → bump tier to "enterprise" → re-encode WITHOUT re-signing.
    const original = JSON.parse(new TextDecoder().decode(decodeBase64Url(token))) as SignedLicense;
    const tampered: SignedLicense = { ...original, tier: "enterprise" };
    const tamperedToken = encodeBase64Url(new TextEncoder().encode(JSON.stringify(tampered)));

    try {
      await verifyLicense(tamperedToken, publicKey);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("SIGNATURE_INVALID");
    }
  });

  test("expired token → EXPIRED", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await mintToken(privateKey, freshClaims({
      iat: nowSec - 7200,
      exp: nowSec - 3600, // expired 1h ago
    }));

    try {
      await verifyLicense(token, publicKey);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("EXPIRED");
    }
  });

  test("garbage input → KEY_MALFORMED", async () => {
    const { publicKey } = await generateRegistryKeypair();
    try {
      await verifyLicense("not-base64url-json", publicKey);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("KEY_MALFORMED");
    }
  });

  test("future schema version → VERSION_UNSUPPORTED", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    // Manually construct a v=2 token (signs over the v=2 claims).
    const futureClaims = { ...freshClaims(), v: 2 as unknown as 1 };
    const payload = canonicalizeBytes(futureClaims);
    const sigBytes = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, payload.slice().buffer));
    const signed = { ...futureClaims, sig: encodeBase64Url(sigBytes) };
    const token = encodeBase64Url(new TextEncoder().encode(JSON.stringify(signed)));

    try {
      await verifyLicense(token, publicKey);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("VERSION_UNSUPPORTED");
    }
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  assertLicense — env reading + tier ladder
 * ───────────────────────────────────────────────────────────────── */

describe("assertLicense · env + tier ladder", () => {
  test("missing key in production mode → KEY_MISSING", async () => {
    const { publicKey } = await generateRegistryKeypair();
    delete (process.env as Record<string, string | undefined>)["KASH_LICENSE_KEY_TEST"];

    try {
      await assertLicense({
        pkgName: "@kashscript/test",
        registryPublicKey: publicKey,
        mode: "production",
        envVar: "KASH_LICENSE_KEY_TEST",
      });
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("KEY_MISSING");
    }
  });

  test("missing key in development mode → null + warning (no throw)", async () => {
    const { publicKey } = await generateRegistryKeypair();
    delete (process.env as Record<string, string | undefined>)["KASH_LICENSE_KEY_TEST"];
    _resetWarnedForTest();
    const got = await assertLicense({
      pkgName: "@kashscript/test",
      registryPublicKey: publicKey,
      mode: "development",
      envVar: "KASH_LICENSE_KEY_TEST",
    });
    expect(got).toBeNull();
  });

  test("tier ladder: requiredTier=team rejects a paid license", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    const token = await mintToken(privateKey, freshClaims({ tier: "paid" }));
    process.env["KASH_LICENSE_KEY_TEST"] = token;

    try {
      await assertLicense({
        pkgName: "@kashscript/test",
        registryPublicKey: publicKey,
        requiredTier: "team",
        envVar: "KASH_LICENSE_KEY_TEST",
      });
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as LicenseError).code).toBe("TIER_INSUFFICIENT");
    }
  });

  test("tier ladder: requiredTier=trial accepts enterprise", async () => {
    const { publicKey, privateKey } = await generateRegistryKeypair();
    const token = await mintToken(privateKey, freshClaims({ tier: "enterprise" }));
    process.env["KASH_LICENSE_KEY_TEST"] = token;

    const got = await assertLicense({
      pkgName: "@kashscript/test",
      registryPublicKey: publicKey,
      requiredTier: "trial",
      envVar: "KASH_LICENSE_KEY_TEST",
    });
    expect(got).not.toBeNull();
    expect(got?.tier).toBe("enterprise" as LicenseTier);
  });
});
