/**
 * M2 acceptance (ROADMAP done-when #3, JWKS): the published JWKS is public-only
 * and matches the Indusland verifier wire shape byte-for-byte. `parseJwks`
 * REJECTS any key carrying a private scalar `d`.
 */

import { describe, it, expect } from "bun:test";
import { deriveDid, encodeBase64Url, generateKeyPair } from "@kashscript/identity-core";

import {
  JWKS_CACHE_CONTROL,
  JWKS_CONTENT_TYPE,
  jwkFromEd25519PublicKey,
  parseJwks,
  publicKeyFromJwks,
  publishJwks,
} from "../src/jwks";
import { KashscriptIdentityMalformedPayloadError } from "../src/errors";

describe("M2 JWKS — public-only Ed25519 JWK Set", () => {
  it("publishes the canonical wire shape (Indus-compatible)", async () => {
    const kp = await generateKeyPair();
    const kid = deriveDid(kp.publicKey);
    const jwks = publishJwks([{ publicKey: kp.publicKey, kid }]);

    expect(jwks.keys.length).toBe(1);
    const jwk = jwks.keys[0]!;
    expect(jwk).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: encodeBase64Url(kp.publicKey),
      kid,
      use: "sig",
      alg: "EdDSA",
    });
    // No private material anywhere in a published JWK.
    expect("d" in jwk).toBe(false);
  });

  it("exposes the correct response headers", () => {
    expect(JWKS_CONTENT_TYPE).toBe("application/jwk-set+json");
    expect(JWKS_CACHE_CONTROL).toBe("public, max-age=3600");
  });

  it("round-trips a public key through parse → publicKeyFromJwks", async () => {
    const kp = await generateKeyPair();
    const kid = "key-1";
    const jwks = parseJwks(publishJwks([{ publicKey: kp.publicKey, kid }]));
    const recovered = publicKeyFromJwks(jwks, kid);
    expect(recovered).not.toBeNull();
    expect([...recovered!]).toEqual([...kp.publicKey]);
    expect(publicKeyFromJwks(jwks, "missing")).toBeNull();
  });

  it("REJECTS a JWKS that leaks a private scalar d", async () => {
    const kp = await generateKeyPair();
    const pub = jwkFromEd25519PublicKey(kp.publicKey, { kid: "k" });
    const leaky = { keys: [{ ...pub, d: encodeBase64Url(kp.privateKey) }] };
    expect(() => parseJwks(leaky)).toThrow(KashscriptIdentityMalformedPayloadError);
  });

  it("rejects a structurally malformed JWKS", () => {
    expect(() => parseJwks({ keys: [{ kty: "RSA" }] })).toThrow(KashscriptIdentityMalformedPayloadError);
    expect(() => parseJwks(null)).toThrow(KashscriptIdentityMalformedPayloadError);
  });
});
