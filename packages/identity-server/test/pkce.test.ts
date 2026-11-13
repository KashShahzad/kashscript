/**
 * M2 acceptance (ROADMAP done-when #3, PKCE): S256-only Proof Key for Code
 * Exchange (RFC 7636). Verified against the RFC 7636 Appendix B test vector.
 */

import { describe, it, expect } from "bun:test";
import {
  PKCE_METHOD,
  assertValidCodeVerifier,
  codeChallengeS256,
  generateCodeVerifier,
  verifyPkce,
} from "../src/pkce";
import { KashscriptIdentityMalformedPayloadError } from "../src/errors";

// RFC 7636 Appendix B.
const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("M2 PKCE — S256 only", () => {
  it("is S256", () => {
    expect(PKCE_METHOD).toBe("S256");
  });

  it("derives the RFC 7636 Appendix B challenge from its verifier", async () => {
    expect(await codeChallengeS256(RFC_VERIFIER)).toBe(RFC_CHALLENGE);
  });

  it("generates a valid 43-char verifier that round-trips", async () => {
    const v = generateCodeVerifier();
    expect(v.length).toBe(43);
    assertValidCodeVerifier(v); // must not throw
    const challenge = await codeChallengeS256(v);
    expect(await verifyPkce(v, challenge)).toBe(true);
  });

  it("fails verification against a wrong challenge", async () => {
    const v = generateCodeVerifier();
    expect(await verifyPkce(v, RFC_CHALLENGE)).toBe(false);
    expect(await verifyPkce(v, "")).toBe(false);
  });

  it("rejects an out-of-spec verifier (too short / bad charset)", () => {
    expect(() => assertValidCodeVerifier("tooshort")).toThrow(KashscriptIdentityMalformedPayloadError);
    expect(() => assertValidCodeVerifier("has spaces and~invalid chars but long enough xxxxxxxxxx")).toThrow(
      KashscriptIdentityMalformedPayloadError,
    );
  });
});
