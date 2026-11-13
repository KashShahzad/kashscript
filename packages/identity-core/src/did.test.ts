/**
 * Round-trip + format tests for the did:kash method.
 *
 * did:kash is self-certifying — the DID is a multibase encoding of the
 * raw public key. These pin the derive↔parse round-trip and the
 * accept/reject boundary (including rejecting the legacy did:ks form).
 */

import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "./keys";
import { deriveDid, parseDid, isKashDid } from "./did";

describe("did:kash · derive ↔ parse round-trip", () => {
  test("parseDid(deriveDid(pk)) === pk, byte-for-byte", async () => {
    for (let i = 0; i < 5; i++) {
      const kp = await generateKeyPair();
      const did = deriveDid(kp.publicKey);
      const recovered = parseDid(did);
      expect(Array.from(recovered)).toEqual(Array.from(kp.publicKey));
    }
  });

  test("deriveDid is deterministic for a fixed key", async () => {
    const kp = await generateKeyPair();
    expect(deriveDid(kp.publicKey)).toBe(deriveDid(kp.publicKey));
  });

  test("distinct keys derive distinct DIDs", async () => {
    const a = deriveDid((await generateKeyPair()).publicKey);
    const b = deriveDid((await generateKeyPair()).publicKey);
    expect(a).not.toBe(b);
  });
});

describe("did:kash · format guard", () => {
  test("accepts a freshly-derived did:kash", async () => {
    const did = deriveDid((await generateKeyPair()).publicKey);
    expect(isKashDid(did)).toBe(true);
    expect(did.startsWith("did:kash:")).toBe(true);
  });

  test("rejects the legacy did:ks form (the drift bug)", () => {
    expect(isKashDid("did:ks:abc123")).toBe(false);
  });

  test("rejects garbage", () => {
    expect(isKashDid("not-a-did")).toBe(false);
    expect(isKashDid("did:kash:")).toBe(false);
    expect(isKashDid("")).toBe(false);
  });
});
