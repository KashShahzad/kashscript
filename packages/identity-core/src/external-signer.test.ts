/**
 * KS-Q4 — an Ed25519 Kash-Event signed through `sign(bytes)` (Indorania
 * ADR-0003's first finding): a key service that never hands over its seed
 * makes exactly the bytes the seed path makes, and a service that answers with
 * another key, a short signature or an error is refused before anything leaves.
 */

import { describe, expect, test } from "bun:test";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { generateKeyPair } from "./keys";
import { kashEventSigningInput, signEvent, signEventWith, verifyEvent } from "./signatures";
import { KashCryptoError } from "./errors";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
/** A key service, as Indorania's platform/signing has it: a seed behind a reference, signing bytes on request. */
function keyService(seed: Uint8Array): (bytes: Uint8Array) => Promise<Uint8Array> {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  return async (bytes) => new Uint8Array(nodeSign(null, Buffer.from(bytes), key));
}

const header = { typ: "countersign-request", v: 1 };
const body = { requestId: "csr_00000000000000000000000000000001", statement: "Confirm you received this.", n: 3 };

describe("an Ed25519 signer that never hands over its key", () => {
  test("makes the same signature as the seed, under every DST and encoding, and verifies", async () => {
    const pair = await generateKeyPair();
    const signer = { alg: "ed25519" as const, publicKey: pair.publicKey, sign: keyService(pair.privateKey) };
    for (const opts of [undefined, { dst: "kash-countersign-request-v1\n" }, { dst: "kash-key-claim-v1\n", encoding: "base64url" as const }, { encoding: "hex" as const, kid: "did:kash:x#1" }]) {
      const viaService = await signEventWith(header, body, signer, opts);
      const viaSeed = await signEvent(header, body, pair.privateKey, opts);
      expect(viaService).toEqual(viaSeed);
      expect(await verifyEvent({ header, body, signature: viaService }, pair.publicKey)).toBe(true);
    }
  });

  test("signs exactly DST ‖ JCS({header, body}) — the recipe a platform no longer needs to copy", async () => {
    const pair = await generateKeyPair();
    let seen: Uint8Array | null = null;
    const inner = keyService(pair.privateKey);
    await signEventWith(header, body, { alg: "ed25519", publicKey: pair.publicKey, sign: async (b) => ((seen = b), inner(b)) }, { dst: "kash-record-v1\n" });
    expect(seen).not.toBeNull();
    expect(Buffer.from(seen!).toString("hex")).toBe(Buffer.from(kashEventSigningInput(header, body, "kash-record-v1\n")).toString("hex"));
  });

  test("a service that answers with another key, a short signature, a non-signature or an error is refused", async () => {
    const [mine, other] = [await generateKeyPair(), await generateKeyPair()];
    const wrongKey = { alg: "ed25519" as const, publicKey: mine.publicKey, sign: keyService(other.privateKey) };
    await expect(signEventWith(header, body, wrongKey)).rejects.toThrow("does not verify under its public key");
    const short = { alg: "ed25519" as const, publicKey: mine.publicKey, sign: async (b: Uint8Array) => (await keyService(mine.privateKey)(b)).slice(0, 63) };
    await expect(signEventWith(header, body, short)).rejects.toThrow("64 bytes");
    const notBytes = { alg: "ed25519" as const, publicKey: mine.publicKey, sign: async () => "signature" as unknown as Uint8Array };
    await expect(signEventWith(header, body, notBytes)).rejects.toThrow("64 bytes");
    const failing = { alg: "ed25519" as const, publicKey: mine.publicKey, sign: async () => { throw new Error("key service unreachable"); } };
    let thrown: unknown;
    try {
      await signEventWith(header, body, failing);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(KashCryptoError);
    expect((thrown as KashCryptoError).code).toBe("SIGN_FAILED");
    await expect(signEventWith(header, body, { alg: "ed25519", publicKey: new Uint8Array(31), sign: keyService(mine.privateKey) })).rejects.toThrow();
  });
});
