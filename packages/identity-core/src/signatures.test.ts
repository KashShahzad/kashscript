/**
 * Sign / verify behavioural tests — the security-critical surface.
 *
 * Ed25519 over `DST ‖ JCS({header, body})`. These cover the four
 * properties that matter: round-trip validity, tamper rejection,
 * wrong-key rejection, and DST binding (a signature can't be reused
 * under a different domain-separation tag).
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "./signer";
import { signEvent, verifyEvent, DEFAULT_KASH_RECORD_DST } from "./signatures";
import type { SignedKashEvent } from "./signatures";

async function freshSigned(): Promise<{ signer: Signer; event: SignedKashEvent }> {
  const signer = await Signer.generate();
  const header = { did: signer.did, lexicon: "kash.test.record@1.0.0", iat: "2026-05-28T00:00:00Z" };
  const body = { msg: "hello", n: 42, nested: { b: 1, a: 2 } };
  const signature = await signer.sign(header, body);
  return { signer, event: { header, body, signature } };
}

describe("signatures · round-trip", () => {
  test("a freshly signed event verifies under its own public key", async () => {
    const { signer, event } = await freshSigned();
    expect(await verifyEvent(event, signer.publicKey)).toBe(true);
  });

  test("Ed25519 is deterministic — same key + payload → same signature", async () => {
    const signer = await Signer.generate();
    const header = { did: signer.did, iat: "2026-05-28T00:00:00Z" };
    const body = { x: 1 };
    const a = await signer.sign(header, body);
    const b = await signer.sign(header, body);
    expect(a.sig).toBe(b.sig);
  });
});

describe("signatures · negative cases", () => {
  test("a tampered body fails verification", async () => {
    const { signer, event } = await freshSigned();
    const tampered: SignedKashEvent = { ...event, body: { ...(event.body as object), msg: "goodbye" } };
    expect(await verifyEvent(tampered, signer.publicKey)).toBe(false);
  });

  test("a tampered header fails verification", async () => {
    const { signer, event } = await freshSigned();
    const tampered: SignedKashEvent = {
      ...event,
      header: { ...(event.header as object), iat: "2099-01-01T00:00:00Z" },
    };
    expect(await verifyEvent(tampered, signer.publicKey)).toBe(false);
  });

  test("verification under the wrong public key fails", async () => {
    const { event } = await freshSigned();
    const other = await Signer.generate();
    expect(await verifyEvent(event, other.publicKey)).toBe(false);
  });

  test("DST binding — swapping the signature's dst breaks verification", async () => {
    const { signer, event } = await freshSigned();
    expect(event.signature.dst).toBe(DEFAULT_KASH_RECORD_DST);
    const reDst: SignedKashEvent = {
      ...event,
      signature: { ...event.signature, dst: "kash-neuron-handshake-v1\n" },
    };
    // Payload reconstructed with the new DST won't match the signed bytes.
    expect(await verifyEvent(reDst, signer.publicKey)).toBe(false);
  });
});
