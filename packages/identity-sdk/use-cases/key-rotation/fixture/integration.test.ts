/**
 * Key rotation — voluntary succession-chain flagship.
 *
 * Scenario: a PhD student suspects their laptop was exposed at a
 * conference. They still HOLD the key, so this is rotation (pre-emptive,
 * self-signed) not recovery (loss, advisor-attested). They generate a
 * fresh key on a clean device and sign a succession link with the old
 * key. Later they rotate again (scheduled hygiene). A journal that
 * pinned their genesis DID walks the chain and learns the current key —
 * no resolver, no trusted third party.
 *
 * Layers:
 *   1. Single rotation — old key signs successor; verifies under old key
 *   2. Multi-link chain — genesis → B → C walks to the active head
 *   3. Adversarial — wrong prior key, seq drift, successor-key spoof,
 *      no-op rotation refused
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "@kashscript/identity-core/signer";
import { deriveDid } from "@kashscript/identity-core/did";
import {
  signKeyRotation,
  verifyKeyRotation,
  verifyRotationChain,
  KASH_ROTATION_DST,
} from "@kashscript/identity-sdk/rotation";

/* ─────────────────────────────────────────────────────────────────
 *  Layer 1 — single rotation
 * ───────────────────────────────────────────────────────────────── */

describe("Key rotation · single link", () => {
  test("old key signs successor; link verifies under the old key", async () => {
    const oldKey = await Signer.generate();
    const newKey = await Signer.generate();
    const link = await signKeyRotation(oldKey, newKey.publicKey, 0, "suspected-exposure");

    expect(link.signature.dst).toBe(KASH_ROTATION_DST);
    expect(link.body.priorDid).toBe(oldKey.did);
    expect(link.body.newDid).toBe(newKey.did);
    expect(link.body.reason).toBe("suspected-exposure");
    expect(await verifyKeyRotation(link, oldKey.publicKey)).toBe(true);
  });

  test("a no-op rotation (successor === current) is refused", async () => {
    const k = await Signer.generate();
    await expect(signKeyRotation(k, k.publicKey, 0)).rejects.toThrow(/no-op/);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 2 — multi-link chain walks to the active head
 * ───────────────────────────────────────────────────────────────── */

describe("Key rotation · chain", () => {
  test("genesis → B → C resolves to C as the active key", async () => {
    const genesis = await Signer.generate();
    const b = await Signer.generate();
    const c = await Signer.generate();

    const link0 = await signKeyRotation(genesis, b.publicKey, 0, "device-change");
    const link1 = await signKeyRotation(b, c.publicKey, 1, "scheduled");

    const result = await verifyRotationChain(genesis.publicKey, [link0, link1]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.activeDid).toBe(c.did);
      expect(result.length).toBe(2);
    }
  });

  test("an empty chain resolves to the genesis key itself", async () => {
    const genesis = await Signer.generate();
    const result = await verifyRotationChain(genesis.publicKey, []);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.activeDid).toBe(deriveDid(genesis.publicKey));
  });

  test("a journal that pinned genesis can confirm a 3-hop current key", async () => {
    const keys = await Promise.all(Array.from({ length: 4 }, () => Signer.generate()));
    const links = [];
    for (let i = 0; i < 3; i++) {
      links.push(await signKeyRotation(keys[i]!, keys[i + 1]!.publicKey, i));
    }
    const result = await verifyRotationChain(keys[0]!.publicKey, links);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.activeDid).toBe(keys[3]!.did);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 3 — adversarial
 * ───────────────────────────────────────────────────────────────── */

describe("Key rotation · adversarial", () => {
  test("a link not signed by the prior key breaks the chain at that index", async () => {
    const genesis = await Signer.generate();
    const b = await Signer.generate();
    const c = await Signer.generate();
    const imposter = await Signer.generate();

    const link0 = await signKeyRotation(genesis, b.publicKey, 0);
    // link1 is signed by an imposter, not by b
    const link1 = await signKeyRotation(imposter, c.publicKey, 1);

    const result = await verifyRotationChain(genesis.publicKey, [link0, link1]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.breakAt).toBe(1);
  });

  test("seq drift breaks the chain", async () => {
    const genesis = await Signer.generate();
    const b = await Signer.generate();
    const c = await Signer.generate();
    const link0 = await signKeyRotation(genesis, b.publicKey, 0);
    const linkBadSeq = await signKeyRotation(b, c.publicKey, 5); // should be 1

    const result = await verifyRotationChain(genesis.publicKey, [link0, linkBadSeq]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/seq drift/);
  });

  test("a successor-key spoof (newDid not matching newPublicKeyB58) fails verify", async () => {
    const oldKey = await Signer.generate();
    const realSuccessor = await Signer.generate();
    const otherKey = await Signer.generate();
    const link = await signKeyRotation(oldKey, realSuccessor.publicKey, 0);

    // Tamper: claim a different newDid than the one the key derives to.
    const spoofed = {
      ...link,
      body: { ...link.body, newDid: otherKey.did },
    };
    expect(await verifyKeyRotation(spoofed, oldKey.publicKey)).toBe(false);
  });

  test("verifying a genuine link under the WRONG prior key fails", async () => {
    const oldKey = await Signer.generate();
    const newKey = await Signer.generate();
    const wrong = await Signer.generate();
    const link = await signKeyRotation(oldKey, newKey.publicKey, 0);
    expect(await verifyKeyRotation(link, wrong.publicKey)).toBe(false);
  });
});
