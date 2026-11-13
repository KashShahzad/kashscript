/**
 * Permit revocation — issuer-revocation flagship.
 *
 * Scenario: a municipal authority issues a signed operating permit to a
 * vendor. Months later the vendor's licence lapses, so the authority
 * revokes the permit. A market inspector checking the permit must see
 * it as INVALID — even though the original signature is still
 * mathematically valid (signatures are immutable; revocation is a
 * separate signed event the issuer mints).
 *
 * Layers:
 *   1. Issue + check-valid — a fresh permit passes checkCredential
 *   2. Revoke + re-check — after the authority revokes, the permit reads REVOKED
 *   3. Authorisation — only the issuer can revoke; a third party can't
 *   4. Tamper — a forged permit fails on BAD_SIGNATURE, not REVOKED
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "@kashscript/identity-core/signer";
import { encodeBase58 } from "@kashscript/identity-core/base58";
import { createBodyCommitment } from "@kashscript/identity-zkp/disclosure";
import type { SignedKashEvent } from "@kashscript/identity-core";
import {
  signRevocation,
  verifyRevocation,
  checkCredential,
  InMemoryRevocationRegistry,
  RevocationError,
} from "@kashscript/identity-sdk/revocation";

interface PermitBody {
  readonly holderDid: string;
  readonly permitType: string;
  readonly zone: string;
  readonly issuedFor: string;
}

/** Authority issues a signed permit; returns the event + its credentialId
 *  (we use the Merkle-commitment root as the stable id). */
async function issuePermit(authority: Signer, body: PermitBody): Promise<{ event: SignedKashEvent; credentialId: string }> {
  const commitment = await createBodyCommitment(body as unknown as Record<string, unknown>);
  const credentialId = encodeBase58(commitment.root);
  const header = {
    did: authority.did,
    lexicon: "kash.civic.permit@1.0.0",
    iat: "2026-01-15T00:00:00Z",
    cid: credentialId,
  };
  const signature = await authority.sign(header, body);
  return { event: { header, body, signature }, credentialId };
}

function samplePermit(holderDid: string): PermitBody {
  return { holderDid, permitType: "street-vendor", zone: "F-7-markaz", issuedFor: "2026" };
}

/* ─────────────────────────────────────────────────────────────────
 *  Layer 1 — issue + valid
 * ───────────────────────────────────────────────────────────────── */

describe("Permit revocation · issue + valid", () => {
  test("a freshly issued permit checks valid", async () => {
    const authority = await Signer.generate();
    const vendor = await Signer.generate();
    const { event, credentialId } = await issuePermit(authority, samplePermit(vendor.did));
    const registry = new InMemoryRevocationRegistry();

    const status = await checkCredential({
      credential: event,
      credentialId,
      issuerPublicKey: authority.publicKey,
      registry,
    });
    expect(status.valid).toBe(true);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 2 — revoke + re-check
 * ───────────────────────────────────────────────────────────────── */

describe("Permit revocation · revoke", () => {
  test("after the authority revokes, the permit reads REVOKED with the reason", async () => {
    const authority = await Signer.generate();
    const vendor = await Signer.generate();
    const { event, credentialId } = await issuePermit(authority, samplePermit(vendor.did));
    const registry = new InMemoryRevocationRegistry();

    // Valid before revocation.
    expect((await checkCredential({ credential: event, credentialId, issuerPublicKey: authority.publicKey, registry })).valid).toBe(true);

    // Authority revokes.
    const rev = await signRevocation(authority, credentialId, "policy");
    await registry.revoke(rev, authority.publicKey);

    const status = await checkCredential({ credential: event, credentialId, issuerPublicKey: authority.publicKey, registry });
    expect(status.valid).toBe(false);
    if (!status.valid) {
      expect(status.reason).toBe("REVOKED");
      expect(status.detail).toBe("policy");
    }
  });

  test("re-revoking the same credential is idempotent", async () => {
    const authority = await Signer.generate();
    const { credentialId } = await issuePermit(authority, samplePermit((await Signer.generate()).did));
    const registry = new InMemoryRevocationRegistry();
    const rev = await signRevocation(authority, credentialId, "error");
    await registry.revoke(rev, authority.publicKey);
    await registry.revoke(rev, authority.publicKey); // no throw, no double-record
    expect(registry.isRevoked(authority.did as never, credentialId)).toBe(true);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 3 — only the issuer can revoke
 * ───────────────────────────────────────────────────────────────── */

describe("Permit revocation · authorisation", () => {
  test("a third party cannot mint a revocation the registry will accept", async () => {
    const authority = await Signer.generate();
    const attacker = await Signer.generate();
    const { credentialId } = await issuePermit(authority, samplePermit((await Signer.generate()).did));
    const registry = new InMemoryRevocationRegistry();

    // Attacker signs a revocation for the authority's credential.
    const forged = await signRevocation(attacker, credentialId, "policy");

    // Verified against the AUTHORITY's key → fails (attacker isn't the issuer).
    expect(await verifyRevocation(forged, authority.publicKey)).toBe(false);
    // Registry refuses to record it under the authority's key.
    await expect(registry.revoke(forged, authority.publicKey)).rejects.toThrow(RevocationError);
  });

  test("a revocation signed by the issuer verifies under the issuer key", async () => {
    const authority = await Signer.generate();
    const { credentialId } = await issuePermit(authority, samplePermit((await Signer.generate()).did));
    const rev = await signRevocation(authority, credentialId, "superseded");
    expect(await verifyRevocation(rev, authority.publicKey)).toBe(true);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 4 — tamper distinguishes BAD_SIGNATURE from REVOKED
 * ───────────────────────────────────────────────────────────────── */

describe("Permit revocation · tamper", () => {
  test("a tampered permit body fails BAD_SIGNATURE (not REVOKED)", async () => {
    const authority = await Signer.generate();
    const vendor = await Signer.generate();
    const { event, credentialId } = await issuePermit(authority, samplePermit(vendor.did));
    const registry = new InMemoryRevocationRegistry();

    const tampered: SignedKashEvent = {
      ...event,
      body: { ...(event.body as object), zone: "G-9-markaz" }, // changed zone post-signing
    };
    const status = await checkCredential({ credential: tampered, credentialId, issuerPublicKey: authority.publicKey, registry });
    expect(status.valid).toBe(false);
    if (!status.valid) expect(status.reason).toBe("BAD_SIGNATURE");
  });
});
