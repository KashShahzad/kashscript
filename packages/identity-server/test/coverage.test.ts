/**
 * M2 acceptance (ROADMAP done-when #1): @duedale/identity-kernel's export
 * surface is FULLY COVERED by identity-server, and the behaviors ported from
 * the ks-adapters identity bridge hold — guest-DID mint, handshake
 * issue→consume(one-time)→verify, resolve NOT_FOUND/REVOKED, revoke +
 * NOT_A_GUEST_DID, malformed-DID throws, PDS write/read/revision, hashing.
 */

import { describe, it, expect } from "bun:test";
import { deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64, signRaw } from "@kashscript/attest";

import * as ident from "../src/index";
import {
  createIdentityServer,
  InMemoryChallengeStore,
  InMemoryIdentityMetadataStore,
  InMemoryPdsStore,
} from "../src/stores";
import { issueGuestDid } from "../src/guest-did";
import { verifyHandshakeSignature, SUPPORTED_ALGORITHMS } from "../src/handshake";
import { resolveDidPubkey } from "../src/did";
import { sha256HexOfBase64, sha256HexOfUtf8 } from "../src/hashing";
import {
  KashscriptIdentityMalformedDidError,
  KashscriptIdentityMalformedPayloadError,
  KashscriptIdentityNotImplementedError,
  KashscriptIdentityUnsupportedAlgorithmError,
} from "../src/errors";
import type { GuestDidIssuanceRequest, PdsRecord } from "../src/types";

const guestReq = (over: Partial<GuestDidIssuanceRequest> = {}): GuestDidIssuanceRequest => ({
  hostOrigin: "https://embed.example.com",
  clientFingerprintHash: "fp",
  sourceIpHash: "ip",
  userAgentHash: "ua",
  localeCode: "en-US",
  requestedExpirySeconds: 3600,
  ...over,
});

async function freshDid(): Promise<{ did: string; publicKey: Uint8Array; privateKey: Uint8Array }> {
  const kp = await generateKeyPair();
  return { did: deriveDid(kp.publicKey), publicKey: kp.publicKey, privateKey: kp.privateKey };
}

describe("M2 coverage — kernel runtime + error + diagnostic surface is present", () => {
  it("exposes every ported runtime export (module-level or as a server method)", () => {
    // Storeless module-level functions.
    for (const name of [
      "verifyHandshakeSignature",
      "issueGuestDid",
      "resolveDidPubkey",
      "revokeGuestDid",
      "writePdsRecord",
      "readPdsRecord",
      "sha256HexOfBase64",
      "sha256HexOfUtf8",
      "probeAvailability",
      "buildHandshakeChallenge",
      "createIdentityServer",
    ] as const) {
      expect(typeof (ident as Record<string, unknown>)[name]).toBe("function");
    }
    expect(Array.isArray(ident.SUPPORTED_ALGORITHMS)).toBe(true);

    // Store-backed operations are covered as instance methods.
    const server = createIdentityServer();
    for (const name of [
      "issueGuestDid",
      "issueHandshakeChallenge",
      "consumeHandshakeChallenge",
      "resolveDidPubkey",
      "revokeGuestDid",
      "writePdsRecord",
      "readPdsRecord",
    ] as const) {
      expect(typeof server[name]).toBe("function");
    }
  });

  it("exposes the four provider-neutral error classes with KS_IDENTITY_* codes", () => {
    expect(new KashscriptIdentityNotImplementedError("m").code).toBe("KS_IDENTITY_NOT_IMPLEMENTED");
    expect(new KashscriptIdentityMalformedDidError("x").code).toBe("KS_IDENTITY_MALFORMED_DID");
    expect(new KashscriptIdentityMalformedPayloadError("f").code).toBe("KS_IDENTITY_MALFORMED_PAYLOAD");
    expect(new KashscriptIdentityUnsupportedAlgorithmError("rsa").code).toBe("KS_IDENTITY_UNSUPPORTED_ALGORITHM");
    // Provider-neutral: no DD_* leakage.
    expect(new KashscriptIdentityMalformedDidError("x").message).not.toContain("DD_");
  });

  it("SUPPORTED_ALGORITHMS is exactly [ed25519, ecdsa-p256]", () => {
    expect([...SUPPORTED_ALGORITHMS]).toEqual(["ed25519", "ecdsa-p256"]);
  });

  it("probeAvailability reports the surface is implemented (available: true)", () => {
    const probe = ident.probeAvailability();
    expect(probe.available).toBe(true);
    expect(probe.reason).toBe("READY");
    expect(probe.cryptoBackend).toBe("WEB_CRYPTO");
    expect(probe.version).toBe(ident.IDENTITY_SERVER_VERSION);
  });
});

describe("M2 coverage — guest-DID issuance (custodial-at-mint, non-persisting)", () => {
  it("mints a self-certifying did:kash whose pubkey round-trips", async () => {
    const result = await issueGuestDid(guestReq());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { issuance } = result;
    expect(issuance.did.startsWith("did:kash:")).toBe(true);
    expect(issuance.pubkey.isGuestDid).toBe(true);
    expect(issuance.pubkey.algorithm).toBe("ed25519");
    // The DID is derived from the returned public key.
    expect(issuance.did).toBe(deriveDid(base64ToBytes(issuance.pubkey.publicKeyB64)));
    // The one-time private key is a 32-byte Ed25519 seed.
    expect(base64ToBytes(issuance.privateKeyB64).length).toBe(32);
  });

  it("caps expiry at the seven-day guest maximum", async () => {
    const result = await issueGuestDid(guestReq({ requestedExpirySeconds: 999_999_999 }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const window = result.issuance.expiresAtUnix - result.issuance.pubkey.issuedAtUnix;
    expect(window).toBe(7 * 24 * 60 * 60);
  });

  it("rejects a malformed issuance request", async () => {
    await expect(issueGuestDid(guestReq({ requestedExpirySeconds: 0 }))).rejects.toBeInstanceOf(
      KashscriptIdentityMalformedPayloadError,
    );
  });
});

describe("M2 coverage — handshake issue → consume (one-time) → verify", () => {
  it("verifies a genuine signature, and rejects replay + spoof + expiry", async () => {
    const server = createIdentityServer();
    const { did, publicKey, privateKey } = await freshDid();

    const challenge = await server.issueHandshakeChallenge(did);
    expect(challenge.challengeId.startsWith("chal_")).toBe(true);
    expect(challenge.did).toBe(did);

    // One-time consume: first returns the challenge, second returns null.
    const consumed = await server.consumeHandshakeChallenge(challenge.challengeId);
    expect(consumed?.challengeId).toBe(challenge.challengeId);
    expect(await server.consumeHandshakeChallenge(challenge.challengeId)).toBeNull();

    // Sign the raw payload bytes (handshake is DST-free).
    const payloadBytes = base64ToBytes(challenge.payloadB64);
    const signatureB64 = bytesToBase64(await signRaw(payloadBytes, privateKey, publicKey));
    const publicKeyB64 = bytesToBase64(publicKey);

    const good = await verifyHandshakeSignature({ challenge, signatureB64, algorithm: "ed25519", publicKeyB64 });
    expect(good.ok).toBe(true);
    expect(good.reason).toBeNull();

    // Spoof: mutate the signature → SPOOFED_SIGNATURE.
    const flipped = signatureB64.slice(0, -2) + (signatureB64.endsWith("A") ? "BB" : "AA");
    const spoof = await verifyHandshakeSignature({ challenge, signatureB64: flipped, algorithm: "ed25519", publicKeyB64 });
    expect(spoof.ok).toBe(false);
    expect(spoof.reason).toBe("SPOOFED_SIGNATURE");

    // Expired challenge → EXPIRED_CHALLENGE.
    const expired = { ...challenge, expiresAtUnix: challenge.issuedAtUnix - 1 };
    const stale = await verifyHandshakeSignature({ challenge: expired, signatureB64, algorithm: "ed25519", publicKeyB64 });
    expect(stale.ok).toBe(false);
    expect(stale.reason).toBe("EXPIRED_CHALLENGE");
  });

  it("reports PUBKEY_ALGORITHM_UNSUPPORTED for an unknown algorithm", async () => {
    const server = createIdentityServer();
    const { did, publicKey } = await freshDid();
    const challenge = await server.issueHandshakeChallenge(did);
    const res = await verifyHandshakeSignature({
      challenge,
      signatureB64: bytesToBase64(new Uint8Array(64)),
      // deliberately unsupported
      algorithm: "rsa-2048" as unknown as "ed25519",
      publicKeyB64: bytesToBase64(publicKey),
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("PUBKEY_ALGORITHM_UNSUPPORTED");
  });
});

describe("M2 coverage — DID resolution + guest revocation", () => {
  it("resolves an issued guest DID, then reports REVOKED after revocation", async () => {
    const server = createIdentityServer();
    const issued = await server.issueGuestDid(guestReq());
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const did = issued.issuance.did;

    const resolved = await server.resolveDidPubkey(did);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) {
      expect(resolved.pubkey.isGuestDid).toBe(true);
      expect(resolved.pubkey.publicKeyB64).toBe(issued.issuance.pubkey.publicKeyB64);
    }

    const revoked = await server.revokeGuestDid(did);
    expect(revoked.ok).toBe(true);

    const afterRevoke = await server.resolveDidPubkey(did);
    expect(afterRevoke.ok).toBe(false);
    if (!afterRevoke.ok) expect(afterRevoke.reason).toBe("REVOKED");
  });

  it("reports NOT_FOUND for an unregistered (but well-formed) DID", async () => {
    const server = createIdentityServer();
    const { did } = await freshDid();
    const res = await server.resolveDidPubkey(did);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("NOT_FOUND");
  });

  it("reports NOT_A_GUEST_DID when revoking a permanent DID", async () => {
    const metadataStore = new InMemoryIdentityMetadataStore();
    const server = createIdentityServer({ metadataStore });
    const { did } = await freshDid();
    await metadataStore.put({
      did,
      isGuestDid: false,
      issuedAtUnix: 1,
      expiresAtUnix: null,
      pdsEndpoint: null,
      revokedAtUnix: null,
    });
    const res = await server.revokeGuestDid(did);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("NOT_A_GUEST_DID");
  });

  it("throws KashscriptIdentityMalformedDidError on a syntactically invalid DID", async () => {
    const server = createIdentityServer();
    await expect(server.resolveDidPubkey("totally-invalid")).rejects.toBeInstanceOf(
      KashscriptIdentityMalformedDidError,
    );
    // The store-taking function form throws too.
    await expect(resolveDidPubkey(new InMemoryIdentityMetadataStore(), "did:kash:0OIl")).rejects.toBeInstanceOf(
      KashscriptIdentityMalformedDidError,
    );
  });
});

describe("M2 coverage — PDS contract (write / read / revision / provisioning)", () => {
  const record = (over: Partial<PdsRecord> = {}): PdsRecord => ({
    collection: "audit.v1",
    recordKey: "rk-1",
    contentJson: JSON.stringify({ hello: "world" }),
    schemaVersion: 1,
    expectedRevision: null,
    ...over,
  });

  it("rejects a write to an unprovisioned PDS", async () => {
    const server = createIdentityServer();
    const { did } = await freshDid();
    const res = await server.writePdsRecord(did, record());
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("PDS_UNPROVISIONED");
  });

  it("writes then reads a record, and enforces optimistic revisions", async () => {
    const pdsStore = new InMemoryPdsStore();
    const server = createIdentityServer({ pdsStore });
    const { did } = await freshDid();
    pdsStore.provision(did);

    const w1 = await server.writePdsRecord(did, record());
    expect(w1.ok).toBe(true);
    if (!w1.ok) return;
    expect(w1.revision).toBe(1);
    expect(w1.cid.startsWith("cid_sha256_")).toBe(true);

    const r1 = await server.readPdsRecord(did, "audit.v1", "rk-1");
    expect(r1.ok).toBe(true);
    if (r1.ok) expect(r1.revision).toBe(1);

    // Correct expectedRevision advances the record.
    const w2 = await server.writePdsRecord(did, record({ expectedRevision: 1, contentJson: "{\"v\":2}" }));
    expect(w2.ok).toBe(true);
    if (w2.ok) expect(w2.revision).toBe(2);

    // Stale expectedRevision → REVISION_CONFLICT.
    const w3 = await server.writePdsRecord(did, record({ expectedRevision: 0 }));
    expect(w3.ok).toBe(false);
    if (!w3.ok) expect(w3.reason).toBe("REVISION_CONFLICT");
  });
});

describe("M2 coverage — hashing helpers", () => {
  const SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  it("sha256HexOfUtf8 matches the known digest of \"abc\"", async () => {
    expect(await sha256HexOfUtf8("abc")).toBe(SHA256_ABC);
  });

  it("sha256HexOfBase64 hashes the decoded bytes (base64(\"abc\") = \"YWJj\")", async () => {
    expect(await sha256HexOfBase64("YWJj")).toBe(SHA256_ABC);
  });

  it("rejects a non-base64 input", async () => {
    await expect(sha256HexOfBase64("not base64!!")).rejects.toBeInstanceOf(KashscriptIdentityMalformedPayloadError);
  });
});
