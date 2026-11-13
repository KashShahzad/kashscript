/**
 * KS-U1 — a DSSE envelope signed by a phone's P-256 key is checked under the key
 * its `keyid` declares. attest's `verifyEnvelope` already judges a signature by
 * its key's algorithm; what a host must do is hand it a *typed* key. A resolver
 * that returns a bare 32-byte key can only ever verify Ed25519 — the gap
 * Oreoasis's receipt ingest has (FT-2's uplift note), pinned below so the fix
 * stays "return the typed key".
 */

import { describe, expect, it } from "bun:test";
import {
  P256_ORDER,
  deriveDid,
  deriveDidP256,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  encodeBase58,
  generateKeyPair,
  generateP256KeyPair,
} from "@kashscript/identity-core";
import { signEnvelope, verifyEnvelope, type DsseEnvelope } from "../src/dsse";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import { resolveDidKey, resolveVerificationKey, type RawSigner } from "../src/signing";

const WORK_RECORD = "application/vnd.oreoasis.work-record+json";
const record = { spec: "work-record/1", what: "a paid invoice's job", at: 1_760_000_000 };

const didKeyP256 = (pub: Uint8Array): string => `did:key:z${deriveDidP256(pub).slice("did:kash:".length)}`;
const didKeyEd25519 = (pub: Uint8Array): string => `did:key:z${encodeBase58(Uint8Array.of(0xed, 0x01, ...pub))}`;

async function p256() {
  const pair = await generateP256KeyPair();
  return { pair, did: deriveDidP256(pair.publicKey) as string };
}

describe("resolveVerificationKey", () => {
  it("resolves a did:kash of either type, with or without a fragment", async () => {
    const { pair, did } = await p256();
    const ed = await generateKeyPair();
    expect(resolveVerificationKey(did)?.type).toBe("P-256");
    expect(resolveVerificationKey(`${did}#key-1`)?.type).toBe("P-256");
    expect(resolveVerificationKey(deriveDid(ed.publicKey))).toEqual({ type: "Ed25519", publicKey: ed.publicKey });
    expect(resolveVerificationKey(did)?.publicKey).toEqual(resolveDidKey(did)!.publicKey);
    expect(pair.publicKey.length).toBe(33);
  });

  it("resolves a did:key of either type to the same key its did:kash names", async () => {
    const { pair, did } = await p256();
    const ed = await generateKeyPair();
    const k = didKeyP256(pair.publicKey);
    expect(resolveVerificationKey(k)).toEqual(resolveDidKey(did));
    expect(resolveVerificationKey(`${k}#${k.slice("did:key:".length)}`)).toEqual(resolveDidKey(did));
    expect(resolveVerificationKey(didKeyEd25519(ed.publicKey))).toEqual({ type: "Ed25519", publicKey: ed.publicKey });
  });

  it("is null for anything else, and never throws", async () => {
    const { pair } = await p256();
    const wrongCodec = `did:key:z${encodeBase58(Uint8Array.of(0xe7, 0x01, ...pair.publicKey))}`; // secp256k1
    const truncated = didKeyP256(pair.publicKey).slice(0, -4);
    const offCurve = `did:key:z${encodeBase58(Uint8Array.of(0x80, 0x24, 0x02, ...new Uint8Array(32).fill(0xff)))}`;
    for (const bad of ["did:web:example.com", "did:key:z0OIl", "did:key:z", "did:kash:", "not a did", wrongCodec, truncated, offCurve, "", "#"]) {
      expect(resolveVerificationKey(bad)).toBeNull();
    }
    expect(resolveVerificationKey(undefined as unknown as string)).toBeNull();
  });

  it("leaves resolveDidKey did:kash-only", async () => {
    const { pair } = await p256();
    expect(resolveDidKey(didKeyP256(pair.publicKey))).toBeNull();
  });
});

describe("a P-256 DSSE work record verifies through attest's own seam", () => {
  it("software P-256 signer: under its did:kash and its did:key", async () => {
    const { pair, did } = await p256();
    const asDidKey = didKeyP256(pair.publicKey);
    for (const keyid of [did, asDidKey]) {
      const env = await signEnvelope(record, WORK_RECORD, { alg: "ES256", keyid, privateKey: pair.privateKey, publicKey: pair.publicKey });
      expect(base64ToBytes(env.signatures[0]!.sig)[0]).toBe(0x30); // DER, as DSSE tooling expects
      const r = await verifyEnvelope(env, resolveVerificationKey);
      expect(r.ok).toBe(true);
      expect(r.verifiedKeyids).toEqual([keyid]);
      expect(r.payloadJson).toEqual(record);
    }
  });

  it("a hardware-style signer (a callback; the key never in hand), returning DER", async () => {
    const { pair, did } = await p256();
    const { signP256 } = await import("@kashscript/identity-core");
    const chip: RawSigner = {
      alg: "ES256",
      publicKey: pair.publicKey,
      sign: async (m) => ({ signature: ecdsaRawToDer(await signP256(m, pair.privateKey, pair.publicKey)), format: "der" }),
    };
    const env = await signEnvelope(record, WORK_RECORD, { ...chip, keyid: did });
    expect((await verifyEnvelope(env, resolveVerificationKey)).ok).toBe(true);
  });

  it("an Ed25519 did:key signer verifies too, so the one resolver serves both", async () => {
    const ed = await generateKeyPair();
    const keyid = didKeyEd25519(ed.publicKey);
    const env = await signEnvelope(record, WORK_RECORD, { keyid, privateKey: ed.privateKey, publicKey: ed.publicKey });
    expect((await verifyEnvelope(env, resolveVerificationKey)).ok).toBe(true);
  });

  it("a tampered payload, and a signature relabelled under the other type's DID, do not verify", async () => {
    const { pair, did } = await p256();
    const ed = await generateKeyPair();
    const env = await signEnvelope(record, WORK_RECORD, { alg: "ES256", keyid: did, privateKey: pair.privateKey, publicKey: pair.publicKey });
    const tampered: DsseEnvelope = { ...env, payload: bytesToBase64(new TextEncoder().encode(JSON.stringify({ ...record, what: "another job" }))) };
    expect((await verifyEnvelope(tampered, resolveVerificationKey)).ok).toBe(false);
    const relabelled: DsseEnvelope = { ...env, signatures: [{ keyid: didKeyEd25519(ed.publicKey), sig: env.signatures[0]!.sig }] };
    expect((await verifyEnvelope(relabelled, resolveVerificationKey)).ok).toBe(false);
  });

  it("a high-S twin and a non-minimal DER signature are still refused through this resolver", async () => {
    const { pair, did } = await p256();
    const env = await signEnvelope(record, WORK_RECORD, { alg: "ES256", keyid: did, privateKey: pair.privateKey, publicKey: pair.publicKey });
    const raw = ecdsaDerToRaw(base64ToBytes(env.signatures[0]!.sig));
    let s = 0n;
    for (const b of raw.subarray(32)) s = (s << 8n) | BigInt(b);
    let high = P256_ORDER - s;
    const twin = new Uint8Array(64);
    twin.set(raw.subarray(0, 32), 0);
    for (let i = 63; i >= 32; i--) {
      twin[i] = Number(high & 0xffn);
      high >>= 8n;
    }
    const highS: DsseEnvelope = { ...env, signatures: [{ keyid: did, sig: bytesToBase64(ecdsaRawToDer(twin)) }] };
    expect((await verifyEnvelope(highS, resolveVerificationKey)).ok).toBe(false);

    // A well-formed DER sequence whose `r` INTEGER carries one redundant leading 0x00 — valid BER-ish, not minimal.
    const der = base64ToBytes(env.signatures[0]!.sig);
    const rLen = der[3]!;
    const r = der.subarray(4, 4 + rLen);
    const sPart = der.subarray(4 + rLen); // 02 sl s…
    const body = Uint8Array.of(0x02, rLen + 1, 0x00, ...r, ...sPart);
    const nonMinimal: DsseEnvelope = { ...env, signatures: [{ keyid: did, sig: bytesToBase64(Uint8Array.of(0x30, body.length, ...body)) }] };
    // Sanity: the unpadded original does verify, so only the padding can be the reason.
    expect((await verifyEnvelope(env, resolveVerificationKey)).ok).toBe(true);
    expect((await verifyEnvelope(nonMinimal, resolveVerificationKey)).ok).toBe(false);
  });
});

describe("the Oreoasis gap, pinned", () => {
  it("a resolver that returns a bare 32-byte key never verifies an ES256 envelope — return the typed key", async () => {
    const { pair, did } = await p256();
    const env = await signEnvelope(record, WORK_RECORD, { alg: "ES256", keyid: did, privateKey: pair.privateKey, publicKey: pair.publicKey });
    // Oreoasis today: `hexToBytes(agentKeyHex)` — bare bytes are Ed25519 by definition.
    const bare = await verifyEnvelope(env, () => new Uint8Array(32).fill(7));
    expect(bare.ok).toBe(false);
    // The same envelope, the typed key: verifies.
    const typed = await verifyEnvelope(env, (kid) => (kid === did ? resolveDidKey(kid) : null));
    expect(typed.ok).toBe(true);
  });
});
