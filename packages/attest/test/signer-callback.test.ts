/**
 * GP-6 (8) — an Ed25519 key that never leaves where it lives signs through a
 * callback, as PL-2's ES256 hardware key already could. Every signature attest
 * makes in DSSE and JWS goes through one seam (`signBytes`), so DSSE
 * envelopes, trust lists, session lines and their cosignatures, compact JWS
 * and SD-JWT all take it. The recipes Indorania's `platform/signing` builds by
 * hand because the signers took seeds are reproduced here, and attest's own
 * functions, given the same key service, produce them byte for byte.
 */

import { describe, expect, it } from "bun:test";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { canonicalizeBytes, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { pae, signEnvelope, verifyEnvelope } from "../src/dsse";
import { AttestError } from "../src/errors";
import { TRUST_LIST_FORMAT, makeKeyResolver, signTrustList, verifyTrustList } from "../src/holder";
import { decodeJws, signJws, verifyJws } from "../src/sd-jwt/jws";
import { issueSdJwt, verifySdJwt } from "../src/sd-jwt/sd-jwt";
import { type ExternalEd25519Signer } from "../src/signing";
import {
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  cosignSessionEvent,
  sessionEventSha256,
  sessionGenesisSha256,
  signSessionEvent,
  verifySessionReceipt,
  type SessionEventPayload,
} from "../src/exchange";

const T = 1_790_294_400;
const enc = new TextEncoder();
const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

/** A key nobody can read: made non-extractable inside Web Crypto, and used only through `sign`. */
async function heldElsewhere(): Promise<{ signer: ExternalEd25519Signer; did: string; privateKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    signer: { alg: "Ed25519", publicKey, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, m as unknown as BufferSource)) },
    did: deriveDid(publicKey),
    privateKey: pair.privateKey,
  };
}

/** Indorania's local key service, as `platform/signing` has it: a seed behind a reference, signing bytes on request. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function keyServiceOf(seed: Uint8Array): { sign(bytes: Uint8Array): Promise<Uint8Array> } {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  return { sign: async (bytes) => new Uint8Array(nodeSign(null, Buffer.from(bytes), key)) };
}

/** The three recipes `platform/signing` reproduces by hand, transcribed (Indorania was read, not changed). */
const platform = {
  async signDsse(ks: ReturnType<typeof keyServiceOf>, did: string, payloadType: string, payload: unknown) {
    const bytes = canonicalizeBytes(payload);
    return { payloadType, payload: b64(bytes), signatures: [{ keyid: did, sig: b64(await ks.sign(pae(payloadType, bytes))) }] };
  },
  async signJwsVia(ks: ReturnType<typeof keyServiceOf>, header: Record<string, unknown>, payload: Record<string, unknown>) {
    const json = (v: unknown) => b64u(enc.encode(JSON.stringify(v)));
    const h = json({ ...header, alg: "EdDSA" });
    const p = json(payload);
    return `${h}.${p}.${b64u(await ks.sign(enc.encode(`${h}.${p}`)))}`;
  },
  async issueSdJwtVia(ks: ReturnType<typeof keyServiceOf>, header: Record<string, unknown>, claims: Record<string, unknown>) {
    return `${await platform.signJwsVia(ks, { ...header, typ: "dc+sd-jwt" }, claims)}~`;
  },
};

describe("an Ed25519 signer that never hands over its key (GP-6)", () => {
  it("a non-extractable Web Crypto key signs a DSSE envelope and a trust list; attest verifies both", async () => {
    const k = await heldElsewhere();
    await expect(crypto.subtle.exportKey("pkcs8", k.privateKey)).rejects.toThrow();
    expect(Object.keys(k.signer).sort()).toEqual(["alg", "publicKey", "sign"]);

    const env = await signEnvelope({ hello: "world" }, "application/vnd.kash.trust-list+json", { keyid: k.did, ...k.signer }, { canonical: true });
    const v = await verifyEnvelope(env, (kid) => (kid === k.did ? k.signer.publicKey : null));
    expect(v.ok).toBe(true);
    expect(v.verifiedKeyids).toEqual([k.did]);

    const list = await signTrustList(
      { format: TRUST_LIST_FORMAT, listId: "kash-callback-demo", version: 1, publisher: k.did, issuedAtUnix: T, validFromUnix: T, validUntilUnix: T + 86_400, issuers: [] },
      { keyid: k.did, ...k.signer },
    );
    const r = await verifyTrustList(list, { pinnedPublishers: [k.did], nowSec: T + 60 });
    expect(r.reason).toBeNull();
    expect(r.ok).toBe(true);
  });

  it("both parties of a session sign and countersign through callbacks; the receipt is proof", async () => {
    const est = await heldElsewhere();
    const per = await heldElsewhere();
    const sessionId = "ses_callback_demo";
    const lines: Pick<SessionEventPayload, "kind" | "by" | "body">[] = [
      { kind: "open", by: "establishment", body: { profile: "presence+flow", parties: { establishment: est.did, person: per.did }, consent: { records: ["presence", "flow"], asks: [] }, place: null } },
      { kind: "close", by: "establishment", body: { total: { amount: "0.00", currency: "PKR" }, lineItemCount: 0, expiresAtUnix: T + 86_400 } },
    ];
    const events = [];
    let prev = await sessionGenesisSha256(sessionId);
    for (const [seq, l] of lines.entries()) {
      const signed = await signSessionEvent({ spec: SESSION_EVENT_SPEC, sessionId, seq, prevSha256: prev, atUnix: T + seq, ...l }, { keyid: est.did, ...est.signer });
      events.push(await cosignSessionEvent(signed, { keyid: per.did, ...per.signer }));
      prev = await sessionEventSha256(events[seq]!);
    }
    const r = await verifySessionReceipt({ formatVersion: SESSION_RECEIPT_FORMAT, sessionId, profile: "presence+flow", parties: { establishment: est.did, person: per.did }, events, anchor: null }, { nowSec: T });
    expect(r.faults).toEqual([]);
    expect(r.proof).toBe(true);
  });

  it("a compact JWS and a disclosure-free SD-JWT, signed through a callback, verify", async () => {
    const k = await heldElsewhere();
    const jws = await signJws({ kid: k.did }, { iss: k.did, iat: T }, k.signer);
    expect(await verifyJws(decodeJws(jws)!, k.signer.publicKey)).toBe(true);
    const held = await issueSdJwt({ header: { kid: k.did }, claims: { iss: k.did, iat: T }, signer: k.signer });
    expect(held.endsWith("~")).toBe(true);
    const r = await verifySdJwt(held, { resolveKey: makeKeyResolver(new Map(), new Map()), requireKeyBinding: false, nowSec: T });
    expect(r.reason).toBeNull();
    expect(r.issuer).toBe(k.did);
  });

  it("given the platform's key service, attest makes exactly the bytes platform/signing builds by hand — and the seed signer's", async () => {
    const pair = await generateKeyPair();
    const did = deriveDid(pair.publicKey);
    const ks = keyServiceOf(pair.privateKey);
    const viaService: ExternalEd25519Signer = { alg: "Ed25519", publicKey: pair.publicKey, sign: (m) => ks.sign(m) };
    const seed = { privateKey: pair.privateKey, publicKey: pair.publicKey };
    const TYPE = "application/vnd.kash.trust-list+json";
    const payload = { listId: "x", version: 2, issuers: [{ b: 1, a: [2, 3] }] };

    const dsse = JSON.stringify(await signEnvelope(payload, TYPE, { keyid: did, ...viaService }, { canonical: true }));
    expect(dsse).toBe(JSON.stringify(await platform.signDsse(ks, did, TYPE, payload)));
    expect(dsse).toBe(JSON.stringify(await signEnvelope(payload, TYPE, { keyid: did, ...seed }, { canonical: true })));

    const header = { kid: `${did}#standing` };
    const claims = { iss: did, iat: T, sub: "did:kash:holder-demo" };
    const jws = await signJws(header, claims, viaService);
    expect(jws).toBe(await platform.signJwsVia(ks, header, claims));
    expect(jws).toBe(await signJws(header, claims, seed));

    const sd = await issueSdJwt({ header, claims, signer: viaService });
    expect(sd).toBe(await platform.issueSdJwtVia(ks, header, claims));
    expect(sd).toBe(await issueSdJwt({ header, claims, signer: seed }));
  });

  it("a key service that answers with another key, a short signature, or an error is refused before anything is made", async () => {
    const k = await heldElsewhere();
    const other = await heldElsewhere();
    const wrongKey: ExternalEd25519Signer = { alg: "Ed25519", publicKey: k.signer.publicKey, sign: other.signer.sign };
    await expect(signEnvelope({ a: 1 }, "application/vnd.kash.trust-list+json", { keyid: k.did, ...wrongKey })).rejects.toThrow(AttestError);
    await expect(signJws({}, { iss: k.did }, wrongKey)).rejects.toThrow("does not verify under its public key");
    const short: ExternalEd25519Signer = { ...k.signer, sign: async (m) => (await k.signer.sign(m)).slice(0, 63) };
    await expect(signJws({}, { iss: k.did }, short)).rejects.toThrow(AttestError);
    const failing: ExternalEd25519Signer = { ...k.signer, sign: async () => { throw new Error("key service unreachable"); } };
    await expect(signJws({}, { iss: k.did }, failing)).rejects.toThrow("key service unreachable");
  });

  it("a malformed public key is said to be one, not reported as a signature that does not verify", async () => {
    const k = await heldElsewhere();
    for (const publicKey of [k.signer.publicKey.slice(0, 31), new Uint8Array(33), new Uint8Array(0)]) {
      const bad: ExternalEd25519Signer = { ...k.signer, publicKey };
      let thrown: unknown;
      try {
        await signJws({}, { iss: k.did }, bad);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(AttestError);
      expect((thrown as AttestError).code).toBe("INVALID_INPUT");
    }
  });
});
