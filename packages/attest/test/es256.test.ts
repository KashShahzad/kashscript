/**
 * ES256 beside Ed25519 (PL-2, ADR-0020): every family attest signs, with the
 * algorithm taken from the key — never from the envelope, the header, or the
 * signature's own `alg`. Covers the committed vectors (test/vectors/es256),
 * algorithm confusion both ways, high-S in every encoding, and a runtime with
 * no Ed25519 ("not checked here", never "invalid").
 */

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  decodeHex,
  deriveDid,
  deriveDidP256,
  ecdsaDerToRaw,
  generateKeyPair,
  generateP256KeyPair,
  parseDidKey,
  verifyEvent,
  verifyEventForKey,
  type SignedKashEvent,
} from "@kashscript/identity-core";
import { base64ToBytes } from "../src/ed25519";
import { pae, signEnvelope, verifyEnvelope, type DsseEnvelope } from "../src/dsse";
import { verifyCountersignBundle, type CountersignBundle } from "../src/countersign";
import { decodeJws, didOfJwk, jwkOf, keyOfJwk, signJws, verifyJws } from "../src/sd-jwt/jws";
import { verifySdJwt } from "../src/sd-jwt/sd-jwt";
import { makeKeyResolver, verifyHolderExport, verifyStatusList, verifyTrustList, typedKeyOf } from "../src/holder";
import { verifyPredicatePresentation } from "../src/exchange/predicate";
import {
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  cosignSessionEvent,
  sessionGenesisSha256,
  signSessionEvent,
  verifySessionReceipt,
  type SessionEventPayload,
} from "../src/exchange/session";
import { signBytes, verifyBytes } from "../src/signing";
import { verifyKeyClaim, verifySuccessionSet, type HelperKeyClaim, type KeyClaim } from "../src/succession";

const V = join(import.meta.dir, "vectors", "es256");
const json = <T = any>(name: string): T => JSON.parse(readFileSync(join(V, name), "utf8")) as T;
const txt = (name: string): string => readFileSync(join(V, name), "utf8");
const ctx = json<{ nowSec: number; audience: string; nonce: string; trustPublisher: string; holder: string; issuer: string }>("context.v1.json");
const noKeys = makeKeyResolver(new Map(), new Map());
const enc = new TextEncoder();

/** Run `body` with WebCrypto refusing Ed25519, as an older browser does. */
async function withoutEd25519<T>(body: () => Promise<T>): Promise<T> {
  const subtle = crypto.subtle;
  const original = subtle.importKey.bind(subtle);
  (subtle as { importKey: unknown }).importKey = (format: KeyFormat, key: unknown, alg: AlgorithmIdentifier, ...rest: unknown[]) => {
    const name = typeof alg === "string" ? alg : (alg as { name: string }).name;
    if (name === "Ed25519") return Promise.reject(new DOMException("Unrecognized algorithm name", "NotSupportedError"));
    return (original as (...a: unknown[]) => Promise<CryptoKey>)(format, key, alg, ...rest);
  };
  try {
    return await body();
  } finally {
    (subtle as { importKey: unknown }).importKey = original;
  }
}

/* ── the committed vectors ─────────────────────────────────────────────── */

describe("ES256 vectors — committed once, verified offline", () => {
  it("the P-256 did:kash vector: RFC 6979's key, its identifier and its document", () => {
    const v = json("did-p256.v1.json");
    expect(v.did.startsWith("did:kash:Dn")).toBe(true);
    expect(deriveDidP256(decodeHex(v.publicKeyCompressedHex))).toBe(v.did);
    expect(v.didDocument.verificationMethod[0].publicKeyMultibase.startsWith("zDn")).toBe(true);
  });

  it("the ES256 Kash-Event verifies under the key its iss declares", async () => {
    const ev = json<SignedKashEvent>("kash-event-es256.v1.json");
    expect(ev.signature.alg).toBe("es256");
    expect(await verifyEventForKey(ev, parseDidKey(ev.header.iss as string))).toBe(true);
  });

  it("the ES256 trust list and status list verify (strict DER, P-256 signers)", async () => {
    const tl = await verifyTrustList(json("trust-list-es256.v1.json"), { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec });
    expect(tl.ok).toBe(true);
    expect(tl.pinned).toBe(true);
    const sl = await verifyStatusList(json("status-list-es256.v1.json"), { resolveKey: noKeys, nowSec: ctx.nowSec, source: "carried" });
    expect(sl.ok).toBe(true);
  });

  it("the ES256 predicate presentation verifies, holder-bound by an ES256 KB-JWT to a P-256 key", async () => {
    const r = await verifyPredicatePresentation(txt("predicate-presentation-es256.v1.txt"), {
      resolveKey: noKeys,
      audience: ctx.audience,
      nonce: ctx.nonce,
      nowSec: ctx.nowSec,
    } as never);
    expect(r.ok).toBe(true);
    expect(r.holder).toBe(ctx.holder);
    const parts = txt("predicate-presentation-es256.v1.txt").split("~");
    expect(decodeJws(parts.at(-1)!)!.header.alg).toBe("ES256");
    expect(decodeJws(parts[0]!)!.header.alg).toBe("ES256");
  });

  it("the countersign vector: a P-256 countersigner, and key claims Ed25519 → P-256 and P-256 → Ed25519", async () => {
    const r = await verifyCountersignBundle(json<CountersignBundle>("countersign-es256.v1.json"));
    expect(r.ok).toBe(true);
    expect(r.twoSignatureProof).toBe(true);
    expect(r.keyClaims.map((c) => `${c.priorKeyType}→${c.successorKeyType}`)).toEqual(["Ed25519→P-256", "P-256→Ed25519"]);
    expect(r.keyClaims.every((c) => c.path === "prior-key" && c.ok)).toBe(true);
  });

  it("the helper-quorum vector: two of three helpers and the new P-256 key succeed a lost Ed25519 key", async () => {
    const v = json<{ claim: HelperKeyClaim; helpers: string[] }>("succession-helpers.v1.json");
    const r = await verifyKeyClaim(v.claim);
    expect(r.ok).toBe(true);
    expect(r.path).toBe("helpers");
    expect(r.priorSignatureOk).toBe(false);
    expect(r.helpers).toMatchObject({ need: 2, of: 3, counted: 2 });
    expect(`${r.priorKeyType}→${r.successorKeyType}`).toBe("Ed25519→P-256");
  });

  it("the ES256 holder export verifies offline, with both kinds of claim and the new key's helper set", async () => {
    const text = txt("holder-export-es256.v1.json");
    const r = await verifyHolderExport(JSON.parse(text), { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec, rawText: text });
    expect(r.reasons).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(true);
    expect(r.network).toBe("none");
    expect(r.keySuccession.map((c) => c.path)).toEqual(["helpers", "prior-key"]);
    expect(r.recoveryHelpers.length).toBe(1);
    expect(r.recoveryHelpers[0]!.ok).toBe(true);
    expect(r.records.every((rec) => rec.signatureOk)).toBe(true);
  });

  it("the PL-1 export vector still verifies, untouched, and carries no v1.3 field", async () => {
    const text = readFileSync(join(import.meta.dir, "vectors", "holder", "holder-export.v1.json"), "utf8");
    const value = JSON.parse(text);
    expect("recoveryHelpers" in value).toBe(false);
    const r = await verifyHolderExport(value, { nowSec: 1_790_208_000, rawText: text });
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(true);
  });
});

describe("negative vectors — each fails, for its own reason", () => {
  const neg = json("negative.v1.json");

  it("a high-S Kash-Event does not verify", async () => {
    expect(await verifyEvent(neg.kashEventHighS.event, decodeHex(neg.kashEventHighS.publicKeyCompressedHex))).toBe(false);
  });

  it("a high-S DSSE signature, and a non-minimal DER one, do not verify", async () => {
    for (const k of ["dsseHighS", "dsseNonMinimalDer"]) {
      const r = await verifyTrustList(neg[k].envelope, { pinnedPublishers: [neg[k].publisher], nowSec: ctx.nowSec });
      expect(r.reason).toBe("TRUST_LIST_SIGNATURE_INVALID");
    }
  });

  it("a high-S KB-JWT does not bind", async () => {
    const r = await verifySdJwt(neg.kbJwtHighS.presentation, { resolveKey: noKeys, requireKeyBinding: true, audience: ctx.audience, nonce: ctx.nonce, nowSec: ctx.nowSec });
    expect(r.reason).toBe("KEY_BINDING_INVALID");
  });

  it("an Ed25519 signature under a P-256 did:kash, and an ES256 signature under an Ed25519 one, never verify", async () => {
    const a = await verifyTrustList(neg.ed25519SignatureUnderP256Did.envelope, { pinnedPublishers: [neg.ed25519SignatureUnderP256Did.publisher], nowSec: ctx.nowSec });
    expect(a.reason).toBe("TRUST_LIST_SIGNATURE_INVALID");
    const b = await verifyEnvelope(neg.es256SignatureUnderEd25519Did.envelope, (kid) => parseDidKey(kid));
    expect(b.ok).toBe(false);
  });

  it("one helper of three is below the quorum; a set its key did not sign is no set; two successors are a fork", async () => {
    expect((await verifyKeyClaim(neg.belowQuorum.claim)).reason).toBe("BELOW_QUORUM");
    expect((await verifyKeyClaim(neg.helperSetNotSignedByPrior.claim)).reason).toBe("HELPER_SET_INVALID");
    const fork = await verifySuccessionSet(neg.fork.claims as KeyClaim[]);
    expect(fork.claims.every((c) => c.ok)).toBe(true); // each verifies on its own…
    expect(fork.ok).toBe(false); // …but together neither is trusted
    expect(fork.conflicts.length).toBe(1);
    expect(fork.conflicts[0]!.signedBoth).toContain(neg.fork.h3);
  });
});

/* ── the algorithm comes from the key ──────────────────────────────────── */

describe("algorithm confusion — an ES256 signature never verifies under an Ed25519 key, nor the reverse", () => {
  it("raw bytes: both 64 bytes long, and still never confused", async () => {
    const p = await generateP256KeyPair();
    const e = await generateKeyPair();
    const msg = enc.encode("same message");
    const es = await signBytes({ alg: "ES256", privateKey: p.privateKey, publicKey: p.publicKey }, msg, "raw");
    const ed = await signBytes({ privateKey: e.privateKey, publicKey: e.publicKey }, msg, "raw");
    expect(es.length).toBe(64);
    expect(ed.length).toBe(64);
    expect(await verifyBytes(es, msg, { type: "P-256", publicKey: p.publicKey }, "raw")).toBe(true);
    expect(await verifyBytes(ed, msg, e.publicKey, "raw")).toBe(true);
    expect(await verifyBytes(es, msg, e.publicKey, "raw")).toBe(false);
    expect(await verifyBytes(ed, msg, { type: "P-256", publicKey: p.publicKey }, "raw")).toBe(false);
  });

  it("DSSE: the keyid's did:kash decides; the same signature under the other type's DID fails", async () => {
    const p = await generateP256KeyPair();
    const e = await generateKeyPair();
    const pDid = deriveDidP256(p.publicKey);
    const eDid = deriveDid(e.publicKey);
    const env = await signEnvelope({ x: 1 }, "application/vnd.example.delivery+json", { alg: "ES256", keyid: pDid, privateKey: p.privateKey, publicKey: p.publicKey }, { canonical: true });
    const sigBytes = base64ToBytes(env.signatures[0]!.sig);
    expect(sigBytes[0]).toBe(0x30); // DER
    expect((await verifyEnvelope(env, (k) => parseDidKey(k))).ok).toBe(true);
    const relabelled: DsseEnvelope = { ...env, signatures: [{ keyid: eDid, sig: env.signatures[0]!.sig }] };
    expect((await verifyEnvelope(relabelled, (k) => parseDidKey(k))).ok).toBe(false);
    const edEnv = await signEnvelope({ x: 1 }, "application/vnd.example.delivery+json", { keyid: eDid, privateKey: e.privateKey, publicKey: e.publicKey }, { canonical: true });
    const asP: DsseEnvelope = { ...edEnv, signatures: [{ keyid: pDid, sig: edEnv.signatures[0]!.sig }] };
    expect((await verifyEnvelope(asP, (k) => parseDidKey(k))).ok).toBe(false);
  });

  it("JWS: a header naming the other algorithm is false, whatever the bytes", async () => {
    const p = await generateP256KeyPair();
    const e = await generateKeyPair();
    const esJws = decodeJws(await signJws({ typ: "x" }, { a: 1 }, { alg: "ES256", privateKey: p.privateKey, publicKey: p.publicKey }))!;
    const edJws = decodeJws(await signJws({ typ: "x" }, { a: 1 }, { privateKey: e.privateKey, publicKey: e.publicKey }))!;
    expect(esJws.header.alg).toBe("ES256");
    expect(edJws.header.alg).toBe("EdDSA");
    expect(await verifyJws(esJws, { type: "P-256", publicKey: p.publicKey })).toBe(true);
    expect(await verifyJws(edJws, e.publicKey)).toBe(true);
    expect(await verifyJws(esJws, e.publicKey)).toBe(false);
    expect(await verifyJws(edJws, { type: "P-256", publicKey: p.publicKey })).toBe(false);
    // a header lying about its algorithm, over a real signature
    expect(await verifyJws({ ...esJws, header: { ...esJws.header, alg: "EdDSA" } }, { type: "P-256", publicKey: p.publicKey })).toBe(false);
  });

  it("an SD-JWT whose header says EdDSA but whose issuer key is P-256 is refused, and the report says the key decides", async () => {
    const held = txt("predicate-held-es256.v1.txt");
    const [jwt, ...rest] = held.split("~");
    const [h, pl, s] = jwt!.split(".");
    const lying = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(h!, "base64url").toString()), alg: "EdDSA" })).toString("base64url");
    const r = await verifySdJwt([`${lying}.${pl}.${s}`, ...rest].join("~"), { resolveKey: noKeys, requireKeyBinding: false, nowSec: ctx.nowSec });
    expect(r.reason).toBe("ISSUER_SIGNATURE_INVALID");
    expect(r.notes.join(" ")).toContain("the key decides");
  });

  it("JWKs: OKP is Ed25519 and EC is P-256; each names its own did:kash", async () => {
    const p = await generateP256KeyPair();
    const e = await generateKeyPair();
    expect(keyOfJwk(jwkOf({ type: "P-256", publicKey: p.publicKey }))?.type).toBe("P-256");
    expect(keyOfJwk(jwkOf(e.publicKey))?.type).toBe("Ed25519");
    expect(didOfJwk(jwkOf({ type: "P-256", publicKey: p.publicKey }))).toBe(deriveDidP256(p.publicKey));
    expect(didOfJwk(jwkOf(e.publicKey))).toBe(deriveDid(e.publicKey));
  });

  it("trust-list keys may be ES256 (33-byte hex) and resolve typed", async () => {
    const p = await generateP256KeyPair();
    const hex = Buffer.from(p.publicKey).toString("hex");
    expect(typedKeyOf({ keyid: "kid-1", alg: "ES256", publicKeyHex: hex })?.type).toBe("P-256");
    expect(typedKeyOf({ keyid: "kid-1", alg: "ES256", publicKeyHex: "04" + hex.slice(2) })).toBeNull();
    expect(typedKeyOf({ keyid: "kid-1", alg: "Ed25519", publicKeyHex: hex })).toBeNull();
  });
});

/* ── malleability ──────────────────────────────────────────────────────── */

describe("P-256 malleability — signed low-S, verified low-S only", () => {
  it("a DSSE signature's high-S twin, and its non-minimal DER, never verify (WebCrypto would accept the twin)", async () => {
    const neg = json("negative.v1.json");
    const twin = ecdsaDerToRaw(base64ToBytes(neg.dsseHighS.envelope.signatures[0].sig));
    const env: DsseEnvelope = neg.dsseHighS.envelope;
    const pub = parseDidKey(neg.dsseHighS.publisher).publicKey;
    const key = await crypto.subtle.importKey("raw", (await import("@kashscript/identity-core")).decompressP256PublicKey(pub) as unknown as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const message = pae(env.payloadType, base64ToBytes(env.payload));
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, twin as unknown as BufferSource, message as unknown as BufferSource)).toBe(true);
    expect((await verifyEnvelope(env, (k) => parseDidKey(k))).ok).toBe(false);
  });

  it("every signature the seam makes is low-S, from software or from a hardware callback returning high-S DER", async () => {
    const p = await generateP256KeyPair();
    const { isLowS, normaliseLowS, ecdsaRawToDer, signP256, P256_ORDER } = await import("@kashscript/identity-core");
    for (let i = 0; i < 12; i++) {
      const msg = enc.encode(`m${i}`);
      const soft = ecdsaDerToRaw(await signBytes({ alg: "ES256", privateKey: p.privateKey, publicKey: p.publicKey }, msg, "der"));
      expect(isLowS(soft)).toBe(true);
      const hw = await signBytes(
        {
          alg: "ES256",
          publicKey: p.publicKey,
          sign: async (m) => {
            const raw = await signP256(m, p.privateKey, p.publicKey);
            const s = BigInt(`0x${Buffer.from(raw.subarray(32)).toString("hex")}`);
            const high = raw.slice();
            high.set(Buffer.from((P256_ORDER - s).toString(16).padStart(64, "0"), "hex"), 32);
            return { signature: ecdsaRawToDer(high), format: "der" };
          },
        },
        msg,
        "raw",
      );
      expect(isLowS(hw)).toBe(true);
      expect(Buffer.from(normaliseLowS(hw)).equals(Buffer.from(hw))).toBe(true);
      expect(await verifyBytes(hw, msg, { type: "P-256", publicKey: p.publicKey }, "raw")).toBe(true);
    }
  });
});

/* ── a person's P-256 key in a session ─────────────────────────────────── */

describe("a session line signed by an Ed25519 establishment and a P-256 person verifies by each key's type", () => {
  it("both signatures count; a third key still fails it", async () => {
    const est = await generateKeyPair();
    const per = await generateP256KeyPair();
    const estDid = deriveDid(est.publicKey);
    const perDid = deriveDidP256(per.publicKey);
    const sessionId = "ses_es256";
    const payload: SessionEventPayload = {
      spec: SESSION_EVENT_SPEC,
      sessionId,
      seq: 0,
      prevSha256: await sessionGenesisSha256(sessionId),
      kind: "open",
      atUnix: ctx.nowSec,
      by: "establishment",
      body: { profile: "presence+flow", parties: { establishment: estDid, person: perDid }, consent: { records: [], asks: [] }, place: "a practice café" },
    };
    let line = await signSessionEvent(payload, { keyid: estDid, privateKey: est.privateKey, publicKey: est.publicKey });
    line = await cosignSessionEvent(line, { alg: "ES256", keyid: perDid, privateKey: per.privateKey, publicKey: per.publicKey });
    const receipt = { formatVersion: SESSION_RECEIPT_FORMAT, sessionId, profile: "presence+flow", parties: { establishment: estDid, person: perDid }, events: [line], anchor: null };
    const r = await verifySessionReceipt(receipt, { nowSec: ctx.nowSec });
    expect(r.faults).toEqual([]);
    expect(r.events[0]!.bothSigned).toBe(true);
    expect(r.state).toBe("pending"); // open, not closed — and never proof until it is
    const other = await generateP256KeyPair();
    const third = await cosignSessionEvent(line, { alg: "ES256", keyid: deriveDidP256(other.publicKey), privateKey: other.privateKey, publicKey: other.publicKey });
    const r2 = await verifySessionReceipt({ ...receipt, events: [third] }, { nowSec: ctx.nowSec });
    expect(r2.faults.map((f) => f.fault)).toContain("FOREIGN_SIGNER");
  });
});

/* ── a runtime without Ed25519 ─────────────────────────────────────────── */

describe("a runtime with no Ed25519 says 'not checked', never 'invalid' — and ES256 still verifies there", () => {
  it("ES256 vectors verify; Ed25519 artifacts report RUNTIME_CANNOT_CHECK", async () => {
    const countersignFixture = JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "countersign-bundle.json"), "utf8"));
    const pl1Export = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "holder", "holder-export.v1.json"), "utf8"));
    const pl3Presentation = readFileSync(join(import.meta.dir, "vectors", "exchange", "predicate-presentation-a.v1.txt"), "utf8");
    await withoutEd25519(async () => {
      // ES256 still works
      expect((await verifyTrustList(json("trust-list-es256.v1.json"), { pinnedPublishers: [ctx.trustPublisher], nowSec: ctx.nowSec })).ok).toBe(true);
      expect((await verifySdJwt(txt("predicate-presentation-es256.v1.txt"), { resolveKey: noKeys, requireKeyBinding: true, audience: ctx.audience, nonce: ctx.nonce, nowSec: ctx.nowSec })).ok).toBe(true);
      // Ed25519: nothing judged
      expect((await verifyCountersignBundle(countersignFixture)).reason).toBe("RUNTIME_CANNOT_CHECK");
      expect((await verifyHolderExport(pl1Export, { nowSec: 1_790_208_000 })).reasons).toEqual(["RUNTIME_CANNOT_CHECK"]);
      expect((await verifySdJwt(pl3Presentation, { resolveKey: noKeys, requireKeyBinding: true, nowSec: 1_790_208_000 })).reason).toBe("RUNTIME_CANNOT_CHECK");
      const claim = json<CountersignBundle>("countersign-es256.v1.json").keyClaims![0]!;
      expect((await verifyKeyClaim(claim)).reason).toBe("RUNTIME_CANNOT_CHECK");
      // the mixed bundle needs Ed25519 for its requester — so it too is not judged
      expect((await verifyCountersignBundle(json("countersign-es256.v1.json"))).reason).toBe("RUNTIME_CANNOT_CHECK");
    });
  });
});

