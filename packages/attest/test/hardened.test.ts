/**
 * KS-Q4 — hardened checking, every planted attack named (d84 P6: allowed
 * algorithms only, nonce and audience bound into every presentation,
 * short-lived approval links, status lists checked).
 *
 *   • the allow-list: the live signature profiles, and nothing else;
 *   • algorithm confusion: `none`, an HMAC keyed with the issuer's public key,
 *     a reserved post-quantum name, a header naming the other curve, a `crit`
 *     extension, a key planted in the header;
 *   • a presentation without the verifier's audience or nonce, with the wrong
 *     ones, stale, from the future, with no time at all;
 *   • replay: a nonce issued once and accepted once;
 *   • status: an expired list, a stale list, a verifier's own bound, d91's
 *     terminal states, the withdrawal window;
 *   • an approval link open longer than any may be.
 */

import { describe, expect, it } from "bun:test";
import { createHmac } from "node:crypto";
import { deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "../src/chain";
import { base64ToBytes, bytesToBase64, bytesToBase64Url, signRaw } from "../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../src/dsse";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  COUNTERSIGN_MAX_TTL_SECONDS,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  countersignRequestDigest,
  verifyCountersignBundle,
  type CountersignBundle,
} from "../src/countersign";
import { ALLOWED_EVENT_ALGS, ALLOWED_JOSE_ALGS, SIGNATURE_PROFILES, isAllowedJoseAlg, profileOfKey } from "../src/signing";
import { decodeJws, issueSdJwt, jwkOf, presentSdJwt, signJws, verifyJws, verifySdJwt, DEFAULT_PRESENTATION_MAX_AGE_SEC } from "../src/sd-jwt";
import {
  DEFAULT_STATUS_CACHE_SEC,
  STATUS_LIST_FORMAT,
  checkStatus,
  createStatusBitstring,
  encodeStatusList,
  makeKeyResolver,
  setStatusBit,
  signStatusList,
  statusEntryOf,
  verifyStatusList,
  type StatusPurpose,
} from "../src/holder";
import { acceptPresentationOnce, createNonceRegistry } from "../src/exchange";

const T = 1_800_000_000;
const DAY = 86_400;
const VCT = "https://kashscript.com/vct/predicate/1";
const resolveKey = makeKeyResolver(new Map(), new Map());
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });
const enc = new TextEncoder();
const b64uJson = (v: unknown): string => bytesToBase64Url(enc.encode(JSON.stringify(v)));

async function credential(issuer: KashKeyPair, holder: KashKeyPair, header: Record<string, unknown> = {}): Promise<string> {
  const iss = deriveDid(issuer.publicKey);
  return issueSdJwt({ header: { kid: iss, ...header }, claims: { iss, iat: T - (T % DAY), exp: T + 30 * DAY, vct: VCT, cnf: { jwk: jwkOf(holder.publicKey) } }, signer: kjs(issuer) });
}

/** Re-sign an issuer JWT's signing input with a forged header, as an attacker would. */
function withHeader(jwt: string, header: Record<string, unknown>, sign: (input: string) => string): string {
  const [, payload] = jwt.split(".");
  const h = b64uJson(header);
  return `${h}.${payload}.${sign(`${h}.${payload}`)}`;
}

describe("the allow-list — the live signature profiles, and nothing else", () => {
  it("names two live profiles and one reserved, and the allow-lists are exactly the live rows", () => {
    expect(SIGNATURE_PROFILES.map((p) => [p.id, p.status])).toEqual([["Ed25519", "live"], ["ES256", "live"], ["ML-DSA-65", "reserved"]]);
    expect(ALLOWED_JOSE_ALGS).toEqual(["EdDSA", "ES256"]);
    expect(ALLOWED_EVENT_ALGS).toEqual(["ed25519", "es256"]);
    expect(profileOfKey("Ed25519")?.jose).toBe("EdDSA");
    expect(profileOfKey("P-256")?.jose).toBe("ES256");
    // The reserved row names its standard and verifies nothing.
    const pq = SIGNATURE_PROFILES.find((p) => p.id === "ML-DSA-65")!;
    expect(pq.keyType).toBeNull();
    expect(pq.standard).toContain("FIPS 204");
    expect(pq.note).toContain("designed, not built");
  });

  it("refuses none, HMAC, RSA, secp256k1, the reserved name, a lower-case variant and every non-string", () => {
    for (const alg of ["none", "None", "NONE", "HS256", "HS512", "RS256", "PS256", "ES256K", "ES384", "ML-DSA-65", "eddsa", "", undefined, null, 1, ["EdDSA"]]) {
      expect({ alg, allowed: isAllowedJoseAlg(alg) }).toEqual({ alg, allowed: false });
    }
    expect(isAllowedJoseAlg("EdDSA")).toBe(true);
    expect(isAllowedJoseAlg("ES256")).toBe(true);
  });
});

describe("algorithm confusion — the key decides, and the allow-list goes first", () => {
  it("an issuer JWT with alg none is refused, with or without a signature", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const [jwt, ...rest] = held.split("~");
    for (const sig of ["", "AAAA"]) {
      const forged = withHeader(jwt!, { alg: "none", typ: "dc+sd-jwt" }, () => sig);
      expect((await verifySdJwt([forged, ...rest].join("~"), { resolveKey, requireKeyBinding: false, nowSec: T })).reason).toBe("ALG_UNSUPPORTED");
    }
  });

  it("an HMAC keyed with the issuer's own public key — the classic confusion — is refused before any key is read", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const [jwt, ...rest] = held.split("~");
    const hmac = (input: string) => createHmac("sha256", Buffer.from(iss.publicKey)).update(input).digest("base64url");
    const forged = withHeader(jwt!, { alg: "HS256", typ: "dc+sd-jwt", kid: deriveDid(iss.publicKey) }, hmac);
    expect((await verifySdJwt([forged, ...rest].join("~"), { resolveKey, requireKeyBinding: false, nowSec: T })).reason).toBe("ALG_UNSUPPORTED");
    // verifyJws alone refuses it too, whatever key it is handed.
    expect(await verifyJws(decodeJws(forged)!, iss.publicKey)).toBe(false);
  });

  it("the reserved post-quantum name verifies nothing yet", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const [jwt, ...rest] = (await credential(iss, h)).split("~");
    const forged = withHeader(jwt!, { alg: "ML-DSA-65", typ: "dc+sd-jwt" }, () => "AAAA");
    expect((await verifySdJwt([forged, ...rest].join("~"), { resolveKey, requireKeyBinding: false, nowSec: T })).reason).toBe("ALG_UNSUPPORTED");
  });

  it("a header naming the other curve over an Ed25519 signature does not verify — the issuer's key says EdDSA", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const [jwt, ...rest] = (await credential(iss, h)).split("~");
    const [hd, pl, sig] = jwt!.split(".");
    const header = JSON.parse(new TextDecoder().decode(Buffer.from(hd!, "base64url")));
    const lying = `${b64uJson({ ...header, alg: "ES256" })}.${pl}.${sig}`;
    const r = await verifySdJwt([lying, ...rest].join("~"), { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.reason).toBe("ISSUER_SIGNATURE_INVALID");
    expect(r.notes.join(" ")).toContain("the key decides");
  });

  it("a key planted in the header is never used: the key is iss's", async () => {
    const [victim, attacker, h] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const forged = await issueSdJwt({
      header: { jwk: jwkOf(attacker.publicKey) },
      claims: { iss: deriveDid(victim.publicKey), vct: VCT, cnf: { jwk: jwkOf(h.publicKey) } },
      signer: kjs(attacker),
    });
    expect((await verifySdJwt(forged, { resolveKey, requireKeyBinding: false, nowSec: T })).reason).toBe("ISSUER_SIGNATURE_INVALID");
  });

  it("a critical extension this verifier does not implement is refused, in the issuer's header and in the binding's", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const withCrit = await credential(iss, h, { crit: ["x-unknown"], "x-unknown": true });
    expect((await verifySdJwt(withCrit, { resolveKey, requireKeyBinding: false, nowSec: T })).reason).toBe("CRIT_UNSUPPORTED");
    const held = await credential(iss, h);
    const shown = await presentSdJwt(held, () => false, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const base = shown.slice(0, shown.lastIndexOf("~") + 1);
    const kb = decodeJws(shown.slice(shown.lastIndexOf("~") + 1))!;
    const critKb = await signJws({ typ: "kb+jwt", crit: ["x-unknown"] }, kb.payload, kjs(h));
    expect((await verifySdJwt(base + critKb, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T })).reason).toBe("CRIT_UNSUPPORTED");
  });

  it("a key binding with alg none, or an HMAC keyed with the holder's public key, does not bind", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const shown = await presentSdJwt(held, () => false, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const base = shown.slice(0, shown.lastIndexOf("~") + 1);
    const kb = decodeJws(shown.slice(shown.lastIndexOf("~") + 1))!;
    const none = `${b64uJson({ alg: "none", typ: "kb+jwt" })}.${kb.payloadB64u}.`;
    expect((await verifySdJwt(base + none, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T })).reason).toBe("KEY_BINDING_INVALID");
    const hInput = `${b64uJson({ alg: "HS256", typ: "kb+jwt" })}.${kb.payloadB64u}`;
    const hs = `${hInput}.${createHmac("sha256", Buffer.from(h.publicKey)).update(hInput).digest("base64url")}`;
    expect((await verifySdJwt(base + hs, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T })).reason).toBe("KEY_BINDING_INVALID");
  });
});

describe("a presentation is bound to one verifier, now", () => {
  it("is refused without the verifier's audience or nonce — even by a caller that ignores the types", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const p = await presentSdJwt(await credential(iss, h), () => false, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const loose = verifySdJwt as unknown as (input: string, opts: Record<string, unknown>) => ReturnType<typeof verifySdJwt>;
    expect((await loose(p, { resolveKey, requireKeyBinding: true, nowSec: T })).reason).toBe("AUDIENCE_NOT_SUPPLIED");
    expect((await loose(p, { resolveKey, requireKeyBinding: true, audience: "", nonce: "n", nowSec: T })).reason).toBe("AUDIENCE_NOT_SUPPLIED");
    expect((await loose(p, { resolveKey, requireKeyBinding: true, audience: "v", nowSec: T })).reason).toBe("NONCE_NOT_SUPPLIED");
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T })).ok).toBe(true);
  });

  it("is refused for the wrong audience and the wrong nonce", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const p = await presentSdJwt(await credential(iss, h), () => false, kjs(h), { aud: "https://door.example", nonce: "n-1", iatUnix: T });
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "https://other.example", nonce: "n-1", nowSec: T })).reason).toBe("AUDIENCE_MISMATCH");
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "https://door.example", nonce: "n-2", nowSec: T })).reason).toBe("NONCE_MISMATCH");
  });

  it("is fresh for ten minutes either way by default; one from the future, or with no time, is stale", async () => {
    expect(DEFAULT_PRESENTATION_MAX_AGE_SEC).toBe(600);
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const p = await presentSdJwt(held, () => false, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const at = (nowSec: number) => verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec });
    expect((await at(T + 600)).ok).toBe(true);
    expect((await at(T - 600)).ok).toBe(true);
    expect((await at(T + 601)).reason).toBe("KEY_BINDING_STALE");
    expect((await at(T - 601)).reason).toBe("KEY_BINDING_STALE");
    // A binding with no iat is never fresh.
    const base = p.slice(0, p.lastIndexOf("~") + 1);
    const kb = decodeJws(p.slice(p.lastIndexOf("~") + 1))!;
    const { iat: _drop, ...noIat } = kb.payload;
    const timeless = await signJws({ typ: "kb+jwt" }, noIat, kjs(h));
    expect((await verifySdJwt(base + timeless, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T })).reason).toBe("KEY_BINDING_STALE");
  });
});

describe("replay — a nonce is issued once and accepted once", () => {
  async function presentedFor(nonce: string, nowSec = T) {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    return presentSdJwt(await credential(iss, h), () => false, kjs(h), { aud: "https://door.example", nonce, iatUnix: nowSec });
  }

  it("the same presentation sent twice is accepted once; the second is a replay", async () => {
    const reg = createNonceRegistry({ now: () => T });
    const nonce = reg.issue();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(reg.issue()).not.toBe(nonce);
    const p = await presentedFor(nonce);
    const opts = { resolveKey, requireKeyBinding: true as const, audience: "https://door.example", nonce, nowSec: T };
    const first = await acceptPresentationOnce(p, reg, opts);
    expect([first.ok, first.reason, first.nonce]).toEqual([true, null, "accepted"]);
    const again = await acceptPresentationOnce(p, reg, opts);
    expect([again.ok, again.reason, again.nonce]).toEqual([false, "NONCE_REPLAYED", "used"]);
    // The signature still checks — it is the registry that refuses.
    expect(again.report.ok).toBe(true);
  });

  it("a nonce this verifier never issued, or one past its lifetime, is not accepted", async () => {
    let now = T;
    const reg = createNonceRegistry({ ttlSec: 300, now: () => now });
    const made = await presentedFor("chosen-by-the-holder");
    const unknown = await acceptPresentationOnce(made, reg, { resolveKey, requireKeyBinding: true, audience: "https://door.example", nonce: "chosen-by-the-holder", nowSec: T });
    expect([unknown.ok, unknown.reason]).toEqual([false, "NONCE_UNKNOWN"]);
    const nonce = reg.issue();
    now = T + 301;
    const late = await presentedFor(nonce, T + 301);
    const expired = await acceptPresentationOnce(late, reg, { resolveKey, requireKeyBinding: true, audience: "https://door.example", nonce, nowSec: T + 301 });
    expect([expired.ok, expired.reason, expired.nonce]).toEqual([false, "NONCE_UNKNOWN", "expired"]);
  });

  it("a forged answer never burns the nonce its real holder is about to use", async () => {
    const reg = createNonceRegistry({ now: () => T });
    const nonce = reg.issue();
    // Change the key binding's signature where every character carries data: its first. (Its last character carries
    // two bits and four padding bits, which a base64url decoder may ignore — changing it can leave the bytes as they were.)
    const presented = await presentedFor(nonce);
    const at = presented.lastIndexOf(".") + 1;
    const forged = presented.slice(0, at) + (presented[at] === "A" ? "B" : "A") + presented.slice(at + 1);
    const bad = await acceptPresentationOnce(forged, reg, { resolveKey, requireKeyBinding: true, audience: "https://door.example", nonce, nowSec: T });
    expect(bad.ok).toBe(false);
    expect(bad.nonce).toBeNull();
    const real = await acceptPresentationOnce(await presentedFor(nonce), reg, { resolveKey, requireKeyBinding: true, audience: "https://door.example", nonce, nowSec: T });
    expect(real.ok).toBe(true);
  });

  it("is bounded: past its size the oldest nonce is forgotten, so a flood costs its own requests", () => {
    const reg = createNonceRegistry({ max: 2, now: () => T });
    const a = reg.issue();
    const b = reg.issue();
    const c = reg.issue();
    expect(reg.size).toBe(2);
    expect(reg.consume(a)).toBe("unknown");
    expect(reg.consume(b)).toBe("accepted");
    expect(reg.consume(c)).toBe("accepted");
    expect(() => createNonceRegistry({ ttlSec: 0 })).toThrow();
    expect(() => createNonceRegistry({ max: 0 })).toThrow();
  });
});

describe("status — checked, with a stated cache time; d91's terminal states", () => {
  async function list(purpose: StatusPurpose, opts: { issuedAtUnix?: number; validUntilUnix?: number | null; ttl?: number; set?: number[] } = {}) {
    const issuer = await generateKeyPair();
    const did = deriveDid(issuer.publicKey);
    const bits = createStatusBitstring();
    for (const i of opts.set ?? []) setStatusBit(bits, i, true);
    const env = await signStatusList(
      {
        format: STATUS_LIST_FORMAT,
        type: "BitstringStatusList",
        id: `https://issuer.example/status/${purpose}`,
        issuer: did,
        statusPurpose: purpose,
        encodedList: await encodeStatusList(bits),
        issuedAtUnix: opts.issuedAtUnix ?? T,
        validUntilUnix: opts.validUntilUnix ?? null,
        ...(opts.ttl !== undefined ? { ttl: opts.ttl } : {}),
      },
      { keyid: did, ...kjs(issuer) },
    );
    const report = await verifyStatusList(env, { resolveKey, nowSec: T });
    const entry = (index: number) => statusEntryOf({ credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: purpose, statusListIndex: String(index), statusListCredential: `https://issuer.example/status/${purpose}` } });
    return { report, entry };
  }

  it("a list past its validUntil decides nothing — an expired status, whatever its bits say", async () => {
    const l = await list("revocation", { validUntilUnix: T - 1, set: [3] });
    expect(l.report.ok).toBe(true); // its signature holds
    expect(l.report.current).toBe(false); // and it is over
    for (const index of [3, 4]) {
      const v = checkStatus(l.entry(index), [l.report], { nowSec: T });
      expect(v.state).toBe("unknown");
      expect(v.text).toContain("past its validUntil");
    }
  });

  it("states its cache time — the list's ttl, or the checker's day — and past it the reading stands, marked stale", async () => {
    expect(DEFAULT_STATUS_CACHE_SEC).toBe(DAY);
    const withTtl = await list("revocation", { ttl: 3_600_000 });
    expect(withTtl.report.cacheUntilUnix).toBe(T + 3600);
    const fresh = checkStatus(withTtl.entry(1), [withTtl.report], { nowSec: T + 3600 });
    expect([fresh.state, fresh.stale, fresh.cacheUntilUnix]).toEqual(["not-revoked", false, T + 3600]);
    const stale = checkStatus(withTtl.entry(1), [withTtl.report], { nowSec: T + 3601 });
    expect([stale.state, stale.stale]).toEqual(["not-revoked", true]);
    expect(stale.text).toContain("older than its cache time");
    const noTtl = await list("revocation");
    expect(noTtl.report.cacheUntilUnix).toBe(T + DAY);
    const capped = await list("revocation", { ttl: 10 * DAY * 1000, validUntilUnix: T + 60 });
    expect(capped.report.cacheUntilUnix).toBe(T + 60);
  });

  it("a verifier's own bound turns an older list into no verdict at all", async () => {
    const l = await list("revocation", { set: [7] });
    expect(checkStatus(l.entry(7), [l.report], { nowSec: T + 100, maxAgeSec: 300 }).state).toBe("revoked");
    const old = checkStatus(l.entry(7), [l.report], { nowSec: T + 301, maxAgeSec: 300 });
    expect(old.state).toBe("unknown");
    expect(old.text).toContain("older than this verifier accepts");
  });

  it("names superseded and withdrawn, and expired by the record's own clock whatever any list says", async () => {
    const sup = await list("supersession", { set: [2] });
    const s = checkStatus(sup.entry(2), [sup.report], { nowSec: T });
    expect(s.state).toBe("superseded");
    expect(s.text).toContain("this list does not say which");
    expect(checkStatus(sup.entry(3), [sup.report], { nowSec: T }).text).toStartWith("not superseded, as of ");
    const wd = await list("withdrawal", { set: [5] });
    expect(checkStatus(wd.entry(5), [wd.report], { nowSec: T }).state).toBe("withdrawn");
    expect(checkStatus(wd.entry(6), [wd.report], { nowSec: T }).text).toStartWith("not withdrawn, as of ");
    const expired = checkStatus(wd.entry(6), [wd.report], { nowSec: T + 10, recordExpiresAtUnix: T + 5 });
    expect(expired.state).toBe("expired");
    expect(expired.text).toContain("terminal");
  });

  it("a withdrawal counts inside the window; a list dated after the window says it cannot show that; unset, it says the window was not checked", async () => {
    const wd = await list("withdrawal", { set: [5], issuedAtUnix: T });
    const inside = checkStatus(wd.entry(5), [wd.report], { nowSec: T, recordSignedAtUnix: T - 3600, withdrawalWindowSec: 7200 });
    expect(inside.text).toContain("inside the withdrawal window");
    const after = checkStatus(wd.entry(5), [wd.report], { nowSec: T, recordSignedAtUnix: T - 3 * DAY, withdrawalWindowSec: DAY });
    expect(after.text).toContain("dated after the withdrawal window closed");
    const unset = checkStatus(wd.entry(5), [wd.report], { nowSec: T });
    expect(unset.text).toContain("the withdrawal window was not checked here");
  });

  it("refuses a list whose ttl is not a whole number of milliseconds", async () => {
    const issuer = await generateKeyPair();
    const did = deriveDid(issuer.publicKey);
    const payload = { format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: "https://i.example/s", issuer: did, statusPurpose: "revocation", encodedList: await encodeStatusList(createStatusBitstring()), issuedAtUnix: T, validUntilUnix: null, ttl: -5 };
    const env = await signEnvelope(payload, "application/vnd.kash.status-list+json", { keyid: did, ...kjs(issuer) }, { canonical: true });
    expect((await verifyStatusList(env, { resolveKey, nowSec: T })).reason).toBe("MALFORMED_STATUS_LIST");
  });
});

describe("an approval link is short-lived — for every implementation", () => {
  it("a request open longer than 90 days is refused by the checker, whoever minted it", async () => {
    expect(COUNTERSIGN_MAX_TTL_SECONDS).toBe(90 * DAY);
    const holder = await generateKeyPair();
    const signer = await generateKeyPair();
    const [hDid, sDid] = [deriveDid(holder.publicKey), deriveDid(signer.publicKey)];
    const subject: DsseEnvelope = await signEnvelope({ thing: 1 }, "application/vnd.example.thing+json", { keyid: hDid, ...kjs(holder) }, { canonical: true });
    const make = async (windowSec: number): Promise<CountersignBundle> => {
      const body = {
        requestId: "csr_00000000000000000000000000000091",
        requesterDid: hDid,
        subjectPayloadType: subject.payloadType,
        subjectDigestSha256: await sha256Hex(base64ToBytes(subject.payload)),
        statement: "Confirm you received this.",
        disclosures: [],
        nonceB64: bytesToBase64(new Uint8Array(32).fill(7)),
        issuedAtUnix: T,
        expiresAtUnix: T + windowSec,
        relationshipContext: "ctx",
        withdrawalFeed: null,
      };
      const reqHeader = { typ: "countersign-request", v: 1 };
      const request = { header: reqHeader, body, signature: await signEvent(reqHeader, body, holder.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
      const payloadBytes = base64ToBytes(subject.payload);
      const sig = await signRaw(pae(subject.payloadType, payloadBytes), signer.privateKey, signer.publicKey);
      const accBody = {
        act: "countersign" as const,
        requestId: body.requestId,
        requestDigestSha256: await countersignRequestDigest(request),
        subjectPayloadType: subject.payloadType,
        subjectDigestSha256: body.subjectDigestSha256,
        countersignerDid: sDid,
        keyCustody: "subject-generated" as const,
        signedAtUnix: T + 60,
      };
      const accHeader = { typ: "countersign", v: 1 };
      return {
        formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
        subject: { ...subject, signatures: [...subject.signatures, { keyid: sDid, sig: bytesToBase64(sig) }] },
        request,
        acceptances: [{ header: accHeader, body: accBody, signature: await signEvent(accHeader, accBody, signer.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) }],
        withdrawal: null,
      };
    };
    expect((await verifyCountersignBundle(await make(90 * DAY))).ok).toBe(true);
    const long = await verifyCountersignBundle(await make(91 * DAY));
    expect(long.ok).toBe(false);
    expect(long.reason).toBe("REQUEST_WINDOW_TOO_LONG");
    expect(long.notes.join(" ")).toContain("longer than any approval link may be");
  });
});
