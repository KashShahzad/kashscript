/**
 * SD-JWT: issuance, holder-bound presentation, offline verification and the
 * unlinkability check — built and broken with attest + identity-core alone.
 */

import { describe, it, expect } from "bun:test";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { bytesToBase64Url } from "../src/ed25519";
import { makeKeyResolver } from "../src/holder/keys";
import {
  decodeJws,
  issueSdJwt,
  jwkOf,
  linkabilityBetween,
  parseSdJwt,
  presentSdJwt,
  signJws,
  verifySdJwt,
} from "../src/sd-jwt";

const T = 1_790_294_400;
const resolveKey = makeKeyResolver(new Map(), new Map());
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });

async function credential(issuer: KashKeyPair, holder: KashKeyPair, extra: Record<string, unknown> = {}) {
  return issueSdJwt({
    header: { kid: deriveDid(issuer.publicKey) },
    claims: { iss: deriveDid(issuer.publicKey), iat: T - (T % 86_400), exp: T + 86_400 * 30, vct: "https://kashscript.com/vct/predicate/1", cnf: { jwk: jwkOf(holder.publicKey) }, ...extra },
    sdProperties: { note: "only if the holder wants" },
    sdArrays: { restsOn: ["a".repeat(64), "b".repeat(64)] },
    decoys: 3,
    signer: kjs(issuer),
  });
}

describe("sd-jwt — issue, hold, present, verify", () => {
  it("a held credential verifies without key binding, and says it proves nothing about who shows it", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const r = await verifySdJwt(await credential(iss, h), { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.ok).toBe(true);
    expect(r.claims?.restsOn).toHaveLength(2);
    expect(r.holder).toBe(deriveDid(h.publicKey));
    expect(r.notes.join(" ")).toContain("proves nothing about who shows it");
  });

  it("a presentation discloses only what the holder chose — undisclosed claims and decoys vanish", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const p = await presentSdJwt(await credential(iss, h), () => false, kjs(h), { aud: "did:kash:v", nonce: "n", iatUnix: T });
    const r = await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "did:kash:v", nonce: "n", nowSec: T });
    expect(r.ok).toBe(true);
    expect(r.claims?.restsOn).toEqual([]);
    expect(r.claims?.note).toBeUndefined();
    expect(r.disclosed).toHaveLength(0);
  });

  it("a presentation must carry key binding", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const r = await verifySdJwt(await credential(iss, h), { resolveKey, requireKeyBinding: true, nowSec: T });
    expect(r.reason).toBe("KEY_BINDING_MISSING");
  });
});

describe("sd-jwt — tamper, replay and theft", () => {
  it("rejects a tampered issuer JWT", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const [jwt, ...rest] = held.split("~");
    const [hd, , sig] = jwt!.split(".");
    const forged = `${hd}.${bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ ...decodeJws(jwt!)!.payload, exp: T + 1e9 })))}.${sig}`;
    const r = await verifySdJwt([forged, ...rest].join("~"), { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.reason).toBe("ISSUER_SIGNATURE_INVALID");
  });

  it("rejects a disclosure the issuer never signed", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const fake = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(["salt", "c".repeat(64)])));
    const r = await verifySdJwt(`${held}${fake}~`, { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.reason).toBe("UNREFERENCED_DISCLOSURE");
  });

  it("rejects the same disclosure twice", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const p = parseSdJwt(await credential(iss, h))!;
    const r = await verifySdJwt(`${p.issuerJwt}~${p.disclosures[0]}~${p.disclosures[0]}~`, { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.reason).toBe("DUPLICATE_DISCLOSURE");
  });

  it("rejects a disclosure slipped in after the holder signed (sd_hash)", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const shown = await presentSdJwt(held, () => false, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const p = parseSdJwt(held)!;
    const kb = shown.slice(shown.lastIndexOf("~") + 1);
    const spliced = `${p.issuerJwt}~${p.disclosures[0]}~${kb}`;
    const r = await verifySdJwt(spliced, { resolveKey, requireKeyBinding: true, nowSec: T });
    expect(r.reason).toBe("SD_HASH_MISMATCH");
  });

  it("rejects a presentation re-signed by anyone but the holder — a stolen credential cannot be shown", async () => {
    const [iss, h, thief] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const p = await presentSdJwt(await credential(iss, h), () => false, kjs(thief), { aud: "v", nonce: "n", iatUnix: T });
    const r = await verifySdJwt(p, { resolveKey, requireKeyBinding: true, nowSec: T });
    expect(r.reason).toBe("KEY_BINDING_INVALID");
  });

  it("rejects the wrong audience, the wrong nonce, and a stale binding when asked", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const p = await presentSdJwt(await credential(iss, h), () => false, kjs(h), { aud: "v1", nonce: "n1", iatUnix: T });
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "v2", nowSec: T })).reason).toBe("AUDIENCE_MISMATCH");
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, audience: "v1", nonce: "n2", nowSec: T })).reason).toBe("NONCE_MISMATCH");
    expect((await verifySdJwt(p, { resolveKey, requireKeyBinding: true, nowSec: T + 3600, maxKbAgeSec: 300 })).reason).toBe("KEY_BINDING_STALE");
  });

  it("rejects an expired credential, an unsupported alg, a wrong typ, and an issuer it cannot resolve", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    expect((await verifySdJwt(await credential(iss, h), { resolveKey, requireKeyBinding: false, nowSec: T + 86_400 * 31 })).reason).toBe("CREDENTIAL_EXPIRED");
    const hs = await signJws({ typ: "dc+sd-jwt" }, { iss: deriveDid(iss.publicKey) }, kjs(iss));
    const [, p, s] = hs.split(".");
    const noneAlg = `${bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "dc+sd-jwt" })))}.${p}.${s}~`;
    expect((await verifySdJwt(noneAlg, { resolveKey, requireKeyBinding: false })).reason).toBe("ALG_UNSUPPORTED");
    const wrongTyp = `${await signJws({ typ: "JWT" }, { iss: deriveDid(iss.publicKey) }, kjs(iss))}~`;
    expect((await verifySdJwt(wrongTyp, { resolveKey, requireKeyBinding: false })).reason).toBe("TYP_MISMATCH");
    const opaque = `${await signJws({ typ: "dc+sd-jwt" }, { iss: "https://issuer.example.org" }, kjs(iss))}~`;
    expect((await verifySdJwt(opaque, { resolveKey, requireKeyBinding: false })).reason).toBe("ISSUER_KEY_UNRESOLVED");
  });
});

describe("sd-jwt — the key is the issuer's, never a header's (AU-3, A7-01)", () => {
  const VCT = "https://kashscript.com/vct/predicate/1";

  it("refuses a credential whose kid names another key than iss — the forgery in another organisation's name", async () => {
    const [victim, attacker, h] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    // The attacker signs with its own key K, writes K into `kid` and the victim's DID into `iss`.
    const forged = await issueSdJwt({
      header: { kid: deriveDid(attacker.publicKey) },
      claims: { iss: deriveDid(victim.publicKey), iat: T - (T % 86_400), exp: T + 86_400 * 30, vct: VCT, cnf: { jwk: jwkOf(h.publicKey) }, predicate: { kind: "projects", answer: true } },
      signer: kjs(attacker),
    });
    const held = await verifySdJwt(forged, { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(held.ok).toBe(false);
    expect(held.reason).toBe("KID_NOT_ISSUER");
    expect(held.claims).toBeNull();
    // Presented with a valid key binding, it is still the same forgery.
    const shown = await presentSdJwt(forged, () => true, kjs(h), { aud: "v", nonce: "n", iatUnix: T });
    const r = await verifySdJwt(shown, { resolveKey, requireKeyBinding: true, audience: "v", nonce: "n", nowSec: T });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("KID_NOT_ISSUER");
  });

  it("refuses a self-certifying kid beside a trust-listed iss — the listed key is iss's, and resolves through iss alone", async () => {
    const [listed, attacker] = [await generateKeyPair(), await generateKeyPair()];
    const keyid = "https://issuer.example.org#k1";
    const resolver = makeKeyResolver(new Map([[keyid, { publicKey: listed.publicKey, pinned: true }]]), new Map());
    const forged = await issueSdJwt({ header: { kid: deriveDid(attacker.publicKey) }, claims: { iss: keyid, vct: VCT }, signer: kjs(attacker) });
    expect((await verifySdJwt(forged, { resolveKey: resolver, requireKeyBinding: false, nowSec: T })).reason).toBe("KID_NOT_ISSUER");
    const genuine = await issueSdJwt({ claims: { iss: keyid, vct: VCT }, signer: kjs(listed) });
    const r = await verifySdJwt(genuine, { resolveKey: resolver, requireKeyBinding: false, nowSec: T });
    expect(r.ok).toBe(true);
    expect(r.issuerKeySource).toBe("trust-list");
  });

  it("a kid that is iss with a fragment selects among the issuer's keys, and is accepted", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const did = deriveDid(iss.publicKey);
    const c = await issueSdJwt({ header: { kid: `${did}#sig-1` }, claims: { iss: did, vct: VCT, cnf: { jwk: jwkOf(h.publicKey) } }, signer: kjs(iss) });
    const r = await verifySdJwt(c, { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.ok).toBe(true);
    expect(r.issuer).toBe(did);
  });

  it("a credential with no iss has no issuer to bind to, whatever its kid says", async () => {
    const iss = await generateKeyPair();
    const c = await issueSdJwt({ header: { kid: deriveDid(iss.publicKey) }, claims: { vct: VCT }, signer: kjs(iss) });
    const r = await verifySdJwt(c, { resolveKey, requireKeyBinding: false, nowSec: T });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("ISSUER_KEY_UNRESOLVED");
    expect(r.notes.join(" ")).toContain("no iss");
  });
});

describe("sd-jwt — two presentations are unlinkable unless the holder links them (rule 6)", () => {
  it("two copies, two relationship keys, two verifiers: nothing shared", async () => {
    const [iss, h1, h2] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const a = await presentSdJwt(await credential(iss, h1), () => false, kjs(h1), { aud: "va", nonce: "na", iatUnix: T });
    const b = await presentSdJwt(await credential(iss, h2), () => false, kjs(h2), { aud: "vb", nonce: "nb", iatUnix: T });
    expect(await linkabilityBetween(a, b)).toEqual([]);
  });

  it("one copy shown twice is linked by its signature, its key and its digests", async () => {
    const [iss, h] = [await generateKeyPair(), await generateKeyPair()];
    const held = await credential(iss, h);
    const a = await presentSdJwt(held, () => false, kjs(h), { aud: "va", nonce: "na", iatUnix: T });
    const b = await presentSdJwt(held, () => false, kjs(h), { aud: "vb", nonce: "nb", iatUnix: T });
    const kinds = (await linkabilityBetween(a, b)).map((c) => c.kind);
    expect(kinds).toContain("issuer-signature");
    expect(kinds).toContain("holder-key");
    expect(kinds).toContain("disclosure-digest");
  });

  it("disclosing the same record hash to two verifiers links them — the holder's choice, and it is reported", async () => {
    const [iss, h1, h2] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const a = await presentSdJwt(await credential(iss, h1), (d) => d.value === "a".repeat(64), kjs(h1), { aud: "va", nonce: "na", iatUnix: T });
    const b = await presentSdJwt(await credential(iss, h2), (d) => d.value === "a".repeat(64), kjs(h2), { aud: "vb", nonce: "nb", iatUnix: T });
    expect((await linkabilityBetween(a, b)).map((c) => c.kind)).toEqual(["disclosed-value"]);
  });

  it("an iat to the second is a correlator; a day-rounded one is not", async () => {
    const [iss, h1, h2] = [await generateKeyPair(), await generateKeyPair(), await generateKeyPair()];
    const odd = { iat: T + 4321 };
    const a = await presentSdJwt(await credential(iss, h1, odd), () => false, kjs(h1), { aud: "va", nonce: "na", iatUnix: T });
    const b = await presentSdJwt(await credential(iss, h2, odd), () => false, kjs(h2), { aud: "vb", nonce: "nb", iatUnix: T });
    expect((await linkabilityBetween(a, b)).map((c) => c.kind)).toEqual(["issued-at"]);
  });
});
