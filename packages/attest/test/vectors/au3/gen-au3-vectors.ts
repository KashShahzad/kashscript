/**
 * AU-3 vectors (AUDIT-2026-11-11, A7-01 to A7-05) — generated ONCE and committed.
 *
 *   bun packages/attest/test/vectors/au3/gen-au3-vectors.ts
 *
 * Never regenerate: every key below is fresh and thrown away, so a second run
 * changes every byte. Each file is a forgery, an alias or a re-wrapping that a
 * verifier must refuse by name, or a shape it must accept — `expected.v1.json`
 * says which, and `test/au3.test.ts` holds it to that. Everything here is a
 * simulation (ECOSYSTEM d11): no real person, place or organisation.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, encodeHex, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64, signRaw } from "../../../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../../../src/dsse";
import { sha256Hex } from "../../../src/chain";
import { issueSdJwt, jwkOf, presentSdJwt } from "../../../src/sd-jwt";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  countersignRequestDigest,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  type CountersignBundle,
  type SignedCountersignAcceptance,
  type SignedCountersignRequest,
} from "../../../src/countersign";

const DIR = import.meta.dir;
const T0 = 1_794_000_000; // 2026-11-06T13:20:00Z
const DAY = 86_400;
const VCT = "https://kashscript.com/vct/predicate/1";
const TYPE = "application/vnd.oreoasis.work-record+json";
const AUDIENCE = "https://door.practice.invalid";
const NONCE = "au3-nonce-7f3a9c1e";
const LISTED_KEYID = "https://issuer.practice.invalid#k1";

type Party = KashKeyPair & { did: string };
async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });
const write = (name: string, text: string): void => {
  writeFileSync(join(DIR, name), text);
  console.log(`wrote ${name}`);
};

/* ── SD-JWT: the key is the issuer's (A7-01) ───────────────────────────── */

async function sdJwtVectors(listed: Party) {
  const victim = await party();
  const attacker = await party();
  const holder = await party();
  const claims = (iss: string | undefined) => ({
    ...(iss === undefined ? {} : { iss }),
    iat: T0 - (T0 % DAY),
    exp: T0 + 365 * DAY,
    vct: VCT,
    cnf: { jwk: jwkOf(holder.publicKey) },
    predicate: { kind: "projects", answer: true, rule: { id: `${victim.did}/rule/practice-hiring`, version: "1", hash: "0".repeat(64) }, window: { from: "2024-11-06", to: "2026-11-05" } },
  });

  // The forgery: the attacker's key in kid, the victim's DID in iss, presented with a valid key binding.
  const forged = await issueSdJwt({ header: { kid: attacker.did }, claims: claims(victim.did), sdArrays: { restsOn: ["a".repeat(64)] }, decoys: 2, signer: kjs(attacker) });
  write("sdjwt-kid-not-iss.v1.txt", await presentSdJwt(forged, () => false, kjs(holder), { aud: AUDIENCE, nonce: NONCE, iatUnix: T0 }));

  // A self-certifying kid beside a trust-listed iss.
  write("sdjwt-kid-self-iss-listed.v1.txt", await issueSdJwt({ header: { kid: attacker.did }, claims: claims(LISTED_KEYID), signer: kjs(attacker) }));

  // No iss at all.
  write("sdjwt-no-iss.v1.txt", await issueSdJwt({ header: { kid: attacker.did }, claims: claims(undefined), signer: kjs(attacker) }));

  // The honest shapes: kid = iss with a fragment, and the listed issuer resolved through iss alone.
  write("sdjwt-kid-fragment-ok.v1.txt", await issueSdJwt({ header: { kid: `${victim.did}#sig-1` }, claims: claims(victim.did), signer: kjs(victim) }));
  write("sdjwt-listed-iss-ok.v1.txt", await issueSdJwt({ claims: claims(LISTED_KEYID), signer: kjs(listed) }));
  return { victim: victim.did, attacker: attacker.did, holder: holder.did };
}

/* ── countersign: signers by key, never by spelling (A7-02, A7-04, A7-05) ── */

async function subjectFor(signer: Party, payload: unknown): Promise<DsseEnvelope> {
  return signEnvelope(payload, TYPE, { keyid: signer.did, privateKey: signer.privateKey, publicKey: signer.publicKey }, { canonical: true });
}

async function requestFor(requester: Party, subject: DsseEnvelope, n: number): Promise<SignedCountersignRequest> {
  const body = {
    requestId: `csr_${n.toString(16).padStart(32, "0")}`,
    requesterDid: requester.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(base64ToBytes(subject.payload)),
    statement: "Accept this practice milestone.",
    disclosures: [{ label: "Milestone", value: "practice" }],
    nonceB64: bytesToBase64(new Uint8Array(32).fill(n)),
    issuedAtUnix: T0,
    expiresAtUnix: T0 + 7 * DAY,
    relationshipContext: "au3-practice",
    withdrawalFeed: null,
  };
  const header = { typ: "countersign-request", v: 1 };
  return { header, body, signature: await signEvent(header, body, requester.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
}

/** Append `signer`'s signature over the same bytes under `keyid`, and its acceptance under `countersignerDid`. */
async function accept(
  signer: Party,
  keyid: string,
  envelope: DsseEnvelope,
  request: SignedCountersignRequest,
  custody: unknown = "subject-generated",
): Promise<{ envelope: DsseEnvelope; acceptance: SignedCountersignAcceptance }> {
  const payloadBytes = base64ToBytes(envelope.payload);
  const sig = await signRaw(pae(envelope.payloadType, payloadBytes), signer.privateKey, signer.publicKey);
  const body: Record<string, unknown> = {
    act: "countersign",
    requestId: request.body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: envelope.payloadType,
    subjectDigestSha256: await sha256Hex(payloadBytes),
    countersignerDid: keyid,
    signedAtUnix: T0 + 60,
  };
  if (custody !== undefined) body.keyCustody = custody;
  const header = { typ: "countersign", v: 1 };
  return {
    envelope: { ...envelope, signatures: [...envelope.signatures, { keyid, sig: bytesToBase64(sig) }] },
    acceptance: { header, body, signature: await signEvent(header, body, signer.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) } as unknown as SignedCountersignAcceptance,
  };
}

const bundle = (subject: DsseEnvelope, request: SignedCountersignRequest, acceptances: SignedCountersignAcceptance[]): CountersignBundle => ({
  formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
  subject,
  request,
  acceptances,
  withdrawal: null,
});
const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;

async function countersignVectors() {
  const requester = await party();
  const independent = await party();
  const payload = { spec: "oreoasis.work-record/1", receiptId: "01KAU3PRACTICE000000000001", actor: { class: "person", id: requester.did }, shape: "accepted", action: { type: "milestone.accept", summary: "A practice milestone." }, inputs: [], outputs: [], status: "completed", timestamp: "2026-11-06T13:20:00Z", meta: { practice: true } };

  // One key, two spellings: the requester countersigns its own claim as did:kash:X#c.
  const s1 = await subjectFor(requester, payload);
  const r1 = await requestFor(requester, s1, 1);
  const alias = await accept(requester, `${requester.did}#c`, s1, r1);
  write("countersign-alias.v1.json", json(bundle(alias.envelope, r1, [alias.acceptance])));

  // The requester accepts its own request beside an independent countersigner (the cohort profile's shape).
  const s2 = await subjectFor(requester, { ...payload, receiptId: "01KAU3PRACTICE000000000002" });
  const r2 = await requestFor(requester, s2, 2);
  const own = await accept(requester, requester.did, s2, r2);
  const theirs = await accept(independent, independent.did, own.envelope, r2);
  write("countersign-requester-accepts.v1.json", json(bundle(theirs.envelope, r2, [own.acceptance, theirs.acceptance])));

  // A valid bundle with a sibling signature anyone can append.
  const s3 = await subjectFor(requester, { ...payload, receiptId: "01KAU3PRACTICE000000000003" });
  const r3 = await requestFor(requester, s3, 3);
  const good = await accept(independent, independent.did, s3, r3);
  write("countersign-junk-sibling.v1.json", json(bundle({ ...good.envelope, signatures: [...good.envelope.signatures, { keyid: "x", sig: "%%%" }] }, r3, [good.acceptance])));

  // An acceptance that states no custody.
  const s4 = await subjectFor(requester, { ...payload, receiptId: "01KAU3PRACTICE000000000004" });
  const r4 = await requestFor(requester, s4, 4);
  const silent = await accept(independent, independent.did, s4, r4, undefined);
  write("countersign-custody-missing.v1.json", json(bundle(silent.envelope, r4, [silent.acceptance])));

  // A subject whose payload is bytes, not JSON.
  const bytes = new TextEncoder().encode("these bytes are not JSON");
  const sig = await signRaw(pae(TYPE, bytes), requester.privateKey, requester.publicKey);
  const s5: DsseEnvelope = { payloadType: TYPE, payload: bytesToBase64(bytes), signatures: [{ keyid: requester.did, sig: bytesToBase64(sig) }] };
  const r5 = await requestFor(requester, s5, 5);
  const raw = await accept(independent, independent.did, s5, r5);
  write("countersign-nonjson-subject.v1.json", json(bundle(raw.envelope, r5, [raw.acceptance])));

  return { requester: requester.did, independent: independent.did };
}

/* ── expected verdicts and the public context ──────────────────────────── */

async function main(): Promise<void> {
  const listed = await party();
  const sd = await sdJwtVectors(listed);
  const cs = await countersignVectors();
  write("context.v1.json", json({
    note: "Public facts a verifier would already know. The listed issuer's key is the one a trust list would carry under this keyid.",
    nowSec: T0,
    audience: AUDIENCE,
    nonce: NONCE,
    listedKeyid: LISTED_KEYID,
    listedPublicKeyHex: encodeHex(listed.publicKey),
    sdJwt: sd,
    countersign: cs,
  }));
  write("expected.v1.json", json({
    "sdjwt-kid-not-iss.v1.txt": { kind: "sd-jwt", reason: "KID_NOT_ISSUER", audience: AUDIENCE, nonce: NONCE, nowSec: T0, note: "the attacker's key in kid, the victim's DID in iss, a valid key binding — the forgery A7-01 names" },
    "sdjwt-kid-self-iss-listed.v1.txt": { kind: "sd-jwt", reason: "KID_NOT_ISSUER", nowSec: T0, note: "a self-certifying kid beside a trust-listed iss" },
    "sdjwt-no-iss.v1.txt": { kind: "sd-jwt", reason: "ISSUER_KEY_UNRESOLVED", nowSec: T0, note: "no iss: there is no issuer to bind the key to" },
    "sdjwt-kid-fragment-ok.v1.txt": { kind: "sd-jwt", reason: null, nowSec: T0, note: "kid is iss with a fragment — it selects among the issuer's keys" },
    "sdjwt-listed-iss-ok.v1.txt": { kind: "sd-jwt", reason: null, nowSec: T0, note: "a listed issuer, its key found under iss alone" },
    "countersign-alias.v1.json": { kind: "countersign", reason: "COUNTERSIGNER_IS_REQUESTER", independentSignatureCount: 1, countersigners: [], nowSec: T0, note: "did:kash:X and did:kash:X#c are one key — one signer, no proof" },
    "countersign-requester-accepts.v1.json": { kind: "countersign", reason: null, independentSignatureCount: 2, countersigners: [cs.independent], nowSec: T0, note: "the requester's own acceptance is a signature, never a countersignature; the independent one makes the proof" },
    "countersign-junk-sibling.v1.json": { kind: "countersign", reason: null, independentSignatureCount: 2, countersigners: [cs.independent], nowSec: T0, note: "a sibling signature that is not base64 is skipped, not thrown" },
    "countersign-custody-missing.v1.json": { kind: "countersign", reason: null, independentSignatureCount: 2, countersigners: [cs.independent], custody: "unknown", nowSec: T0, note: "no keyCustody stated: unknown, not subject-held" },
    "countersign-nonjson-subject.v1.json": { kind: "countersign", reason: null, independentSignatureCount: 2, countersigners: [cs.independent], nowSec: T0, note: "a subject that is bytes, not JSON, is judged as bytes" },
  }));
  console.log("au3 vectors generated.");
}

await main();
