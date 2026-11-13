// ============================================================================
// @kashscript/identity-server — the countersign ceremony
// ----------------------------------------------------------------------------
// A counterparty receives a link, opens it once, signs, and is done: no
// install, no account, no password. ECOSYSTEM decision 26 names this as the
// mechanic that lifts a record out of self-attestation, and decision 41 states
// the rule it serves — two signatures or it is not proof.
//
// This module owns the CEREMONY. The artifact format and its free offline
// verifier live in `@kashscript/attest` (verification is free — decision 27
// rule 4 — and attest is the package a stranger installs). The dependency runs
// one way: identity-server → attest → identity-core.
//
// ── What one click produces ─────────────────────────────────────────────────
// Two signatures from ONE key:
//
//   1. the countersignature — raw Ed25519 over `PAE(payloadType, payload)`,
//      the byte-identical bytes the first signer signed, appended to the
//      subject envelope's `signatures[]`. No new envelope format;
//   2. the acceptance — a Kash-Event binding the request, the subject digest,
//      the key's custody class and the moment of signing. A raw signature
//      carries no time and no context; this is where both live, so a verifier
//      who was not there can still place the signature in its window.
//
// ── The four properties that are constitutional, not conveniences ───────────
//
//   • **The signing identity is per relationship** (decision 41). A wallet
//     derives it with HKDF from a seed plus a salt over the REQUESTER's DID, so
//     two requesters see two unlinkable DIDs and one requester sees a stable
//     one. Without a wallet, a fresh key per request — unlinkable by
//     construction. Nothing here ever reuses a signing DID across requesters,
//     because a counterparty presenting one stable identifier to everybody is a
//     correlation key across every book in the ecosystem.
//
//   • **The key is the signer's** (decision 27 rule 1). `acceptCountersignRequest`
//     takes key material the caller already holds and never mints one. The
//     default path generates it on the counterparty's own device; the
//     server-minted `issueGuestDid` key (7-day cap) is the fallback for a
//     counterparty whose phone cannot hold a key, and it is labelled
//     `delegated-mint` INSIDE the signed bytes so it is never mistaken for
//     subject-held. See ADR-0018.
//
//   • **Declining is free and leaves no trace** (decision 27 rule 3).
//     `declineCountersignRequest` writes nothing, signs nothing and returns
//     nothing durable. See its doc comment for why a recorded-but-anonymised
//     decline was rejected.
//
//   • **Nothing here answers "what has this counterparty signed."** The store
//     is keyed by request and holds requests only; acceptances are never
//     persisted by this package at all — they are handed back to the caller.
//     Presentation, never lookup.
//
// ── The no-device counterparty ──────────────────────────────────────────────
// The request is a self-contained byte string with three renderings of the same
// value: a URL fragment, a QR payload, and a Crockford-base32 short code short
// enough to dictate over a voice call. Two delivery modes produce IDENTICAL
// signed artifacts — *hosted* (a short code the requester's own host exchanges
// for the request) and *carried* (the whole request travels as bytes, no server
// anywhere). An SMS/USSD/manual-relay path therefore needs a transport, not a
// second protocol. That path is not built here.
// ============================================================================

import {
  canonicalizeBytes,
  deriveDid,
  generateKeyPair,
  signEvent,
  type KashKeyPair,
} from "@kashscript/identity-core";
import {
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  DST_COUNTERSIGN_WITHDRAWAL,
  DST_KEY_CLAIM,
  COUNTERSIGN_BUNDLE_FORMAT,
  base64ToBytes,
  bytesToBase64 as attestBytesToBase64,
  countersignRequestDigest,
  pae,
  sha256Hex,
  signRaw,
  type CountersignAcceptanceBody,
  type CountersignBundle,
  type CountersignDisclosure,
  type CountersignKeyClaim,
  type CountersignRequestBody,
  type DsseEnvelope,
  type KeyCustody,
  type SignedCountersignAcceptance,
  type SignedCountersignRequest,
  type SignedCountersignWithdrawal,
} from "@kashscript/attest";
import { KashscriptIdentityMalformedPayloadError } from "./errors";
import { bytesToBase64, nowUnix, utf8Encode } from "./internal";
import type { Did, UnixSeconds } from "./types";

/* ── Constants ─────────────────────────────────────────────────────────── */

/** Default validity window for a request: 14 days. Long enough for a letter or
 *  a relayed SMS to arrive, short enough that expiry does most of the
 *  revocation work (see `withdrawCountersignRequest`). */
export const COUNTERSIGN_DEFAULT_TTL_SECONDS = 14 * 24 * 60 * 60;

/** Hard ceiling on a request window: 90 days. A request that cannot be answered
 *  in a quarter is a standing claim on somebody, which is what an expiry is for
 *  preventing. */
export const COUNTERSIGN_MAX_TTL_SECONDS = 90 * 24 * 60 * 60;

/** Capability-secret size. 16 bytes = 128 bits, and 26 base32 characters — the
 *  longest string a person can reasonably read down a phone line. */
const CAPABILITY_SECRET_BYTES = 16;

/** Request nonce size. */
const NONCE_BYTES = 32;

/** Crockford base32, excluding I, L, O and U so a dictated code survives
 *  mishearing. Shared alphabet with `@kashscript/attest/ids`' ULIDs. */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Domain separator for the per-relationship salt — never collides with a DST. */
const RELATIONSHIP_SALT_DOMAIN = "kash-countersign-relationship-v1";

/** HKDF `info` string for a relationship signing key. */
const RELATIONSHIP_HKDF_INFO = "kash-countersign-signing-key-v1";

/** RFC 8410 PKCS#8 prefix that wraps a raw 32-byte Ed25519 seed. Same constant
 *  identity-core uses internally; duplicated here only because deriving the
 *  PUBLIC half of a derived seed needs an extractable import, which
 *  identity-core deliberately does not expose. */
const PKCS8_ED25519_PREFIX = Uint8Array.of(
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
);

/* ── Compact encodings (one protocol, three renderings) ────────────────── */

/** Crockford-base32 encode. Unpadded; length is deterministic in the input. */
export function encodeCrockford32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

/** Crockford-base32 decode. Case-insensitive, and forgiving of the four
 *  substitutions a person makes when reading a code aloud (I/L→1, O→0) plus any
 *  hyphens or spaces they add. */
export function decodeCrockford32(text: string): Uint8Array {
  const cleaned = text
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of cleaned) {
    const idx = CROCKFORD.indexOf(ch);
    if (idx < 0) throw new KashscriptIdentityMalformedPayloadError("capabilitySecret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/* ── Per-relationship signing identity ─────────────────────────────────── */

/** A signing identity for exactly one relationship. */
export interface RelationshipSigningKey {
  readonly did: Did;
  readonly publicKey: Uint8Array;
  /** SECRET. Never transmitted, never persisted by this package. */
  readonly privateKey: Uint8Array;
  readonly custody: KeyCustody;
}

/**
 * The salt that separates one relationship from every other.
 *
 * `SHA-256(domain ‖ requesterDid ‖ 0x00 ‖ contextLabel)`. Derived from who is
 * asking, never from who is answering — which is the whole point: the
 * counterparty contributes no stable input, so nothing about them leaks across
 * requesters.
 */
export async function deriveRelationshipSalt(input: {
  readonly requesterDid: Did;
  readonly contextLabel: string;
}): Promise<string> {
  if (typeof input?.requesterDid !== "string" || input.requesterDid.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("requesterDid");
  }
  if (typeof input.contextLabel !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("contextLabel");
  }
  const domain = utf8Encode(RELATIONSHIP_SALT_DOMAIN);
  const requester = utf8Encode(input.requesterDid);
  const context = utf8Encode(input.contextLabel);
  const composed = new Uint8Array(domain.length + requester.length + 1 + context.length);
  composed.set(domain, 0);
  composed.set(requester, domain.length);
  composed[domain.length + requester.length] = 0x00;
  composed.set(context, domain.length + requester.length + 1);
  return sha256Hex(composed);
}

/** Derive the public half of an Ed25519 seed. WebCrypto will not hand it over
 *  from a non-extractable import, so the seed goes in as PKCS#8 and comes back
 *  out as a JWK. Works identically under Node 20+, Bun and browsers. */
async function publicKeyForSeed(seed: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as unknown as BufferSource,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  if (typeof jwk.x !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("derivedSeed");
  }
  const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

/**
 * Derive this relationship's signing key from a wallet seed.
 *
 * `HKDF-SHA256(masterSeed, salt = deriveRelationshipSalt(...))` → a 32-byte
 * Ed25519 seed → its own self-certifying `did:kash`. Deterministic, so the same
 * requester and context always yield the same DID (a holder's own book sees one
 * counterparty, not a stranger each time) while a different requester yields an
 * unlinkable one.
 *
 * The seed never leaves the caller. Custody is `subject-generated` by
 * definition — a derived key is only as subject-held as the seed it came from,
 * and a wallet seed is the subject's.
 */
export async function deriveRelationshipSigningKey(input: {
  readonly masterSeed: Uint8Array;
  readonly relationshipSalt: string;
}): Promise<RelationshipSigningKey> {
  if (!(input?.masterSeed instanceof Uint8Array) || input.masterSeed.length < 32) {
    throw new KashscriptIdentityMalformedPayloadError("masterSeed");
  }
  if (typeof input.relationshipSalt !== "string" || input.relationshipSalt.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("relationshipSalt");
  }
  const ikm = await crypto.subtle.importKey(
    "raw",
    input.masterSeed as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8Encode(input.relationshipSalt) as unknown as BufferSource,
      info: utf8Encode(RELATIONSHIP_HKDF_INFO) as unknown as BufferSource,
    },
    ikm,
    256,
  );
  const privateKey = new Uint8Array(derived);
  const publicKey = await publicKeyForSeed(privateKey);
  return { did: deriveDid(publicKey), publicKey, privateKey, custody: "subject-generated" };
}

/**
 * A one-time signing key for a counterparty with no wallet.
 *
 * Generated where the ceremony runs — the counterparty's own browser or agent —
 * and never transmitted, so custody is `subject-generated`. It is unlinkable to
 * every other request by construction, and correspondingly unstable: a second
 * request from the same requester yields a different DID. Stability within a
 * relationship is what a wallet seed buys; this is the honest cost of not
 * having one.
 */
export async function generateOneTimeSigningKey(): Promise<RelationshipSigningKey> {
  const pair: KashKeyPair = await generateKeyPair();
  return {
    did: deriveDid(pair.publicKey),
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    custody: "subject-generated",
  };
}

/**
 * Wrap key material that somebody ELSE minted — the `issueGuestDid` path, or a
 * relay operator keying a counterparty who holds a feature phone.
 *
 * Custody is `delegated-mint`, which travels inside every signature made with
 * it. Whoever minted the key may still hold a copy, so a record signed under one
 * is **not subject-held**; `claimCountersignKey` moves future authority to a
 * key the subject generated, and cures nothing retroactively.
 */
export function adoptDelegatedSigningKey(input: {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
}): RelationshipSigningKey {
  if (!(input?.publicKey instanceof Uint8Array) || !(input.privateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("delegatedKeyPair");
  }
  return {
    did: deriveDid(input.publicKey),
    publicKey: input.publicKey,
    privateKey: input.privateKey,
    custody: "delegated-mint",
  };
}

/* ── Creating a request ────────────────────────────────────────────────── */

export interface CreateCountersignRequestInput {
  /** The subject envelope as the holder already signed it. */
  readonly subject: DsseEnvelope;
  /** The holder's DID. Its key must be the one signing this request. */
  readonly requesterDid: Did;
  /** SECRET. The holder's 32-byte Ed25519 seed. */
  readonly requesterPrivateKey: Uint8Array;
  /** One plain sentence. This is the whole of what the counterparty is told
   *  they are signing, so it carries the meaning, not a reference to it. */
  readonly statement: string;
  /** Only what the counterparty must see to decide. Everything else stays in
   *  the payload, hashed. */
  readonly disclosures?: readonly CountersignDisclosure[];
  /** An opaque, requester-scoped label — a book, a corridor, an engagement.
   *  Part of the per-relationship salt. Never identifies a person. */
  readonly relationshipContext?: string;
  readonly ttlSeconds?: number;
  /** An address THE REQUESTER controls where it publishes withdrawals. Never
   *  ours. No verifier fetches it. */
  readonly withdrawalFeed?: string | null;
  readonly nowSec?: UnixSeconds;
}

export interface CreatedCountersignRequest {
  readonly request: SignedCountersignRequest;
  readonly requestId: string;
  /** SECRET, and the whole address. Deliver it out of band; whoever holds it
   *  can open the request, and holding the `requestId` alone cannot. */
  readonly capabilitySecretB32: string;
  /** The request as self-contained bytes — the *carried* delivery mode, which
   *  needs no server anywhere. */
  readonly compactB64u: string;
  /** The *hosted* delivery mode. The secret rides in the URL fragment, which
   *  browsers do not send to the host. `baseUrl` is the requester's own. */
  linkFor(baseUrl: string): string;
}

function b64u(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** `csr_<32hex>` — the first 16 bytes of SHA-256 over the capability secret.
 *  One-way, so the id may be logged, indexed and quoted while the secret is the
 *  only thing that opens the request. */
export async function requestIdForCapability(capabilitySecret: Uint8Array): Promise<string> {
  return `csr_${(await sha256Hex(capabilitySecret)).slice(0, 32)}`;
}

/**
 * Mint a countersign request.
 *
 * The request names **no counterparty**. Possession of the capability secret is
 * the address, which is why the same object can travel by link, by QR, by print
 * or by dictated code without changing a byte.
 */
export async function createCountersignRequest(
  input: CreateCountersignRequestInput,
): Promise<CreatedCountersignRequest> {
  if (typeof input?.statement !== "string" || input.statement.trim().length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("statement");
  }
  if (typeof input.requesterDid !== "string" || input.requesterDid.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("requesterDid");
  }
  if (!(input.requesterPrivateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("requesterPrivateKey");
  }
  const subject = input.subject;
  if (
    typeof subject?.payloadType !== "string" ||
    typeof subject.payload !== "string" ||
    !Array.isArray(subject.signatures)
  ) {
    throw new KashscriptIdentityMalformedPayloadError("subject");
  }

  const nowSec = input.nowSec ?? nowUnix();
  const ttl = Math.min(
    input.ttlSeconds ?? COUNTERSIGN_DEFAULT_TTL_SECONDS,
    COUNTERSIGN_MAX_TTL_SECONDS,
  );
  if (ttl <= 0) throw new KashscriptIdentityMalformedPayloadError("ttlSeconds");

  const capabilitySecret = crypto.getRandomValues(new Uint8Array(CAPABILITY_SECRET_BYTES));
  const requestId = await requestIdForCapability(capabilitySecret);
  const subjectDigestSha256 = await sha256Hex(base64ToBytes(subject.payload));

  const body: CountersignRequestBody = {
    requestId,
    requesterDid: input.requesterDid,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256,
    statement: input.statement,
    disclosures: input.disclosures ?? [],
    nonceB64: bytesToBase64(crypto.getRandomValues(new Uint8Array(NONCE_BYTES))),
    issuedAtUnix: nowSec,
    expiresAtUnix: nowSec + ttl,
    relationshipContext: input.relationshipContext ?? "",
    withdrawalFeed: input.withdrawalFeed ?? null,
  };
  const header = { typ: "countersign-request", v: 1 } as const;
  const signature = await signEvent(header, body, input.requesterPrivateKey, {
    dst: DST_COUNTERSIGN_REQUEST,
  });
  const request: SignedCountersignRequest = { header, body, signature };

  const capabilitySecretB32 = encodeCrockford32(capabilitySecret);
  return {
    request,
    requestId,
    capabilitySecretB32,
    compactB64u: b64u(canonicalizeBytes(request)),
    linkFor(baseUrl: string): string {
      const base = baseUrl.replace(/\/+$/, "");
      return `${base}/c/${requestId}#${capabilitySecretB32}`;
    },
  };
}

/** Parse a request that travelled in *carried* mode. Structural only — the
 *  signature is checked by `@kashscript/attest`'s verifier, never here. */
export function decodeCompactCountersignRequest(compactB64u: string): SignedCountersignRequest {
  if (typeof compactB64u !== "string" || compactB64u.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("compactB64u");
  }
  const b64 = compactB64u.replace(/-/g, "+").replace(/_/g, "/");
  const json = new TextDecoder().decode(base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4)));
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new KashscriptIdentityMalformedPayloadError("compactB64u", err);
  }
  const candidate = parsed as SignedCountersignRequest;
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    typeof candidate.body !== "object" ||
    candidate.body === null
  ) {
    throw new KashscriptIdentityMalformedPayloadError("compactB64u");
  }
  return candidate;
}

/* ── The ceremony ──────────────────────────────────────────────────────── */

export interface AcceptCountersignRequestInput {
  readonly request: SignedCountersignRequest;
  /** The envelope the request describes, as the holder signed it. */
  readonly subject: DsseEnvelope;
  /** The counterparty's own key. This function never mints one — decision 27
   *  rule 1 is a property of where the key came from, not of what we promise. */
  readonly signingKey: RelationshipSigningKey;
  readonly nowSec?: UnixSeconds;
}

export type AcceptCountersignRequestResult =
  | {
      readonly ok: true;
      /** The subject envelope with the second signature appended. Ordinary
       *  DSSE: any standard tool verifies it. */
      readonly envelope: DsseEnvelope;
      readonly acceptance: SignedCountersignAcceptance;
      readonly countersignerDid: Did;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "REQUEST_EXPIRED"
        | "REQUEST_NOT_YET_VALID"
        | "SUBJECT_MISMATCH"
        | "ALREADY_COUNTERSIGNED";
    };

/**
 * The one click.
 *
 * Signs the SAME canonical bytes the first signer signed — `PAE(payloadType,
 * payload)` — and appends the result to the envelope, then signs an acceptance
 * that carries the time, the request binding and the key's custody class.
 *
 * Refuses outside the request's window, and refuses when the request does not
 * describe this envelope. Both checks are repeated by the verifier, because a
 * check made only at signing time is a check a stranger cannot repeat.
 */
export async function acceptCountersignRequest(
  input: AcceptCountersignRequestInput,
): Promise<AcceptCountersignRequestResult> {
  const { request, subject, signingKey } = input;
  if (typeof request?.body !== "object" || request.body === null) {
    throw new KashscriptIdentityMalformedPayloadError("request");
  }
  if (typeof subject?.payload !== "string" || typeof subject.payloadType !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("subject");
  }
  if (!(signingKey?.privateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("signingKey");
  }

  const nowSec = input.nowSec ?? nowUnix();
  const body = request.body;
  if (nowSec < body.issuedAtUnix) return { ok: false, reason: "REQUEST_NOT_YET_VALID" };
  if (nowSec > body.expiresAtUnix) return { ok: false, reason: "REQUEST_EXPIRED" };

  const payloadBytes = base64ToBytes(subject.payload);
  const subjectDigestSha256 = await sha256Hex(payloadBytes);
  if (
    body.subjectPayloadType !== subject.payloadType ||
    body.subjectDigestSha256 !== subjectDigestSha256
  ) {
    return { ok: false, reason: "SUBJECT_MISMATCH" };
  }
  if (subject.signatures.some((s) => s.keyid === signingKey.did)) {
    return { ok: false, reason: "ALREADY_COUNTERSIGNED" };
  }

  // 1. The countersignature — the same bytes, a different key.
  const countersignature = await signRaw(
    pae(subject.payloadType, payloadBytes),
    signingKey.privateKey,
    signingKey.publicKey,
  );
  const envelope: DsseEnvelope = {
    payloadType: subject.payloadType,
    payload: subject.payload,
    signatures: [
      ...subject.signatures,
      { keyid: signingKey.did, sig: attestBytesToBase64(countersignature) },
    ],
  };

  // 2. The acceptance — where the time, the binding and the custody class live.
  const acceptanceBody: CountersignAcceptanceBody = {
    act: "countersign",
    requestId: body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256,
    countersignerDid: signingKey.did,
    keyCustody: signingKey.custody,
    signedAtUnix: nowSec,
  };
  const header = { typ: "countersign", v: 1 } as const;
  const signature = await signEvent(header, acceptanceBody, signingKey.privateKey, {
    dst: DST_COUNTERSIGN_ACCEPTANCE,
  });

  return {
    ok: true,
    envelope,
    acceptance: { header, body: acceptanceBody, signature },
    countersignerDid: signingKey.did,
  };
}

export interface DeclineCountersignRequestInput {
  /** The counterparty's copy of the capability secret, so it can be zeroised.
   *  Optional — declining works without it. */
  readonly capabilitySecret?: Uint8Array;
}

export interface DeclineCountersignRequestResult {
  readonly ok: true;
  /** Always `false`. Present so the guarantee is legible at the call site and
   *  assertable in a test, rather than being an absence somebody has to notice. */
  readonly recorded: false;
}

/**
 * Decline — and leave nothing behind.
 *
 * No artifact is produced, nothing is signed, no store is touched, and the
 * request's state is exactly what it was. A decline is therefore
 * indistinguishable from silence and from expiry, which is the only form that
 * satisfies decision 27 rule 3 (*non-participation stays viable*) and decision
 * 42 (*declining an ask costs only the thing asked for*).
 *
 * **Why not a recorded-but-anonymised decline.** The requester already knows,
 * out of band, which link went to whom — they sent it. So any signal at all,
 * however hashed, anonymised or aggregated, is joinable back to a person on the
 * requester's side and reconstitutes exactly the report decision 41's
 * never-build list forbids: *a report naming the individuals who have not
 * confirmed*. A count is the same object with one column dropped. The only
 * decline that cannot be aggregated is a decline that does not exist.
 *
 * The holder learns nothing from a decline and is not meant to; the expiry is
 * how they stop waiting.
 */
export function declineCountersignRequest(
  input: DeclineCountersignRequestInput = {},
): DeclineCountersignRequestResult {
  // The one local effect: destroy the counterparty's own copy of the secret so
  // the link cannot be used by whoever next holds the device. This mutates
  // caller-owned memory and touches nothing shared.
  if (input.capabilitySecret instanceof Uint8Array) {
    input.capabilitySecret.fill(0);
  }
  return { ok: true, recorded: false };
}

/* ── Withdrawal ────────────────────────────────────────────────────────── */

/**
 * Withdraw a request — as a signed artifact, never as a service.
 *
 * Whoever wants to show that a request was withdrawn **presents** this; no
 * verifier asks us, or anyone, whether one exists (decision 28). Its honest
 * limit is unavoidable and is stated in the verifier's own output: absence of a
 * withdrawal cannot be proven offline. Which is why a short expiry, not this,
 * does most of the revocation work.
 */
export async function withdrawCountersignRequest(input: {
  readonly request: SignedCountersignRequest;
  readonly requesterPrivateKey: Uint8Array;
  readonly nowSec?: UnixSeconds;
}): Promise<SignedCountersignWithdrawal> {
  if (typeof input?.request?.body !== "object" || input.request.body === null) {
    throw new KashscriptIdentityMalformedPayloadError("request");
  }
  if (!(input.requesterPrivateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("requesterPrivateKey");
  }
  const body = {
    act: "withdraw",
    requestId: input.request.body.requestId,
    requestDigestSha256: await countersignRequestDigest(input.request),
    withdrawnAtUnix: input.nowSec ?? nowUnix(),
  } as const;
  const header = { typ: "countersign-withdrawal", v: 1 } as const;
  const signature = await signEvent(header, body, input.requesterPrivateKey, {
    dst: DST_COUNTERSIGN_WITHDRAWAL,
  });
  return { header, body, signature };
}

/* ── Key succession (claim and rekey) ──────────────────────────────────── */

/**
 * Claim a signing identity with a key the subject generated.
 *
 * Both keys sign one body, so a stranger holding the pair can check the
 * succession offline. Use it when a counterparty who signed under a
 * `delegated-mint` key (the `issueGuestDid` path, or a relay) later obtains a
 * device and wants their records to follow.
 *
 * **What this does not do.** It does not make the earlier record subject-held.
 * If the prior key was minted by somebody else, that party could forge this
 * claim too — so a claim moves FUTURE authority and cures nothing behind it.
 * The original acceptance keeps its `delegated-mint` label permanently, and the
 * verifier keeps printing it. ADR-0018 records this in full.
 */
export async function claimCountersignKey(input: {
  readonly priorDid: Did;
  readonly priorPrivateKey: Uint8Array;
  readonly successor: RelationshipSigningKey;
  readonly nowSec?: UnixSeconds;
}): Promise<CountersignKeyClaim> {
  if (!(input?.priorPrivateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("priorPrivateKey");
  }
  if (!(input.successor?.privateKey instanceof Uint8Array)) {
    throw new KashscriptIdentityMalformedPayloadError("successor");
  }
  const body = {
    act: "claim-key",
    priorDid: input.priorDid,
    successorDid: input.successor.did,
    successorKeyCustody: input.successor.custody,
    claimedAtUnix: input.nowSec ?? nowUnix(),
  } as const;
  // The header carries no DID: both signatures must be over identical bytes.
  const header = { typ: "key-claim", v: 1 } as const;
  const [prior, successor] = await Promise.all([
    signEvent(header, body, input.priorPrivateKey, { dst: DST_KEY_CLAIM }),
    signEvent(header, body, input.successor.privateKey, { dst: DST_KEY_CLAIM }),
  ]);
  return { header, body, signatures: { prior, successor } };
}

/* ── Assembling what a stranger checks ─────────────────────────────────── */

/** Collect the signed parts into the container `@kashscript/attest` verifies.
 *  The container is unsigned on purpose — every part inside it carries its own
 *  signature, and every binding between them is checked by digest. */
export function assembleCountersignBundle(input: {
  readonly subject: DsseEnvelope;
  readonly request: SignedCountersignRequest;
  readonly acceptances: readonly SignedCountersignAcceptance[];
  readonly withdrawal?: SignedCountersignWithdrawal | null;
  readonly keyClaims?: readonly CountersignKeyClaim[];
}): CountersignBundle {
  return {
    formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
    subject: input.subject,
    request: input.request,
    acceptances: input.acceptances,
    withdrawal: input.withdrawal ?? null,
    ...(input.keyClaims !== undefined ? { keyClaims: input.keyClaims } : {}),
  };
}
