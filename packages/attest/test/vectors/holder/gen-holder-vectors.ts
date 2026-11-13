/**
 * Holder-contract conformance vectors — generated ONCE and committed.
 *
 *   bun packages/attest/test/vectors/holder/gen-holder-vectors.ts
 *
 * Never regenerate: every signature below uses a fresh key, so a second run
 * changes every byte and silently invalidates anything built against them.
 *
 * What it writes (see README.md beside it):
 *   • trust-list.v1.json            — a signed kashscript-trust-list/1
 *   • status-list.v1.json           — a signed kashscript-status-list/1, 131,072 entries
 *   • holder-export.v1.json         — a kashscript-holder-export/1, canonical bytes
 *   • holder-export-backup.v1.json  — the same format with a real JWE key backup
 *
 * The export holds one record of every kind the holder contract must carry
 * untouched. Two are COPIES of existing vectors, never re-made: the IVFC1
 * token and the countersign bundle from ../../fixtures, and the Oreoasis agent
 * receipt and work record envelopes from ./source (copied from Oreoasis's own
 * vectors). The rest are samples built with each issuer's exact construction,
 * read from its source. Every sample is a simulation (d11); nothing here
 * describes a real person, venue or organisation.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, deriveDid, encodeHex, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { base64UrlToBytes, bytesToBase64Url, signRaw } from "../../../src/ed25519";
import { signEnvelope, type DsseEnvelope } from "../../../src/dsse";
import { canonicalJson, chainBlockHash, GENESIS_PREV_HASH, sha256Hex } from "../../../src/chain";
import { signLedgerBlock } from "../../../src/ledger";
import { DST_KEY_CLAIM } from "../../../src/countersign";
import { INDUS_MARK_DST, INDUS_MARK_REVOKE_DST, indusMarkDigest } from "../../../src/compat/indus-mark";
import {
  STATUS_LIST_FORMAT,
  TRUST_LIST_FORMAT,
  createStatusBitstring,
  encodeStatusList,
  recordIdOf,
  serializeHolderExport,
  setStatusBit,
  signStatusList,
  signTrustList,
  statusEntryOf,
  type HeldArtifact,
  type HeldRecord,
  type HolderExport,
  type HoldingManifest,
  type StatusListEntry,
} from "../../../src/holder";

const DIR = import.meta.dir;
const FIXTURES = join(DIR, "..", "..", "fixtures");
const enc = new TextEncoder();
const b64u = (s: string): string => bytesToBase64Url(enc.encode(s));

const T0 = 1_767_225_600; // 2026-01-01T00:00:00Z
const DAY = 86_400;
const YEAR = 365 * DAY;
const T_UNTIL = 2_082_758_400; // 2036-01-01T00:00:00Z
const EXPORTED_AT = 1_790_208_000; // 2026-09-24T00:00:00Z

const signerOf = (kp: KashKeyPair, keyid = deriveDid(kp.publicKey)) => ({ keyid, privateKey: kp.privateKey, publicKey: kp.publicKey });
const didOf = (kp: KashKeyPair): string => deriveDid(kp.publicKey);

/** DST ‖ 0x00 ‖ headerB64u ‖ "." ‖ bodyB64u — the Indus token signing input. */
async function indusToken(prefix: string, dst: string, headerB64u: string, bodyB64u: string, kp: KashKeyPair): Promise<string> {
  const input = new Uint8Array([...enc.encode(dst), 0, ...enc.encode(headerB64u), ...enc.encode("."), ...enc.encode(bodyB64u)]);
  const sig = await signRaw(input, kp.privateKey, kp.publicKey);
  return `${prefix}.${headerB64u}.${bodyB64u}.${bytesToBase64Url(sig)}`;
}

/* ── keys ──────────────────────────────────────────────────────────────── */
const publisher = await generateKeyPair(); // the trust list's publisher
const indusPlatform = await generateKeyPair(); // marks, revocations, IBPS1
const venue = await generateKeyPair(); // an IPOE1 venue key
const device = await generateKeyPair(); // the holder's own device (IGEO1)
const browser = await generateKeyPair(); // the holder's own browser (Indorania practice receipts)
const org = await generateKeyPair(); // an Oreoasis establishment's Org key (predicates, status list)
const relA = await generateKeyPair(); // the holder's relationship key with the platform (before rotation)
const relB = await generateKeyPair(); // … and after
const relVenue = await generateKeyPair();
const relOrg = await generateKeyPair();

const indusPlatformDid = didOf(indusPlatform);
const orgDid = didOf(org);
const VENUE_KID = "01JB6VENUEDEMO0000000000A1";
const BPS_KID = "indus.platform.bps.v1";
const DEVICE_KID = "device-01JB6DEMO000000000000";

/* ── copies of existing vectors (never re-made) ────────────────────────── */
const ivfc1 = readFileSync(join(FIXTURES, "indus-ivfc1.token.txt"), "utf8").trim();
const ivfcJwks = JSON.parse(readFileSync(join(FIXTURES, "indus-keys.json"), "utf8")) as { keys: { kid: string; x: string }[] };
const ivfcKey = ivfcJwks.keys[0]!;
const countersignBundle = JSON.parse(readFileSync(join(FIXTURES, "countersign-bundle.json"), "utf8")) as Record<string, any>;
const agentReceipt = JSON.parse(readFileSync(join(DIR, "source", "oreoasis-agent-receipt.json"), "utf8")) as { keyid: string; publicKeyHex: string; envelope: DsseEnvelope };
const workRecord = JSON.parse(readFileSync(join(DIR, "source", "oreoasis-work-record.json"), "utf8")) as { keyid: string; publicKeyHex: string; envelope: DsseEnvelope };

/* ── new samples, each with its issuer's exact construction ────────────── */

// IPOE1 — apps/web/app/api/business/industown/venues/[venueId]/qr/route.ts:
// header JSON.stringify, body JCS.
const ipoe1 = await indusToken(
  "IPOE1",
  "indus.poe.v1.qr",
  b64u(JSON.stringify({ alg: "EdDSA", kid: VENUE_KID, v: 1 })),
  b64u(canonicalize({ iss: "00000000-0000-4000-8000-00000000c0de", poi: "00000000-0000-4000-8000-0000000000a1", geo: { lat: 35.9208, lng: 74.3089, r: 60 }, iat: T0 + 30 * DAY, exp: T0 + 30 * DAY + 90, nonce: b64u("ipoe1-sample-nonce").slice(0, 22), rot: 60, tier: "public" })),
  venue,
);

// IGEO1 — apps/mobile/lib/geo/canonical.ts: header AND body JCS, signed by the device key.
const igeo1 = await indusToken(
  "IGEO1",
  "indus.poe.v1.geo",
  b64u(canonicalize({ alg: "EdDSA", kid: DEVICE_KID, v: 1 })),
  b64u(canonicalize({ cid: "cp-demo-1", lt: "landmark", li: "lm-demo-1", geo: { lat: 36.3167, lng: 74.65, r: 150 }, pos: { lat: 36.3169, lng: 74.6502, acc: 12 }, dwell: 420, iat: T0 + 31 * DAY, exp: T0 + 31 * DAY + 3600, nonce: b64u("igeo1-sample-nonce").slice(0, 22) })),
  device,
);

// IBPS1 — supabase/functions/issue-booking-pass/index.ts: header JSON.stringify, body JCS, platform key.
const ibps1 = await indusToken(
  "IBPS1",
  "indus.bps.v1.bpass",
  b64u(JSON.stringify({ alg: "EdDSA", kid: BPS_KID, v: 1, typ: "IBPS1" })),
  b64u(canonicalize({ jti: b64u("ibps1-sample-jti!").slice(0, 22), bookingId: "00000000-0000-4000-8000-0000000000b1", sub: "00000000-0000-4000-8000-0000000000e1", org: "00000000-0000-4000-8000-0000000000d1", venueKid: VENUE_KID, slotStart: T0 + 40 * DAY, slotEnd: T0 + 40 * DAY + 7200, party: 2, iat: T0 + 35 * DAY, exp: T0 + 40 * DAY + 7200 + 1800 })),
  indusPlatform,
);

// The issuer's status list: 131,072 entries, indexes assigned at random, one revoked.
const STATUS_URL = "https://status.example.org/oreoasis-demo/predicates/2026-q3";
const KEPT_INDEX = 17_403;
const REVOKED_INDEX = 90_211;
const bits = createStatusBitstring();
setStatusBit(bits, REVOKED_INDEX, true);
const statusList = await signStatusList(
  {
    format: STATUS_LIST_FORMAT,
    type: "BitstringStatusList",
    id: STATUS_URL,
    issuer: orgDid,
    statusPurpose: "revocation",
    encodedList: await encodeStatusList(bits),
    issuedAtUnix: EXPORTED_AT - DAY,
    validUntilUnix: null,
    ttl: 86_400_000,
  },
  signerOf(org),
);
const entry = (index: number): StatusListEntry => ({
  type: "BitstringStatusListEntry",
  statusPurpose: "revocation",
  statusListIndex: String(index),
  statusListCredential: STATUS_URL,
});

// Predicates — Oreoasis apps/oreoasis-core-host/src/predicate.ts, signed with the
// Org key, canonical payload — plus the one field an issuer adopting the status
// list adds: `credentialStatus`.
async function predicate(answer: boolean, statusIndex: number): Promise<DsseEnvelope> {
  return signEnvelope(
    {
      spec: "oreoasis.predicate/1",
      kind: "cited-rule-in-force",
      establishment: "est-demo-1",
      rule: { id: "rule-demo-1", version: "3", hash: "a".repeat(64) },
      window: { from: "2026-07-01T00:00:00.000Z", to: "2026-08-01T00:00:00.000Z" },
      answer,
      justificationHash: "b".repeat(64),
      issuedAt: "2026-08-02T09:00:00.000Z",
      credentialStatus: entry(statusIndex),
    },
    "application/vnd.oreoasis.predicate+json",
    signerOf(org),
    { canonical: true },
  );
}
const predicateKept = await predicate(true, KEPT_INDEX);
const predicateRevoked = await predicate(true, REVOKED_INDEX);

// Indorania practice receipts — Indorania apps/site-indorania/lib/receipts.ts,
// signed with the visitor's own browser key. They attest a session in the
// model, never a real-world fact, and say so in their own payload.
const POSTURE = {
  simulated: true,
  attests: "session-in-model",
  note:
    "Indorania is an invented model of a country; this receipt is really signed. It attests the " +
    "integrity and continuity of what you did inside the model — never a real-world fact. The signing " +
    "key lives only in the visitor's browser and is never sent anywhere.",
};
const browserDid = didOf(browser);
const visa = await signEnvelope(
  {
    sessionId: "visa-01JB6DEMOSAMPLE0000000000",
    rows: [],
    dids: [{ did: browserDid, publicKeyHex: encodeHex(browser.publicKey) }],
    exportedAtIso: "2026-08-10T12:00:00.000Z",
    posture: POSTURE,
    visa: { persona: "maker", stamps: [{ path: "/regions/delta", label: "The delta", at: "2026-08-10T11:40:00.000Z" }], daysWorked: ["workshop"] },
  },
  "application/vnd.indorania.visa+json",
  signerOf(browser),
  { canonical: true },
);
const daySession = "day-workshop-01JB6DEMOSAMPLE00000000";
const dayRows: Record<string, unknown>[] = [];
let prev = GENESIS_PREV_HASH;
const events = [
  { ledger: "journey", line: "arrived at the workshop", scene: "gate", choice: "enter" },
  { ledger: "deed", line: "finished the bench", scene: "bench", choice: "sign" },
];
for (let i = 0; i < events.length; i++) {
  const payloadMutation = { ...events[i]! };
  const signature = await signLedgerBlock({ sessionId: daySession, stepIndex: i, actorDid: browserDid, previousBlockHash: prev, payloadMutation }, browser.privateKey);
  const cur = await chainBlockHash({ sessionId: daySession, stepIndex: i, actorDid: browserDid, payloadMutation, signature }, prev);
  dayRows.push({ sessionId: daySession, stepIndex: i, previousBlockHash: prev, currentTransactionBlockHash: cur, actorDid: browserDid, payloadMutation, signature, emittedAt: `2026-08-10T12:0${i}:00.000Z`, localId: i + 1 });
  prev = cur;
}
const day = await signEnvelope(
  {
    sessionId: daySession,
    rows: dayRows,
    dids: [{ did: browserDid, publicKeyHex: encodeHex(browser.publicKey) }],
    exportedAtIso: "2026-08-10T12:05:00.000Z",
    posture: POSTURE,
    day: { domain: "workshop", title: "A day at the workshop", completedAtIso: "2026-08-10T12:04:00.000Z" },
  },
  "application/vnd.indorania.day+json",
  signerOf(browser),
  { canonical: true },
);

// A Tehzeeb mark and its revocation — Indusland apps/web/lib/tehzeeb/mark.ts.
const markKid = `${indusPlatformDid}#sig-1`;
const markHeader = { typ: "indus.mark", v: 1, iss: indusPlatformDid, kid: markKid };
const markBody = {
  orgId: "00000000-0000-4000-8000-0000000000d2",
  service: "suroor",
  standardVersion: "1.0.0",
  standardHash: "c".repeat(64),
  issuedAt: "2026-03-01T00:00:00.000Z",
  expiresAt: "2027-03-01T00:00:00.000Z",
};
const mark = { header: markHeader, body: markBody, signature: await signEvent(markHeader, markBody, indusPlatform.privateKey, { dst: INDUS_MARK_DST, kid: markKid }) };
const revHeader = { typ: "indus.mark.revoke", v: 1, iss: indusPlatformDid, kid: markKid };
const revBody = {
  markId: "demo-mark-row-1",
  markSha256: await indusMarkDigest(mark as never),
  reasonSha256: await sha256Hex(enc.encode("sample reason — the text stays with the business")),
  revokedAt: "2026-06-15T10:00:00.000Z",
};
const revocation = { header: revHeader, body: revBody, signature: await signEvent(revHeader, revBody, indusPlatform.privateKey, { dst: INDUS_MARK_REVOKE_DST, kid: markKid }) };

// Key succession for the holder's platform relationship key — identity-server's
// claimCountersignKey shape: one body, signed by the prior and the successor.
const claimHeader = { typ: "key-claim", v: 1 };
const claimBody = { act: "claim-key", priorDid: didOf(relA), successorDid: didOf(relB), successorKeyCustody: "subject-generated", claimedAtUnix: T0 + 60 * DAY };
const keyClaim = {
  header: claimHeader,
  body: claimBody,
  signatures: {
    prior: await signEvent(claimHeader, claimBody, relA.privateKey, { dst: DST_KEY_CLAIM }),
    successor: await signEvent(claimHeader, claimBody, relB.privateKey, { dst: DST_KEY_CLAIM }),
  },
};

/* ── the trust list ────────────────────────────────────────────────────── */
const hexOfJwkX = (x: string): string => encodeHex(base64UrlToBytes(x));
const trustList = await signTrustList(
  {
    format: TRUST_LIST_FORMAT,
    listId: "kash-demo-trust",
    version: 1,
    publisher: didOf(publisher),
    issuedAtUnix: T0,
    validFromUnix: T0,
    validUntilUnix: T_UNTIL,
    issuers: [
      {
        issuerId: indusPlatformDid,
        label: "Travel platform (sample)",
        keys: [
          { keyid: ivfcKey.kid, alg: "Ed25519", publicKeyHex: hexOfJwkX(ivfcKey.x) },
          { keyid: BPS_KID, alg: "Ed25519", publicKeyHex: encodeHex(indusPlatform.publicKey) },
        ],
        dsts: ["indus.vfc.v1.cert", "indus.bps.v1.bpass", "indus.label.v1\n", INDUS_MARK_DST, INDUS_MARK_REVOKE_DST],
        validFromUnix: T0,
        validUntilUnix: T_UNTIL,
      },
      {
        issuerId: "venue-demo-1",
        label: "A mountain museum (sample)",
        keys: [{ keyid: VENUE_KID, alg: "Ed25519", publicKeyHex: encodeHex(venue.publicKey) }],
        dsts: ["indus.poe.v1.qr"],
        validFromUnix: T0,
        validUntilUnix: T_UNTIL,
      },
      {
        issuerId: orgDid,
        label: "A repair workshop (sample)",
        keys: [{ keyid: agentReceipt.keyid, alg: "Ed25519", publicKeyHex: agentReceipt.publicKeyHex }],
        dsts: ["application/vnd.oreoasis.predicate+json", "application/vnd.oreoasis.agent-receipt+json"],
        validFromUnix: T0,
        validUntilUnix: T_UNTIL,
      },
    ],
  },
  signerOf(publisher),
);

/* ── the export ────────────────────────────────────────────────────────── */
interface Spec {
  artifact: HeldArtifact;
  issuer: string;
  relationship: string | null;
  tag: string;
  family: "dsse-type" | "kash-event" | "indus";
  attestation: "countersigned" | "issuer-signed" | "device-asserted";
  receivedAtUnix: number;
  expiresAtUnix: number | null;
  retentionSource: "record" | "issuer-declared" | "none-declared";
  status: StatusListEntry | null;
  listing: "listed" | "unlisted";
  keptUnlistedAtUnix: number | null;
}
async function held(s: Spec): Promise<HeldRecord> {
  const manifest: HoldingManifest = {
    recordId: await recordIdOf(s.artifact),
    issuer: s.issuer,
    relationship: s.relationship,
    type: { tag: s.tag, family: s.family, attestation: s.attestation },
    receivedAtUnix: s.receivedAtUnix,
    expiresAtUnix: s.expiresAtUnix,
    retentionSource: s.retentionSource,
    status: s.status,
    listing: s.listing,
    keptUnlistedAtUnix: s.keptUnlistedAtUnix,
  };
  return { manifest, artifact: s.artifact };
}
const TWO_YEARS = 2 * YEAR;
const csCounterparty = countersignBundle.acceptances[0].body.countersignerDid as string;

const records: HeldRecord[] = [
  await held({ artifact: { kind: "indus-token", value: ipoe1 }, issuer: VENUE_KID, relationship: didOf(relVenue), tag: "indus.poe.v1.qr", family: "indus", attestation: "issuer-signed", receivedAtUnix: T0 + 30 * DAY, expiresAtUnix: T0 + 30 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: null, listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "indus-token", value: igeo1 }, issuer: DEVICE_KID, relationship: null, tag: "indus.poe.v1.geo", family: "indus", attestation: "device-asserted", receivedAtUnix: T0 + 31 * DAY, expiresAtUnix: T0 + 31 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: null, listing: "unlisted", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "indus-token", value: ivfc1 }, issuer: ivfcKey.kid, relationship: didOf(relB), tag: "indus.vfc.v1.cert", family: "indus", attestation: "issuer-signed", receivedAtUnix: T0 + 32 * DAY, expiresAtUnix: T0 + 32 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: null, listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "indus-token", value: ibps1 }, issuer: BPS_KID, relationship: didOf(relB), tag: "indus.bps.v1.bpass", family: "indus", attestation: "issuer-signed", receivedAtUnix: T0 + 35 * DAY, expiresAtUnix: T0 + 35 * DAY + YEAR, retentionSource: "issuer-declared", status: null, listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "dsse", value: agentReceipt.envelope }, issuer: agentReceipt.keyid, relationship: didOf(relOrg), tag: "application/vnd.oreoasis.agent-receipt+json", family: "dsse-type", attestation: "issuer-signed", receivedAtUnix: T0 + 50 * DAY, expiresAtUnix: T0 + 50 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: null, listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "dsse", value: workRecord.envelope }, issuer: workRecord.keyid, relationship: null, tag: "application/vnd.oreoasis.work-record+json", family: "dsse-type", attestation: "issuer-signed", receivedAtUnix: T0 + 51 * DAY, expiresAtUnix: null, retentionSource: "none-declared", status: null, listing: "unlisted", keptUnlistedAtUnix: T0 + 51 * DAY }),
  await held({ artifact: { kind: "dsse", value: predicateKept }, issuer: orgDid, relationship: didOf(relOrg), tag: "application/vnd.oreoasis.predicate+json", family: "dsse-type", attestation: "issuer-signed", receivedAtUnix: T0 + 214 * DAY, expiresAtUnix: T0 + 214 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: statusEntryOf({ credentialStatus: entry(KEPT_INDEX) }), listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "dsse", value: predicateRevoked }, issuer: orgDid, relationship: didOf(relOrg), tag: "application/vnd.oreoasis.predicate+json", family: "dsse-type", attestation: "issuer-signed", receivedAtUnix: T0 + 214 * DAY, expiresAtUnix: T0 + 214 * DAY + TWO_YEARS, retentionSource: "issuer-declared", status: statusEntryOf({ credentialStatus: entry(REVOKED_INDEX) }), listing: "listed", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "countersign-bundle", value: countersignBundle }, issuer: countersignBundle.request.body.requesterDid, relationship: csCounterparty, tag: countersignBundle.subject.payloadType, family: "dsse-type", attestation: "countersigned", receivedAtUnix: countersignBundle.acceptances[0].body.signedAtUnix, expiresAtUnix: null, retentionSource: "none-declared", status: null, listing: "unlisted", keptUnlistedAtUnix: countersignBundle.acceptances[0].body.signedAtUnix }),
  await held({ artifact: { kind: "dsse", value: visa }, issuer: browserDid, relationship: null, tag: "application/vnd.indorania.visa+json", family: "dsse-type", attestation: "device-asserted", receivedAtUnix: T0 + 221 * DAY, expiresAtUnix: null, retentionSource: "none-declared", status: null, listing: "unlisted", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "dsse", value: day }, issuer: browserDid, relationship: null, tag: "application/vnd.indorania.day+json", family: "dsse-type", attestation: "device-asserted", receivedAtUnix: T0 + 221 * DAY, expiresAtUnix: null, retentionSource: "none-declared", status: null, listing: "unlisted", keptUnlistedAtUnix: null }),
  await held({ artifact: { kind: "kash-event", value: mark }, issuer: indusPlatformDid, relationship: didOf(relB), tag: INDUS_MARK_DST, family: "kash-event", attestation: "issuer-signed", receivedAtUnix: T0 + 59 * DAY, expiresAtUnix: Math.floor(Date.parse(markBody.expiresAt) / 1000), retentionSource: "record", status: null, listing: "listed", keptUnlistedAtUnix: null }),
];

const heldKeys = [
  { keyid: DEVICE_KID, alg: "Ed25519" as const, publicKeyHex: encodeHex(device.publicKey), note: "the holder's own device key (IGEO1 check-ins)" },
  { keyid: workRecord.keyid, alg: "Ed25519" as const, publicKeyHex: workRecord.publicKeyHex, note: "the holder's own signing key as a doer (work records they signed)" },
];

const exportDoc: HolderExport = {
  formatVersion: "kashscript-holder-export/1",
  exportedAtUnix: EXPORTED_AT,
  records,
  keySuccession: [keyClaim as never],
  trustLists: [trustList],
  statusLists: [statusList],
  revocations: [revocation as never],
  heldKeys,
  encryptedKeyBackup: null,
};

/* ── the backup variant: a real JWE (RFC 7516 / 7518 PBES2) ────────────── */
const PASSPHRASE = "test vector only — never a real backup";
async function jweBackup(plaintext: string): Promise<HolderExport["encryptedKeyBackup"]> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const header = { alg: "PBES2-HS256+A128KW", enc: "A256GCM", p2s: bytesToBase64Url(salt), p2c: 100_000, cty: "application/json" };
  const protectedB64u = b64u(JSON.stringify(header));
  const saltInput = new Uint8Array([...enc.encode(header.alg), 0, ...salt]);
  const pass = await crypto.subtle.importKey("raw", enc.encode(PASSPHRASE), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: saltInput, iterations: header.p2c }, pass, { name: "AES-KW", length: 128 }, false, ["wrapKey"]);
  const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey("raw", cek, kek, "AES-KW"));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(protectedB64u), tagLength: 128 }, cek, enc.encode(plaintext)));
  return {
    protected: protectedB64u,
    encrypted_key: bytesToBase64Url(wrapped),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(sealed.slice(0, sealed.length - 16)),
    tag: bytesToBase64Url(sealed.slice(sealed.length - 16)),
  };
}
const backupPlaintext = JSON.stringify({
  keys: [
    { keyid: didOf(relB), alg: "Ed25519", privateKeyHex: encodeHex(relB.privateKey) },
    { keyid: DEVICE_KID, alg: "Ed25519", privateKeyHex: encodeHex(device.privateKey) },
  ],
});
const backupDoc: HolderExport = {
  ...exportDoc,
  records: records.filter((r) => r.artifact.kind === "indus-token" && r.manifest.type.tag === "indus.poe.v1.geo"),
  keySuccession: [],
  statusLists: [],
  revocations: [],
  heldKeys: heldKeys.filter((k) => k.keyid === DEVICE_KID),
  encryptedKeyBackup: await jweBackup(backupPlaintext),
};

/* ── write ─────────────────────────────────────────────────────────────── */
writeFileSync(join(DIR, "trust-list.v1.json"), JSON.stringify(trustList, null, 2) + "\n");
writeFileSync(join(DIR, "status-list.v1.json"), JSON.stringify(statusList, null, 2) + "\n");
// The two exports are written as their exact canonical bytes: one line, no trailing newline.
writeFileSync(join(DIR, "holder-export.v1.json"), serializeHolderExport(exportDoc));
writeFileSync(join(DIR, "holder-export-backup.v1.json"), serializeHolderExport(backupDoc));
console.log(`publisher (pin this): ${didOf(publisher)}`);
console.log(`org / status-list issuer: ${orgDid}`);
console.log(`records: ${records.length}; kept index ${KEPT_INDEX}, revoked index ${REVOKED_INDEX}`);
console.log(`mark digest check: ${canonicalJson(mark).length} bytes`);
