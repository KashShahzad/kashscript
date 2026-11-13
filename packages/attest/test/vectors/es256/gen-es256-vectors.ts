/**
 * ES256, cross-algorithm succession and helper-quorum recovery — conformance
 * vectors for PL-2, generated ONCE and committed.
 *
 *   bun packages/attest/test/vectors/es256/gen-es256-vectors.ts
 *
 * Never regenerate: apart from the RFC 6979 key, every key below is fresh and
 * ECDSA signatures are randomised, so a second run changes every byte. See
 * README.md beside it. Everything here is a simulation (d11): no real person,
 * place or organisation, and only attest's own formats are sampled.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  createDidDocument,
  decodeBase58,
  decodeHex,
  deriveDid,
  deriveDidP256,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  encodeBase58,
  encodeHex,
  generateKeyPair,
  generateP256KeyPair,
  P256_ORDER,
  p256PublicKeyFromScalar,
  signEvent,
  signEventWith,
  type KashKeyPair,
  type P256KeyPair,
} from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64, bytesToBase64Url, base64UrlToBytes } from "../../../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../../../src/dsse";
import { sha256Hex } from "../../../src/chain";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  countersignRequestDigest,
  type CountersignBundle,
} from "../../../src/countersign";
import {
  approveKeyClaim,
  draftHelperClaim,
  signHelperSet,
  signKeyClaim,
  withApprovals,
  type SuccessionSigner,
} from "../../../src/succession";
import { signBytes } from "../../../src/signing";
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
  type HeldRecord,
  type HolderExport,
  type StatusListEntry,
} from "../../../src/holder";
import { issuePredicateCredential } from "../../../src/exchange/predicate";
import { PREDICATE_VCT } from "../../../src/exchange/constants";
import { presentSdJwt } from "../../../src/sd-jwt/sd-jwt";

const DIR = import.meta.dir;
const T0 = 1_790_812_800; // 2026-10-01T00:00:00Z
const DAY = 86_400;
const YEAR = 365 * DAY;
const write = (name: string, value: unknown): void =>
  writeFileSync(join(DIR, name), typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`);

/* ── keys ──────────────────────────────────────────────────────────────── */

/** RFC 6979 §A.2.5's P-256 key. Its scalar is published — a test key, never a real one. */
const RFC6979_D = decodeHex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
const rfc6979: P256KeyPair = { privateKey: RFC6979_D, publicKey: await p256PublicKeyFromScalar(RFC6979_D) };

const p = async () => {
  const k = await generateP256KeyPair();
  return { ...k, did: deriveDidP256(k.publicKey) };
};
const e = async () => {
  const k = await generateKeyPair();
  return { ...k, did: deriveDid(k.publicKey) };
};
type PKey = P256KeyPair & { did: string };
type EKey = KashKeyPair & { did: string };
const es = (k: PKey) => ({ alg: "ES256" as const, keyid: k.did, did: k.did, privateKey: k.privateKey, publicKey: k.publicKey });
const ed = (k: EKey) => ({ keyid: k.did, did: k.did, privateKey: k.privateKey, publicKey: k.publicKey });
const succP = (k: PKey): SuccessionSigner => ({ alg: "es256", did: k.did, privateKey: k.privateKey, publicKey: k.publicKey });
const succE = (k: EKey): SuccessionSigner => ({ alg: "ed25519", did: k.did, privateKey: k.privateKey });

const issuer = await p(); // a practice records desk, its key in a P-256 key store
const publisher = await p(); // a practice trust-list publisher, P-256
const holderCopy = await p(); // the holder's copy key for one verifier — a phone's secure chip
const requester = await e(); // a countersign requester, Ed25519 as before PL-2
const countersigner = await p(); // a counterparty signing from a phone's secure chip
const relOld = await e(); // the holder's relationship key on the LOST phone — Ed25519
const relNew = await p(); // its successor on the new phone — P-256 in hardware
const relB = await p(); // another relationship key, rotated voluntarily…
const relBNext = await e(); // …to Ed25519: succession runs either way
const [h1, h2, h3] = [await p(), await e(), await e()]; // helper keys for relOld's place — either type
const [h4, h5, h6] = [await e(), await p(), await e()]; // fresh helper keys for relNew's place — never reused

/* ── 1. the P-256 did:kash ─────────────────────────────────────────────── */

const rfcDid = deriveDidP256(rfc6979.publicKey);
write("did-p256.v1.json", {
  note: "RFC 6979 §A.2.5's P-256 test key. Its private scalar is published in the RFC; never use it for anything real.",
  privateScalarHex: encodeHex(RFC6979_D),
  publicKeyCompressedHex: encodeHex(rfc6979.publicKey),
  did: rfcDid,
  didDocument: createDidDocument({ did: rfcDid, publicKey: rfc6979.publicKey, pdsEndpoint: "https://pds.practice.invalid" }),
});

/* ── 2. an ES256 Kash-Event ────────────────────────────────────────────── */

const eventHeader = { iss: rfcDid, typ: "practice-record", v: 1 };
const eventBody = { what: "a practice record, signed ES256", at: T0 };
const eventSig = await signEventWith(eventHeader, eventBody, { alg: "es256", privateKey: rfc6979.privateKey, publicKey: rfc6979.publicKey }, { kid: `${rfcDid}#sig-1` });
const kashEvent = { header: eventHeader, body: eventBody, signature: eventSig };
write("kash-event-es256.v1.json", kashEvent);

/* ── 3. ES256 DSSE: a trust list and a status list, signed with P-256 ─── */

const STATUS_URL = "https://records.practice.invalid/status/es256-1";
const bits = createStatusBitstring();
setStatusBit(bits, 70411, true); // one revoked copy; the held one (index 3209) is clear
const statusList = await signStatusList(
  {
    format: STATUS_LIST_FORMAT,
    type: "BitstringStatusList",
    id: STATUS_URL,
    issuer: issuer.did,
    statusPurpose: "revocation",
    encodedList: await encodeStatusList(bits),
    issuedAtUnix: T0,
    validUntilUnix: T0 + 30 * DAY,
  },
  es(issuer),
);
write("status-list-es256.v1.json", statusList);

const trustList = await signTrustList(
  {
    format: TRUST_LIST_FORMAT,
    listId: "practice-es256-list",
    version: 1,
    publisher: publisher.did,
    issuedAtUnix: T0,
    validFromUnix: T0,
    validUntilUnix: T0 + YEAR,
    issuers: [
      { issuerId: issuer.did, label: "A practice records desk", keys: [], dsts: [PREDICATE_VCT, "kash-record-v1\n"], validFromUnix: T0, validUntilUnix: T0 + YEAR },
    ],
  },
  es(publisher),
);
write("trust-list-es256.v1.json", trustList);

/* ── 4. an ES256 SD-JWT VC with an ES256 key binding ──────────────────── */

const entry: StatusListEntry = { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "3209", statusListCredential: STATUS_URL };
const heldPredicate = await issuePredicateCredential({
  issuer: es(issuer),
  holderPublicKey: { type: "P-256", publicKey: holderCopy.publicKey },
  predicate: {
    kind: "practice-visits",
    answer: true,
    rule: { id: "practice-rule", version: "1", hash: "0".repeat(64) },
    window: { from: "2026-07-01", to: "2026-09-30" },
  },
  restsOn: ["a".repeat(64), "b".repeat(64)],
  credentialStatus: entry,
  iatUnix: T0 - 2 * DAY,
  expUnix: T0 + YEAR,
});
const presentation = await presentSdJwt(heldPredicate, () => false, { alg: "ES256", privateKey: holderCopy.privateKey, publicKey: holderCopy.publicKey }, {
  aud: "https://verifier.practice.invalid",
  nonce: "nonce-es256-5d1c",
  iatUnix: T0 + 3600,
});
write("predicate-held-es256.v1.txt", heldPredicate);
write("predicate-presentation-es256.v1.txt", presentation);
write("context.v1.json", {
  nowSec: T0 + 7200,
  audience: "https://verifier.practice.invalid",
  nonce: "nonce-es256-5d1c",
  trustPublisher: publisher.did,
  holder: deriveDidP256(holderCopy.publicKey),
  issuer: issuer.did,
});

/* ── 5. a countersign bundle with a P-256 countersigner, and claims both ways ── */

const subjectPayload = { practice: "a delivery, accepted", at: T0 };
// The same subject type as the countersign fixture: a countersigned thing keeps its own payloadType.
const subject1 = await signEnvelope(subjectPayload, "application/vnd.example.delivery+json", ed(requester), { canonical: true });
const subjectType = subject1.payloadType;
const payloadBytes = base64ToBytes(subject1.payload);
const subjectDigest = await sha256Hex(payloadBytes);
const requestBody = {
  requestId: `csr_${"5".repeat(32)}`,
  requesterDid: requester.did,
  subjectPayloadType: subjectType,
  subjectDigestSha256: subjectDigest,
  statement: "A practice delivery was accepted.",
  disclosures: [],
  nonceB64: bytesToBase64(new Uint8Array(32).fill(7)),
  issuedAtUnix: T0,
  expiresAtUnix: T0 + 14 * DAY,
  relationshipContext: "",
  withdrawalFeed: null,
};
const requestHeader = { typ: "countersign-request", v: 1 };
const request = { header: requestHeader, body: requestBody, signature: await signEvent(requestHeader, requestBody, requester.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
const counterSig = await signBytes(es(countersigner), pae(subjectType, payloadBytes), "der");
const subject: DsseEnvelope = { ...subject1, signatures: [...subject1.signatures, { keyid: countersigner.did, sig: bytesToBase64(counterSig) }] };
const acceptanceBody = {
  act: "countersign" as const,
  requestId: requestBody.requestId,
  requestDigestSha256: await countersignRequestDigest(request),
  subjectPayloadType: subjectType,
  subjectDigestSha256: subjectDigest,
  countersignerDid: countersigner.did,
  keyCustody: "subject-generated" as const,
  signedAtUnix: T0 + 600,
};
const acceptanceHeader = { typ: "countersign", v: 1 };
const acceptance = {
  header: acceptanceHeader,
  body: acceptanceBody,
  signature: await signEventWith(acceptanceHeader, acceptanceBody, succP(countersigner), { dst: DST_COUNTERSIGN_ACCEPTANCE }),
};
const requesterNext = await p();
const countersignerNext = await e();
const bundle: CountersignBundle = {
  formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
  subject,
  request,
  acceptances: [acceptance],
  withdrawal: null,
  keyClaims: [
    await signKeyClaim({ prior: succE(requester), successor: succP(requesterNext), claimedAtUnix: T0 + DAY }), // Ed25519 → P-256
    await signKeyClaim({ prior: succP(countersigner), successor: succE(countersignerNext), claimedAtUnix: T0 + DAY }), // P-256 → Ed25519
  ],
};
write("countersign-es256.v1.json", bundle);

/* ── 6. recovery: a helper set signed in advance, and a 2-of-3 claim ───── */

const helperSet = await signHelperSet({ subject: succE(relOld), helpers: [h1.did, h2.did, h3.did], need: 2, sequence: 1, issuedAtUnix: T0 - 60 * DAY });
const draft = await draftHelperClaim({ helperSet, successor: succP(relNew), claimedAtUnix: T0 });
const recovered = withApprovals(draft, [await approveKeyClaim(draft, succP(h1)), await approveKeyClaim(draft, succE(h3))]);
write("succession-helpers.v1.json", {
  note: "relOld (Ed25519, on a lost phone) named three helper keys in advance; two of them and the new P-256 key moved its authority.",
  helpers: [h1.did, h2.did, h3.did],
  claim: recovered,
});

/* ── 7. a holder export carrying it all ───────────────────────────────── */

const recordValue = await (async () => {
  const header = { iss: issuer.did, typ: "practice-record", v: 1 };
  const body = { what: "a practice visit, recorded by the desk", at: T0 - DAY, expiresAtUnix: T0 + YEAR };
  return { header, body, signature: await signEventWith(header, body, succP(issuer)) };
})();
const records: HeldRecord[] = [
  {
    manifest: {
      recordId: await recordIdOf({ kind: "kash-event", value: recordValue }),
      issuer: issuer.did,
      relationship: relOld.did,
      type: { tag: "kash-record-v1\n", family: "kash-event", attestation: "issuer-signed" },
      receivedAtUnix: T0 - DAY,
      expiresAtUnix: T0 + YEAR,
      retentionSource: "record",
      status: null,
      listing: "listed",
      keptUnlistedAtUnix: null,
    },
    artifact: { kind: "kash-event", value: recordValue },
  },
  {
    manifest: {
      recordId: await recordIdOf({ kind: "sd-jwt", value: heldPredicate }),
      issuer: issuer.did,
      relationship: deriveDidP256(holderCopy.publicKey),
      type: { tag: PREDICATE_VCT, family: "sd-jwt-vct", attestation: "issuer-signed" },
      receivedAtUnix: T0 - 2 * DAY,
      expiresAtUnix: T0 + YEAR,
      retentionSource: "record",
      status: entry,
      listing: "listed",
      keptUnlistedAtUnix: null,
    },
    artifact: { kind: "sd-jwt", value: heldPredicate },
  },
];
const newSet = await signHelperSet({ subject: succP(relNew), helpers: [h4.did, h5.did, h6.did], need: 2, sequence: 1, issuedAtUnix: T0 + 60 });
const rotation = await signKeyClaim({ prior: succP(relB), successor: succE(relBNext), claimedAtUnix: T0 + 120 });
const exp: HolderExport = {
  formatVersion: "kashscript-holder-export/1",
  exportedAtUnix: T0 + 3600,
  records,
  keySuccession: [recovered, rotation],
  trustLists: [trustList],
  statusLists: [statusList],
  revocations: [],
  heldKeys: [],
  encryptedKeyBackup: null,
  recoveryHelpers: [{ counterparty: "https://records.practice.invalid", helperSet: newSet }],
};
write("holder-export-es256.v1.json", serializeHolderExport(exp));

/* ── 8. negatives — each must fail, for the reason named ──────────────── */

const flipS = (raw: Uint8Array): Uint8Array => {
  const s = BigInt(`0x${encodeHex(raw.subarray(32))}`);
  const out = raw.slice();
  out.set(decodeHex((P256_ORDER - s).toString(16).padStart(64, "0")), 32);
  return out;
};
const highEvent = { ...kashEvent, signature: { ...eventSig, sig: `z${encodeBase58(flipS(decodeBase58(eventSig.sig.slice(1))))}` } };
const tlSig = base64ToBytes(trustList.signatures[0]!.sig);
const tlHigh = { ...trustList, signatures: [{ keyid: publisher.did, sig: bytesToBase64(ecdsaRawToDer(flipS(ecdsaDerToRaw(tlSig)))) }] };
const padded = (() => {
  // r gains a needless 0x00: same number, non-minimal DER.
  const raw = ecdsaDerToRaw(tlSig);
  const der = ecdsaRawToDer(raw);
  const rLen = der[3]!;
  const r = der.subarray(4, 4 + rLen);
  const rest = der.subarray(4 + rLen);
  const out = new Uint8Array(der.length + 1);
  out.set([0x30, der[1]! + 1, 0x02, rLen + 1, 0x00], 0);
  out.set(r, 5);
  out.set(rest, 5 + rLen);
  return out;
})();
const tlPadded = { ...trustList, signatures: [{ keyid: publisher.did, sig: bytesToBase64(padded) }] };
const parts = presentation.split("~");
const kb = parts[parts.length - 1]!.split(".");
const kbHigh = [...parts.slice(0, -1), [kb[0], kb[1], bytesToBase64Url(flipS(base64UrlToBytes(kb[2]!)))].join(".")].join("~");
const edKey = await e();
const edUnderP256 = { ...trustList, signatures: [{ keyid: publisher.did, sig: bytesToBase64(await signBytes(ed(edKey), pae(trustList.payloadType, base64ToBytes(trustList.payload)), "der")) }] };
const esUnderEd = await (async () => {
  const env = await signEnvelope({ practice: "an ES256 signature under an Ed25519 keyid" }, "application/vnd.example.delivery+json", es(issuer), { canonical: true });
  return { ...env, signatures: [{ keyid: edKey.did, sig: env.signatures[0]!.sig }] };
})();
const oneHelper = withApprovals(draft, [await approveKeyClaim(draft, succP(h1))]);
const forgedSet = await (async () => {
  // claims to be relOld's set, but h1 signed it
  const body = { ...helperSet.body };
  return { header: helperSet.header, body, signature: await signEventWith(helperSet.header, body, succP(h1), { dst: "kash-recovery-helpers-v1\n" }) };
})();
const forgedDraft = await draftHelperClaim({ helperSet: forgedSet, successor: succP(relNew), claimedAtUnix: T0 });
const onForged = withApprovals(forgedDraft, [await approveKeyClaim(forgedDraft, succP(h1)), await approveKeyClaim(forgedDraft, succE(h2))]);
const thief = await p();
const forkDraft = await draftHelperClaim({ helperSet, successor: succP(thief), claimedAtUnix: T0 + 30 });
const forkClaim = withApprovals(forkDraft, [await approveKeyClaim(forkDraft, succE(h2)), await approveKeyClaim(forkDraft, succE(h3))]);
write("negative.v1.json", {
  note: "Each case must FAIL. The P-256 public keys are inside the did:kash identifiers.",
  kashEventHighS: { event: highEvent, publicKeyCompressedHex: encodeHex(rfc6979.publicKey), expect: "false: high-S" },
  dsseHighS: { envelope: tlHigh, publisher: publisher.did, expect: "TRUST_LIST_SIGNATURE_INVALID" },
  dsseNonMinimalDer: { envelope: tlPadded, publisher: publisher.did, expect: "TRUST_LIST_SIGNATURE_INVALID" },
  kbJwtHighS: { presentation: kbHigh, expect: "KEY_BINDING_INVALID" },
  ed25519SignatureUnderP256Did: { envelope: edUnderP256, publisher: publisher.did, expect: "TRUST_LIST_SIGNATURE_INVALID" },
  es256SignatureUnderEd25519Did: { envelope: esUnderEd, keyid: edKey.did, expect: "no keyid verifies" },
  belowQuorum: { claim: oneHelper, expect: "BELOW_QUORUM" },
  helperSetNotSignedByPrior: { claim: onForged, expect: "HELPER_SET_INVALID" },
  fork: { claims: [recovered, forkClaim], expect: "conflict; signedBoth names h3", h3: h3.did },
});

console.log("wrote ES256 vectors to", DIR);
