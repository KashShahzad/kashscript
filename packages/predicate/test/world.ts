/**
 * A practice world for the door's tests: a hiring organisation, a freelancer
 * whose work clients countersigned, a listed language assessor, Oreoasis's
 * predicate issuer — real keys, real signatures, no network.
 */

import { deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "@kashscript/attest/chain";
import { COUNTERSIGN_BUNDLE_FORMAT, countersignRequestDigest, DST_COUNTERSIGN_ACCEPTANCE, DST_COUNTERSIGN_REQUEST, type CountersignBundle } from "@kashscript/attest/countersign";
import { pae, signEnvelope } from "@kashscript/attest/dsse";
import { base64ToBytes, bytesToBase64, signRaw } from "@kashscript/attest/ed25519";
import { issuePredicateCredential } from "@kashscript/attest/exchange";
import {
  createStatusBitstring,
  encodeStatusList,
  setStatusBit,
  signStatusList,
  signTrustList,
  STATUS_LIST_FORMAT,
  TRUST_LIST_FORMAT,
  verifyStatusList,
  verifyTrustList,
  makeKeyResolver,
  type StatusListReport,
  type TrustListReport,
} from "@kashscript/attest/holder";
import { issueSdJwt, jwkOf } from "@kashscript/attest/sd-jwt";
import { readRule, signRule, type ReadRule, type RuleBody } from "../src/rule";
import { hiringRule, PRACTICE_AS_OF, PRACTICE_VCT, registerPracticeTypes, WORK_RECORD_TYPE, type HiringParties } from "../src/fixtures";

export const DAY = 86_400;
export const AS_OF = PRACTICE_AS_OF;
export const T0 = Date.parse(AS_OF) / 1000;
export const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
export const dateOf = (unix: number): string => iso(unix).slice(0, 10);

export type Party = KashKeyPair & { readonly did: string; readonly keyid: string };

export async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

let counter = 0;
const rid = (): string => `rcpt_${(++counter).toString(16).padStart(26, "0")}`;

/** A Client Sign-off approval: the doer's work record, countersigned by the client. */
export async function workRecord(
  doer: Party,
  client: Party,
  opts: { readonly at: number; readonly stack: readonly string[]; readonly status?: "completed" | "stopped" },
): Promise<CountersignBundle> {
  const payload = {
    spec: "oreoasis.work-record/1",
    receiptId: rid(),
    actor: { class: "person", id: doer.did },
    shape: "accepted",
    action: { type: "milestone.accept", summary: "A practice milestone, accepted by the client." },
    inputs: [],
    outputs: [],
    status: opts.status ?? "completed",
    timestamp: iso(opts.at),
    meta: { stack: [...opts.stack], practice: true },
  };
  return countersigned(doer, client, payload, opts.at);
}

/**
 * Any work-record payload, signed by `signer` and countersigned by `accepter` — Client
 * Sign-off's two-signature shape, for tests whose records carry their own payload.
 */
export async function countersigned(signer: Party, accepter: Party, payload: Readonly<Record<string, unknown>>, at: number): Promise<CountersignBundle> {
  const subject = await signEnvelope(payload, WORK_RECORD_TYPE, signer, { canonical: true });
  const payloadBytes = base64ToBytes(subject.payload);
  const body = {
    requestId: `csr_${(counter++).toString(16).padStart(32, "0")}`,
    requesterDid: signer.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(payloadBytes),
    statement: "Accept this milestone.",
    disclosures: [],
    nonceB64: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
    issuedAtUnix: at,
    expiresAtUnix: at + 7 * DAY,
    relationshipContext: "practice",
    withdrawalFeed: null,
  };
  const reqHeader = { typ: "countersign-request", v: 1 };
  const request = { header: reqHeader, body, signature: await signEvent(reqHeader, body, signer.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
  const sig = await signRaw(pae(subject.payloadType, payloadBytes), accepter.privateKey, accepter.publicKey);
  const accBody = {
    act: "countersign" as const,
    requestId: body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: body.subjectDigestSha256,
    countersignerDid: accepter.did,
    keyCustody: "subject-generated" as const,
    signedAtUnix: at + 60,
  };
  const accHeader = { typ: "countersign", v: 1 };
  return {
    formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
    subject: { ...subject, signatures: [...subject.signatures, { keyid: accepter.did, sig: bytesToBase64(sig) }] },
    request,
    acceptances: [{ header: accHeader, body: accBody, signature: await signEvent(accHeader, accBody, accepter.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) }],
    withdrawal: null,
  };
}

/**
 * OA-V1's `booking.delivered/1`, shaped as Oreoasis's `composeBookingClaim` (written here,
 * never imported): the host's book signs and asks; the guest countersigns with a key for
 * this one relationship. The payload names only the host.
 */
export async function bookingDelivered(host: Party, guest: Party, opts: { readonly start: number; readonly end: number }): Promise<CountersignBundle> {
  const payload = {
    spec: "oreoasis.work-record/1",
    receiptId: "01JCPRACT1CE0B00K1NG0000" + (counter++ % 90 + 10).toString(),
    org: "practice-host",
    actor: { class: "organisation", id: host.did },
    shape: "accepted",
    action: { type: "booking.delivered", summary: "Delivered a booking under the agreement this record names." },
    inputs: [],
    outputs: [],
    status: "completed",
    timestamp: iso(opts.start + 3600),
    meta: {
      profile: "booking.delivered/1",
      reference: `kash-trade:0x${"ab".repeat(32)}`,
      door: "sabaat",
      listing: `${host.did}/listing/practice-room`,
      window: { start: iso(opts.start), end: iso(opts.end) },
    },
  };
  return countersigned(host, guest, payload, opts.start + 3600);
}

/** A second acceptance of the same request and bytes, by `accepter` — two countersigners. */
export async function withAcceptance(bundle: CountersignBundle, accepter: Party, at: number): Promise<CountersignBundle> {
  const payloadBytes = base64ToBytes(bundle.subject.payload);
  const sig = await signRaw(pae(bundle.subject.payloadType, payloadBytes), accepter.privateKey, accepter.publicKey);
  const accBody = {
    act: "countersign" as const,
    requestId: bundle.request.body.requestId,
    requestDigestSha256: await countersignRequestDigest(bundle.request),
    subjectPayloadType: bundle.subject.payloadType,
    subjectDigestSha256: bundle.request.body.subjectDigestSha256,
    countersignerDid: accepter.did,
    keyCustody: "subject-generated" as const,
    signedAtUnix: at,
  };
  const accHeader = { typ: "countersign", v: 1 };
  const signatures = bundle.subject.signatures.some((s) => s.keyid === accepter.did) ? bundle.subject.signatures : [...bundle.subject.signatures, { keyid: accepter.did, sig: bytesToBase64(sig) }];
  return {
    ...bundle,
    subject: { ...bundle.subject, signatures },
    acceptances: [...bundle.acceptances, { header: accHeader, body: accBody, signature: await signEvent(accHeader, accBody, accepter.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) }],
  };
}

export const STATUS_URL = "https://assessor.practice.invalid/status/1";

/** An assessor's language certificate, issued to one copy key. `level` and `assessedOn` are selectively disclosable. */
export async function englishCert(
  assessor: Party,
  copyKey: Party,
  opts: { readonly level?: string; readonly exp?: number; readonly statusIndex?: number } = {},
): Promise<string> {
  return issueSdJwt({
    header: { kid: assessor.did },
    claims: {
      iss: assessor.did,
      iat: T0 - 30 * DAY - ((T0 - 30 * DAY) % DAY),
      exp: opts.exp ?? T0 + 365 * DAY,
      vct: PRACTICE_VCT.languageAssessment,
      cnf: { jwk: jwkOf(copyKey.publicKey) },
      language: "en",
      framework: "CEFR",
      practice: true,
      ...(opts.statusIndex !== undefined
        ? { credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: String(opts.statusIndex), statusListCredential: STATUS_URL } }
        : {}),
    },
    sdProperties: { level: opts.level ?? "B2", assessedOn: dateOf(T0 - 30 * DAY) },
    decoys: 2,
    signer: assessor,
  });
}

/** Oreoasis's yes for one criterion of one rule version, to one copy key. */
export async function criterionPredicate(issuer: Party, copyKey: Party, rule: ReadRule, criterion: string, opts: { readonly windowTo?: number; readonly version?: string } = {}): Promise<string> {
  const to = opts.windowTo ?? T0 - DAY;
  return issuePredicateCredential({
    issuer,
    holderPublicKey: copyKey.publicKey,
    predicate: { kind: criterion, answer: true, rule: { id: rule.body.id, version: opts.version ?? String(rule.body.version), hash: rule.hash }, window: { from: iso(to - 730 * DAY), to: iso(to) } },
    restsOn: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
    credentialStatus: null,
    iatUnix: T0 - DAY,
    expUnix: T0 + 90 * DAY,
  });
}

export async function trustList(publisher: Party, listId: string, issuers: readonly { readonly did: string; readonly label: string; readonly dsts: readonly string[] }[]): Promise<TrustListReport> {
  const env = await signTrustList(
    {
      format: TRUST_LIST_FORMAT,
      listId,
      version: 1,
      publisher: publisher.did,
      issuedAtUnix: T0 - 10 * DAY,
      validFromUnix: T0 - 10 * DAY,
      validUntilUnix: T0 + 400 * DAY,
      issuers: issuers.map((i) => ({ issuerId: i.did, label: i.label, keys: [], dsts: [...i.dsts], validFromUnix: T0 - 10 * DAY, validUntilUnix: T0 + 400 * DAY })),
    },
    publisher,
  );
  return verifyTrustList(env, { pinnedPublishers: [publisher.did], nowSec: T0 });
}

export async function statusList(issuer: Party, revoked: readonly number[]): Promise<StatusListReport> {
  const bits = createStatusBitstring();
  for (const i of revoked) setStatusBit(bits, i, true);
  const env = await signStatusList(
    { format: STATUS_LIST_FORMAT, type: "BitstringStatusList", id: STATUS_URL, issuer: issuer.did, statusPurpose: "revocation", encodedList: await encodeStatusList(bits), issuedAtUnix: T0 - DAY, validUntilUnix: null },
    issuer,
  );
  return verifyStatusList(env, { resolveKey: makeKeyResolver(new Map(), new Map()), nowSec: T0 });
}

/** Everything the hiring tests need. */
export async function hiringWorld() {
  registerPracticeTypes();
  const [door, doer, oreoasis, assessor, publisher, stranger] = await Promise.all([party(), party(), party(), party(), party(), party()]);
  const clients = await Promise.all([party(), party(), party(), party()]);
  const parties: HiringParties = { author: door.did, predicateIssuer: oreoasis.did, assessorList: `${publisher.did}#assessors` };
  const body: RuleBody = hiringRule(parties);
  const rule = await readRule(await signRule(body, door));
  const list = await trustList(publisher, "assessors", [{ did: assessor.did, label: "A practice language assessor", dsts: [PRACTICE_VCT.languageAssessment] }]);
  const projects = [
    await workRecord(doer, clients[0]!, { at: T0 - 300 * DAY, stack: ["React", "TypeScript"] }),
    await workRecord(doer, clients[1]!, { at: T0 - 200 * DAY, stack: ["Go"] }),
    await workRecord(doer, clients[2]!, { at: T0 - 100 * DAY, stack: ["Python"] }),
  ];
  const old = await workRecord(doer, clients[3]!, { at: T0 - 900 * DAY, stack: ["React"] });
  return { door, doer, oreoasis, assessor, publisher, stranger, clients, parties, body, rule, list, projects, old };
}

export type HiringWorld = Awaited<ReturnType<typeof hiringWorld>>;
