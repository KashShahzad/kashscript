/**
 * Countersigned records for attest's own tests and the example script (RW-15): the engine's two-signature shape
 * (Duedale's since d99), written here and never imported from an engine — the signer's work record as a DSSE subject, the signer's (or
 * another requester's) request, the accepter's countersignature over the same bytes and its acceptance
 * Kash-Event. Practice parties, real keys, no network. The shape follows predicate's test world
 * (`packages/predicate/test/world.ts`) so both repositories' tests read the same records.
 */

import { deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "../../src/chain";
import { COUNTERSIGN_BUNDLE_FORMAT, countersignRequestDigest, DST_COUNTERSIGN_ACCEPTANCE, DST_COUNTERSIGN_REQUEST, type CountersignBundle, type KeyCustody } from "../../src/countersign";
import { pae, signEnvelope } from "../../src/dsse";
import { base64ToBytes, bytesToBase64, signRaw } from "../../src/ed25519";

/** The engine's work record type, registered in attest's registry; identifiers inside signed records keep their `oreoasis` name (d99). */
export const WORK_RECORD_TYPE = "application/vnd.oreoasis.work-record+json" as const;
export const DAY = 86_400;

export type Party = KashKeyPair & { readonly did: string; readonly keyid: string };

export async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

export const iso = (unix: number): string => new Date(unix * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

let counter = 0;

export interface CountersignOptions {
  /** The one plain sentence the counterparty reads. */
  readonly statement?: string;
  /** Who asks for the acceptance. Default: the signer. An organisation may ask on its doer's record. */
  readonly requester?: Party;
  /** Seconds after `at` the accepter signs. Default 60. */
  readonly acceptedAfterSec?: number;
  readonly keyCustody?: KeyCustody;
}

/**
 * Any work-record payload, signed by `signer`, asked for by the requester, and countersigned by `accepter` —
 * Client Sign-off's two-signature shape.
 */
export async function countersigned(signer: Party, accepter: Party, payload: Readonly<Record<string, unknown>>, at: number, opts: CountersignOptions = {}): Promise<CountersignBundle> {
  const requester = opts.requester ?? signer;
  const subject = await signEnvelope(payload, WORK_RECORD_TYPE, signer, { canonical: true });
  const payloadBytes = base64ToBytes(subject.payload);
  const body = {
    requestId: `csr_${(counter++).toString(16).padStart(32, "0")}`,
    requesterDid: requester.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(payloadBytes),
    statement: opts.statement ?? "Accept this record.",
    disclosures: [],
    nonceB64: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
    issuedAtUnix: at,
    expiresAtUnix: at + 7 * DAY,
    relationshipContext: "practice",
    withdrawalFeed: null,
  };
  const reqHeader = { typ: "countersign-request", v: 1 };
  const request = { header: reqHeader, body, signature: await signEvent(reqHeader, body, requester.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
  const sig = await signRaw(pae(subject.payloadType, payloadBytes), accepter.privateKey, accepter.publicKey);
  const accBody = {
    act: "countersign" as const,
    requestId: body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: body.subjectDigestSha256,
    countersignerDid: accepter.did,
    keyCustody: opts.keyCustody ?? ("subject-generated" as const),
    signedAtUnix: at + (opts.acceptedAfterSec ?? 60),
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

/** OA-V1's `booking.delivered/1`: the host's book signs and asks; the guest countersigns with a key for this one relationship. The payload names only the host. */
export async function bookingDelivered(host: Party, guest: Party, opts: { readonly start: number; readonly end: number; readonly practice?: boolean; readonly reference?: string }): Promise<CountersignBundle> {
  const payload = {
    spec: "oreoasis.work-record/1",
    receiptId: `01JCPRACT1CE0B00K1NG00${(counter++ % 90 + 10).toString()}`,
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
      reference: opts.reference ?? `kash-trade:0x${"ab".repeat(32)}`,
      door: "sabaat",
      listing: `${host.did}/listing/practice-room`,
      window: { start: iso(opts.start), end: iso(opts.end) },
      ...(opts.practice === true ? { practice: true } : {}),
    },
  };
  return countersigned(host, guest, payload, opts.start + 3600, { statement: "Accept this delivered booking." });
}

/** A Client Sign-off approval: the doer's work record, asked for by the agency, countersigned by the client. */
export async function clientSignoff(doer: Party, agency: Party, client: Party, opts: { readonly at: number; readonly status?: "completed" | "stopped" }): Promise<CountersignBundle> {
  const payload = {
    spec: "oreoasis.work-record/1",
    receiptId: `rcpt_${(counter++).toString(16).padStart(26, "0")}`,
    actor: { class: "person", id: doer.did },
    shape: "accepted",
    action: { type: "milestone.accept", summary: "A practice milestone, accepted by the client." },
    inputs: [],
    outputs: [],
    status: opts.status ?? "completed",
    timestamp: iso(opts.at),
    meta: { stack: ["React"], practice: true },
  };
  return countersigned(doer, client, payload, opts.at, { requester: agency, statement: "Accept this milestone." });
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
