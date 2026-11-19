#!/usr/bin/env bun
/**
 * Writes the worked examples of the attestation profile into `specs/attestation/examples/` (RW-14).
 *
 * **Run once; never regenerated.** The keys are made fresh here and thrown away: only public keys, DIDs and
 * signed bytes are written, so the examples carry no key material (the public tree refuses it). SD-JWT salts
 * are random, so a second run would write different bytes — the test checks what was written, never re-runs
 * this. Everything is `practice: true`; every party is SAMPLE.
 *
 * *One exception, recorded:* regenerated once on 2026-11-19, inside RW-14 and before anything was exported or
 * published, when part two's review found that the first copies' `_sd` length and capped `exp` could join them
 * (specs/attestation/README.md §3 G1). From here the rule holds.
 *
 *   bun scripts/attestation-examples.ts            # refuses to overwrite an existing example
 *
 * The ceremony order is the spec's (§2.3): the record is made when the counterparty answers — the counterparty
 * signs the final bytes first, then the issuer (or its delegate) — so nothing names a counterparty before it
 * has answered. The decision example is predicate's (`packages/predicate/scripts/decision-example.ts`).
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../src/dsse";
import { signBytes } from "../src/signing";
import { issueSdJwt, presentSdJwt, verifySdJwt } from "../src/sd-jwt";
import { makeKeyResolver, type StatusListEntry } from "../src/holder";
import {
  ATTESTATION_DST,
  MANDATE_DST,
  checkAttestation,
  checkMandate,
  copyClaimsOf,
  payloadSha256,
  projectVc,
  verifyAttestationRecord,
  viewOfCopy,
  type AttestationBody,
  type MandateBody,
  type RecordCheckOptions,
} from "../src/attestation";

const OUT = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "examples");

type Party = KashKeyPair & { readonly did: string; readonly keyid: string };
async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  return { ...kp, did, keyid: did };
}

/** The examples' clock: copies issued on 2026-11-19, presented that morning. */
const ISSUED = Date.parse("2026-11-19T00:00:00Z") / 1000;
const PRESENTED = Date.parse("2026-11-19T09:30:00Z") / 1000;
const VERIFIER = "https://review-door.example/verifier";
const NOTE = "SAMPLE parties, practice only. Public identifiers; no key material.";
const status = (list: string, index: string): StatusListEntry => ({ type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: index, statusListCredential: list });

const json = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;

function write(dir: string, files: Record<string, string>): void {
  const d = join(OUT, dir);
  if (existsSync(d)) throw new Error(`${d} exists — the examples are generated once and never regenerated`);
  mkdirSync(d, { recursive: true });
  for (const [name, text] of Object.entries(files)) writeFileSync(join(d, name), text);
}

function must(name: string, r: { ok: boolean; faults: readonly { code: string; message: string }[] }): void {
  if (!r.ok) throw new Error(`${name} does not check: ${r.faults.map((f) => `${f.code} ${f.message}`).join("; ")}`);
}

/** The record of truth, in the spec's order: the counterparty's signer first, then the issuer's. Two entries over the same bytes. */
async function recordOf(body: AttestationBody, issuerSigner: Party, counterpartySigner?: Party): Promise<DsseEnvelope> {
  must("body", checkAttestation(body));
  const first = counterpartySigner ?? issuerSigner;
  let env = await signEnvelope(body, ATTESTATION_DST, first, { canonical: true });
  if (counterpartySigner !== undefined) {
    const sig = await signBytes(issuerSigner, pae(env.payloadType, base64ToBytes(env.payload)), "der");
    env = { ...env, signatures: [...env.signatures, { keyid: issuerSigner.keyid, sig: bytesToBase64(sig) }] };
  }
  return env;
}

async function checkedRecord(name: string, record: DsseEnvelope, opts: RecordCheckOptions = {}): Promise<string> {
  const r = await verifyAttestationRecord(record, opts);
  if (!r.ok || r.contentId === null) throw new Error(`${name}: the record does not check — ${r.problems.map((p) => `${p.code} ${p.message}`).join("; ")}`);
  return r.contentId;
}

async function mandateOf(body: MandateBody, principal: Party): Promise<DsseEnvelope> {
  must("mandate", checkMandate(body));
  return signEnvelope(body, MANDATE_DST, principal, { canonical: true });
}

/**
 * The two further forms of a record that checks: one copy for one verifier, issued by `issuer`, a presentation of
 * it that discloses `disclose`, and the VC 2.0 projection of what the verifier then sees.
 */
async function copyForms(name: string, record: DsseEnvelope, opts: RecordCheckOptions, issuer: Party, holderKey: Party, disclose: readonly string[]) {
  // No status entry on a copy (§2.4): its bit could be set only by an issuer that keeps which index is which record.
  const { claims, sdProperties, decoys } = await copyClaimsOf(record, { holderKey: holderKey.publicKey, iatUnix: ISSUED }, opts);
  const copy = await issueSdJwt({ header: { kid: issuer.did }, claims, sdProperties, decoys, signer: issuer });
  const nonce = `sample-nonce-${name}`;
  const presentation = await presentSdJwt(copy, (d) => d.name !== null && disclose.includes(d.name), holderKey, { aud: VERIFIER, nonce, iatUnix: PRESENTED });
  const seen = await verifySdJwt(presentation, { resolveKey: makeKeyResolver(new Map(), new Map()), requireKeyBinding: true, audience: VERIFIER, nonce, nowSec: PRESENTED + 60 });
  if (!seen.ok || seen.claims === null) throw new Error(`${name}: the presentation does not verify (${seen.reason})`);
  return {
    files: { "copy.sd-jwt.txt": `${copy}\n`, "presentation.sd-jwt.txt": `${presentation}\n`, "projection.vc.json": json(projectVc(viewOfCopy(seen.claims))) },
    presentation: { audience: VERIFIER, nonce, iatUnix: PRESENTED, disclosed: disclose, copyKey: holderKey.did },
  };
}

async function main(): Promise<void> {
  // ── Client Sign-off: an agency's delivery, accepted by the client company through one employee's seat ──
  const [agency, client, employee] = await Promise.all([party(), party(), party()]);
  const clientMandate: MandateBody = {
    id: `${client.did}/mandate/delivery-approvals`,
    principal: client.did,
    delegate: { key: employee.did, kind: "seat", role: "Product owner" },
    scope: { kinds: ["receipt"], outcomes: ["accepted", "not-yet"] },
    dates: { from: "2026-09-01T00:00:00Z", until: "2027-08-31T00:00:00Z" },
    credentialStatus: status("https://client.example/status/mandates", "61204"),
    practice: true,
  };
  const clientMandateRecord = await mandateOf(clientMandate, client);
  const clientMandateCitation = { id: clientMandate.id, hash: await payloadSha256(clientMandateRecord) };

  const signoff: AttestationBody = {
    issuer: agency.did,
    kind: "receipt",
    outcome: "accepted",
    reference: { kind: "artefact", sha256: "3f1c9a52e6b07d48a1e2c5f9b8d4a6017e3c2b9f5d8a1e4c7b0f3a6d9e2c5b81", version: 1 },
    statement: "Milestone 2 of the agreed website build: the booking form and its tests, delivered and accepted.",
    profile: "client-signoff/1",
    counterparty: client.did,
    counterpartyMandate: clientMandateCitation,
    grade: 1,
    claimedAt: "2026-11-16T14:30:00Z",
    expiresAt: "2031-11-16T14:30:00Z",
    credentialStatus: status("https://agency.example/status/records-2026-11", "48211"),
    practice: true,
  };
  const signoffRecord = await recordOf(signoff, agency, employee);
  const signoffSha = await checkedRecord("receipt-client-signoff", signoffRecord, { counterpartyMandate: clientMandateRecord });
  write("receipt-client-signoff", {
    "body.json": json(signoff),
    "record.dsse.json": json(signoffRecord),
    "counterparty-mandate.body.json": json(clientMandate),
    "counterparty-mandate.dsse.json": json(clientMandateRecord),
    "context.json": json({
      note: NOTE,
      issuer: agency.did,
      signers: { issuer: agency.did, counterparty: employee.did },
      counterparty: client.did,
      record: signoffSha,
      copies: "none — the agency holds its own sign-off, so a copy it issued would be its own word (d26). A door that needs the client's acceptance reads this record of truth (a kash-artifact query with attestation: countersigned), whose two signatures are the proof (§2.4).",
    }),
  });

  const notYet: AttestationBody = {
    issuer: agency.did,
    kind: "receipt",
    outcome: "not-yet",
    reference: { kind: "artefact", sha256: "8b2e4d6f1a3c5e7092b4d6f8a1c3e5079b2d4f6a8c1e3507a9c2e4f6b8d1a3c5", version: 1 },
    statement: "Milestone 3: the payment page. Not yet — the error states are missing.",
    profile: "client-signoff/1",
    counterparty: client.did,
    counterpartyMandate: clientMandateCitation,
    grade: 1,
    claimedAt: "2026-11-17T10:05:00Z",
    expiresAt: "2031-11-17T10:05:00Z",
    reasons: ["error-states-missing"],
    practice: true,
  };
  const notYetRecord = await recordOf(notYet, agency, employee);
  const notYetSha = await checkedRecord("receipt-not-yet", notYetRecord, { counterpartyMandate: clientMandateRecord });
  write("receipt-not-yet", {
    "body.json": json(notYet),
    "record.dsse.json": json(notYetRecord),
    "context.json": json({
      note: NOTE,
      issuer: agency.did,
      signers: { issuer: agency.did, counterparty: employee.did },
      counterparty: client.did,
      counterpartyMandate: "../receipt-client-signoff/counterparty-mandate.dsse.json",
      record: notYetSha,
      copies: "none — held by its parties; the reasons are the client's words, written when the client answered (§2.3).",
    }),
  });

  // ── A booking: the host's book issues, the guest accepts at grade 1 and keeps it ──
  const [host, guest, guestForReviewDoor, guestForAnotherDoor] = await Promise.all([party(), party(), party(), party()]);
  const terms = "a7c3e9f1b5d7a3c9e1f5b7d3a9c5e1f7b3d9a5c1e7f3b9d5a1c7e3f9b5d1a7c3";
  const booking: AttestationBody = {
    issuer: host.did,
    kind: "receipt",
    outcome: "accepted",
    reference: { kind: "agreement", sha256: terms, version: 1 },
    statement: "Two nights in the garden room, 14 to 16 November, delivered as booked.",
    profile: "booking.delivered/1",
    counterparty: guest.did,
    grade: 1,
    claimedAt: "2026-11-16T11:00:00Z",
    expiresAt: "2028-11-16T11:00:00Z",
    practice: true,
  };
  const bookingRecord = await recordOf(booking, host, guest);
  const bookingSha = await checkedRecord("receipt-booking", bookingRecord);
  const bookingForms = await copyForms("receipt-booking", bookingRecord, {}, host, guestForReviewDoor, []);
  write("receipt-booking", {
    "body.json": json(booking),
    "record.dsse.json": json(bookingRecord),
    ...bookingForms.files,
    "context.json": json({
      note: NOTE,
      issuer: host.did,
      signers: { issuer: host.did, counterparty: guest.did },
      counterparty: guest.did,
      record: bookingSha,
      presentation: bookingForms.presentation,
      checkAt: PRESENTED + 60,
    }),
  });

  // The host corrects the dates: a new record, both signatures, citing the first (d91(a): superseded by a citing attestation).
  const corrected: AttestationBody = {
    ...booking,
    statement: "Two nights in the garden room, 15 to 17 November, delivered as booked.",
    claimedAt: "2026-11-18T09:15:00Z",
    expiresAt: "2028-11-18T09:15:00Z",
    supersedes: bookingSha,
  };
  const correctedRecord = await recordOf(corrected, host, guest);
  const correctedSha = await checkedRecord("supersession", correctedRecord, { superseded: bookingRecord });
  const correctedForms = await copyForms("supersession", correctedRecord, { superseded: bookingRecord }, host, guestForAnotherDoor, ["supersedes"]);
  write("supersession", {
    "body.json": json(corrected),
    "record.dsse.json": json(correctedRecord),
    ...correctedForms.files,
    "context.json": json({
      note: NOTE,
      issuer: host.did,
      signers: { issuer: host.did, counterparty: guest.did },
      counterparty: guest.did,
      record: correctedSha,
      supersedes: "../receipt-booking/record.dsse.json",
      presentation: correctedForms.presentation,
      checkAt: PRESENTED + 60,
    }),
  });

  // ── A finding: an assessor's seat signs under the assessor's mandate; the doer countersigns and keeps it (d43) ──
  const [assessor, seat, doer, doerForEmployer] = await Promise.all([party(), party(), party(), party()]);
  const mandate: MandateBody = {
    id: `${assessor.did}/mandate/site-review-seat`,
    principal: assessor.did,
    delegate: { key: seat.did, kind: "seat", role: "Site reviewer" },
    scope: { kinds: ["finding"], outcomes: ["finding"] },
    dates: { from: "2026-11-01T00:00:00Z", until: "2027-10-31T00:00:00Z" },
    credentialStatus: status("https://assessor.example/status/mandates", "1907"),
    practice: true,
  };
  const mandateRecord = await mandateOf(mandate, assessor);
  const mandateSha = await payloadSha256(mandateRecord);
  write("mandate-seat", {
    "body.json": json(mandate),
    "record.dsse.json": json(mandateRecord),
    "context.json": json({ note: NOTE, principal: assessor.did, delegate: seat.did, record: mandateSha }),
  });

  const finding: AttestationBody = {
    issuer: assessor.did,
    kind: "finding",
    outcome: "finding",
    reference: { kind: "standard", id: "SAMPLE site safety standard, clause 4.2", version: 3, sha256: "c4a8e2f6b0d4a8c2e6f0b4d8a2c6e0f4b8d2a6c0e4f8b2d6a0c4e8f2b6d0a4c8" },
    statement: "The fire exit on the second floor was blocked by stock during the visit; cleared before the visit ended.",
    profile: "site-review/1",
    counterparty: doer.did,
    grade: 2,
    mandate: { id: mandate.id, hash: mandateSha },
    claimedAt: "2026-11-12T11:20:00Z",
    expiresAt: "2028-11-12T11:20:00Z",
    reasons: ["at-risk"],
    practice: true,
  };
  const findingRecord = await recordOf(finding, seat, doer);
  const findingSha = await checkedRecord("finding-under-mandate", findingRecord, { mandate: mandateRecord });
  const findingForms = await copyForms("finding-under-mandate", findingRecord, { mandate: mandateRecord }, assessor, doerForEmployer, ["statement", "mandate"]);
  write("finding-under-mandate", {
    "body.json": json(finding),
    "record.dsse.json": json(findingRecord),
    ...findingForms.files,
    "context.json": json({
      note: NOTE,
      issuer: assessor.did,
      signers: { issuer: seat.did, counterparty: doer.did },
      counterparty: doer.did,
      mandate: "../mandate-seat/record.dsse.json",
      record: findingSha,
      presentation: findingForms.presentation,
      checkAt: PRESENTED + 60,
    }),
  });

  console.log(`wrote the examples to ${OUT}`);
}

await main();
