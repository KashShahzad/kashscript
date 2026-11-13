/**
 * Age-proof — selective disclosure flagship.
 *
 * Scenario: a university registrar issues a student-ID envelope that
 * commits to five fields about the student — legal name, date of birth,
 * CNIC, citizenship, and a derived `isOver18` boolean. The student
 * keeps the body + the per-field salts. When the student wants to
 * borrow from the adult-only section of the library, they create a
 * disclosure that reveals ONLY `isOver18 = true` and redacts the rest.
 *
 * The library verifies the disclosure against the registrar's public
 * key. It learns the student is 18+, but it learns nothing about the
 * actual birthday, name, CNIC, or citizenship. The Merkle commitment
 * + signature combination proves the registrar attested to that
 * particular `isOver18` value — the holder can't lie.
 *
 * Three layers exercised:
 *   1. Issuance — Registrar signs an envelope; cid is the Merkle root.
 *   2. Selective disclosure — Student reveals only `isOver18`.
 *   3. Verification — Library accepts; tampering fails.
 */

import { Signer } from "@kashscript/identity-core/signer";
import { encodeBase58 } from "@kashscript/identity-core/base58";
import {
  createBodyCommitment,
  createSelectiveDisclosure,
  signHeaderAttestation,
  verifySelectiveDisclosure,
  KASH_HEADER_ATTESTATION_DST,
  type BodyCommitment,
  type SelectiveDisclosure,
} from "@kashscript/identity-zkp/disclosure";
import type { SignedKashEvent, KashEventSignature } from "@kashscript/identity-core";

/* ─────────────────────────────────────────────────────────────────
 *  Body shape — what the registrar commits to
 * ───────────────────────────────────────────────────────────────── */

export interface StudentIdBody {
  /** Student's legal name. */
  readonly legalName: string;
  /** ISO date of birth — most-sensitive field. */
  readonly dateOfBirth: string;
  /** Pakistan CNIC — also sensitive. */
  readonly cnic: string;
  /** Citizenship — moderately sensitive. */
  readonly citizenship: string;
  /** Derived at issuance — true iff DOB ≥ 18 years from now.
   *  This is the one field the library needs to see. */
  readonly isOver18: boolean;
}

export interface IssuedStudentId {
  /** The signed envelope. Wire-shareable. */
  readonly event: SignedKashEvent;
  /** The full body — kept by the student, not transmitted. */
  readonly body: StudentIdBody;
  /** Per-field salts — kept by the student. Required to disclose. */
  readonly commitment: BodyCommitment;
  /**
   * Header-only attestation under DST kash-header-attestation-v1.
   * Closes GAP-ZKP-001: lets verifiers confirm issuer identity even
   * with redacted fields. Carried through on every disclosure the
   * student creates.
   */
  readonly headerAttestation: KashEventSignature;
  /** Registrar's public key — what verifiers check against. */
  readonly registrarPublicKey: Uint8Array;
}

/* ─────────────────────────────────────────────────────────────────
 *  Registrar — issues student IDs with selective-disclosure-ready
 *  commitments
 * ───────────────────────────────────────────────────────────────── */

export class Registrar {
  constructor(private readonly signer: Signer) {}

  get did(): string {
    return this.signer.did;
  }

  get publicKey(): Uint8Array {
    return this.signer.publicKey;
  }

  /**
   * Issue a student-ID envelope. Computes the Merkle root over the
   * body's five fields, packs it into `header.cid`, signs the
   * envelope, and returns everything the student needs to disclose.
   */
  async issue(body: StudentIdBody): Promise<IssuedStudentId> {
    const commitment = await createBodyCommitment(
      body as unknown as Record<string, unknown>,
    );
    const header = {
      did: this.signer.did,
      lexicon: "kash.education.student-id@1.0.0",
      iat: new Date().toISOString(),
      cid: encodeBase58(commitment.root),
    };
    const signature = await this.signer.sign(header, body);
    const event: SignedKashEvent = { header, body, signature };
    // GAP-ZKP-001 fix: mint a separate header-only attestation so
    // verifiers can confirm issuer identity even with redacted fields.
    const headerAttestation = await signHeaderAttestation(header, (h) =>
      this.signer.sign(h, {}, { dst: KASH_HEADER_ATTESTATION_DST }),
    );
    return {
      event,
      body,
      commitment,
      headerAttestation,
      registrarPublicKey: this.signer.publicKey,
    };
  }
}

/* ─────────────────────────────────────────────────────────────────
 *  StudentWallet — holds the issued ID; produces disclosures on
 *  request
 * ───────────────────────────────────────────────────────────────── */

export class StudentWallet {
  constructor(private readonly issued: IssuedStudentId) {}

  /** Create a disclosure that reveals only `isOver18` — the four
   *  sensitive fields (legalName, dateOfBirth, cnic, citizenship)
   *  appear in `redacted` as leaf-hash inclusion proofs. */
  async discloseAgeOnly(): Promise<SelectiveDisclosure> {
    return await createSelectiveDisclosure({
      event: this.issued.event,
      body: this.issued.body as unknown as Record<string, unknown>,
      salts: this.issued.commitment.salts,
      hiddenFields: ["legalName", "dateOfBirth", "cnic", "citizenship"],
      headerAttestation: this.issued.headerAttestation,
    });
  }

  /** Create a disclosure that reveals citizenship + isOver18 (e.g.,
   *  for a visa-restricted academic conference). The DOB + CNIC +
   *  name stay hidden. */
  async discloseCitizenshipAndAge(): Promise<SelectiveDisclosure> {
    return await createSelectiveDisclosure({
      event: this.issued.event,
      body: this.issued.body as unknown as Record<string, unknown>,
      salts: this.issued.commitment.salts,
      hiddenFields: ["legalName", "dateOfBirth", "cnic"],
      headerAttestation: this.issued.headerAttestation,
    });
  }
}

/* ─────────────────────────────────────────────────────────────────
 *  Library — verifies disclosures, checks that the registrar
 *  attested to the claimed value
 * ───────────────────────────────────────────────────────────────── */

export class AdultLibrary {
  constructor(private readonly trustedRegistrarPublicKey: Uint8Array) {}

  /** Returns true iff the disclosure validates AND reveals
   *  `isOver18 === true`. */
  async accepts(disclosure: SelectiveDisclosure): Promise<boolean> {
    const ok = await verifySelectiveDisclosure(
      disclosure,
      this.trustedRegistrarPublicKey,
    );
    if (!ok) return false;
    const isOver18Field = disclosure.disclosed["isOver18"];
    return isOver18Field?.value === true;
  }
}
