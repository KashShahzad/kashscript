/**
 * The practice receipt types the fixtures read. Each `vct` sits under
 * `practice.invalid`, a name that can never resolve, so no fixture can be
 * mistaken for a real credential type; the work record is Oreoasis's real,
 * registered type, and every fixture record says `practice` inside what is signed.
 */

import { isRegisteredDst, registerDst } from "@kashscript/attest/dst";

/** Oreoasis's work record (attest's registry). Client Sign-off's approvals are countersigned work records. */
export const WORK_RECORD_TYPE = "application/vnd.oreoasis.work-record+json" as const;

export const PRACTICE_VCT = {
  /** A language assessment from an independent assessor: `level` (CEFR), `language`, `framework`, `assessedOn`. */
  languageAssessment: "https://practice.invalid/vct/language-assessment/1",
  /** A campus's internship record: `weeks[].approvedOn` (each approved by the site supervisor), `finalReviewOn`, `hoursStated`. */
  internshipRecord: "https://practice.invalid/vct/internship-record/1",
  /** A provider's CPD record: `recordId` (the same in every copy), `hours`, `structured`, `completedOn`. */
  cpdRecord: "https://practice.invalid/vct/cpd-record/1",
  /** A payer's confirmation of a payment it made: `recordId`, `amount`, `currency`, `paidOn`. */
  paymentConfirmed: "https://practice.invalid/vct/payment-confirmed/1",
  /** A chamber's certificate of origin for a product: `countryOfOrigin` (ISO 3166-1 alpha-2), `issuedOn`. A product's, never a person's. */
  originCertificate: "https://practice.invalid/vct/certificate-of-origin/1",
} as const;

/**
 * Register the practice types at runtime, so a practice trust list may name
 * them (attest admits only registered types on a list). They are never added to
 * attest's own registry: they are practice, and say so.
 */
export function registerPracticeTypes(): void {
  for (const [name, tag] of Object.entries(PRACTICE_VCT)) {
    if (!isRegisteredDst(tag)) registerDst({ tag, owner: "@kashscript/predicate (practice fixtures)", family: "sd-jwt-vct", kind: `PRACTICE ONLY — the ${name} type KS-Q1's and KS-Q1b's fixtures read` });
  }
}

/** The dates every fixture is written against. */
export const PRACTICE_PUBLISHED = "2026-10-01T00:00:00Z";
export const PRACTICE_RENEW = "2027-09-30T00:00:00Z";
export const PRACTICE_ENDS = "2028-09-30T00:00:00Z";
export const PRACTICE_AS_OF = "2026-10-28T09:00:00Z";
