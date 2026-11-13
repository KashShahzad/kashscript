// ============================================================================
// @kashscript/whiffin/mandate — purpose-bound mandate domain types
// ----------------------------------------------------------------------------
// The data shapes of the mandate loop (ISSUE → DELIVER → REDEEM). Whiffin never
// moves money: payment happens on the payer's own rail, and arrival is proven by
// the recipient's countersignature (d41: two signatures or it is not proof).
// Types and the closed vocabularies they name. Money is INTEGER minor units
// (`Cents`); no float ever touches an amount. Ported from the duedale-core grant
// + program seeds (M4, ADR-0016).
//
// A `Grant` is the signed mandate: this value, for this purpose, within these
// limits, until this date, with arrival confirmed by this party (see
// credential.ts for the AP2 Intent Mandate view). Every mandate carries:
//   • its PURPOSE   — `purposeTag`, from the program's closed allow-list;
//   • its LIMITS    — a fixed `amountPaisa` and an approved-vendor Merkle root;
//   • its END DATE  — `expiryUnix`, REQUIRED (d43: every rule expires);
//   • its ARRIVAL   — `arrival`: who confirms, and that it takes two signatures.
// ============================================================================

import type { KashEventSignature } from "@kashscript/identity-core";
import type { Cents } from "../money";

/** did:kash identifier (branded `KashDid` at the signing layer). */
export type Did = string;
/** Unix epoch seconds (integer). */
export type UnixSeconds = number;

// JSON value vocabulary for metadata fields.
export type JsonPrimitive = string | number | boolean | null;
export type JsonObject = { readonly [key: string]: JsonValue };
export type JsonArray = readonly JsonValue[];
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

/**
 * Lifecycle of a single purpose-bound grant.
 *   ISSUED · DELIVERED · REDEEMED · EXPIRED
 *
 * Narrowed in 0.2.0: the three states that existed only while a licensed partner
 * held value are gone — under d41 whiffin holds nothing, so there is nothing to
 * pay out, return or recall (Duedale ADR-0019 made the same cut).
 * Reports signed under the wider 0.1.0 union keep verifying: a signature is
 * checked over the report's own JSON, never against this type.
 */
export const GRANT_LIFECYCLE_STATES = ["ISSUED", "DELIVERED", "REDEEMED", "EXPIRED"] as const;
export type GrantLifecycleState = (typeof GRANT_LIFECYCLE_STATES)[number];

/** Who authored a grant state transition. */
export type GrantActorClass =
  | "FUNDER"
  | "BENEFICIARY"
  | "VENDOR"
  | "PARTNER"
  | "PROTOCOL"
  | "RECONCILER";

/**
 * Who confirms that value arrived, and how many signatures make it proof.
 *
 * d41: two signatures or it is not proof — so `signatures` is the literal `2` and
 * a one-signature mandate cannot be expressed. `confirmedBy` is a ROLE, never a
 * DID: the recipient the mandate is already declared for. It names no one new,
 * and a mandate naming no confirmer by identity cannot become a list of who has
 * not confirmed. Confirming is never a condition of being paid (d27.3).
 */
export interface ArrivalClause {
  readonly confirmedBy: "RECIPIENT";
  readonly signatures: 2;
}

/**
 * The signed, purpose-bound grant — the wire artifact of the ISSUE step. Fixed
 * amount, bound to one beneficiary + one purpose + an approved vendor set (by
 * Merkle root), single-use (nonce), time-boxed (expiry). Signed over the
 * canonical bytes (RFC 8785) under a `kash-grant-v1` domain-separation tag.
 *
 * `arrival` is OPTIONAL on the type so a grant signed under 0.1.0 (which has
 * none) still verifies byte for byte; `issueGrant` writes it on every new grant.
 */
export interface Grant {
  readonly grantId: string;
  readonly programId: string;
  readonly funderDid: Did;
  readonly beneficiaryDid: Did;
  /** A code from the program's closed purpose allow-list (e.g. "GROCERY"). */
  readonly purposeTag: string;
  /** Merkle root (hex) of the approved vendor DID set; redemption supplies an inclusion proof. */
  readonly vendorAllowlistRoot: string;
  readonly amountPaisa: Cents;
  /** REQUIRED end date (unix seconds). A mandate with no end date cannot be issued (d43). */
  readonly expiryUnix: UnixSeconds;
  /** Single-use nonce; burned atomically at REDEEM to prevent double-spend. */
  readonly singleUseNonce: string;
  /** Who confirms arrival. Written by `issueGrant`; absent on grants signed under 0.1.0. */
  readonly arrival?: ArrivalClause;
}

/** A grant plus the operator's Ed25519 signature over its canonical bytes. */
export interface SignedGrant {
  readonly grant: Grant;
  readonly signature: KashEventSignature;
}

/** One append-only transition row in the grant lifecycle ledger. */
export interface GrantTransition {
  readonly grantId: string;
  readonly toState: GrantLifecycleState;
  readonly actorDid: Did;
  readonly actorClass: GrantActorClass;
  readonly reason: string;
  /** Optional app-semantic code (venture-supplied; neutral here). */
  readonly code: string | null;
  readonly atUnix: UnixSeconds;
}

/** A persisted grant: the signed artifact + its append-only transition history. */
export interface GrantRecord {
  readonly signed: SignedGrant;
  readonly state: GrantLifecycleState;
  readonly transitions: readonly GrantTransition[];
}

/** A funder's request to mint one grant in a program. */
export interface IssueRequest {
  readonly programId: string;
  readonly beneficiaryDid: string;
  /** Must be one of the program's SegmentPolicy.purposeCodes. */
  readonly purposeTag: string;
  readonly amountPaisa: Cents;
  /** Optional explicit end date; otherwise now + program.defaultExpirySeconds.
   *  Either way the issued grant always carries one — it must be in the future. */
  readonly expiryUnix?: UnixSeconds;
}

/** The result of a successful ISSUE. */
export interface IssueResult {
  readonly signed: SignedGrant;
  readonly record: GrantRecord;
}

// ----------------------------------------------------------------------------
// Program + SegmentPolicy — the policy-blind core
// ----------------------------------------------------------------------------
// One frozen, validated SegmentPolicy per program drives a POLICY-BLIND
// pipeline: no code downstream may read `segmentTag` to branch behaviour.
// `segmentTag` is a LABEL only — carried for reporting/analytics, never branched
// on. The venture supplies the policy CONTENT (fixtures); whiffin owns the type.

export type SegmentTag =
  | "ENTERPRISE"
  | "INSTITUTIONAL_GIVING"
  | "GOVERNMENT"
  | "SME_DIRECTED"
  | "DIASPORA";

export type FunderEntityType = "EMPLOYER" | "FOUNDATION" | "GOVERNMENT_BODY" | "FUND" | "INDIVIDUAL";
export type BeneficiaryEntityType = "EMPLOYEE" | "HOUSEHOLD" | "CITIZEN" | "SME" | "FAMILY_MEMBER";

/** How the approved-vendor set is expressed. Phase 1 implements ALLOWLIST. */
export type VendorRule = "ALLOWLIST" | "CATEGORY_MCC" | "SINGLE_VENDOR";
/** How a voucher binds to its beneficiary at redemption. */
export type BindingRule = "BENEFICIARY_DID" | "SMS_OTP" | "PASSKEY";

export interface ReportingProfile {
  readonly visibility: "PARTICIPANT_PRIVATE" | "FUNDER_VISIBLE" | "PUBLIC_AGGREGATE";
}

/** The frozen, validated policy record that drives one program's pipeline.
 *  `segmentTag` is a label only — the pipeline stays policy-blind. */
export interface SegmentPolicy {
  readonly programId: string;
  readonly segmentTag: SegmentTag;
  readonly funderEntityType: FunderEntityType;
  readonly beneficiaryEntityType: BeneficiaryEntityType;
  /** Closed allow-list of purpose codes a grant in this program may carry. */
  readonly purposeCodes: readonly string[];
  readonly vendorRule: VendorRule;
  readonly bindingRule: BindingRule;
  readonly reporting: ReportingProfile;
}

export type ProgramStatus = "ACTIVE" | "PAUSED" | "CLOSED";

/** A funder's configured mandate circuit. Invariant: `policy.programId === programId`. */
export interface Program {
  readonly programId: string;
  readonly funderDid: Did;
  readonly displayName: string;
  readonly policy: SegmentPolicy;
  /** Approved vendor DIDs — hashed into the grant's `vendorAllowlistRoot` at issue. */
  readonly approvedVendorDids: readonly Did[];
  /** Default voucher lifetime, applied when an issue request omits an expiry. */
  readonly defaultExpirySeconds: number;
  readonly status: ProgramStatus;
  readonly createdAtUnix: UnixSeconds;
}
