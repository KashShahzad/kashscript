// ============================================================================
// @kashscript/whiffin/credential — mandates as W3C Verifiable Credentials
// with AP2 mandate semantics.
// ----------------------------------------------------------------------------
// Conforms to the W3C Verifiable Credentials Data Model 2.0 (@context, type,
// issuer, validFrom/validUntil, credentialSubject, proof) and the Agent Payments
// Protocol (AP2) mandate model — web-verified, not invented:
//
//   • Intent Mandate (human-not-present): pre-approved conditions authorizing an
//     agent to act later. The purpose-bound GRANT IS an Intent Mandate — a fixed
//     max amount, a purpose lock, an allowed-vendor set, an expiry/TTL, a nonce.
//   • Cart Mandate (human-present): the merchant-signed cart the user approves —
//     the basis of offer → receipt → dispute.
//
// AP2 signs mandates "ECDSA over P-256 (or stronger)"; Ed25519 satisfies that.
// The credential's `proof` embeds the EXISTING Kash-Event Ed25519 signature (no
// new crypto): the proof is over the underlying grant/cart canonical bytes, and
// the credential carries every field so the artifact reconstructs losslessly.
//
// EVERY MANDATE EXPIRES (d43). `validUntil` is required, and the verifier checks
// it against the signed `expiryUnix` — the ISO strings are a view, and a view
// that could drift from the signed bytes would let a holder show a longer life
// than the issuer granted. A mandate also states who confirms arrival (d41).
// ============================================================================

import { signEvent, verifyEvent } from "@kashscript/identity-core";
import type { KashEventSignature, SignedKashEvent } from "@kashscript/identity-core";

import { GRANT_DST, isArrivalClause, verifyGrant } from "./mandate/grant";
import type { ArrivalClause, Grant, SignedGrant } from "./mandate/types";

/** W3C VC 2.0 base context. */
export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
/** The KashScript mandate vocabulary (bare host — never `www.`, per protocol-id rule). */
export const MANDATE_CONTEXT = "https://kashscript.com/ns/mandate/v1";
/** Domain-separation tag for cart-mandate Kash-Events (distinct from grants). */
export const CART_DST = "kash-cart-v1\n";

// ----------------------------------------------------------------------------
// Credential shapes (W3C VC 2.0)
// ----------------------------------------------------------------------------

/** A Data-Integrity-style proof embedding the Kash-Event Ed25519 signature. */
export interface KashEventProof {
  readonly type: "KashEventSignature2026";
  readonly cryptosuite: "ed25519-jcs-2026";
  readonly created: string;
  readonly verificationMethod: string;
  readonly proofPurpose: "assertionMethod";
  /** The domain-separation tag the signature was scoped under. */
  readonly domainSeparationTag: string;
  /** The identity-core Kash-Event signature over the artifact's canonical bytes. */
  readonly proofValue: KashEventSignature;
}

/** AP2 Intent Mandate constraints — the pre-approved conditions. */
export interface IntentMandateConstraints {
  readonly maxAmountPaisa: number;
  readonly currency: string;
  /** Merkle root of the allowed vendor/merchant set. */
  readonly allowedVendorsRoot: string;
  /** Human/interop expiry (ISO 8601). */
  readonly expiry: string;
  /** Exact expiry (unix seconds) — used for lossless grant reconstruction. */
  readonly expiryUnix: number;
  readonly singleUseNonce: string;
  /** Who confirms arrival (d41). Absent on credentials issued under 0.1.0. */
  readonly arrival?: ArrivalClause;
}

export interface IntentMandateSubject {
  /** The subject/holder — the beneficiary DID. */
  readonly id: string;
  readonly mandateType: "IntentMandate";
  readonly grantId: string;
  readonly programId: string;
  /** The purpose lock (grant.purposeTag). */
  readonly purpose: string;
  /** The funder DID authorizing the mandate. */
  readonly funder: string;
  readonly constraints: IntentMandateConstraints;
}

export interface CartLineItem {
  readonly sku: string;
  readonly amountPaisa: number;
  readonly qty: number;
}

export interface CartMandateSubject {
  /** The subject/holder — the payer DID. */
  readonly id: string;
  readonly mandateType: "CartMandate";
  readonly cartId: string;
  readonly merchant: string;
  readonly items: readonly CartLineItem[];
  readonly totalPaisa: number;
  readonly currency: string;
  readonly expiry: string;
  readonly expiryUnix: number;
  readonly nonce: string;
}

export type MandateCredentialSubject = IntentMandateSubject | CartMandateSubject;

/** A mandate expressed as a W3C Verifiable Credential (2.0). */
export interface MandateCredential {
  readonly "@context": readonly string[];
  readonly id?: string;
  readonly type: readonly string[];
  readonly issuer: string;
  readonly validFrom: string;
  /** REQUIRED (d43: every rule expires). Must equal the signed `expiryUnix`. */
  readonly validUntil: string;
  readonly credentialSubject: MandateCredentialSubject;
  readonly proof: KashEventProof;
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function toIso(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString();
}

function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

// ----------------------------------------------------------------------------
// Intent Mandate (grant) — express + verify
// ----------------------------------------------------------------------------

export interface ToMandateCredentialOptions {
  /** The issuer DID (the operator/grant-authority whose key signed the grant). */
  readonly issuer: string;
  /** ISO currency label for the max-amount constraint (default "PKR"). */
  readonly currency?: string;
  /** `validFrom` (unix seconds); defaults to now. */
  readonly validFromUnix?: number;
  /** Optional credential `id`. */
  readonly id?: string;
}

/**
 * Express a signed grant as an AP2 Intent Mandate W3C Verifiable Credential.
 * The proof embeds the grant's existing `kash-grant-v1` Ed25519 signature; the
 * credentialSubject carries every grant field for lossless verification.
 */
export function toMandateCredential(signed: SignedGrant, opts: ToMandateCredentialOptions): MandateCredential {
  const g = signed.grant;
  const currency = opts.currency ?? "PKR";
  const subject: IntentMandateSubject = {
    id: g.beneficiaryDid,
    mandateType: "IntentMandate",
    grantId: g.grantId,
    programId: g.programId,
    purpose: g.purposeTag,
    funder: g.funderDid,
    constraints: {
      maxAmountPaisa: g.amountPaisa,
      currency,
      allowedVendorsRoot: g.vendorAllowlistRoot,
      expiry: toIso(g.expiryUnix),
      expiryUnix: g.expiryUnix,
      singleUseNonce: g.singleUseNonce,
      ...(g.arrival !== undefined ? { arrival: g.arrival } : {}),
    },
  };
  return {
    "@context": [VC_CONTEXT_V2, MANDATE_CONTEXT],
    ...(opts.id !== undefined ? { id: opts.id } : {}),
    type: ["VerifiableCredential", "MandateCredential", "IntentMandate"],
    issuer: opts.issuer,
    validFrom: toIso(opts.validFromUnix ?? nowUnix()),
    validUntil: toIso(g.expiryUnix),
    credentialSubject: subject,
    proof: {
      type: "KashEventSignature2026",
      cryptosuite: "ed25519-jcs-2026",
      created: toIso(opts.validFromUnix ?? nowUnix()),
      verificationMethod: `${opts.issuer}#grant-authority`,
      proofPurpose: "assertionMethod",
      domainSeparationTag: GRANT_DST,
      proofValue: signed.signature,
    },
  };
}

/** Reconstruct the exact `Grant` from an Intent Mandate credentialSubject. */
export function grantFromMandateCredential(subject: IntentMandateSubject): Grant {
  return {
    grantId: subject.grantId,
    programId: subject.programId,
    funderDid: subject.funder,
    beneficiaryDid: subject.id,
    purposeTag: subject.purpose,
    vendorAllowlistRoot: subject.constraints.allowedVendorsRoot,
    amountPaisa: subject.constraints.maxAmountPaisa,
    expiryUnix: subject.constraints.expiryUnix,
    singleUseNonce: subject.constraints.singleUseNonce,
    // Only when present: a 0.1.0 grant has no clause, and an `undefined` key would change the signed bytes.
    ...(subject.constraints.arrival !== undefined ? { arrival: subject.constraints.arrival } : {}),
  };
}

// ----------------------------------------------------------------------------
// Cart Mandate (offer → receipt → dispute) — sign, express, verify
// ----------------------------------------------------------------------------

/** The cart an AP2 Cart Mandate authorizes. */
export interface Cart {
  readonly cartId: string;
  readonly payerDid: string;
  readonly merchantDid: string;
  readonly items: readonly CartLineItem[];
  readonly totalPaisa: number;
  readonly currency: string;
  readonly expiryUnix: number;
  readonly nonce: string;
}

export interface SignedCart {
  readonly cart: Cart;
  readonly signature: KashEventSignature;
}

function cartHeader(cart: Cart): Readonly<Record<string, unknown>> {
  return { typ: "kash/cart", v: 1, cartId: cart.cartId };
}

/** Sign a cart as a Kash-Event under the cart DST (the merchant/user signature). */
export async function forgeCartMandate(cart: Cart, privateKey: Uint8Array): Promise<SignedCart> {
  const signature = await signEvent(cartHeader(cart), cart, privateKey, { dst: CART_DST });
  return { cart, signature };
}

/** Express a signed cart as an AP2 Cart Mandate W3C Verifiable Credential. */
export function toCartMandateCredential(signed: SignedCart, opts: ToMandateCredentialOptions): MandateCredential {
  const c = signed.cart;
  const subject: CartMandateSubject = {
    id: c.payerDid,
    mandateType: "CartMandate",
    cartId: c.cartId,
    merchant: c.merchantDid,
    items: c.items,
    totalPaisa: c.totalPaisa,
    currency: c.currency,
    expiry: toIso(c.expiryUnix),
    expiryUnix: c.expiryUnix,
    nonce: c.nonce,
  };
  return {
    "@context": [VC_CONTEXT_V2, MANDATE_CONTEXT],
    ...(opts.id !== undefined ? { id: opts.id } : {}),
    type: ["VerifiableCredential", "MandateCredential", "CartMandate"],
    issuer: opts.issuer,
    validFrom: toIso(opts.validFromUnix ?? nowUnix()),
    validUntil: toIso(c.expiryUnix),
    credentialSubject: subject,
    proof: {
      type: "KashEventSignature2026",
      cryptosuite: "ed25519-jcs-2026",
      created: toIso(opts.validFromUnix ?? nowUnix()),
      verificationMethod: `${opts.issuer}#cart-signer`,
      proofPurpose: "assertionMethod",
      domainSeparationTag: CART_DST,
      proofValue: signed.signature,
    },
  };
}

function cartFromMandateCredential(subject: CartMandateSubject): Cart {
  return {
    cartId: subject.cartId,
    payerDid: subject.id,
    merchantDid: subject.merchant,
    items: subject.items,
    totalPaisa: subject.totalPaisa,
    currency: subject.currency,
    expiryUnix: subject.expiryUnix,
    nonce: subject.nonce,
  };
}

// ----------------------------------------------------------------------------
// Unified verification
// ----------------------------------------------------------------------------

export type MandateVerifyReason =
  | "MALFORMED_CREDENTIAL"
  | "WRONG_TYPE"
  | "UNSUPPORTED_MANDATE_TYPE"
  | "SIGNATURE_INVALID"
  /** `validUntil` (or the Intent Mandate's `constraints.expiry`) does not match the signed expiry. */
  | "EXPIRY_MISMATCH"
  /** The arrival clause is present but is not "the recipient confirms, two signatures" (d41). */
  | "ARRIVAL_CLAUSE_INVALID";

export interface MandateVerifyResult {
  readonly ok: boolean;
  readonly reason: MandateVerifyReason | null;
  readonly mandateType: "IntentMandate" | "CartMandate" | null;
}

function isMandateCredential(vc: unknown): vc is MandateCredential {
  if (typeof vc !== "object" || vc === null) return false;
  const c = vc as Partial<MandateCredential>;
  return (
    Array.isArray(c["@context"]) &&
    Array.isArray(c.type) &&
    typeof c.issuer === "string" &&
    typeof c.validUntil === "string" && // every mandate has an end date
    typeof c.credentialSubject === "object" &&
    c.credentialSubject !== null &&
    typeof c.proof === "object" &&
    c.proof !== null
  );
}

/**
 * Verify a mandate credential's proof against the signer's public key. Rebuilds
 * the underlying grant/cart from the credential and verifies its Kash-Event
 * signature, then checks that the human-readable end date and the arrival clause
 * agree with what was signed. Never throws for a well-formed-but-invalid
 * credential. A credential with no `validUntil` is malformed: it has no end date.
 */
export async function verifyMandateCredential(
  vc: unknown,
  publicKey: Uint8Array,
): Promise<MandateVerifyResult> {
  if (!isMandateCredential(vc)) return { ok: false, reason: "MALFORMED_CREDENTIAL", mandateType: null };
  if (!vc.type.includes("VerifiableCredential") || !vc.type.includes("MandateCredential")) {
    return { ok: false, reason: "WRONG_TYPE", mandateType: null };
  }
  const subject = vc.credentialSubject;

  if (subject.mandateType === "IntentMandate") {
    const grant = grantFromMandateCredential(subject);
    const signed: SignedGrant = { grant, signature: vc.proof.proofValue };
    const valid = await verifyGrant(signed, publicKey);
    if (!valid) return { ok: false, reason: "SIGNATURE_INVALID", mandateType: "IntentMandate" };
    // The signature holds; now the views must not drift from it.
    const end = toIso(grant.expiryUnix);
    if (vc.validUntil !== end || subject.constraints.expiry !== end) {
      return { ok: false, reason: "EXPIRY_MISMATCH", mandateType: "IntentMandate" };
    }
    if (grant.arrival !== undefined && !isArrivalClause(grant.arrival)) {
      return { ok: false, reason: "ARRIVAL_CLAUSE_INVALID", mandateType: "IntentMandate" };
    }
    return { ok: true, reason: null, mandateType: "IntentMandate" };
  }

  if (subject.mandateType === "CartMandate") {
    const cart = cartFromMandateCredential(subject);
    const event: SignedKashEvent = { header: cartHeader(cart), body: cart, signature: vc.proof.proofValue };
    const valid = await verifyEvent(event, publicKey);
    if (!valid) return { ok: false, reason: "SIGNATURE_INVALID", mandateType: "CartMandate" };
    const end = toIso(cart.expiryUnix);
    if (vc.validUntil !== end || subject.expiry !== end) {
      return { ok: false, reason: "EXPIRY_MISMATCH", mandateType: "CartMandate" };
    }
    return { ok: true, reason: null, mandateType: "CartMandate" };
  }

  return { ok: false, reason: "UNSUPPORTED_MANDATE_TYPE", mandateType: null };
}
