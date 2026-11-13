/**
 * completion-receipt.ts — a signed record that an agreement concluded.
 *
 * When an agreement reaches a terminal state, its issuer (a platform, or a
 * witness) issues a signed **completion receipt**: a verifiable credential
 * naming the agreement's outcome and its two parties. A review gate checks it
 * before accepting a review — you cannot review a counterparty you never
 * dealt with, because you cannot produce a receipt naming you as a party to a
 * concluded agreement.
 *
 * A receipt is a {@link SignedKashEvent} (the same envelope `@kashscript/lexicons`
 * uses), signed with a dedicated Domain-Separation Tag ({@link RECEIPT_DST}) so a
 * receipt signature can never be replayed as a record/attestor signature or
 * vice-versa. The issuer is a self-certifying `did:kash`, so verification derives
 * the issuer's public key from the DID itself — no key distribution, and no way
 * to attribute a receipt to an issuer that did not sign it.
 *
 * THE TAG NEVER CHANGES. The header type (`kash.trade.completion`), the header
 * version, {@link RECEIPT_DST} and the `kash-receipt:` id prefix are what a
 * verifier recognises a receipt by, and they are the same here as they have
 * always been. What changed is the CLAIM inside: it is `v: 2` and carries no
 * price, chain or deposit fields. The `manifestId` commits to the price, so a
 * holder may reveal the manifest if they choose and a verifier can hash it and
 * match — the receipt itself shows nobody the amount. A `v: 1` claim is not
 * accepted by this package; it was issued by the retired `@kashscript/trade-core`,
 * which still verifies it.
 *
 * What a receipt does not prove: that any money moved, that the work was good,
 * or that either party can be relied on. It proves that the issuer signed a
 * statement about one agreement. `resolved` says the agreement reached its
 * `Resolved` state; it never says that payment settled.
 *
 * Instants are Unix seconds (UTC). The issuer states `concludedAt`; a verifier
 * with an offline clock is relying on that clock, not on this record.
 *
 * Pure + deterministic apart from WebCrypto (Ed25519 sign/verify, SHA-256 id) —
 * the same crypto surface identity-core itself uses. No network, no storage.
 */

import {
  canonicalizeBytes,
  encodeHex,
  isKashDid,
  parseDid,
  signEvent,
  verifyEvent,
  type KashDid,
  type KashEventSignature,
  type SignableKashEvent,
  type SignedKashEvent,
} from "@kashscript/identity-core";

import { fail } from "./errors";
import { TERMINAL_STATES, isUnixSeconds, type BlueprintType, type ManifestId, type UniversalState } from "./types";

/** Domain-Separation Tag for completion receipts. Scopes the signature to this
 *  subprotocol — a record/attestor signature (different DST) is never a valid
 *  receipt, and a receipt is never a valid record. */
export const RECEIPT_DST = "kash-trade-receipt-v1\n" as const;

/** The agreement kinds a receipt names, in the UPPERCASE form receipts have always used. */
export const RECEIPT_BLUEPRINTS = ["OTDC", "SUBSCRIPTION", "MILESTONE"] as const;
export type ReceiptBlueprint = (typeof RECEIPT_BLUEPRINTS)[number];

/** Lift a manifest's `BlueprintType` to the form a receipt carries. */
export function receiptBlueprint(b: BlueprintType): ReceiptBlueprint {
  return b.toUpperCase() as ReceiptBlueprint;
}

/** Terminal outcomes a receipt can attest. */
export type CompletionOutcome = "resolved" | "reverted" | "cancelled";

/** Terminal state → outcome. (The three members of TERMINAL_STATES.) */
const STATE_TO_OUTCOME: Readonly<Record<"Resolved" | "Reverted" | "Cancelled", CompletionOutcome>> = {
  Resolved: "resolved",
  Reverted: "reverted",
  Cancelled: "cancelled",
};

export interface CompletionPartyRef {
  readonly did: KashDid;
  /** keccak256 of the DID (32 bytes). */
  readonly didCommitment: `0x${string}`;
}

/** The signed claim (the `body` of the receipt event). */
export interface CompletionReceiptClaim {
  readonly v: 2;
  readonly manifestId: ManifestId;
  readonly blueprint: ReceiptBlueprint;
  /** How the agreement ended. `resolved` names the `Resolved` state; it does not say money settled. */
  readonly outcome: CompletionOutcome;
  /** When the agreement concluded, as the issuer states it (Unix seconds). */
  readonly concludedAt: number;
  readonly parties: {
    readonly buyer: CompletionPartyRef;
    readonly seller: CompletionPartyRef;
  };
}

/** The receipt `header` — binds the issuing `did:kash`. The index signature
 *  keeps it assignable to identity-core's generic envelope header
 *  (`Readonly<Record<string, unknown>>`) without casts at the sign/verify seam. */
export interface CompletionReceiptHeader {
  readonly type: "kash.trade.completion";
  readonly v: 1;
  readonly issuer: KashDid;
  readonly [key: string]: unknown;
}

export interface CompletionReceipt extends SignableKashEvent {
  readonly header: CompletionReceiptHeader;
  readonly body: CompletionReceiptClaim;
}

export interface SignedCompletionReceipt extends CompletionReceipt {
  readonly signature: KashEventSignature;
}

/* ─────────────────────────────────────────────────────────────────
 *  Build (pure, sync) — validate facts and shape the canonical receipt.
 * ───────────────────────────────────────────────────────────────── */

export interface BuildCompletionReceiptInput {
  readonly issuer: KashDid;
  readonly manifestId: ManifestId;
  readonly blueprint: ReceiptBlueprint;
  /** Must be a terminal state (Resolved / Reverted / Cancelled). */
  readonly state: UniversalState;
  readonly concludedAt: number;
  readonly buyer: CompletionPartyRef;
  readonly seller: CompletionPartyRef;
}

const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;

export function buildCompletionReceipt(input: BuildCompletionReceiptInput): CompletionReceipt {
  if (!TERMINAL_STATES.has(input.state)) {
    fail("WRONG_STATE", `completion receipt requires a terminal state (Resolved/Reverted/Cancelled), got ${input.state}.`);
  }
  if (!isKashDid(input.issuer)) fail("WRONG_DID", `issuer must be a did:kash, got ${String(input.issuer)}.`);

  const body: CompletionReceiptClaim = {
    v: 2,
    manifestId: input.manifestId,
    blueprint: input.blueprint,
    outcome: STATE_TO_OUTCOME[input.state as "Resolved" | "Reverted" | "Cancelled"],
    concludedAt: input.concludedAt,
    parties: { buyer: input.buyer, seller: input.seller },
  };

  // Single source of body-shape truth — the SAME invariants verify re-checks.
  assertClaimShape(body);

  return { header: { type: "kash.trade.completion", v: 1, issuer: input.issuer }, body };
}

/* ─────────────────────────────────────────────────────────────────
 *  Sign / verify (Ed25519 via identity-core, scoped by RECEIPT_DST).
 * ───────────────────────────────────────────────────────────────── */

export interface SignCompletionReceiptOptions {
  /** Verification-method id to embed (e.g. `did:kash:…#sig-1`). */
  readonly kid?: `${KashDid}#${string}`;
}

/**
 * Sign a built receipt with the issuer's Ed25519 private key under
 * {@link RECEIPT_DST}. The key MUST correspond to `receipt.header.issuer`; a
 * mismatch is caught at verify time (the issuer pubkey is derived from the DID,
 * so a wrong key simply fails to verify — there is no key-override escape hatch).
 */
export async function signCompletionReceipt(
  receipt: CompletionReceipt,
  privateKey: Uint8Array,
  opts?: SignCompletionReceiptOptions,
): Promise<SignedCompletionReceipt> {
  const signature = await signEvent(receipt.header, receipt.body, privateKey, {
    dst: RECEIPT_DST,
    encoding: "multibase",
    ...(opts?.kid !== undefined ? { kid: opts.kid } : {}),
  });
  return { ...receipt, signature };
}

export interface VerifyCompletionReceiptResult {
  readonly valid: boolean;
  readonly claim: CompletionReceiptClaim;
  readonly issuer: KashDid;
  /** Present when `valid` is false — why it failed. */
  readonly reason?: string;
}

/**
 * Verify a completion receipt. The issuer's public key is ALWAYS derived from
 * `header.issuer` (self-certifying did:kash) — there is no key override, so a
 * receipt can never be attributed to an issuer that did not sign it.
 *
 * Returns `{ valid: false, reason }` for a wrong DST, a malformed signature, or
 * a signature that does not verify. Throws `TermsError("INVALID_RECEIPT")`
 * (or `WRONG_DID`) only for a structurally malformed receipt — so a
 * `valid: true` result GUARANTEES a structurally complete claim that
 * {@link canReview} can rely on.
 */
export async function verifyCompletionReceipt(
  signed: SignedCompletionReceipt,
): Promise<VerifyCompletionReceiptResult> {
  assertReceiptShape(signed);
  assertClaimShape(signed.body); // a valid:true receipt is always structurally complete
  const issuer = signed.header.issuer;

  // DST gate FIRST — a non-receipt signature (e.g. a record signature) is
  // rejected before any crypto, closing cross-subprotocol replay.
  if (signed.signature.dst !== RECEIPT_DST) {
    return { valid: false, claim: signed.body, issuer, reason: `wrong DST ${JSON.stringify(signed.signature.dst)} (expected the completion-receipt DST).` };
  }

  const pubkey = parseDid(issuer); // issuer validated as did:kash in assertReceiptShape
  let ok: boolean;
  try {
    ok = await verifyEvent(signed, pubkey);
  } catch {
    // A malformed signature field (undecodable sig, unknown alg) is a failed
    // verification, not a structural receipt error — honour the typed contract.
    return { valid: false, claim: signed.body, issuer, reason: "signature is malformed or does not verify." };
  }
  return ok
    ? { valid: true, claim: signed.body, issuer }
    : { valid: false, claim: signed.body, issuer, reason: "signature does not verify under the issuer key." };
}

/**
 * Content id of a receipt — `kash-receipt:0x<sha256(JCS({header,body}))>`.
 * Stable handle for dedup / referencing a receipt from a review record.
 */
export async function completionReceiptId(receipt: CompletionReceipt): Promise<`kash-receipt:0x${string}`> {
  const bytes = canonicalizeBytes({ header: receipt.header, body: receipt.body });
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return `kash-receipt:0x${encodeHex(new Uint8Array(digest))}`;
}

/* ─────────────────────────────────────────────────────────────────
 *  Review gate
 * ───────────────────────────────────────────────────────────────── */

export interface ReviewEligibility {
  readonly eligible: boolean;
  /** The reviewer's role in the agreement, when eligible. */
  readonly role?: "buyer" | "seller";
  /** Whom the reviewer may review, when eligible. */
  readonly subject?: CompletionPartyRef;
  /** The agreement's outcome (review context). */
  readonly outcome: CompletionOutcome;
}

/**
 * The review gate: decide whether `reviewerDid` may write a review off this
 * receipt, and whom they review. Two-sided — buyer reviews seller and vice
 * versa. ⚠ The caller MUST {@link verifyCompletionReceipt} first; `canReview`
 * assumes an already-verified claim. As defense-in-depth it still shape-guards
 * the claim and refuses a degenerate buyer===seller agreement.
 */
export function canReview(claim: CompletionReceiptClaim, reviewerDid: KashDid): ReviewEligibility {
  if (!claim || typeof claim !== "object" || !claim.parties || typeof claim.parties !== "object") {
    fail("INVALID_RECEIPT", "canReview requires a structurally valid claim — verify the receipt first.");
  }
  const { buyer, seller } = claim.parties;
  if (!buyer || !seller || !isKashDid(buyer.did) || !isKashDid(seller.did)) {
    fail("INVALID_RECEIPT", "claim.parties must carry valid buyer/seller did:kash.");
  }
  if (buyer.did === seller.did) return { eligible: false, outcome: claim.outcome }; // no self-review
  if (reviewerDid === buyer.did) return { eligible: true, role: "buyer", subject: seller, outcome: claim.outcome };
  if (reviewerDid === seller.did) return { eligible: true, role: "seller", subject: buyer, outcome: claim.outcome };
  return { eligible: false, outcome: claim.outcome };
}

/* ─────────────────────────────────────────────────────────────────
 *  Internals
 * ───────────────────────────────────────────────────────────────── */

function assertParty(p: CompletionPartyRef, label: string): void {
  if (!p || typeof p !== "object") fail("INVALID_RECEIPT", `${label} must be an object.`);
  if (!isKashDid(p.did)) fail("WRONG_DID", `${label}.did must be a did:kash, got ${String(p.did)}.`);
  if (!BYTES32_RE.test(p.didCommitment)) fail("INVALID_RECEIPT", `${label}.didCommitment must be a 32-byte 0x hash.`);
}

/** The full claim-shape invariant — enforced at BOTH build and verify, so a
 *  verified receipt is guaranteed to carry a structurally complete claim. */
function assertClaimShape(body: CompletionReceiptClaim): void {
  if (!body || typeof body !== "object") fail("INVALID_RECEIPT", "receipt.body must be an object.");
  if ((body.v as number) === 1) {
    fail("INVALID_RECEIPT", "body.v is 1: a v1 claim was issued by the retired @kashscript/trade-core and is not accepted here.");
  }
  if (body.v !== 2) fail("INVALID_RECEIPT", `body.v must be 2, got ${String(body.v)}.`);
  if (typeof body.manifestId !== "string" || !body.manifestId.startsWith("kash-trade:")) {
    fail("INVALID_RECEIPT", "body.manifestId must be a kash-trade: id.");
  }
  if (!RECEIPT_BLUEPRINTS.includes(body.blueprint)) {
    fail("INVALID_RECEIPT", `body.blueprint must be one of ${RECEIPT_BLUEPRINTS.join("/")}, got ${String(body.blueprint)}.`);
  }
  if (body.outcome !== "resolved" && body.outcome !== "reverted" && body.outcome !== "cancelled") {
    fail("INVALID_RECEIPT", `body.outcome must be resolved/reverted/cancelled, got ${String(body.outcome)}.`);
  }
  if (!isUnixSeconds(body.concludedAt)) {
    fail("INVALID_RECEIPT", `body.concludedAt must be a Unix timestamp in seconds — milliseconds are refused; got ${String(body.concludedAt)}.`);
  }
  if (!body.parties || typeof body.parties !== "object") fail("INVALID_RECEIPT", "body.parties must be an object.");
  assertParty(body.parties.buyer, "buyer");
  assertParty(body.parties.seller, "seller");
  if (body.parties.buyer.did === body.parties.seller.did) {
    fail("INVALID_RECEIPT", "buyer and seller must be distinct DIDs.");
  }
}

function assertReceiptShape(signed: SignedCompletionReceipt): void {
  if (!signed || typeof signed !== "object") fail("INVALID_RECEIPT", "receipt must be an object.");
  const h = signed.header as CompletionReceiptHeader | undefined;
  const sig = signed.signature as KashEventSignature | undefined;
  if (!h || typeof h !== "object") fail("INVALID_RECEIPT", "receipt.header must be an object.");
  if (!sig || typeof sig !== "object") fail("INVALID_RECEIPT", "receipt.signature must be an object.");
  if (h.type !== "kash.trade.completion") fail("INVALID_RECEIPT", `receipt.header.type must be "kash.trade.completion".`);
  if (!isKashDid(h.issuer)) fail("WRONG_DID", `receipt.header.issuer must be a did:kash.`);
  if (typeof sig.dst !== "string" || typeof sig.sig !== "string") fail("INVALID_RECEIPT", "receipt.signature is malformed.");
}
