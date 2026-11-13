/**
 * @kashscript/identity-sdk/recovery
 *
 * Headless M-of-N social-recovery primitives. Promoted from the
 * `jinnahnook-recovery` use-case fixture after the persona audit
 * pass showed they're general-purpose enough to belong in the SDK.
 *
 * The React-side `recover()` method on `KashAuthProvider` is the UI
 * layer above these primitives. Hosts that don't use React (Node,
 * Bun, edge runtimes, native apps, audit tools) can import directly
 * from this subpath and run the full M-of-N quorum-verify flow
 * without a browser.
 *
 * Construction:
 *
 *   1. ENROLMENT — the user signs a `set-recovery-quorum` envelope
 *      naming M-of-N advisor DIDs + pubkeys.
 *   2. LOSS — user's private key is gone (Ed25519 is non-recoverable
 *      by design; that's the point).
 *   3. NEW DEVICE — user generates a fresh Ed25519 keypair.
 *   4. RECOVERY CLAIM — anyone publishes an unsigned claim binding
 *      the new pubkey to the original DID.
 *   5. ATTESTATION — each advisor independently signs the claim.
 *   6. VERIFICATION — `verifyRecovery` checks ≥M distinct attestations,
 *      each in the quorum, each signing the same claim body.
 *
 * All signatures are Ed25519 under DST `kash-recovery-v1\n`. Same
 * cryptographic primitive identity-core uses for record + handshake
 * signing; the DST scopes recovery signatures so they can't be
 * cross-protocol-replayed.
 */

import { Signer } from "@kashscript/identity-core/signer";
import { verifyEvent } from "@kashscript/identity-core/signatures";
import { encodeBase58, decodeBase58 } from "@kashscript/identity-core/base58";
import type { SignedKashEvent } from "@kashscript/identity-core";

/** Domain-separation tag for recovery signatures. Distinct from
 *  record / handshake DSTs so a recovery signature can never be
 *  replayed against another protocol. */
export const KASH_RECOVERY_DST = "kash-recovery-v1\n" as const;

/* ─────────────────────────────────────────────────────────────────
 *  Wire shapes
 * ───────────────────────────────────────────────────────────────── */

/** A pointer to one advisor that can participate in recovery. */
export interface AdvisorRef {
  /** Advisor's `did:kash:`. */
  readonly did: string;
  /** base58btc-encoded raw Ed25519 public key. */
  readonly publicKeyB58: string;
}

/** Body of the user's enrolment envelope. */
export interface SetRecoveryQuorumBody {
  readonly v: 1;
  /** DID the quorum is set for — same DID this body's signer owns. */
  readonly subjectDid: string;
  /** N candidate advisors. */
  readonly advisors: readonly AdvisorRef[];
  /** Minimum signatures required to recover (must satisfy threshold*2 > N). */
  readonly threshold: number;
  /** ISO timestamp when this quorum was established. */
  readonly setAt: string;
}

/** Body of the new-device claim. Unsigned — advisors sign it. */
export interface RecoveryClaimBody {
  readonly v: 1;
  /** Original DID being recovered. */
  readonly subjectDid: string;
  /** Fresh Ed25519 public key the user generated on the new device. */
  readonly newPublicKeyB58: string;
  /** Pointer to the original `set-recovery-quorum` envelope this claim
   *  binds to. Typically a sha256 hash; the SDK doesn't enforce a
   *  specific shape here so hosts can use IPFS/cid, Postgres ids, etc. */
  readonly quorumEnvelopeRef: string;
  /** ISO timestamp. */
  readonly claimedAt: string;
}

/** Final result of `verifyRecovery`. */
export type RecoveryResult =
  | { readonly ok: true; readonly newPublicKeyB58: string }
  | { readonly ok: false; readonly reason: string };

/* ─────────────────────────────────────────────────────────────────
 *  Enrolment — user signs their quorum envelope
 * ───────────────────────────────────────────────────────────────── */

/**
 * Sign a `set-recovery-quorum` envelope under the user's current key.
 * Throws if `threshold` is not a strict majority of `advisors.length`
 * (a non-strict-majority quorum would be unsafe — colluding advisors
 * could rotate the DID without the user's other-half consent).
 */
export async function setRecoveryQuorum(
  userSigner: Signer,
  advisors: readonly AdvisorRef[],
  threshold: number,
): Promise<SignedKashEvent> {
  if (threshold * 2 <= advisors.length) {
    throw new Error(
      `threshold ${threshold} of ${advisors.length} advisors is not strict majority — recovery would be unsafe`,
    );
  }
  const body: SetRecoveryQuorumBody = {
    v: 1,
    subjectDid: userSigner.did,
    advisors,
    threshold,
    setAt: new Date().toISOString(),
  };
  const header = {
    did: userSigner.did,
    lexicon: "kash.identity.set-recovery-quorum@1.0.0",
    iat: body.setAt,
  };
  const signature = await userSigner.sign(header, body, { dst: KASH_RECOVERY_DST });
  return { header, body, signature };
}

/* ─────────────────────────────────────────────────────────────────
 *  Recovery claim — new device proposes a fresh pubkey
 * ───────────────────────────────────────────────────────────────── */

/** Build an unsigned recovery claim. Advisors sign this body
 *  separately via {@link advisorAttestRecovery}. */
export function buildRecoveryClaim(
  subjectDid: string,
  newPublicKey: Uint8Array,
  quorumEnvelopeRef: string,
): RecoveryClaimBody {
  return {
    v: 1,
    subjectDid,
    newPublicKeyB58: encodeBase58(newPublicKey),
    quorumEnvelopeRef,
    claimedAt: new Date().toISOString(),
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Attestation — each advisor independently signs the claim
 * ───────────────────────────────────────────────────────────────── */

/** Each advisor signs the recovery claim with their own key under
 *  the recovery DST. */
export async function advisorAttestRecovery(
  advisorSigner: Signer,
  claim: RecoveryClaimBody,
): Promise<SignedKashEvent> {
  const header = {
    did: advisorSigner.did,
    lexicon: "kash.identity.recovery-attestation@1.0.0",
    iat: new Date().toISOString(),
    subject: claim.subjectDid,
  };
  const signature = await advisorSigner.sign(header, claim, { dst: KASH_RECOVERY_DST });
  return { header, body: claim, signature };
}

/* ─────────────────────────────────────────────────────────────────
 *  Verification — aggregate the quorum
 * ───────────────────────────────────────────────────────────────── */

/**
 * Verify a recovery proposal.
 *
 * Checks:
 *  1. The quorum envelope is signed by the subject DID itself (the
 *     user authentically named this advisor set).
 *  2. Every attestation's signature verifies under its advisor's
 *     pubkey (no forged advisor signatures).
 *  3. Every attestation's body matches the recovery claim byte-for-byte
 *     (no advisor signed a different claim).
 *  4. Each attestation comes from a DISTINCT advisor in the quorum.
 *  5. At least `threshold` distinct advisors attested.
 */
export async function verifyRecovery(opts: {
  readonly quorumEnvelope: SignedKashEvent;
  readonly userOriginalPublicKey: Uint8Array;
  readonly claim: RecoveryClaimBody;
  readonly attestations: readonly SignedKashEvent[];
}): Promise<RecoveryResult> {
  // 1. Quorum envelope is signed by the user's original key.
  const quorumOk = await verifyEvent(opts.quorumEnvelope, opts.userOriginalPublicKey);
  if (!quorumOk) {
    return {
      ok: false,
      reason: "quorum envelope signature does not verify under the user's original public key",
    };
  }

  const quorumBody = opts.quorumEnvelope.body as SetRecoveryQuorumBody;
  const advisorByDid = new Map<string, AdvisorRef>();
  for (const a of quorumBody.advisors) advisorByDid.set(a.did, a);

  const seenAdvisors = new Set<string>();
  for (const att of opts.attestations) {
    // 2. Advisor's signature verifies.
    const headerDid = att.header["did"] as string;
    const advisorRef = advisorByDid.get(headerDid);
    if (!advisorRef) {
      return { ok: false, reason: `attestation from did "${headerDid}" is not in the quorum` };
    }
    const advisorPubKey = decodeBase58(advisorRef.publicKeyB58);
    const sigOk = await verifyEvent(att, advisorPubKey);
    if (!sigOk) {
      return { ok: false, reason: `attestation signature from "${advisorRef.did}" does not verify` };
    }

    // 3. Body matches the claim byte-for-byte.
    if (JSON.stringify(att.body) !== JSON.stringify(opts.claim)) {
      return { ok: false, reason: `attestation from "${advisorRef.did}" attests to a different claim body` };
    }

    // 4. Distinct advisor.
    if (seenAdvisors.has(advisorRef.did)) {
      return { ok: false, reason: `duplicate attestation from "${advisorRef.did}" — only counts once` };
    }
    seenAdvisors.add(advisorRef.did);
  }

  // 5. Quorum threshold.
  if (seenAdvisors.size < quorumBody.threshold) {
    return {
      ok: false,
      reason: `only ${seenAdvisors.size} distinct attestations; need ${quorumBody.threshold}`,
    };
  }

  return { ok: true, newPublicKeyB58: opts.claim.newPublicKeyB58 };
}

/* ─────────────────────────────────────────────────────────────────
 *  Convenience — turn a held Signer into a wire-friendly AdvisorRef
 * ───────────────────────────────────────────────────────────────── */

export function advisorRefFromSigner(signer: Signer): AdvisorRef {
  return {
    did: signer.did,
    publicKeyB58: encodeBase58(signer.publicKey),
  };
}
