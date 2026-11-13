/**
 * @kashscript/identity-sdk/rotation
 *
 * Voluntary key rotation for did:kash — the lifecycle operation that
 * was missing alongside social recovery. Recovery rotates a key you've
 * LOST (M-of-N advisors attest a successor); rotation rotates a key you
 * still HOLD (you sign the succession yourself, pre-emptively, e.g.
 * after a suspected exposure or on a scheduled cadence).
 *
 * # The self-certifying subtlety
 *
 * A did:kash IS its public key — there is no separate stable identifier
 * to keep constant while the key underneath changes. So rotation here is
 * a SIGNED SUCCESSION CHAIN, not an in-place document edit:
 *
 *     did:kash:A  ──(signed by A)──▶  did:kash:B  ──(signed by B)──▶  did:kash:C
 *
 * Each link is a `KeyRotation` envelope signed by the OUTGOING key,
 * naming the incoming key as its successor. An identity's continuity is
 * the verifiable chain from a known genesis key to the current active
 * key — anyone holding the genesis DID + the chain can confirm "C is the
 * legitimate current key for the identity that started at A" without a
 * resolver or any trusted third party.
 *
 * Counterparties that pinned `did:kash:A` update their record to the
 * chain head once they verify the chain. (When a hosted resolver exists,
 * it can serve the chain head directly; the chain is the portable proof
 * that works WITHOUT one.)
 *
 * All signatures are Ed25519 under DST `kash-rotation-v1\n` — distinct
 * from record/handshake/recovery DSTs so a rotation signature can't be
 * replayed against another protocol.
 */

import { Signer } from "@kashscript/identity-core/signer";
import { verifyEvent } from "@kashscript/identity-core/signatures";
import { encodeBase58 } from "@kashscript/identity-core/base58";
import { deriveDid, type KashDid } from "@kashscript/identity-core/did";
import type { SignedKashEvent } from "@kashscript/identity-core";

/** Domain-separation tag for key-rotation signatures. */
export const KASH_ROTATION_DST = "kash-rotation-v1\n" as const;

/* ─────────────────────────────────────────────────────────────────
 *  Wire shape
 * ───────────────────────────────────────────────────────────────── */

export interface KeyRotationBody {
  readonly v: 1;
  /** The outgoing identity (the key signing this rotation). */
  readonly priorDid: KashDid;
  /** The incoming successor identity. */
  readonly newDid: KashDid;
  /** base58btc-encoded raw Ed25519 public key of the successor. */
  readonly newPublicKeyB58: string;
  /** Monotonic sequence number — link 0 is the first rotation off genesis. */
  readonly seq: number;
  /** ISO timestamp. */
  readonly rotatedAt: string;
  /** Optional human reason (scheduled, suspected-exposure, device-change). */
  readonly reason?: string;
}

/** One signed link in the succession chain. */
export interface KeyRotationEnvelope {
  readonly header: Readonly<Record<string, unknown>>;
  readonly body: KeyRotationBody;
  readonly signature: SignedKashEvent["signature"];
}

export type RotationChainResult =
  | { readonly ok: true; readonly activeDid: KashDid; readonly activePublicKeyB58: string; readonly length: number }
  | { readonly ok: false; readonly breakAt: number; readonly reason: string };

/* ─────────────────────────────────────────────────────────────────
 *  Sign a rotation (outgoing key authorises the successor)
 * ───────────────────────────────────────────────────────────────── */

/**
 * Sign a succession link. `currentSigner` is the key being retired; it
 * signs over the successor's public key. Returns the envelope the
 * identity publishes (to counterparties, a PDS, or a resolver).
 *
 * `seq` must be one greater than the prior link's seq (0 for the first
 * rotation off the genesis key). The verifier enforces monotonicity.
 */
export async function signKeyRotation(
  currentSigner: Signer,
  successorPublicKey: Uint8Array,
  seq: number,
  reason?: string,
): Promise<KeyRotationEnvelope> {
  const newDid = deriveDid(successorPublicKey);
  if (newDid === (currentSigner.did as KashDid)) {
    throw new Error("rotation successor key is identical to the current key — no-op rotation refused");
  }
  const rotatedAt = new Date().toISOString();
  const body: KeyRotationBody = {
    v: 1,
    priorDid: currentSigner.did as KashDid,
    newDid,
    newPublicKeyB58: encodeBase58(successorPublicKey),
    seq,
    rotatedAt,
    ...(reason !== undefined ? { reason } : {}),
  };
  const header = {
    did: currentSigner.did,
    lexicon: "kash.identity.key-rotation@1.0.0",
    iat: rotatedAt,
  };
  const signature = await currentSigner.sign(header, body, { dst: KASH_ROTATION_DST });
  return { header, body, signature };
}

/* ─────────────────────────────────────────────────────────────────
 *  Verify a single link
 * ───────────────────────────────────────────────────────────────── */

/**
 * Verify that `envelope` is a valid rotation signed by `priorPublicKey`.
 * Confirms (1) the signature verifies under the prior key, (2) the
 * envelope's priorDid matches the prior key, (3) newDid actually derives
 * from the declared newPublicKeyB58 (no successor-key spoofing).
 */
export async function verifyKeyRotation(
  envelope: KeyRotationEnvelope,
  priorPublicKey: Uint8Array,
): Promise<boolean> {
  const expectedPriorDid = deriveDid(priorPublicKey);
  if (envelope.body.priorDid !== expectedPriorDid) return false;
  if (envelope.header["did"] !== expectedPriorDid) return false;

  // newDid must derive from the declared successor key (binds the named
  // DID to the actual bytes the chain walker will adopt).
  let successorKey: Uint8Array;
  try {
    successorKey = (await import("@kashscript/identity-core/base58")).decodeBase58(envelope.body.newPublicKeyB58);
  } catch {
    return false;
  }
  if (deriveDid(successorKey) !== envelope.body.newDid) return false;

  return await verifyEvent(envelope as unknown as SignedKashEvent, priorPublicKey);
}

/* ─────────────────────────────────────────────────────────────────
 *  Walk a full chain from genesis → active head
 * ───────────────────────────────────────────────────────────────── */

/**
 * Walk an ordered succession chain starting from a known genesis key.
 *
 * Returns the current active DID + public key, or a localised break.
 * Enforces, at every link:
 *   - the link is signed by the PRIOR key in the chain (link 0 by genesis),
 *   - seq increments by exactly 1 from the prior link (0-based),
 *   - the successor DID derives from the declared successor key.
 *
 * A counterparty that pinned the genesis DID runs this to learn the
 * current key with no trusted third party in the loop.
 */
export async function verifyRotationChain(
  genesisPublicKey: Uint8Array,
  chain: readonly KeyRotationEnvelope[],
): Promise<RotationChainResult> {
  let priorKey = genesisPublicKey;
  let expectedSeq = 0;

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]!;
    if (link.body.seq !== expectedSeq) {
      return { ok: false, breakAt: i, reason: `seq drift at link ${i}: expected ${expectedSeq}, got ${link.body.seq}` };
    }
    const linkOk = await verifyKeyRotation(link, priorKey);
    if (!linkOk) {
      return { ok: false, breakAt: i, reason: `link ${i} not signed by the prior key in the chain (or successor-key mismatch)` };
    }
    const { decodeBase58 } = await import("@kashscript/identity-core/base58");
    priorKey = decodeBase58(link.body.newPublicKeyB58);
    expectedSeq += 1;
  }

  return {
    ok: true,
    activeDid: deriveDid(priorKey),
    activePublicKeyB58: encodeBase58(priorKey),
    length: chain.length,
  };
}
