/**
 * Paceplug co-founder multi-sig identity — startup persona flagship.
 *
 * Scenario: a startup has three co-founders. The company's DID is
 * owned by an M-of-N quorum of those founders — no single founder
 * can unilaterally sign a board-level action (banking, hiring,
 * equity grants). Each board action is a Kash-Event whose body the
 * founders co-sign; the company DID is only "authorised" for that
 * action when M of N founder signatures are aggregated.
 *
 * Two flows demonstrated:
 *
 *   1. ESTABLISH — the founding partnership signs a "co-founder set"
 *      envelope listing each founder's DID + pubkey and the M-of-N
 *      threshold. This is the company's constitution record.
 *
 *   2. CO-SIGN A BOARD ACTION — for any future board action, each
 *      founder independently signs the action body. A verifier
 *      aggregates the signatures, checks every advisor is in the set
 *      and signs the same body, and accepts iff M distinct signatures
 *      verify.
 *
 * The construction is identical in shape to the M-of-N social
 * recovery from `jinnahnook-recovery` — both are quorum attestations
 * over a shared body. The difference is semantic: recovery rotates
 * the canonical key, multi-sig company DIDs authorise per-action
 * decisions.
 */

import { Signer } from "@kashscript/identity-core/signer";
import { verifyEvent } from "@kashscript/identity-core/signatures";
import { encodeBase58, decodeBase58 } from "@kashscript/identity-core/base58";
import type { SignedKashEvent } from "@kashscript/identity-core";

const MULTISIG_DST = "kash-multisig-v1\n";

/* ─────────────────────────────────────────────────────────────────
 *  Constitution — the founding set + threshold
 * ───────────────────────────────────────────────────────────────── */

export interface FounderRef {
  readonly did: string;
  readonly publicKeyB58: string;
}

export interface CofounderConstitutionBody {
  readonly v: 1;
  /** Company name — display-only. */
  readonly companyName: string;
  /** Company DID — pinned by the quorum, not held by any single key. */
  readonly companyDid: string;
  /** Founder set. */
  readonly founders: readonly FounderRef[];
  /** Quorum threshold. Must satisfy threshold*2 > founders.length. */
  readonly threshold: number;
  /** ISO date the company was constituted. */
  readonly constitutedAt: string;
}

/** Build the constitution body — caller co-signs it with each founder's key. */
export function buildConstitution(
  companyName: string,
  companyDid: string,
  founders: readonly FounderRef[],
  threshold: number,
): CofounderConstitutionBody {
  if (threshold * 2 <= founders.length) {
    throw new Error(
      `threshold ${threshold} of ${founders.length} founders is not strict majority — refusing to constitute`,
    );
  }
  return {
    v: 1,
    companyName,
    companyDid,
    founders,
    threshold,
    constitutedAt: new Date().toISOString(),
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Founder co-sign — each founder independently signs the same body
 *  under the multisig DST
 * ───────────────────────────────────────────────────────────────── */

export async function founderCoSign(
  founderSigner: Signer,
  body: Readonly<Record<string, unknown>>,
): Promise<SignedKashEvent> {
  const header = {
    did: founderSigner.did,
    lexicon: "kash.org.multisig-action@1.0.0",
    iat: new Date().toISOString(),
  };
  const signature = await founderSigner.sign(header, body, { dst: MULTISIG_DST });
  return { header, body, signature };
}

/* ─────────────────────────────────────────────────────────────────
 *  Aggregator — verify the quorum on any board action
 * ───────────────────────────────────────────────────────────────── */

export type QuorumResult =
  | { readonly ok: true;  readonly approvedBy: readonly string[] }
  | { readonly ok: false; readonly reason: string };

/**
 * Verify a quorum of founder signatures over a single board-action body.
 *
 * Checks:
 *  1. Every signature verifies under its founder's pubkey AND was made
 *     under the multisig DST.
 *  2. Every signer is in the founder set.
 *  3. Every signed body matches the proposed body byte-for-byte.
 *  4. Each founder counts at most once.
 *  5. At least `threshold` distinct founders signed.
 */
export async function verifyBoardAction(opts: {
  readonly constitution: CofounderConstitutionBody;
  readonly proposedBody: Readonly<Record<string, unknown>>;
  readonly cosignatures: readonly SignedKashEvent[];
}): Promise<QuorumResult> {
  const byDid = new Map<string, FounderRef>();
  for (const f of opts.constitution.founders) byDid.set(f.did, f);

  const seen = new Set<string>();
  for (const event of opts.cosignatures) {
    const founderDid = event.header["did"] as string;
    const ref = byDid.get(founderDid);
    if (!ref) {
      return { ok: false, reason: `co-signature from "${founderDid}" is not in the founder set` };
    }

    if (event.signature.dst !== MULTISIG_DST) {
      return { ok: false, reason: `co-signature from "${founderDid}" uses wrong DST: "${event.signature.dst}"` };
    }

    if (JSON.stringify(event.body) !== JSON.stringify(opts.proposedBody)) {
      return { ok: false, reason: `co-signature from "${founderDid}" signs a different body than proposed` };
    }

    const sigOk = await verifyEvent(event, decodeBase58(ref.publicKeyB58));
    if (!sigOk) {
      return { ok: false, reason: `co-signature from "${founderDid}" does not verify under their pubkey` };
    }

    if (seen.has(founderDid)) {
      return { ok: false, reason: `duplicate co-signature from "${founderDid}" — counts once` };
    }
    seen.add(founderDid);
  }

  if (seen.size < opts.constitution.threshold) {
    return {
      ok: false,
      reason: `only ${seen.size} distinct co-signatures; need ${opts.constitution.threshold}`,
    };
  }

  return { ok: true, approvedBy: Array.from(seen) };
}

/* ─────────────────────────────────────────────────────────────────
 *  Helper — turn a Signer into a FounderRef
 * ───────────────────────────────────────────────────────────────── */

export function founderRefFromSigner(signer: Signer): FounderRef {
  return {
    did: signer.did,
    publicKeyB58: encodeBase58(signer.publicKey),
  };
}
