/**
 * Compat — Indusland's Tehzeeb mark revocation (`indus.mark.revoke.v1`),
 * mapped onto the holder contract's status verdict WITHOUT changing it.
 *
 * The revocation is a platform-signed Kash-Event whose body binds the mark by
 * `markSha256 = SHA-256(canonicalJson(signed mark event))` — the exact digest
 * `Indusland 2.0/apps/web/lib/tehzeeb/mark.ts` computes. So a holder can carry
 * the revocation beside the mark and anyone can check it offline: same issuer,
 * same DST, the digest of THIS mark. The body's `markId` is a database row id
 * and cannot be checked offline; the digest is what binds.
 */

import { verifyEvent, type SignedKashEvent } from "@kashscript/identity-core";
import { canonicalJson, sha256Hex } from "../chain";
import { selfCertifyingKey, stripFragment } from "../holder/keys";

export const INDUS_MARK_DST = "indus.mark.v1\n" as const;
export const INDUS_MARK_REVOKE_DST = "indus.mark.revoke.v1\n" as const;

export async function indusMarkDigest(mark: SignedKashEvent): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalJson(mark)));
}

export interface PresentedMarkRevocation {
  /** The revocation's own date (ISO), as its issuer signed it. */
  readonly revokedAt: string;
  readonly revocation: SignedKashEvent;
}

function issuerOf(event: SignedKashEvent): string | null {
  const iss = (event.header as Record<string, unknown> | undefined)?.iss;
  return typeof iss === "string" ? stripFragment(iss) : null;
}

/** The first presented revocation that verifiably revokes this mark, or null. */
export async function findMarkRevocation(
  mark: SignedKashEvent,
  presented: readonly unknown[],
): Promise<PresentedMarkRevocation | null> {
  const markIss = issuerOf(mark);
  if (markIss === null) return null;
  const key = selfCertifyingKey(markIss);
  if (key === null) return null;
  const digest = await indusMarkDigest(mark);
  for (const r of presented) {
    const rev = r as SignedKashEvent;
    const header = rev?.header as Record<string, unknown> | undefined;
    const body = rev?.body as Record<string, unknown> | undefined;
    if (rev?.signature?.dst !== INDUS_MARK_REVOKE_DST || header?.typ !== "indus.mark.revoke") continue;
    if (issuerOf(rev) !== markIss || body?.markSha256 !== digest || typeof body?.revokedAt !== "string") continue;
    let ok = false;
    try {
      ok = await verifyEvent(rev, key);
    } catch {
      ok = false;
    }
    if (ok) return { revokedAt: body.revokedAt, revocation: rev };
  }
  return null;
}
