/**
 * The predicate credential and its holder-bound presentation
 * (specs/presentation.md §2–3).
 *
 * A predicate is issued TO the holder as an SD-JWT VC: always visible are its
 * kind, its answer, the rule version it was judged against (d43) and its
 * window; the record hashes it rests on are selectively disclosable, hidden
 * unless the holder shows them. The holder presents it with a KB-JWT from the
 * relationship key in `cnf` — one copy per verifier, so two presentations share
 * nothing (rule 6). Verification is offline except for status, which is read
 * from lists already verified (carried by the holder, or fetched by the caller).
 */

import { deriveDid } from "@kashscript/identity-core";
import { issueSdJwt, verifySdJwt, type SdJwtReport } from "../sd-jwt/sd-jwt";
import { jwkOf, type JwsSigner } from "../sd-jwt/jws";
import type { VerifyKey } from "../signing";
import type { KeyResolver } from "../holder/keys";
import { findListing, type ListingMatch, type TrustListReport } from "../holder/trust-list";
import { checkStatus, statusEntryOf, type StatusListEntry, type StatusListReport, type StatusVerdict } from "../holder/status-list";
import { recordIdOf, type HeldArtifactValue } from "../holder/record-id";
import { PREDICATE_VCT } from "./constants";
import type { Ask } from "./ask";


export interface PredicateClaim {
  readonly kind: string;
  readonly answer: boolean;
  /** d43: every predicate names the rule version it was judged against. */
  readonly rule: { readonly id: string; readonly version: string; readonly hash: string };
  readonly window: { readonly from: string; readonly to: string };
}

export interface IssuePredicateInput {
  /** The issuing establishment; its `did:kash` is `iss`. */
  readonly issuer: JwsSigner & { readonly did: string };
  /** The holder's relationship key for this verifier — one copy per verifier. A
   *  bare 32-byte key is Ed25519; a typed key may be P-256 (a phone's secure chip). */
  readonly holderPublicKey: VerifyKey;
  readonly predicate: PredicateClaim;
  /** Hex SHA-256 digests of the records the answer rests on (holder-contract record ids). */
  readonly restsOn: readonly string[];
  /** This copy's own status entry — a fresh random index per copy. */
  readonly credentialStatus: StatusListEntry | null;
  /** Rounded down to the day here, so copies do not carry a unique time. */
  readonly iatUnix: number;
  readonly expUnix: number;
  /** Decoys padding `restsOn`, so how many records there are does not show. Default 4. */
  readonly decoys?: number;
}

export async function issuePredicateCredential(input: IssuePredicateInput): Promise<string> {
  if (typeof input.predicate.rule?.version !== "string" || input.predicate.rule.version.length === 0) {
    throw new Error("a predicate names the rule version it was judged against (d43)");
  }
  return issueSdJwt({
    header: { kid: input.issuer.did },
    claims: {
      iss: input.issuer.did,
      iat: input.iatUnix - (input.iatUnix % 86_400),
      exp: input.expUnix,
      vct: PREDICATE_VCT,
      cnf: { jwk: jwkOf(input.holderPublicKey) },
      ...(input.credentialStatus !== null ? { credentialStatus: input.credentialStatus } : {}),
      predicate: input.predicate,
    },
    sdArrays: { restsOn: input.restsOn },
    decoys: input.decoys ?? 4,
    signer: input.issuer,
  });
}

export type PredicateFailureReason =
  | "SD_JWT_INVALID"
  | "NOT_A_PREDICATE"
  | "PREDICATE_MALFORMED"
  | "RULE_VERSION_MISSING"
  | "ATTACHMENT_NOT_BOUND"
  | "ASK_MISMATCH";

export interface PredicatePresentationReport {
  readonly ok: boolean;
  readonly reason: PredicateFailureReason | null;
  readonly sdJwt: SdJwtReport;
  readonly issuer: string | null;
  /** The relationship identifier the holder presented under. */
  readonly holder: string | null;
  readonly predicate: PredicateClaim | null;
  /** Record hashes the holder chose to disclose. Empty by default. */
  readonly disclosedRecordHashes: readonly string[];
  readonly attachments: readonly { readonly recordId: string; readonly bound: boolean }[];
  readonly status: StatusVerdict;
  readonly listing: ListingMatch | null;
  readonly trusted: boolean;
  readonly notes: readonly string[];
}

export interface VerifyPredicateOptions {
  readonly resolveKey: KeyResolver;
  /** The verifier's own identifier and the nonce it sent. */
  readonly audience?: string;
  readonly nonce?: string;
  readonly nowSec?: number;
  readonly maxKbAgeSec?: number;
  readonly statusLists?: readonly StatusListReport[];
  readonly trustLists?: readonly TrustListReport[];
  /** Records the holder chose to attach. Each must match a disclosed hash. */
  readonly attachedRecords?: readonly HeldArtifactValue[];
  /** Check the presentation answers this need of this ask. */
  readonly ask?: Ask;
  readonly needId?: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function predicateOf(claims: Record<string, unknown> | null): PredicateClaim | null {
  const p = claims?.predicate;
  if (!isPlainObject(p) || typeof p.kind !== "string" || typeof p.answer !== "boolean") return null;
  if (!isPlainObject(p.rule) || typeof p.rule.id !== "string" || typeof p.rule.hash !== "string") return null;
  if (!isPlainObject(p.window) || typeof p.window.from !== "string" || typeof p.window.to !== "string") return null;
  return p as unknown as PredicateClaim;
}

/** Verify a holder-bound predicate presentation. Offline except for status. */
export async function verifyPredicatePresentation(
  presentation: string,
  opts: VerifyPredicateOptions,
): Promise<PredicatePresentationReport> {
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const sd = await verifySdJwt(presentation, {
    resolveKey: opts.resolveKey,
    requireKeyBinding: true,
    nowSec,
    ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    ...(opts.maxKbAgeSec !== undefined ? { maxKbAgeSec: opts.maxKbAgeSec } : {}),
  });
  const notes: string[] = [...sd.notes];
  const predicate = predicateOf(sd.claims);
  const restsOn = Array.isArray(sd.claims?.restsOn) ? (sd.claims.restsOn as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const status = checkStatus(statusEntryOf(sd.claims), opts.statusLists ?? []);
  const listing = sd.issuer === null ? null : findListing(sd.issuer, PREDICATE_VCT, opts.trustLists ?? [], nowSec);

  let reason: PredicateFailureReason | null = null;
  if (!sd.ok) reason = "SD_JWT_INVALID";
  else if (sd.vct !== PREDICATE_VCT) reason = "NOT_A_PREDICATE";
  else if (predicate === null) reason = "PREDICATE_MALFORMED";
  else if (typeof predicate.rule.version !== "string" || predicate.rule.version.length === 0) reason = "RULE_VERSION_MISSING";

  // Raw records travel only because the holder attached them — and each must
  // be one the issuer's yes rests on, shown by a hash the holder disclosed.
  const attachments: { recordId: string; bound: boolean }[] = [];
  for (const a of opts.attachedRecords ?? []) {
    const recordId = await recordIdOf(a);
    const bound = restsOn.includes(recordId);
    attachments.push({ recordId, bound });
    if (!bound) reason ??= "ATTACHMENT_NOT_BOUND";
  }

  if (opts.ask !== undefined && predicate !== null) {
    const need = opts.ask.needs.find((n) => n.id === (opts.needId ?? opts.ask!.needs[0]?.id));
    const windowEnd = Date.parse(predicate.window.to) / 1000;
    if (need === undefined || need.predicate !== predicate.kind) reason ??= "ASK_MISMATCH";
    else if (!(windowEnd >= nowSec - need.withinDays * 86_400)) reason ??= "ASK_MISMATCH";
    else if (need.issuers !== undefined && (sd.issuer === null || !need.issuers.includes(sd.issuer))) reason ??= "ASK_MISMATCH";
    if (sd.keyBinding.audience !== null && sd.keyBinding.audience !== opts.ask.who.id) {
      reason ??= "ASK_MISMATCH";
      notes.push("the presentation is bound to a different verifier than the ask names");
    }
  }
  if (restsOn.length > 0) notes.push("the holder disclosed record hashes — shown to two verifiers, they link the presentations");
  if (listing !== null && !listing.pinned) notes.push(`issuer listed by ${listing.publisher}, not pinned here — shown as unlisted`);

  return {
    ok: reason === null,
    reason,
    sdJwt: sd,
    issuer: sd.issuer,
    holder: sd.holder,
    predicate,
    disclosedRecordHashes: restsOn,
    attachments,
    status,
    listing,
    trusted: listing?.pinned === true,
    notes,
  };
}

/** The holder's relationship identifier for a public key (a convenience for wallets). */
export function relationshipIdOf(publicKey: Uint8Array): string {
  return deriveDid(publicKey);
}
