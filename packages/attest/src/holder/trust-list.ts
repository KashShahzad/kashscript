/**
 * The trust list — which issuers a wallet admits (specs/holder-contract.md §3).
 *
 * A DSSE envelope, `payloadType` = {@link DST_TRUST_LIST}, signed by its
 * publisher's self-certifying `did:kash`. It is **a policy, not the format**
 * (ECOSYSTEM d47(e)): the record format stays holdable by any wallet, a holder
 * may keep a record from an unlisted issuer by explicit choice, and nothing
 * here can make a record fail to verify. It can only say who is listed.
 *
 * Two rules keep it honest:
 *   • **Grants are exact tags.** An issuer is listed for the registered DSTs it
 *     names, never a whole family — a `dsse-type` grant would let one member
 *     vouch for another's payloadType.
 *   • **An unpinned publisher lists nobody.** Anyone can sign a list. Only a
 *     publisher the verifier pinned out of band makes a record "listed"; any
 *     other list is reported as that publisher's word and nothing more.
 */

import { AttestError } from "../errors";
import { base64ToBytes } from "../ed25519";
import { signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "../dsse";
import { isRegisteredDst } from "../dst";
import { isAlgorithmUnsupported } from "@kashscript/identity-core";
import { selfCertifyingTypedKey, stripFragment, typedKeyOf, type ListedKey, type PublicKeyEntry } from "./keys";

export const DST_TRUST_LIST = "application/vnd.kash.trust-list+json" as const;
export const TRUST_LIST_FORMAT = "kashscript-trust-list/1" as const;

export interface TrustListIssuer {
  /** The issuer's identifier — a `did:kash`, or a stable id when its keys are listed below. */
  readonly issuerId: string;
  /** A plain name a person can read (d44: never a concept they must learn). */
  readonly label: string;
  /** Keys for signers whose identifiers are not self-certifying (JWKS kids, structured DIDs). */
  readonly keys: readonly PublicKeyEntry[];
  /** The exact registered DSTs this issuer may issue. */
  readonly dsts: readonly string[];
  readonly validFromUnix: number;
  readonly validUntilUnix: number;
}

export interface TrustListPayload {
  readonly format: typeof TRUST_LIST_FORMAT;
  readonly listId: string;
  /** Monotonic. A verifier holding several versions of one list uses the highest. */
  readonly version: number;
  /** The self-certifying `did:kash` that signs the envelope. */
  readonly publisher: string;
  readonly issuedAtUnix: number;
  readonly validFromUnix: number;
  readonly validUntilUnix: number;
  readonly issuers: readonly TrustListIssuer[];
}

export type TrustListFailureReason =
  | "MALFORMED_TRUST_LIST"
  | "TRUST_LIST_TYPE_MISMATCH"
  | "TRUST_LIST_PUBLISHER_NOT_SELF_CERTIFYING"
  | "TRUST_LIST_SIGNATURE_INVALID"
  | "TRUST_LIST_UNREGISTERED_DST"
  | "TRUST_LIST_BAD_KEY";

export interface TrustListReport {
  /** The signature and the structure hold. Says nothing about pinning or time. */
  readonly ok: boolean;
  readonly listId: string | null;
  readonly version: number | null;
  readonly publisher: string | null;
  /** The publisher is one the verifier pinned. Only a pinned list makes a record "listed". */
  readonly pinned: boolean;
  /** `validFromUnix <= now <= validUntilUnix`. A list outside its window lists nobody. */
  readonly current: boolean;
  readonly issuedAtUnix: number | null;
  readonly validUntilUnix: number | null;
  readonly issuers: readonly TrustListIssuer[];
  readonly reason: TrustListFailureReason | null;
  readonly notes: readonly string[];
}

export interface VerifyTrustListOptions {
  /** Publisher DIDs the verifier trusts, pinned out of band. attest ships none. */
  readonly pinnedPublishers?: readonly string[];
  readonly nowSec?: number;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

/** JSON inside a DSSE envelope, or null. Never throws. */
export function decodeEnvelopePayload(envelope: unknown): unknown {
  if (!isPlainObject(envelope) || typeof envelope.payload !== "string") return null;
  try {
    return JSON.parse(new TextDecoder().decode(base64ToBytes(envelope.payload)));
  } catch {
    return null;
  }
}

/** Structural check of one issuer entry; the reason, or null. */
function issuerFault(e: unknown): TrustListFailureReason | null {
  if (!isPlainObject(e)) return "MALFORMED_TRUST_LIST";
  if (typeof e.issuerId !== "string" || typeof e.label !== "string") return "MALFORMED_TRUST_LIST";
  if (!Array.isArray(e.keys) || !Array.isArray(e.dsts)) return "MALFORMED_TRUST_LIST";
  if (!isInt(e.validFromUnix) || !isInt(e.validUntilUnix)) return "MALFORMED_TRUST_LIST";
  for (const k of e.keys) {
    if (!isPlainObject(k) || typeof k.keyid !== "string" || typedKeyOf(k as unknown as PublicKeyEntry) === null) {
      return "TRUST_LIST_BAD_KEY";
    }
  }
  for (const d of e.dsts) {
    if (typeof d !== "string" || !isRegisteredDst(d)) return "TRUST_LIST_UNREGISTERED_DST";
  }
  return null;
}

function failed(reason: TrustListFailureReason, note: string, partial: Partial<TrustListReport> = {}): TrustListReport {
  return {
    ok: false,
    listId: null,
    version: null,
    publisher: null,
    pinned: false,
    current: false,
    issuedAtUnix: null,
    validUntilUnix: null,
    issuers: [],
    ...partial,
    reason,
    notes: [note],
  };
}

/**
 * Verify a trust list offline. Structurally junk input returns a report, never
 * a throw. The publisher's key comes out of its `did:kash`; nothing is fetched.
 */
export async function verifyTrustList(
  envelope: DsseEnvelope,
  opts: VerifyTrustListOptions = {},
): Promise<TrustListReport> {
  if (!isPlainObject(envelope) || typeof envelope.payloadType !== "string" || !Array.isArray(envelope.signatures)) {
    return failed("MALFORMED_TRUST_LIST", "not a DSSE envelope");
  }
  if (envelope.payloadType !== DST_TRUST_LIST) {
    return failed("TRUST_LIST_TYPE_MISMATCH", `payloadType is ${JSON.stringify(envelope.payloadType)}`);
  }
  const p = decodeEnvelopePayload(envelope);
  if (
    !isPlainObject(p) ||
    p.format !== TRUST_LIST_FORMAT ||
    typeof p.listId !== "string" ||
    !isInt(p.version) ||
    typeof p.publisher !== "string" ||
    !isInt(p.issuedAtUnix) ||
    !isInt(p.validFromUnix) ||
    !isInt(p.validUntilUnix) ||
    !Array.isArray(p.issuers)
  ) {
    return failed("MALFORMED_TRUST_LIST", "payload is not a kashscript-trust-list/1 document");
  }
  const partial = {
    listId: p.listId,
    version: p.version,
    publisher: p.publisher,
    issuedAtUnix: p.issuedAtUnix,
    validUntilUnix: p.validUntilUnix,
  };
  const publisherKey = selfCertifyingTypedKey(p.publisher);
  if (publisherKey === null) {
    return failed("TRUST_LIST_PUBLISHER_NOT_SELF_CERTIFYING", "the publisher must be a self-certifying did:kash", partial);
  }
  let verified: readonly string[];
  try {
    const res = await verifyEnvelope(envelope, (kid) => (kid === p.publisher ? publisherKey : null));
    verified = res.verifiedKeyids;
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    return failed("MALFORMED_TRUST_LIST", "envelope does not parse", partial);
  }
  if (!verified.includes(p.publisher as string)) {
    return failed("TRUST_LIST_SIGNATURE_INVALID", "not signed by its named publisher", partial);
  }
  for (const e of p.issuers) {
    const fault = issuerFault(e);
    if (fault !== null) return failed(fault, "an issuer entry is invalid", partial);
  }

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const pinned = (opts.pinnedPublishers ?? []).includes(p.publisher);
  const current = p.validFromUnix <= now && now <= p.validUntilUnix;
  const notes: string[] = [];
  if (!pinned) notes.push(`publisher ${p.publisher} is not pinned — this list is its word only and lists nobody`);
  if (!current) notes.push("outside its validity window — it lists nobody until a current version is presented");
  notes.push("offline: a newer version may exist; this check can only use the versions presented");
  return {
    ok: true,
    ...partial,
    pinned,
    current,
    issuers: p.issuers as unknown as readonly TrustListIssuer[],
    reason: null,
    notes,
  };
}

/** The lists that can list anything: verified, current, and the highest version of each listId per publisher. */
export function currentTrustLists(reports: readonly TrustListReport[]): readonly TrustListReport[] {
  const best = new Map<string, TrustListReport>();
  for (const r of reports) {
    if (!r.ok || !r.current || r.listId === null || r.version === null || r.publisher === null) continue;
    const key = `${r.publisher}:${r.listId}`;
    const prev = best.get(key);
    if (prev === undefined) {
      best.set(key, r);
    } else if (prev.pinned && !r.pinned) {
      // a pinned publisher's list is never replaced by an unpinned one
      continue;
    } else if (!prev.pinned && r.pinned) {
      best.set(key, r);
    } else if ((prev.version ?? -1) < r.version) {
      best.set(key, r);
    }
  }
  return [...best.values()];
}

export interface ListingMatch {
  readonly listId: string;
  readonly version: number;
  readonly publisher: string;
  readonly issuerId: string;
  readonly label: string;
  /** Only a pinned match makes a record "listed". */
  readonly pinned: boolean;
}

/**
 * Is `signer` listed to issue `tag` right now? Prefers a pinned list. Checks the
 * entry's own window as well as the list's.
 */
export function findListing(
  signer: string,
  tag: string,
  lists: readonly TrustListReport[],
  nowSec: number,
): ListingMatch | null {
  let unpinned: ListingMatch | null = null;
  for (const list of currentTrustLists(lists)) {
    for (const e of list.issuers) {
      if (!e.dsts.includes(tag)) continue;
      if (nowSec < e.validFromUnix || nowSec > e.validUntilUnix) continue;
      const bySelf = stripFragment(signer) === e.issuerId && selfCertifyingTypedKey(signer) !== null;
      const byKey = e.keys.some((k) => k.keyid === signer);
      if (!bySelf && !byKey) continue;
      const match: ListingMatch = {
        listId: list.listId as string,
        version: list.version as number,
        publisher: list.publisher as string,
        issuerId: e.issuerId,
        label: e.label,
        pinned: list.pinned,
      };
      if (list.pinned) return match;
      unpinned ??= match;
    }
  }
  return unpinned;
}

/** Every key the current lists name, marked with whether its list is pinned. */
export function trustListKeyMap(lists: readonly TrustListReport[]): ReadonlyMap<string, ListedKey> {
  const out = new Map<string, ListedKey>();
  for (const list of currentTrustLists(lists)) {
    for (const e of list.issuers) {
      for (const k of e.keys) {
        const key = typedKeyOf(k);
        if (key === null) continue;
        const prev = out.get(k.keyid);
        if (prev === undefined || (!prev.pinned && list.pinned)) out.set(k.keyid, { publicKey: key.publicKey, type: key.type, pinned: list.pinned });
      }
    }
  }
  return out;
}

/** Sign a trust list (the publisher's side). Refuses an unregistered tag or a bad key. */
export async function signTrustList(payload: TrustListPayload, signer: DsseSigner): Promise<DsseEnvelope> {
  if (payload.format !== TRUST_LIST_FORMAT) throw new AttestError("INVALID_INPUT", "format must be kashscript-trust-list/1");
  if (signer.keyid !== payload.publisher) throw new AttestError("INVALID_INPUT", "the signer must be the named publisher");
  for (const e of payload.issuers) {
    const fault = issuerFault(e);
    if (fault !== null) throw new AttestError("INVALID_INPUT", `issuer ${JSON.stringify(e.issuerId)}: ${fault}`);
  }
  return signEnvelope(payload, DST_TRUST_LIST, signer, { canonical: true });
}
