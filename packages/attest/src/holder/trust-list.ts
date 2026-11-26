/**
 * The trust list — which issuers a wallet admits (specs/holder-contract.md §3).
 *
 * A DSSE envelope, `payloadType` = {@link DST_TRUST_LIST}, signed by its
 * publisher's self-certifying key — spelled `did:kash` or `did:key` (RW-19 B;
 * two spellings of one key are one publisher wherever this file compares,
 * A7-02's rule). It is **a policy, not the format**
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
import { canonicalSignerOf } from "../signing";
import { selfCertifyingTypedKey, stripFragment, typedKeyOf, type ListedKey, type PublicKeyEntry } from "./keys";

/** One name for a self-certifying identifier of either spelling; anything else stays itself. */
const canonicalOrSelf = (id: string): string => canonicalSignerOf(id) ?? id;

export const DST_TRUST_LIST = "application/vnd.kash.trust-list+json" as const;
export const TRUST_LIST_FORMAT = "kashscript-trust-list/1" as const;

/** d91(f)'s issuer classes. An assurance carries the assessor's liability; Indorania carries none for a fact. Equal to lexicons' (a muffler test keeps them so). */
export const ISSUER_CLASSES = ["self-issuer", "counterparty", "assessor", "accredited-body", "insurer"] as const;
export type IssuerClass = (typeof ISSUER_CLASSES)[number];

/** d91(f)'s standing. Only `listed` lists; the other two say why an entry is still written down. */
export const STANDINGS = ["listed", "suspended", "removed"] as const;
export type Standing = (typeof STANDINGS)[number];

/** The floor an entry conforms to (d91(f): every trust entry cites the version of the floor it conforms to). */
export interface FloorRef {
  readonly version: string;
  readonly hash?: string;
}

/** A reference an issuer may attest against — a rule, a standard's clause — by id, and by hash when one version is meant. */
export interface TrustListReference {
  readonly id: string;
  readonly hash?: string;
}

export interface TrustListIssuer {
  /** The issuer's identifier — a `did:kash`, or a stable id when its keys are listed below. */
  readonly issuerId: string;
  /** A plain name a person can read (d44: never a concept they must learn). */
  readonly label: string;
  /** Keys for signers whose identifiers are not self-certifying (JWKS kids, structured DIDs). */
  readonly keys: readonly PublicKeyEntry[];
  /** Scope, part one: the exact registered DSTs this issuer may issue. */
  readonly dsts: readonly string[];
  readonly validFromUnix: number;
  readonly validUntilUnix: number;
  /** Identity: which class of issuer (d91(f)). Absent in a list written before d91. */
  readonly class?: IssuerClass;
  /** Standing: only `listed` lists. Absent reads as listed — a list written before d91 lists by its windows alone. */
  readonly standing?: Standing;
  /** Identity: the grade at which this key was shown to be this organisation's (d91(d)); 3 is the organisation signing as itself. */
  readonly grade?: 0 | 1 | 2 | 3;
  /** Scope, part two: the references it may attest against. Absent: any. */
  readonly references?: readonly TrustListReference[];
  /** This entry's floor, where it differs from the list's. */
  readonly floor?: FloorRef;
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
  /** The floor every entry is bound to, unless its own says otherwise (d91(f)). */
  readonly floor?: FloorRef;
  readonly practice?: boolean;
}

export type TrustListFailureReason =
  | "MALFORMED_TRUST_LIST"
  | "TRUST_LIST_TYPE_MISMATCH"
  | "TRUST_LIST_PUBLISHER_NOT_SELF_CERTIFYING"
  | "TRUST_LIST_SIGNATURE_INVALID"
  | "TRUST_LIST_UNREGISTERED_DST"
  | "TRUST_LIST_BAD_KEY"
  /** A class, standing, grade, reference or floor that is not one of the values d91 defines (KS-Q4). */
  | "TRUST_LIST_BAD_ASSERTION";

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
  /** The floor the list binds its entries to, or null for a list written before d91. */
  readonly floor: FloorRef | null;
  readonly practice: boolean;
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

const HEX64 = /^[0-9a-f]{64}$/;
const shortText = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max;

/** A floor reference: a version's name and, once the floor is a record, its hash. */
function isFloorRef(v: unknown): v is FloorRef {
  return isPlainObject(v) && shortText(v.version, 64) && (v.hash === undefined || (typeof v.hash === "string" && HEX64.test(v.hash))) && Object.keys(v).every((k) => k === "version" || k === "hash");
}

function isReference(v: unknown): v is TrustListReference {
  return isPlainObject(v) && shortText(v.id, 256) && (v.hash === undefined || (typeof v.hash === "string" && HEX64.test(v.hash))) && Object.keys(v).every((k) => k === "id" || k === "hash");
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
  // d91's three assertions, when written: each only one of the values d91 defines (KS-Q4).
  if (e.class !== undefined && !(ISSUER_CLASSES as readonly unknown[]).includes(e.class)) return "TRUST_LIST_BAD_ASSERTION";
  if (e.standing !== undefined && !(STANDINGS as readonly unknown[]).includes(e.standing)) return "TRUST_LIST_BAD_ASSERTION";
  if (e.grade !== undefined && !(isInt(e.grade) && e.grade >= 0 && e.grade <= 3)) return "TRUST_LIST_BAD_ASSERTION";
  if (e.references !== undefined && !(Array.isArray(e.references) && e.references.length <= 64 && e.references.every(isReference))) return "TRUST_LIST_BAD_ASSERTION";
  if (e.floor !== undefined && !isFloorRef(e.floor)) return "TRUST_LIST_BAD_ASSERTION";
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
    floor: null,
    practice: false,
    ...partial,
    reason,
    notes: [note],
  };
}

/**
 * Verify a trust list offline. Structurally junk input returns a report, never
 * a throw. The publisher's key comes out of its self-certifying identifier —
 * `did:kash` or `did:key` — and nothing is fetched.
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
  const canonicalPublisher = canonicalSignerOf(p.publisher);
  if (publisherKey === null || canonicalPublisher === null) {
    return failed("TRUST_LIST_PUBLISHER_NOT_SELF_CERTIFYING", "the publisher must be a self-certifying key (did:kash or did:key)", partial);
  }
  let verified: readonly string[];
  try {
    const res = await verifyEnvelope(envelope, (kid) => (canonicalSignerOf(kid) === canonicalPublisher ? publisherKey : null));
    verified = res.verifiedKeyids;
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    return failed("MALFORMED_TRUST_LIST", "envelope does not parse", partial);
  }
  if (!verified.some((kid) => canonicalSignerOf(kid) === canonicalPublisher)) {
    return failed("TRUST_LIST_SIGNATURE_INVALID", "not signed by its named publisher", partial);
  }
  for (const e of p.issuers) {
    const fault = issuerFault(e);
    if (fault !== null) return failed(fault, "an issuer entry is invalid", partial);
  }
  if (p.floor !== undefined && !isFloorRef(p.floor)) return failed("TRUST_LIST_BAD_ASSERTION", "the list's floor is not a version and an optional hash", partial);
  if (p.practice !== undefined && typeof p.practice !== "boolean") return failed("MALFORMED_TRUST_LIST", "practice is true or false", partial);

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  // Two spellings of one key are one publisher: a pin matches whichever spelling the list was signed under.
  const pinned = (opts.pinnedPublishers ?? []).some((pin) => canonicalOrSelf(pin) === canonicalPublisher);
  const current = p.validFromUnix <= now && now <= p.validUntilUnix;
  const notes: string[] = [];
  if (!pinned) notes.push(`publisher ${p.publisher} is not pinned — this list is its word only and lists nobody`);
  if (!current) notes.push("outside its validity window — it lists nobody until a current version is presented");
  const issuers = p.issuers as unknown as readonly TrustListIssuer[];
  const held = issuers.filter((e) => e.standing === "suspended" || e.standing === "removed").length;
  if (held > 0) notes.push(`${held} entr${held === 1 ? "y is" : "ies are"} suspended or removed — written down, listing nothing`);
  if (p.practice === true) notes.push("a practice list — not a real-world fact");
  notes.push("offline: a newer version may exist; this check can only use the versions presented");
  return {
    ok: true,
    ...partial,
    pinned,
    current,
    issuers,
    floor: p.floor === undefined ? null : (p.floor as FloorRef),
    practice: p.practice === true,
    reason: null,
    notes,
  };
}

/** The lists that can list anything: verified, current, and the highest version of each listId per publisher. */
export function currentTrustLists(reports: readonly TrustListReport[]): readonly TrustListReport[] {
  const best = new Map<string, TrustListReport>();
  for (const r of reports) {
    if (!r.ok || !r.current || r.listId === null || r.version === null || r.publisher === null) continue;
    const key = `${canonicalOrSelf(r.publisher)}:${r.listId}`;
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

/**
 * Scope, part two, for one entry: `unscoped` when the entry names no references
 * (it may attest against any); `not-checked` when it names some but the caller
 * did not say what the record is against; `in-scope` or `out-of-scope` otherwise.
 */
export type ListingScope = "in-scope" | "out-of-scope" | "unscoped" | "not-checked";

export interface ListingMatch {
  readonly listId: string;
  readonly version: number;
  readonly publisher: string;
  readonly issuerId: string;
  readonly label: string;
  /** Only a pinned match makes a record "listed". */
  readonly pinned: boolean;
  /** Identity: the issuer's class, or null for a list written before d91. */
  readonly class: IssuerClass | null;
  /** Identity: the grade the key was shown at, or null. */
  readonly grade: 0 | 1 | 2 | 3 | null;
  /** Standing, as the entry writes it (absent reads as listed). */
  readonly standing: Standing;
  readonly scope: ListingScope;
  /** The entry's floor, else the list's, else null. */
  readonly floor: FloorRef | null;
}

/** A pinned, current list names the signer for this tag and does not list it. */
export interface ListingRefusal extends ListingMatch {
  readonly why: "suspended" | "removed" | "out-of-scope";
}

export interface ListingLookup {
  /** The listing that lists it now: standing listed, inside its window, in scope; a pinned list's first. */
  readonly listing: ListingMatch | null;
  /** Why a pinned list that names it does not list it, when none does. A suspension or removal in any pinned list stands over a listing elsewhere. */
  readonly refused: ListingRefusal | null;
}

export interface FindListingOptions {
  /** What the record is against — a rule's id and hash — so the entry's scope can be read. */
  readonly reference?: TrustListReference;
}

function scopeOf(e: TrustListIssuer, reference: TrustListReference | undefined): ListingScope {
  if (e.references === undefined || e.references.length === 0) return "unscoped";
  if (reference === undefined) return "not-checked";
  const hit = e.references.some((r) => r.id === reference.id && (r.hash === undefined || reference.hash === undefined || r.hash === reference.hash));
  return hit ? "in-scope" : "out-of-scope";
}

/**
 * Is `signer` listed to issue `tag` right now — and if a pinned list names it
 * without listing it, why not? Reads d91's three assertions: identity (class,
 * grade), standing (only `listed` lists; a suspended or removed entry is a
 * refusal whatever its window) and scope (the exact tag, and the reference when
 * the caller names one). Prefers a pinned list. Checks the entry's own window as
 * well as the list's.
 */
export function lookupListing(
  signer: string,
  tag: string,
  lists: readonly TrustListReport[],
  nowSec: number,
  opts: FindListingOptions = {},
): ListingLookup {
  let pinnedMatch: ListingMatch | null = null;
  let unpinned: ListingMatch | null = null;
  let sanction: ListingRefusal | null = null;
  let outOfScope: ListingRefusal | null = null;
  for (const list of currentTrustLists(lists)) {
    for (const e of list.issuers) {
      if (!e.dsts.includes(tag)) continue;
      const bySelf = selfCertifyingTypedKey(signer) !== null && canonicalOrSelf(stripFragment(signer)) === canonicalOrSelf(e.issuerId);
      const byKey = e.keys.some((k) => k.keyid === signer);
      if (!bySelf && !byKey) continue;
      const standing: Standing = e.standing ?? "listed";
      const scope = scopeOf(e, opts.reference);
      const match: ListingMatch = {
        listId: list.listId as string,
        version: list.version as number,
        publisher: list.publisher as string,
        issuerId: e.issuerId,
        label: e.label,
        pinned: list.pinned,
        class: e.class ?? null,
        grade: e.grade ?? null,
        standing,
        scope,
        floor: e.floor ?? list.floor ?? null,
      };
      if (standing !== "listed") {
        // A sanction is read whatever the entry's window says (its window ends when it is written: lexicons' STANDING_WINDOW).
        if (list.pinned) sanction ??= { ...match, why: standing };
        continue;
      }
      if (nowSec < e.validFromUnix || nowSec > e.validUntilUnix) continue;
      if (scope === "out-of-scope") {
        if (list.pinned) outOfScope ??= { ...match, why: "out-of-scope" };
        continue;
      }
      if (list.pinned) pinnedMatch ??= match;
      else unpinned ??= match;
    }
  }
  if (sanction !== null) return { listing: null, refused: sanction };
  const listing = pinnedMatch ?? unpinned;
  return { listing, refused: listing?.pinned === true ? null : outOfScope };
}

/**
 * Is `signer` listed to issue `tag` right now? Prefers a pinned list. Checks the
 * entry's own window as well as the list's, its standing, and its scope when a
 * reference is given. {@link lookupListing} also says why not.
 */
export function findListing(
  signer: string,
  tag: string,
  lists: readonly TrustListReport[],
  nowSec: number,
  opts: FindListingOptions = {},
): ListingMatch | null {
  return lookupListing(signer, tag, lists, nowSec, opts).listing;
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
