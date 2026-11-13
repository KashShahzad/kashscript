/**
 * Key succession — how a key's authority moves to a successor, checkable by
 * anyone holding the claim, offline (specs/recovery.md, specs/countersign.md;
 * ADR-0018, ADR-0020). One DST, `kash-key-claim-v1`, and two paths:
 *
 *   • **prior-key** — the prior key and its successor sign one body. This is
 *     ADR-0018's claim, byte for byte.
 *   • **helpers** — the prior key is lost with its phone (d47(g)(4): recovery
 *     by succession, never by copying). The successor and a STRICT MAJORITY of
 *     the helper keys the prior key named IN ADVANCE — a signed
 *     `kash-recovery-helpers-v1` record — sign one body.
 *
 * Either path crosses algorithms: Ed25519 → P-256 and P-256 → Ed25519. Every
 * key's algorithm comes from its own `did:kash`, never from a signature.
 *
 * **A succession is not a takeover.** It needs the old key or the helper
 * quorum; the successor must sign too, so a claim names only a key someone
 * actually holds. A strict majority means any two quorums share a helper, so
 * two successors claimed for one prior expose the helper who signed both — and
 * the verifier trusts neither ({@link verifySuccessionSet}).
 *
 * **What it proves:** whoever held the prior key, or a quorum of the helpers it
 * chose, endorses the successor. **What it does not prove:** that the helpers
 * are distinct people (keys are not people), that the prior key was ever
 * subject-held (a `delegated-mint` key's minter could have made the claim, or
 * named the helpers), or anything about a record. It moves FUTURE authority;
 * it re-signs nothing and cures nothing behind it.
 */

import {
  canonicalizeBytes,
  isAlgorithmUnsupported,
  parseDidKey,
  signEventWith,
  verifyEventForKey,
  type EventSigner,
  type KashEventSignature,
  type KashKeyType,
  type SignedKashEvent,
} from "@kashscript/identity-core";
import { sha256Hex } from "./chain";
import type { KeyCustody, ReportedKeyCustody } from "./countersign";

/** What a claim says about its successor key's custody: the two words a signer may write, or `unknown` for anything else (AU-3, A7-05). */
function custodyOf(value: unknown): ReportedKeyCustody {
  return value === "subject-generated" ? "subject-generated" : value === "delegated-mint" ? "delegated-mint" : "unknown";
}

/** DST of a key-succession claim, either path. Registered in `./dst`. */
export const DST_KEY_CLAIM = "kash-key-claim-v1\n" as const;
/** DST of the helper record a key signs in advance. Registered in `./dst`. */
export const DST_RECOVERY_HELPERS = "kash-recovery-helpers-v1\n" as const;

/** At least this many helpers must agree. One is a single key holding everything — a copy, not a quorum. */
export const HELPERS_MIN_NEED = 2;
/** At most this many helper keys in one record: a bound on a verifier's work, not advice. */
export const HELPERS_MAX = 16;

const CLAIM_HEADER = { typ: "key-claim", v: 1 } as const;
const HELPERS_HEADER = { typ: "recovery-helpers", v: 1 } as const;

/* ── shapes ────────────────────────────────────────────────────────────── */

/** The claim body. On the helper path it also carries `by` and `helperSetSha256`. */
export interface CountersignKeyClaimBody {
  readonly act: "claim-key";
  readonly priorDid: string;
  readonly successorDid: string;
  readonly successorKeyCustody: KeyCustody;
  readonly claimedAtUnix: number;
}

/** The prior-key path: the prior key and its successor sign one body (ADR-0018). */
export interface CountersignKeyClaim {
  readonly header: Readonly<Record<string, unknown>>;
  readonly body: CountersignKeyClaimBody;
  /** Both over the identical `{header, body}` — which is why the header carries no DID of its own. */
  readonly signatures: {
    readonly prior: KashEventSignature;
    readonly successor: KashEventSignature;
  };
}

/** What a key names, in advance, as the helpers who may succeed it once it is lost. */
export interface HelperSetBody {
  readonly act: "name-helpers";
  /** The key these helpers may succeed — the key that signs this record. */
  readonly subjectDid: string;
  /** Helper keys: distinct `did:kash`es, never the subject. Per relationship, so no two places share one. */
  readonly helpers: readonly string[];
  /** How many must agree: at least 2, and a strict majority of `helpers`. */
  readonly need: number;
  /** A higher sequence for the same subject, when presented, supersedes a lower one. */
  readonly sequence: number;
  readonly issuedAtUnix: number;
  /** Null: no expiry — superseded, not lapsed (a lapsed set would lock its holder out). */
  readonly expiresAtUnix: number | null;
}

export interface SignedHelperSet {
  readonly header: Readonly<Record<string, unknown>>;
  readonly body: HelperSetBody;
  /** Signed by `subjectDid`'s key, under `kash-recovery-helpers-v1`. */
  readonly signature: KashEventSignature;
}

export interface HelperKeyClaimBody extends CountersignKeyClaimBody {
  readonly by: "helpers";
  /** SHA-256 over JCS(`{header, body}`) of the helper set this claim rests on. */
  readonly helperSetSha256: string;
}

/** One helper's signature over the claim's `{header, body}`, under `kash-key-claim-v1`. */
export interface HelperApproval {
  readonly did: string;
  readonly signature: KashEventSignature;
}

/** The helper path: the successor and a quorum of the named helpers sign one body. */
export interface HelperKeyClaim {
  readonly header: Readonly<Record<string, unknown>>;
  readonly body: HelperKeyClaimBody;
  readonly signatures: {
    readonly successor: KashEventSignature;
    readonly helpers: readonly HelperApproval[];
  };
  /** The record the prior key signed in advance, carried so the claim checks on its own. */
  readonly helperSet: SignedHelperSet;
}

export type KeyClaim = CountersignKeyClaim | HelperKeyClaim;

/** A signer known by its `did:kash`: an Ed25519 or P-256 software key, or a hardware key. */
export type SuccessionSigner = EventSigner & { readonly did: string };

/* ── reports ───────────────────────────────────────────────────────────── */

export type KeyClaimFailure =
  | "MALFORMED_CLAIM"
  | "UNKNOWN_PATH"
  | "SAME_KEY"
  | "PRIOR_SIGNATURE_INVALID"
  | "SUCCESSOR_SIGNATURE_INVALID"
  | "HELPER_SET_INVALID"
  | "HELPER_SET_NOT_FOR_PRIOR"
  | "HELPER_SET_MISMATCH"
  | "SUCCESSOR_IS_HELPER"
  | "OUTSIDE_HELPER_SET_WINDOW"
  | "BELOW_QUORUM"
  /** This runtime cannot run a key's algorithm (older browsers lack Ed25519). Nothing was judged. */
  | "RUNTIME_CANNOT_CHECK";

export interface CountersignKeyClaimReport {
  readonly priorDid: string;
  readonly successorDid: string;
  /** `unknown` when the claim states none, or a word outside the two (AU-3, A7-05) — never read as subject-held. */
  readonly successorKeyCustody: ReportedKeyCustody;
  /** The prior key's own signature. Always false on the helper path — that key is gone. */
  readonly priorSignatureOk: boolean;
  readonly successorSignatureOk: boolean;
  readonly ok: boolean;
  /** PL-2: which authority moved the key. */
  readonly path: "prior-key" | "helpers";
  readonly priorKeyType: KashKeyType | null;
  readonly successorKeyType: KashKeyType | null;
  /** The helper path's count, or null on the prior-key path. */
  readonly helpers: {
    readonly need: number;
    readonly of: number;
    readonly counted: number;
    readonly signers: readonly string[];
    readonly sequence: number;
  } | null;
  readonly reason: KeyClaimFailure | null;
  readonly notes: readonly string[];
}

export type HelperSetFailure = "MALFORMED_HELPER_SET" | "RULES_BROKEN" | "SIGNATURE_INVALID" | "RUNTIME_CANNOT_CHECK";

export interface HelperSetReport {
  readonly ok: boolean;
  readonly subjectDid: string | null;
  readonly need: number | null;
  readonly of: number | null;
  readonly sequence: number | null;
  readonly signatureOk: boolean;
  readonly reason: HelperSetFailure | null;
  /** Each rule the record breaks, in words. */
  readonly problems: readonly string[];
}

/* ── shared ────────────────────────────────────────────────────────────── */

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

function keyTypeOf(did: unknown): KashKeyType | null {
  if (typeof did !== "string") return null;
  try {
    return parseDidKey(did).type;
  } catch {
    return null;
  }
}

/** Verify a Kash-Event under an EXPECTED DST and the key its signer's `did:kash`
 *  declares. A runtime that cannot run that algorithm throws; anything else that
 *  fails is simply not ok. */
async function signedBy(event: SignedKashEvent, did: string, dst: string): Promise<boolean> {
  if (!isPlainObject(event.signature) || event.signature.dst !== dst) return false;
  let key;
  try {
    key = parseDidKey(did);
  } catch {
    return false;
  }
  try {
    return await verifyEventForKey(event, key);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) throw err;
    return false;
  }
}

/** SHA-256 over JCS(`{header, body}`) — the value a helper claim binds its set by. */
export async function helperSetSha256(set: Pick<SignedHelperSet, "header" | "body">): Promise<string> {
  return sha256Hex(canonicalizeBytes({ header: set.header, body: set.body }));
}

/** SHA-256 over JCS(`{header, body}`) of a claim — what every signer of it signed. */
export async function keyClaimSha256(claim: Pick<KeyClaim, "header" | "body">): Promise<string> {
  return sha256Hex(canonicalizeBytes({ header: claim.header, body: claim.body }));
}

/** Every rule a helper set breaks, in words. Empty means the record is well formed. */
export function helperSetProblems(body: unknown): string[] {
  const out: string[] = [];
  if (!isPlainObject(body)) return ["not an object"];
  if (body.act !== "name-helpers") out.push('act is not "name-helpers"');
  if (keyTypeOf(body.subjectDid) === null) out.push("subjectDid is not a did:kash");
  const helpers = body.helpers;
  if (!Array.isArray(helpers)) {
    out.push("helpers is not a list");
  } else {
    if (helpers.length < HELPERS_MIN_NEED) out.push(`fewer than ${HELPERS_MIN_NEED} helpers`);
    if (helpers.length > HELPERS_MAX) out.push(`more than ${HELPERS_MAX} helpers`);
    if (helpers.some((h) => keyTypeOf(h) === null)) out.push("a helper is not a did:kash");
    if (new Set(helpers).size !== helpers.length) out.push("a helper key is listed twice — one key is one vote");
    if (helpers.includes(body.subjectDid)) out.push("the subject names itself as a helper");
  }
  const need = body.need;
  if (!isInt(need) || need < HELPERS_MIN_NEED) out.push(`need is below ${HELPERS_MIN_NEED} — one key alone is a copy, not a quorum`);
  else if (Array.isArray(helpers)) {
    if (need > helpers.length) out.push("need is more than the helpers named");
    if (need * 2 <= helpers.length) out.push("need is not a strict majority — two separate quorums could each claim the key");
  }
  if (!isInt(body.sequence) || body.sequence < 1) out.push("sequence is not a positive integer");
  if (!isInt(body.issuedAtUnix)) out.push("issuedAtUnix is not an integer");
  if (body.expiresAtUnix !== null && (!isInt(body.expiresAtUnix) || !isInt(body.issuedAtUnix) || body.expiresAtUnix <= body.issuedAtUnix)) {
    out.push("expiresAtUnix is neither null nor after issuedAtUnix");
  }
  return out;
}

/* ── signing ───────────────────────────────────────────────────────────── */

/**
 * The record a key signs in advance, naming the helper keys that may succeed
 * it. Refuses a record that breaks a rule, so a wallet cannot write one a
 * verifier would reject.
 */
export async function signHelperSet(input: {
  readonly subject: SuccessionSigner;
  readonly helpers: readonly string[];
  readonly need: number;
  readonly sequence: number;
  readonly issuedAtUnix: number;
  readonly expiresAtUnix?: number | null;
}): Promise<SignedHelperSet> {
  const body: HelperSetBody = {
    act: "name-helpers",
    subjectDid: input.subject.did,
    helpers: [...input.helpers],
    need: input.need,
    sequence: input.sequence,
    issuedAtUnix: input.issuedAtUnix,
    expiresAtUnix: input.expiresAtUnix ?? null,
  };
  const problems = helperSetProblems(body);
  if (problems.length > 0) throw new Error(`helper set refused: ${problems.join("; ")}`);
  const signature = await signEventWith(HELPERS_HEADER, body, input.subject, { dst: DST_RECOVERY_HELPERS });
  return { header: HELPERS_HEADER, body, signature };
}

/** The prior-key path, any algorithm on either side: both keys sign one body. */
export async function signKeyClaim(input: {
  readonly prior: SuccessionSigner;
  readonly successor: SuccessionSigner;
  readonly successorKeyCustody?: KeyCustody;
  readonly claimedAtUnix: number;
}): Promise<CountersignKeyClaim> {
  if (input.prior.did === input.successor.did) throw new Error("a key cannot succeed itself");
  const body: CountersignKeyClaimBody = {
    act: "claim-key",
    priorDid: input.prior.did,
    successorDid: input.successor.did,
    successorKeyCustody: input.successorKeyCustody ?? "subject-generated",
    claimedAtUnix: input.claimedAtUnix,
  };
  const [prior, successor] = await Promise.all([
    signEventWith(CLAIM_HEADER, body, input.prior, { dst: DST_KEY_CLAIM }),
    signEventWith(CLAIM_HEADER, body, input.successor, { dst: DST_KEY_CLAIM }),
  ]);
  return { header: CLAIM_HEADER, body, signatures: { prior, successor } };
}

/** The helper path, before any helper has signed: the successor signs, and the claim names the set. */
export async function draftHelperClaim(input: {
  readonly helperSet: SignedHelperSet;
  readonly successor: SuccessionSigner;
  readonly successorKeyCustody?: KeyCustody;
  readonly claimedAtUnix: number;
}): Promise<HelperKeyClaim> {
  const set = input.helperSet.body;
  if (input.successor.did === set.subjectDid) throw new Error("a key cannot succeed itself");
  if (set.helpers.includes(input.successor.did)) throw new Error("a helper key cannot be the successor");
  const body: HelperKeyClaimBody = {
    act: "claim-key",
    priorDid: set.subjectDid,
    successorDid: input.successor.did,
    successorKeyCustody: input.successorKeyCustody ?? "subject-generated",
    claimedAtUnix: input.claimedAtUnix,
    by: "helpers",
    helperSetSha256: await helperSetSha256(input.helperSet),
  };
  const successor = await signEventWith(CLAIM_HEADER, body, input.successor, { dst: DST_KEY_CLAIM });
  return { header: CLAIM_HEADER, body, signatures: { successor, helpers: [] }, helperSet: input.helperSet };
}

/** One helper signs a claim — only if the claim's set names that helper's key. */
export async function approveKeyClaim(claim: HelperKeyClaim, helper: SuccessionSigner): Promise<HelperApproval> {
  if (!claim.helperSet.body.helpers.includes(helper.did)) throw new Error("this claim's helper set does not name that key");
  const signature = await signEventWith(claim.header, claim.body, helper, { dst: DST_KEY_CLAIM });
  return { did: helper.did, signature };
}

/** The claim with these approvals added — one per helper key, the first kept. */
export function withApprovals(claim: HelperKeyClaim, approvals: readonly HelperApproval[]): HelperKeyClaim {
  const helpers = [...claim.signatures.helpers];
  for (const a of approvals) if (!helpers.some((h) => h.did === a.did)) helpers.push(a);
  return { ...claim, signatures: { ...claim.signatures, helpers } };
}

/* ── verifying ─────────────────────────────────────────────────────────── */

/** Verify a helper set on its own: well formed, and signed by its subject's key. */
export async function verifyHelperSet(set: unknown): Promise<HelperSetReport> {
  const empty = { subjectDid: null, need: null, of: null, sequence: null, signatureOk: false };
  if (!isPlainObject(set) || !isPlainObject(set.body) || !isPlainObject(set.header) || !isPlainObject(set.signature)) {
    return { ok: false, ...empty, reason: "MALFORMED_HELPER_SET", problems: ["not a signed helper set"] };
  }
  const body = set.body as unknown as HelperSetBody;
  const base = {
    subjectDid: typeof body.subjectDid === "string" ? body.subjectDid : null,
    need: isInt(body.need) ? body.need : null,
    of: Array.isArray(body.helpers) ? body.helpers.length : null,
    sequence: isInt(body.sequence) ? body.sequence : null,
  };
  const problems = helperSetProblems(body);
  let signatureOk = false;
  try {
    signatureOk = typeof body.subjectDid === "string" && (await signedBy(set as unknown as SignedKashEvent, body.subjectDid, DST_RECOVERY_HELPERS));
  } catch (err) {
    if (!isAlgorithmUnsupported(err)) throw err;
    return { ok: false, ...base, signatureOk: false, reason: "RUNTIME_CANNOT_CHECK", problems };
  }
  const reason: HelperSetFailure | null = problems.length > 0 ? "RULES_BROKEN" : !signatureOk ? "SIGNATURE_INVALID" : null;
  return { ok: reason === null, ...base, signatureOk, reason, problems };
}

function blankReport(claim: unknown, reason: KeyClaimFailure, note: string): CountersignKeyClaimReport {
  const body = isPlainObject(claim) && isPlainObject(claim.body) ? claim.body : {};
  return {
    priorDid: typeof body.priorDid === "string" ? body.priorDid : "",
    successorDid: typeof body.successorDid === "string" ? body.successorDid : "",
    successorKeyCustody: custodyOf(body.successorKeyCustody),
    priorSignatureOk: false,
    successorSignatureOk: false,
    ok: false,
    path: body.by === "helpers" ? "helpers" : "prior-key",
    priorKeyType: keyTypeOf(body.priorDid),
    successorKeyType: keyTypeOf(body.successorDid),
    helpers: null,
    reason,
    notes: [note],
  };
}

/**
 * Verify one key-succession claim, offline, on whichever path it takes. Used
 * for the claims in a countersign bundle and the key-succession records a
 * holder exports. What it proves and does not prove is in the module header.
 */
export async function verifyKeyClaim(claim: KeyClaim): Promise<CountersignKeyClaimReport> {
  try {
    return await verifyKeyClaimInner(claim);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) {
      return blankReport(claim, "RUNTIME_CANNOT_CHECK", "this runtime cannot run a key's algorithm (Ed25519 arrived late in some browsers) — nothing was judged");
    }
    throw err;
  }
}

async function verifyKeyClaimInner(claim: KeyClaim): Promise<CountersignKeyClaimReport> {
  if (!isPlainObject(claim) || !isPlainObject(claim.body) || !isPlainObject(claim.signatures) || !isPlainObject(claim.header)) {
    return blankReport(claim, "MALFORMED_CLAIM", "not a key claim");
  }
  const cb = claim.body as HelperKeyClaimBody | CountersignKeyClaimBody;
  const by = (cb as { by?: unknown }).by;
  if (by !== undefined && by !== "helpers") return blankReport(claim, "UNKNOWN_PATH", `unknown path ${JSON.stringify(by)}`);
  const path = by === "helpers" ? "helpers" : "prior-key";
  const priorKeyType = keyTypeOf(cb.priorDid);
  const successorKeyType = keyTypeOf(cb.successorDid);
  const custody: ReportedKeyCustody = custodyOf(cb.successorKeyCustody);
  const notes: string[] = ["a claim moves future authority only; it re-signs nothing and cures nothing behind it"];
  if (priorKeyType !== null && successorKeyType !== null && priorKeyType !== successorKeyType) {
    notes.push(`succession across algorithms: ${priorKeyType} → ${successorKeyType}`);
  }
  if (custody === "delegated-mint") notes.push("the successor key is delegated-mint — not subject-held");
  if (custody === "unknown") notes.push("the claim states no custody for the successor key — unknown, so not subject-held");

  const asEvent = (signature: unknown): SignedKashEvent =>
    ({ header: claim.header, body: claim.body, signature }) as unknown as SignedKashEvent;
  const successorSignatureOk =
    typeof cb.successorDid === "string" && (await signedBy(asEvent(claim.signatures.successor), cb.successorDid, DST_KEY_CLAIM));
  const common = { priorDid: String(cb.priorDid ?? ""), successorDid: String(cb.successorDid ?? ""), successorKeyCustody: custody, path, priorKeyType, successorKeyType } as const;
  const sameKey = cb.priorDid === cb.successorDid;
  const malformedBody = cb.act !== "claim-key" || priorKeyType === null || successorKeyType === null || !isInt(cb.claimedAtUnix);

  if (path === "prior-key") {
    const sigs = claim.signatures as CountersignKeyClaim["signatures"];
    const priorSignatureOk = typeof cb.priorDid === "string" && (await signedBy(asEvent(sigs.prior), cb.priorDid, DST_KEY_CLAIM));
    const reason: KeyClaimFailure | null = malformedBody
      ? "MALFORMED_CLAIM"
      : sameKey
        ? "SAME_KEY"
        : !priorSignatureOk
          ? "PRIOR_SIGNATURE_INVALID"
          : !successorSignatureOk
            ? "SUCCESSOR_SIGNATURE_INVALID"
            : null;
    return { ...common, priorSignatureOk, successorSignatureOk, ok: reason === null, helpers: null, reason, notes };
  }

  // The helper path.
  notes.push("the prior key was lost; a quorum of the helpers it named in advance stood in for it");
  notes.push("helpers are keys, not people — a quorum is only as independent as the people behind its keys");
  const hc = claim as HelperKeyClaim;
  const setReport = await verifyHelperSet(hc.helperSet);
  const set = isPlainObject(hc.helperSet) && isPlainObject(hc.helperSet.body) ? (hc.helperSet.body as HelperSetBody) : null;
  const named = new Set(Array.isArray(set?.helpers) ? set!.helpers : []);
  const signers: string[] = [];
  const approvals = Array.isArray(hc.signatures.helpers) ? hc.signatures.helpers : [];
  for (const a of approvals) {
    if (!isPlainObject(a) || typeof a.did !== "string" || !named.has(a.did) || signers.includes(a.did)) continue;
    if (a.did === cb.priorDid || a.did === cb.successorDid) continue;
    if (await signedBy(asEvent(a.signature), a.did, DST_KEY_CLAIM)) signers.push(a.did);
  }
  const need = set !== null && isInt(set.need) ? set.need : 0;
  const helpers = { need, of: named.size, counted: signers.length, signers, sequence: set !== null && isInt(set.sequence) ? set.sequence : 0 };
  if (approvals.length > signers.length) notes.push(`${approvals.length - signers.length} helper signature(s) did not count — not named in the set, repeated, or not valid`);

  let reason: KeyClaimFailure | null = null;
  if (malformedBody) reason = "MALFORMED_CLAIM";
  else if (sameKey) reason = "SAME_KEY";
  else if (setReport.reason === "RUNTIME_CANNOT_CHECK") reason = "RUNTIME_CANNOT_CHECK";
  else if (!setReport.ok || set === null) reason = "HELPER_SET_INVALID";
  else if (set.subjectDid !== cb.priorDid) reason = "HELPER_SET_NOT_FOR_PRIOR";
  else if ((cb as HelperKeyClaimBody).helperSetSha256 !== (await helperSetSha256(hc.helperSet))) reason = "HELPER_SET_MISMATCH";
  else if (named.has(cb.successorDid)) reason = "SUCCESSOR_IS_HELPER";
  else if (cb.claimedAtUnix < set.issuedAtUnix || (set.expiresAtUnix !== null && cb.claimedAtUnix > set.expiresAtUnix)) reason = "OUTSIDE_HELPER_SET_WINDOW";
  else if (!successorSignatureOk) reason = "SUCCESSOR_SIGNATURE_INVALID";
  else if (signers.length < need) reason = "BELOW_QUORUM";
  if (setReport.problems.length > 0) notes.push(...setReport.problems.map((p) => `helper set: ${p}`));
  return { ...common, priorSignatureOk: false, successorSignatureOk, ok: reason === null, helpers, reason, notes };
}

export interface SuccessionConflict {
  readonly priorDid: string;
  /** Two or more successors, each on a claim that verified on its own. */
  readonly successors: readonly string[];
  /** Helper keys that signed more than one of them — a strict majority guarantees one when both used helpers. */
  readonly signedBoth: readonly string[];
}

export interface SuccessionSetReport {
  readonly ok: boolean;
  readonly claims: readonly CountersignKeyClaimReport[];
  /** A fork: neither side is trusted for future authority. */
  readonly conflicts: readonly SuccessionConflict[];
  /** Helper claims resting on a set that a newer presented set (same subject, higher sequence, issued before the claim) supersedes. */
  readonly superseded: readonly { readonly priorDid: string; readonly successorDid: string; readonly sequence: number; readonly newerSequence: number }[];
  readonly notes: readonly string[];
}

/**
 * Verify several claims together, as a holder's export or a bundle presents
 * them. Each claim must verify on its own; then two successors for one prior
 * are a **conflict** (neither is trusted), and a helper claim whose set a newer
 * presented set supersedes does not count. Offline, a verifier knows only what
 * it is shown: the report says so.
 */
export async function verifySuccessionSet(
  claims: readonly KeyClaim[],
  helperSets: readonly SignedHelperSet[] = [],
): Promise<SuccessionSetReport> {
  const reports: CountersignKeyClaimReport[] = [];
  for (const c of claims) reports.push(await verifyKeyClaim(c));

  // Every verified set presented, from the list and from the claims themselves.
  const sets: HelperSetBody[] = [];
  for (const s of [...helperSets, ...claims.flatMap((c) => ("helperSet" in c && isPlainObject(c.helperSet) ? [c.helperSet] : []))]) {
    if ((await verifyHelperSet(s)).ok) sets.push(s.body);
  }
  const superseded: SuccessionSetReport["superseded"][number][] = [];
  for (const r of reports) {
    if (!r.ok || r.path !== "helpers" || r.helpers === null) continue;
    const claimedAt = (claims[reports.indexOf(r)]!.body as CountersignKeyClaimBody).claimedAtUnix;
    const newer = sets
      .filter((s) => s.subjectDid === r.priorDid && s.sequence > r.helpers!.sequence && s.issuedAtUnix <= claimedAt)
      .reduce<number | null>((m, s) => (m === null || s.sequence > m ? s.sequence : m), null);
    if (newer !== null) superseded.push({ priorDid: r.priorDid, successorDid: r.successorDid, sequence: r.helpers.sequence, newerSequence: newer });
  }

  const byPrior = new Map<string, CountersignKeyClaimReport[]>();
  for (const r of reports) {
    if (!r.ok || superseded.some((s) => s.priorDid === r.priorDid && s.successorDid === r.successorDid)) continue;
    byPrior.set(r.priorDid, [...(byPrior.get(r.priorDid) ?? []), r]);
  }
  const conflicts: SuccessionConflict[] = [];
  for (const [priorDid, rs] of byPrior) {
    const successors = [...new Set(rs.map((r) => r.successorDid))];
    if (successors.length < 2) continue;
    const counts = new Map<string, number>();
    for (const r of rs) for (const h of r.helpers?.signers ?? []) counts.set(h, (counts.get(h) ?? 0) + 1);
    conflicts.push({ priorDid, successors, signedBoth: [...counts].filter(([, n]) => n > 1).map(([h]) => h) });
  }
  const notes: string[] = [];
  if (conflicts.length > 0) notes.push("two successors were claimed for one key — neither is trusted for future authority; ask the person");
  if (superseded.length > 0) notes.push("a helper claim rests on a set its own subject later replaced — it does not count");
  notes.push("offline, a verifier knows only the claims and sets it was shown — absence of a conflicting claim is not proof none exists");
  return {
    ok: reports.every((r) => r.ok) && conflicts.length === 0 && superseded.length === 0,
    claims: reports,
    conflicts,
    superseded,
    notes,
  };
}
