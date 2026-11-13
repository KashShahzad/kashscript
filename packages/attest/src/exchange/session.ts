/**
 * The session receipt (ECOSYSTEM d42 §4; specs/session-receipt.md).
 *
 * A session is one encounter between a person and an establishment. Every line
 * is a DSSE envelope (`application/vnd.indorania.session-event+json`) that BOTH
 * parties sign with their relationship keys over the same bytes. The receipt
 * is an unsigned container — every part carries its own signatures and every
 * link is checked by digest, so it is trusted for nothing.
 *
 *   • two relationship ids, and only those two may sign — **Indorania anchors a
 *     session and never signs one** (d47(d)); any other signer fails it.
 *   • one signature is **pending, never proof** (d41).
 *   • the total is shared; line items are salted commitments — that a person
 *     bought a flat white is provable only if they keep the opening and choose
 *     to show it (d41: arrival, not consumption).
 *   • either side may close, neither may delete: a disagreement is a new signed
 *     line; its countersignature acknowledges it was raised, not its merit.
 *   • the anchor's second version (GP-6) makes the head one leaf of an RFC 6962
 *     batch: a receipt carries its own audit path, so checking it shows no other
 *     session. A first-version anchor verifies forever and says it proves no batch.
 */

import { canonicalizeBytes, isAlgorithmUnsupported } from "@kashscript/identity-core";
import { bytesToHex, hexToBytes, sha256Hex } from "../chain";
import { base64ToBytes, bytesToBase64 } from "../ed25519";
import { pae, signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "../dsse";
import { AttestError } from "../errors";
import { selfCertifyingTypedKey } from "../holder/keys";
import { signBytes } from "../signing";
import type { AnchorWitness } from "../witness";
import { rfc6962LeafHash, rfc6962Tree, rfc6962VerifyInclusion } from "../witness/rfc6962";
import { SESSION_EVENT_DST, SESSION_HEAD_LEAF_DST } from "./constants";

export const SESSION_RECEIPT_FORMAT = "kashscript-session-receipt/1" as const;
export const SESSION_EVENT_SPEC = "indorania.session-event/1" as const;

export type SessionProfile = "presence+flow" | "process+flow" | "presence+process+flow" | "flow+process";
export type SessionEventKind = "open" | "presence" | "flow" | "process" | "disagreement" | "close";
export type SessionParty = "establishment" | "person";

/** What each profile may record, so a coffee does not record what a repair needs. */
export const SESSION_PROFILES: Readonly<Record<SessionProfile, { readonly kinds: readonly SessionEventKind[]; readonly place: boolean; readonly example: string }>> = {
  "presence+flow": { kinds: ["presence", "flow"], place: true, example: "a coffee" },
  "process+flow": { kinds: ["process", "flow"], place: true, example: "a repair — the place, no presence line" },
  "presence+process+flow": { kinds: ["presence", "process", "flow"], place: true, example: "a guided day" },
  "flow+process": { kinds: ["flow", "process"], place: false, example: "a grant tranche — no presence, no place" },
};
const EVERY_PROFILE: readonly SessionEventKind[] = ["open", "disagreement", "close"];

export interface SessionEventPayload {
  readonly spec: typeof SESSION_EVENT_SPEC;
  readonly sessionId: string;
  readonly seq: number;
  readonly prevSha256: string;
  readonly kind: SessionEventKind;
  readonly atUnix: number;
  /** Who wrote the line. They sign first; the other party's signature completes it. */
  readonly by: SessionParty;
  readonly body: Readonly<Record<string, unknown>>;
}

/** The anchor's second version (GP-6): the head as one leaf of an RFC 6962 batch. */
export const SESSION_ANCHOR_FORMAT = "kashscript-session-anchor/2" as const;

/** The first anchor (PL-3): a line's head and a witness. It says nothing about any batch. */
export interface SessionAnchorV1 {
  /** Absent in every first-version anchor written so far; `kashscript-session-anchor/1` means the same. */
  readonly formatVersion?: "kashscript-session-anchor/1";
  /** SHA-256 of the event it covers (its payload bytes). */
  readonly headSha256: string;
  readonly coversSeq: number;
  /** A transparency-log receipt over the head hash. A log that requires the
   *  anchoring host to sign the hash records an ANCHORING signature — never a
   *  party signature over an event. */
  readonly witness: AnchorWitness;
}

/**
 * The second anchor (GP-6): the head is one leaf of an RFC 6962 batch,
 * SHA-256(0x00 ‖ "kash-session-head-v1\n" ‖ treeSize (8 bytes, big-endian) ‖ head).
 * It carries the batch's root and its own audit path — the sibling hashes up to
 * that root — and nothing of any other session in the batch.
 */
export interface SessionAnchorV2 {
  readonly formatVersion: typeof SESSION_ANCHOR_FORMAT;
  /** SHA-256 of the event it covers (its payload bytes). */
  readonly headSha256: string;
  readonly coversSeq: number;
  /** The batch's root, hex: what the witness witnessed. */
  readonly root: string;
  readonly inclusion: {
    readonly treeSize: number;
    readonly leafIndex: number;
    /** Sibling hashes, hex, nearest first. */
    readonly path: readonly string[];
  };
  /** A transparency-log receipt over the ROOT — an anchoring signature, never a party signature. */
  readonly witness: AnchorWitness;
}

export type SessionAnchor = SessionAnchorV1 | SessionAnchorV2;

export interface SessionReceipt {
  readonly formatVersion: typeof SESSION_RECEIPT_FORMAT;
  readonly sessionId: string;
  readonly profile: SessionProfile;
  /** Pairwise relationship identifiers — never anyone's global id. */
  readonly parties: { readonly establishment: string; readonly person: string };
  readonly events: readonly DsseEnvelope[];
  readonly anchor: SessionAnchor | null;
}

/* ── building (both parties' side) ─────────────────────────────────────── */

export function sessionGenesisSha256(sessionId: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(`indorania-session-genesis\u0000${sessionId}`));
}

export async function sessionEventSha256(event: DsseEnvelope): Promise<string> {
  return sha256Hex(base64ToBytes(event.payload));
}

/** The author signs a line (canonical payload). */
export function signSessionEvent(payload: SessionEventPayload, author: DsseSigner): Promise<DsseEnvelope> {
  return signEnvelope(payload, SESSION_EVENT_DST, author, { canonical: true });
}

/** The other party signs the same PAE bytes — the line becomes complete. Either
 *  party's key may be Ed25519 or P-256 (a phone's secure chip); each verifies by its own type. */
export async function cosignSessionEvent(event: DsseEnvelope, cosigner: DsseSigner): Promise<DsseEnvelope> {
  const sig = await signBytes(cosigner, pae(event.payloadType, base64ToBytes(event.payload)), "der");
  return { ...event, signatures: [...event.signatures, { keyid: cosigner.keyid, sig: bytesToBase64(sig) }] };
}

/** A line item as a salted commitment: SHA-256(salt ‖ JCS(item)). The person keeps salt and item. */
export async function lineItemCommitment(saltHex: string, item: unknown): Promise<string> {
  const salt = hexToBytes(saltHex);
  const body = canonicalizeBytes(item);
  const buf = new Uint8Array(salt.length + body.length);
  buf.set(salt, 0);
  buf.set(body, salt.length);
  return sha256Hex(buf);
}

/** Open a commitment the holder chose to show. */
export async function openLineItem(commitment: string, saltHex: string, item: unknown): Promise<boolean> {
  try {
    return (await lineItemCommitment(saltHex, item)) === commitment;
  } catch {
    return false;
  }
}

export function newLineItemSalt(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

/* ── anchoring (the anchoring host's side) ─────────────────────────────── */

/**
 * The leaf a session's head becomes in a batch of `treeSize`:
 * SHA-256(0x00 ‖ "kash-session-head-v1\n" ‖ treeSize as 8 bytes, big-endian ‖ head).
 * RFC 6962's path alone does not fix the tree's size — a proof for a batch of 5
 * can pass as one of 6 — so every leaf carries it, and the root commits to it.
 */
export async function sessionHeadLeafHash(headSha256: string, treeSize: number): Promise<Uint8Array> {
  if (typeof headSha256 !== "string" || !HEX64.test(headSha256)) {
    throw new AttestError("INVALID_INPUT", "a session head is 64 lowercase hex characters");
  }
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) throw new AttestError("INVALID_INPUT", "a batch holds at least one session");
  const tag = new TextEncoder().encode(SESSION_HEAD_LEAF_DST);
  const data = new Uint8Array(tag.length + 8 + 32);
  data.set(tag, 0);
  const size = new DataView(data.buffer, tag.length, 8);
  size.setUint32(0, Math.floor(treeSize / 2 ** 32));
  size.setUint32(4, treeSize % 2 ** 32);
  data.set(hexToBytes(headSha256), tag.length + 8);
  return rfc6962LeafHash(data);
}

export interface SessionAnchorBatch {
  /** The batch's root, hex — the one thing a witness is asked to witness. */
  readonly root: string;
  readonly treeSize: number;
  /** The i-th session's anchor: its own path and the batch's witness, nothing of the others. */
  anchorFor(index: number, witness: AnchorWitness): SessionAnchorV2;
}

/**
 * For an anchoring host: one RFC 6962 tree over complete sessions' heads, in
 * the order given. Witness `root` once, then give each receipt
 * `anchorFor(i, witness)`. Only the host ever holds the whole batch.
 */
export async function sessionAnchorBatch(
  entries: readonly { readonly headSha256: string; readonly coversSeq: number }[],
): Promise<SessionAnchorBatch> {
  // Every entry is checked before any leaf is built, and a bad one is named by its index.
  const firstSeen = new Map<string, number>();
  for (const [i, e] of entries.entries()) {
    if (typeof e.headSha256 !== "string" || !HEX64.test(e.headSha256)) {
      throw new AttestError("INVALID_INPUT", `entry ${i}: a session head is 64 lowercase hex characters`);
    }
    if (!isInt(e.coversSeq) || e.coversSeq < 0) {
      throw new AttestError("INVALID_INPUT", `entry ${i}: coversSeq is the index of the line the head hashes`);
    }
    const earlier = firstSeen.get(e.headSha256);
    if (earlier !== undefined) {
      throw new AttestError("INVALID_INPUT", `entries ${earlier} and ${i} carry the same head — a session is anchored once per batch`);
    }
    firstSeen.set(e.headSha256, i);
  }
  const leaves: Uint8Array[] = [];
  for (const e of entries) leaves.push(await sessionHeadLeafHash(e.headSha256, entries.length));
  const tree = await rfc6962Tree(leaves);
  const root = bytesToHex(tree.root);
  return {
    root,
    treeSize: tree.size,
    anchorFor(index: number, witness: AnchorWitness): SessionAnchorV2 {
      const e = Number.isSafeInteger(index) ? entries[index] : undefined;
      if (e === undefined) throw new AttestError("INVALID_INPUT", `no session ${String(index)} in a batch of ${tree.size}`);
      return {
        formatVersion: SESSION_ANCHOR_FORMAT,
        headSha256: e.headSha256,
        coversSeq: e.coversSeq,
        root,
        inclusion: { treeSize: tree.size, leafIndex: index, path: tree.path(index).map(bytesToHex) },
        witness,
      };
    },
  };
}

/* ── verifying ─────────────────────────────────────────────────────────── */

export type SessionFault =
  | "MALFORMED_RECEIPT"
  | "PARTIES_INVALID"
  | "EVENT_TYPE_MISMATCH"
  | "EVENT_MALFORMED"
  | "SESSION_MISMATCH"
  | "SEQ_GAP"
  | "CHAIN_BROKEN"
  | "FOREIGN_SIGNER"
  | "BAD_SIGNATURE"
  | "UNSIGNED_EVENT"
  | "AUTHOR_NOT_SIGNED"
  | "FIRST_EVENT_NOT_OPEN"
  | "OPEN_MISMATCH"
  | "PROFILE_VIOLATION"
  | "PLACE_NOT_ALLOWED"
  | "AFTER_CLOSE"
  | "DUPLICATE_CLOSE"
  | "BAD_DISAGREEMENT"
  | "TOTAL_MALFORMED"
  | "LINE_COUNT_MISMATCH"
  | "ANCHOR_MISMATCH"
  /** This runtime cannot run a party key's algorithm (older browsers lack Ed25519). Nothing was judged. */
  | "RUNTIME_CANNOT_CHECK";

export interface SessionEventReport {
  readonly seq: number;
  readonly kind: SessionEventKind | null;
  readonly by: SessionParty | null;
  readonly signers: readonly SessionParty[];
  readonly bothSigned: boolean;
}

export interface SessionReceiptReport {
  /** No fault. A pending session can be ok. */
  readonly ok: boolean;
  /** complete = closed and every line signed by both. Otherwise pending. */
  readonly state: "pending" | "complete";
  /** Only a complete session is proof (d41: two signatures or it is not proof). */
  readonly proof: boolean;
  readonly sessionId: string | null;
  readonly profile: SessionProfile | null;
  readonly parties: { readonly establishment: string; readonly person: string } | null;
  readonly events: readonly SessionEventReport[];
  readonly total: { readonly amount: string; readonly currency: string } | null;
  readonly lineItemCount: number;
  readonly expiresAtUnix: number | null;
  readonly expired: boolean;
  readonly anchor: {
    readonly coversSeq: number;
    /**
     * The anchor checks out: its head is the hash of the line it names and, for a
     * second-version anchor, its own path reaches the root it names and its witness
     * does not name another. False exactly when `ANCHOR_MISMATCH` is raised, as it
     * always was. `inclusion` says which part failed. That a public log holds the
     * root is never judged here (rekor-cli, ots).
     */
    readonly matches: boolean;
    readonly backend: string;
    /** A second-version anchor only (GP-6): its place in its batch, and whether its own path proves it. */
    readonly inclusion?: SessionAnchorInclusionReport;
  } | null;
  readonly faults: readonly { readonly seq: number | null; readonly fault: SessionFault }[];
  readonly notes: readonly string[];
}

export interface SessionAnchorInclusionReport {
  /** Each is null when the anchor's inclusion proof cannot be read. */
  readonly treeSize: number | null;
  readonly leafIndex: number | null;
  readonly root: string | null;
  /** The audit path leads from this head's leaf to `root`. */
  readonly included: boolean;
  /** The witness receipt names this root (true), another (false), or none (null). */
  readonly witnessNamesRoot: boolean | null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const HEX64 = /^[0-9a-f]{64}$/;

export function isSessionReceipt(value: unknown): value is SessionReceipt {
  return isPlainObject(value) && value.formatVersion === SESSION_RECEIPT_FORMAT;
}

/** The root a witness receipt says it witnessed, in attest's own WitnessClient shapes: `merkleRoot`, or `digest` for OpenTimestamps. */
function rootNamedByWitness(w: unknown): string | null {
  if (!isPlainObject(w) || !isPlainObject(w.receipt)) return null;
  const named = w.backend === "opentimestamps" ? w.receipt.digest : w.receipt.merkleRoot;
  return typeof named === "string" ? named : null;
}

/** A second-version anchor's own path, checked offline. Reads nothing but the anchor. */
async function checkAnchorInclusion(a: Record<string, unknown>): Promise<SessionAnchorInclusionReport> {
  const inc = isPlainObject(a.inclusion) ? a.inclusion : null;
  const treeSize = inc !== null && isInt(inc.treeSize) && Number.isSafeInteger(inc.treeSize) && inc.treeSize >= 1 ? inc.treeSize : null;
  const leafIndex = inc !== null && isInt(inc.leafIndex) && Number.isSafeInteger(inc.leafIndex) && inc.leafIndex >= 0 ? inc.leafIndex : null;
  const root = typeof a.root === "string" && HEX64.test(a.root) ? a.root : null;
  const path = inc !== null && Array.isArray(inc.path) && inc.path.length <= 64 && inc.path.every((p) => typeof p === "string" && HEX64.test(p)) ? (inc.path as string[]) : null;
  const named = rootNamedByWitness(a.witness);
  const witnessNamesRoot = named === null ? null : root !== null && named === root;
  let included = false;
  if (treeSize !== null && leafIndex !== null && root !== null && path !== null && typeof a.headSha256 === "string" && HEX64.test(a.headSha256)) {
    try {
      // The leaf is rebuilt with the size the anchor claims: a misstated size changes the leaf, so the path fails.
      included = await rfc6962VerifyInclusion(await sessionHeadLeafHash(a.headSha256, treeSize), leafIndex, treeSize, path.map(hexToBytes), hexToBytes(root));
    } catch {
      // A verifier of strangers' files fails closed, whatever the input.
      included = false;
    }
  }
  return { treeSize, leafIndex, root, included, witnessNamesRoot };
}

/**
 * What an anchor's own path does and does not show. The path is checked against the root the anchor
 * itself names — a file can name any root — so only a witness gives that root any weight, and a
 * witness's own log is confirmed outside this verifier.
 */
function inclusionNotes(inc: SessionAnchorInclusionReport, backend: string): string[] {
  const notes: string[] = [];
  if (inc.treeSize === null || inc.leafIndex === null || inc.root === null) {
    notes.push("the anchor's inclusion proof cannot be read — it proves nothing about a batch");
  } else if (!inc.included) {
    notes.push(`the anchor's path does not lead from its head to the root it names — it does not prove the head is leaf index ${inc.leafIndex} in a batch of ${inc.treeSize}`);
  } else {
    notes.push(`its path leads from its head, as leaf index ${inc.leafIndex} in a batch of ${inc.treeSize}, to the root this anchor names; this receipt holds no other session's id, head or lines`);
  }
  if (inc.witnessNamesRoot === false) notes.push("the witness receipt names another root than this anchor's");
  notes.push(
    backend === "none"
      ? "that root is recorded but no public log witnessed it — nothing outside this file vouches for it"
      : inc.witnessNamesRoot === null
        ? `anchored in ${backend}, but its receipt names no root — that a log witnessed this root is not checked; an anchoring signature is never a party signature`
        : `its ${backend} receipt names that root — confirm a public log holds it with rekor-cli / ots; until then this file's own claim; an anchoring signature is never a party signature`,
  );
  return notes;
}

/** Verify a session receipt offline. Structurally junk input returns a report;
 *  a runtime that cannot run a party key's algorithm returns `RUNTIME_CANNOT_CHECK`. */
export async function verifySessionReceipt(receipt: unknown, opts: { readonly nowSec?: number } = {}): Promise<SessionReceiptReport> {
  try {
    return await verifySessionReceiptInner(receipt, opts);
  } catch (err) {
    if (!isAlgorithmUnsupported(err)) throw err;
    return {
      ok: false, state: "pending", proof: false, sessionId: null, profile: null, parties: null, events: [],
      total: null, lineItemCount: 0, expiresAtUnix: null, expired: false, anchor: null,
      faults: [{ seq: null, fault: "RUNTIME_CANNOT_CHECK" }],
      notes: ["this runtime cannot run a signature algorithm this receipt needs (Ed25519 arrived late in some browsers) — nothing was judged"],
    };
  }
}

async function verifySessionReceiptInner(receipt: unknown, opts: { readonly nowSec?: number }): Promise<SessionReceiptReport> {
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const faults: { seq: number | null; fault: SessionFault }[] = [];
  const notes: string[] = [];
  const empty: SessionReceiptReport = {
    ok: false, state: "pending", proof: false, sessionId: null, profile: null, parties: null, events: [],
    total: null, lineItemCount: 0, expiresAtUnix: null, expired: false, anchor: null,
    faults: [{ seq: null, fault: "MALFORMED_RECEIPT" }], notes: ["not a kashscript-session-receipt/1"],
  };
  if (!isSessionReceipt(receipt) || typeof receipt.sessionId !== "string" || !Array.isArray(receipt.events) || !isPlainObject(receipt.parties)) return empty;
  const profile = receipt.profile;
  if (!(profile in SESSION_PROFILES)) return { ...empty, faults: [{ seq: null, fault: "PROFILE_VIOLATION" }], notes: ["unknown profile"] };
  const { establishment, person } = receipt.parties;
  const partyKeys = new Map<string, SessionParty>();
  if (typeof establishment === "string" && typeof person === "string" && establishment !== person && selfCertifyingTypedKey(establishment) !== null && selfCertifyingTypedKey(person) !== null) {
    partyKeys.set(establishment, "establishment");
    partyKeys.set(person, "person");
  } else {
    faults.push({ seq: null, fault: "PARTIES_INVALID" });
  }
  const allowed = new Set<SessionEventKind>([...EVERY_PROFILE, ...SESSION_PROFILES[profile].kinds]);

  const eventReports: SessionEventReport[] = [];
  let prev = await sessionGenesisSha256(receipt.sessionId);
  let closed = false;
  let total: { amount: string; currency: string } | null = null;
  let expiresAtUnix: number | null = null;
  let flowItems = 0;
  let closeCount = 0;

  for (let i = 0; i < receipt.events.length; i++) {
    const env = receipt.events[i] as DsseEnvelope;
    const fault = (f: SessionFault): void => {
      faults.push({ seq: i, fault: f });
    };
    if (!isPlainObject(env) || env.payloadType !== SESSION_EVENT_DST || typeof env.payload !== "string" || !Array.isArray(env.signatures)) {
      fault("EVENT_TYPE_MISMATCH");
      eventReports.push({ seq: i, kind: null, by: null, signers: [], bothSigned: false });
      continue;
    }
    // Only the two parties may sign. Any other keyid — an operator, a member,
    // Indorania itself — is a foreign signer, whether or not it verifies.
    if (env.signatures.some((s) => !isPlainObject(s) || !partyKeys.has(s.keyid as string))) fault("FOREIGN_SIGNER");
    let verified: string[] = [];
    let p: unknown = null;
    try {
      // Each party's algorithm comes from its own did:kash — Ed25519 or P-256.
      const res = await verifyEnvelope(env, (kid) => (partyKeys.has(kid) ? selfCertifyingTypedKey(kid) : null));
      verified = [...new Set(res.verifiedKeyids)];
      p = res.payloadJson;
    } catch (err) {
      if (isAlgorithmUnsupported(err)) throw err;
      fault("EVENT_MALFORMED");
    }
    const partySigs = env.signatures.filter((s) => isPlainObject(s) && partyKeys.has(s.keyid as string)).length;
    if (verified.length < partySigs) fault("BAD_SIGNATURE");
    if (verified.length === 0) fault("UNSIGNED_EVENT");
    const signers = verified.map((k) => partyKeys.get(k)!);

    if (!isPlainObject(p) || p.spec !== SESSION_EVENT_SPEC || !isInt(p.seq) || typeof p.prevSha256 !== "string" || !isInt(p.atUnix) || !isPlainObject(p.body) || (p.by !== "establishment" && p.by !== "person")) {
      fault("EVENT_MALFORMED");
      eventReports.push({ seq: i, kind: null, by: null, signers, bothSigned: signers.length === 2 });
      prev = await sessionEventSha256(env).catch(() => prev);
      continue;
    }
    const kind = p.kind as SessionEventKind;
    const body = p.body as Record<string, unknown>;
    if (p.sessionId !== receipt.sessionId) fault("SESSION_MISMATCH");
    if (p.seq !== i) fault("SEQ_GAP");
    if (p.prevSha256 !== prev) fault("CHAIN_BROKEN");
    if (!signers.includes(p.by as SessionParty)) fault("AUTHOR_NOT_SIGNED");
    if (!allowed.has(kind)) fault("PROFILE_VIOLATION");
    if (i === 0 && kind !== "open") fault("FIRST_EVENT_NOT_OPEN");
    if (i > 0 && kind === "open") fault("PROFILE_VIOLATION");
    if (closed && kind !== "disagreement") fault("AFTER_CLOSE");

    if (kind === "open") {
      const parties = body.parties;
      if (!isPlainObject(parties) || parties.establishment !== establishment || parties.person !== person || body.profile !== profile) fault("OPEN_MISMATCH");
      const consent = body.consent;
      if (!isPlainObject(consent) || !Array.isArray(consent.records) || !Array.isArray(consent.asks)) fault("EVENT_MALFORMED");
      if (body.place !== null && body.place !== undefined && !SESSION_PROFILES[profile].place) fault("PLACE_NOT_ALLOWED");
    } else if (kind === "flow") {
      const items = body.lineItems;
      if (!Array.isArray(items) || !items.every((x) => typeof x === "string" && HEX64.test(x))) fault("EVENT_MALFORMED");
      else if (!closed) flowItems += items.length;
      for (const k of Object.keys(body)) if (k !== "lineItems") fault("EVENT_MALFORMED");
    } else if (kind === "process") {
      if (typeof body.step !== "string" || !(body.rule === null || (isPlainObject(body.rule) && typeof body.rule.id === "string" && typeof body.rule.version === "string"))) fault("EVENT_MALFORMED");
    } else if (kind === "disagreement") {
      if (!isInt(body.about) || body.about < 0 || body.about >= i || typeof body.statementSha256 !== "string" || !HEX64.test(body.statementSha256)) fault("BAD_DISAGREEMENT");
    } else if (kind === "close") {
      closeCount += 1;
      if (closeCount > 1) fault("DUPLICATE_CLOSE");
      const t = body.total;
      if (!isPlainObject(t) || typeof t.amount !== "string" || !/^\d+(\.\d{1,8})?$/.test(t.amount) || typeof t.currency !== "string" || !/^[A-Z]{3}$/.test(t.currency) || !isInt(body.lineItemCount) || !isInt(body.expiresAtUnix)) {
        fault("TOTAL_MALFORMED");
      } else {
        total = { amount: t.amount, currency: t.currency };
        expiresAtUnix = body.expiresAtUnix;
        if (body.lineItemCount !== flowItems) fault("LINE_COUNT_MISMATCH");
      }
      closed = true;
    } else if (kind !== "presence") {
      fault("EVENT_MALFORMED");
    }
    eventReports.push({ seq: i, kind, by: p.by as SessionParty, signers, bothSigned: signers.length === 2 });
    prev = await sessionEventSha256(env);
  }
  if (receipt.events.length === 0) faults.push({ seq: null, fault: "FIRST_EVENT_NOT_OPEN" });

  let anchor: SessionReceiptReport["anchor"] = null;
  if (receipt.anchor !== null && receipt.anchor !== undefined) {
    const a: unknown = receipt.anchor;
    const o: Record<string, unknown> = isPlainObject(a) ? a : {};
    const covered = isInt(o.coversSeq) ? receipt.events[o.coversSeq] : undefined;
    const matches = covered !== undefined && isPlainObject(covered) && typeof covered.payload === "string" && o.headSha256 === (await sessionEventSha256(covered as unknown as DsseEnvelope));
    const backend = isPlainObject(o.witness) && typeof o.witness.backend === "string" ? o.witness.backend : "none";
    const coversSeq = isInt(o.coversSeq) ? o.coversSeq : -1;
    if (o.formatVersion === SESSION_ANCHOR_FORMAT) {
      // The second version: the head's own path to its batch's root, and the root the witness names.
      const inclusion = await checkAnchorInclusion(o);
      const checksOut = matches && inclusion.included && inclusion.witnessNamesRoot !== false;
      if (!checksOut) faults.push({ seq: null, fault: "ANCHOR_MISMATCH" });
      anchor = { coversSeq, matches: checksOut, backend, inclusion };
      notes.push(...inclusionNotes(inclusion, backend));
    } else {
      // The first version, or one this verifier does not know: the head, exactly as PL-3 checked it.
      if (!matches) faults.push({ seq: null, fault: "ANCHOR_MISMATCH" });
      anchor = { coversSeq, matches, backend };
      notes.push(
        backend === "none"
          ? "the head hash is recorded but not witnessed by a public log"
          : `anchored in ${backend} — confirm the inclusion with rekor-cli / ots; an anchoring signature is never a party signature`,
      );
      notes.push(
        o.formatVersion === undefined || o.formatVersion === "kashscript-session-anchor/1"
          ? "this anchor carries no inclusion proof — that its head is in a witnessed batch is not checked"
          : `the anchor's format ${JSON.stringify(o.formatVersion).slice(0, 64)} is not known to this verifier — only its head was checked`,
      );
    }
    if (isInt(o.coversSeq) && o.coversSeq < receipt.events.length - 1) notes.push(`the anchor covers lines 0–${o.coversSeq}; later lines are not anchored yet`);
  } else {
    notes.push("not anchored");
  }

  const ok = faults.length === 0;
  const everyLineBoth = eventReports.length > 0 && eventReports.every((e) => e.bothSigned);
  const complete = ok && closed && everyLineBoth;
  if (!everyLineBoth) notes.push("a line carries one signature — pending, never proof (d41)");
  if (!closed) notes.push("not closed yet");
  const expired = expiresAtUnix !== null && now > expiresAtUnix;
  if (expired) notes.push("past its expiry — a wallet deletes it");
  notes.push("line items are commitments: what was bought is provable only if its holder keeps the opening and shows it");

  return {
    ok,
    state: complete ? "complete" : "pending",
    proof: complete,
    sessionId: receipt.sessionId,
    profile,
    parties: partyKeys.size === 2 ? { establishment, person } : null,
    events: eventReports,
    total,
    lineItemCount: flowItems,
    expiresAtUnix,
    expired,
    anchor,
    faults,
    notes,
  };
}
