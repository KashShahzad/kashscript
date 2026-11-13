/**
 * Recovery by succession, never by copying (d47(g)(4); specs/recovery.md).
 *
 * A lost phone means new keys, and a key claim countersigned by helpers the
 * person chose. Old records stay valid under the old keys; helpers never see a
 * record; the platform is never a helper by default — a wallet starts with no
 * helpers at all, and nothing here adds one but the person.
 *
 * **The holder's side.** The person invites people they trust; each helper's
 * own wallet answers with a pool of fresh keys made for this person alone.
 * The person chooses how many must agree — at least two, and a strict
 * majority, so two separate groups can never each claim the same key. Every
 * place's key then signs, in advance, a helper set naming a DIFFERENT key from
 * each helper's pool, so no helper key links two places (d41).
 *
 * **The helper's side.** A request arrives in person or by link. The helper's
 * wallet shows a six-digit code and how many places; the helper says yes only
 * after talking to the person and seeing the same code on their screen. It
 * signs each claim with the one pool key that claim's set names — and sees
 * only opaque keys, never a record and never a place.
 *
 * **The new phone.** It needs the copy the person kept (an export, or the
 * account's encrypted backup): records come back from it, and so do the
 * helper sets. New keys are made — in the secure chip where there is one —
 * and each place's claim is drafted, signed by its new key. With a quorum's
 * approvals each place moves to its new key; one approval short, nothing
 * changes. A place sees the new key only when the person shows it the claim.
 *
 * **Honest limits.** Keys are not people: one person with two phones can hold
 * two helper keys, and nothing cryptographic can tell. A helper who colludes
 * with a place can tell it the person recovered there. Without a saved copy,
 * nothing comes back.
 */

import { canonicalizeBytes, didKeyType, type KashEventSignature } from "@kashscript/identity-core";
import {
  approveKeyClaim,
  draftHelperClaim,
  HELPERS_MAX,
  HELPERS_MIN_NEED,
  keyClaimSha256,
  signHelperSet,
  verifyHelperSet,
  verifyKeyClaim,
  withApprovals,
  type HelperApproval,
  type HelperKeyClaim,
  type KeyClaim,
  type SignedHelperSet,
} from "@kashscript/attest/succession";
import { isHolderExport, type RecoveryHelpersEntry } from "@kashscript/attest/holder";
import { bytesToHex, sha256Hex } from "./crypto/bytes";
import type { WalletCore } from "./core";
import { fill } from "./copy";
import { WalletError } from "./errors";
import type { Relationship } from "./relationships";
import { PREFIX, RECOVERY, RECOVERY_PENDING } from "./vault";

/** Keys a helper makes for one person: one per place of theirs, never reused. */
export const HELPER_POOL_SIZE = 32;

/* ── the wallet messages (specs/recovery.md §6) ────────────────────────── */

/** Shown by the person, scanned by a helper — in person. */
export interface HelperInvite {
  readonly format: "kashscript-recovery-invite/1";
  /** A random name for this person's circle of helpers, so one phone cannot enrol twice. */
  readonly circle: string;
}

/** The helper's answer: fresh keys made for this person alone. */
export interface HelperEnrolment {
  readonly format: "kashscript-recovery-enrolment/1";
  readonly circle: string;
  readonly keys: readonly string[];
}

/** From the new phone to each helper. Signed sets and claims only: no record, no place. */
export interface RecoveryRequest {
  readonly format: "kashscript-recovery-request/1";
  /** The new phone's circle, so helpers re-enrol for it while they are here. */
  readonly circle: string;
  readonly claims: readonly HelperKeyClaim[];
}

export interface RecoveryApproval {
  readonly format: "kashscript-recovery-approval/1";
  readonly approvals: readonly { readonly claimSha256: string; readonly did: string; readonly signature: KashEventSignature }[];
  /** A fresh pool for the new phone, so a second loss is recoverable too. */
  readonly enrolment: HelperEnrolment;
}

/** Someone the person trusts, as the person named them on this device. */
export interface Helper {
  readonly label: string;
  readonly keys: readonly string[];
}

/** How many helpers must agree, of how many chosen. */
export interface Quorum {
  readonly need: number;
  readonly of: number;
}

export interface RecoveryStatus {
  /** True once at least two helpers are chosen. */
  readonly available: boolean;
  readonly helpers: number;
  readonly need: number;
  /** Places whose key has a helper set, and places still without one. */
  readonly covered: number;
  readonly uncovered: number;
  /** How many more places the helpers' pools can cover before they need topping up. */
  readonly placesLeft: number;
  readonly text: string;
}

export interface HelperView {
  /** Six digits. The helper says yes only if the person's screen shows the same. */
  readonly code: string;
  /** How many of the person's places this would move — never which. */
  readonly places: number;
  /** The name the helper gave the person. */
  readonly label: string;
  readonly request: RecoveryRequest;
}

export type FinishResult =
  | { readonly status: "waiting"; readonly recovered: 0; readonly waiting: number }
  | { readonly status: "recovered" | "partly"; readonly recovered: number; readonly waiting: number; readonly helpersAgain: number };

interface HolderState {
  readonly circle: string;
  readonly need: number;
  readonly helpers: readonly Helper[];
  readonly nextSlot: number;
  readonly sequence: number;
  readonly sets: readonly { readonly keyId: string; readonly counterparty: string | null; readonly helperSet: SignedHelperSet }[];
}

interface HelpingEntry {
  readonly circle: string;
  readonly label: string;
  readonly keys: readonly string[];
}

interface PendingClaim {
  readonly counterparty: string | null;
  readonly successorKeyId: string;
  readonly claim: HelperKeyClaim;
}

interface Pending {
  readonly circle: string;
  readonly claims: readonly PendingClaim[];
}

interface StoredClaim {
  readonly counterparty: string | null;
  readonly claim: KeyClaim;
}

/* ── module functions transfer.ts uses too ─────────────────────────────── */

/** Every key-succession claim this wallet holds, oldest first — what an export carries. */
export async function storedClaims(core: WalletCore): Promise<KeyClaim[]> {
  const all = await core.vault.all<StoredClaim>(PREFIX.succession);
  return all
    .map((e) => e.value.claim)
    .sort((a, b) => a.body.claimedAtUnix - b.body.claimedAtUnix || (a.body.successorDid < b.body.successorDid ? -1 : 1));
}

/** Keep claims brought in by an import, once each. */
export async function keepClaims(core: WalletCore, claims: readonly KeyClaim[], counterparty: string | null = null): Promise<void> {
  const have = new Set((await storedClaims(core)).map((c) => `${c.body.priorDid}>${c.body.successorDid}`));
  for (const claim of claims) {
    const id = `${claim.body.priorDid}>${claim.body.successorDid}`;
    if (have.has(id)) continue;
    have.add(id);
    await core.vault.put(PREFIX.succession + (await core.vault.newSlot()), { counterparty, claim } satisfies StoredClaim);
  }
}

/** The current keys' helper sets, with where each key is used — what an export carries (v1.3). */
export async function exportedHelperSets(core: WalletCore): Promise<RecoveryHelpersEntry[]> {
  const state = await core.vault.get<HolderState>(RECOVERY);
  if (state === null) return [];
  const out: RecoveryHelpersEntry[] = [];
  for (const s of state.sets) if ((await core.keys.find(s.keyId)) !== null) out.push({ counterparty: s.counterparty, helperSet: s.helperSet });
  return out;
}

/**
 * Six digits from the request's bytes, for the person and the helper to compare aloud. About 20 bits:
 * it catches a mistake or a careless swap, not an attacker who can search for another request with the
 * same code (specs/recovery.md §6) — against one, the request travels in person.
 */
export async function recoveryCode(request: RecoveryRequest): Promise<string> {
  const hex = await sha256Hex(canonicalizeBytes(request));
  return String(parseInt(hex.slice(0, 8), 16) % 1_000_000).padStart(6, "0");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/* ── the component ─────────────────────────────────────────────────────── */

export class Recovery {
  constructor(
    private readonly core: WalletCore,
    private readonly importFile: (text: string) => Promise<unknown>,
  ) {
    core.relationships.whenKeyMade((r) => this.cover(r));
  }

  private state(): Promise<HolderState | null> {
    return this.core.vault.get<HolderState>(RECOVERY);
  }

  private async circle(): Promise<string> {
    const s = await this.state();
    if (s !== null) return s.circle;
    const circle = bytesToHex(await this.core.random(16));
    await this.core.vault.put(RECOVERY, { circle, need: 0, helpers: [], nextSlot: 0, sequence: 0, sets: [] } satisfies HolderState);
    return circle;
  }

  /** Where things stand, in words a screen can show as they are. */
  async status(): Promise<RecoveryStatus> {
    const s = await this.state();
    const places = (await this.core.relationships.list()).filter((r) => r.keyId !== null);
    const covered = s === null ? 0 : places.filter((r) => s.sets.some((x) => x.keyId === r.keyId)).length;
    const pool = s === null || s.helpers.length === 0 ? 0 : Math.min(...s.helpers.map((h) => h.keys.length));
    const placesLeft = s === null ? 0 : Math.max(0, pool - s.nextSlot);
    const available = s !== null && s.helpers.length >= HELPERS_MIN_NEED;
    const copy = this.core.copy;
    const text = !available
      ? copy.recoveryChooseHelpers
      : covered < places.length
        ? fill(copy.recoveryUncovered, { n: String(places.length - covered) })
        : fill(copy.recoveryReady, { need: String(s.need), count: String(s.helpers.length) });
    return { available, helpers: s?.helpers.length ?? 0, need: s?.need ?? 0, covered, uncovered: places.length - covered, placesLeft, text };
  }

  /* ── the person ───────────────────────────────────────────────────────── */

  /** Show this to someone you trust, in person. Nothing is sent. */
  async invite(): Promise<HelperInvite> {
    return { format: "kashscript-recovery-invite/1", circle: await this.circle() };
  }

  /**
   * Choose helpers from their enrolments, and how many must agree. Then every
   * place's key names its helpers. Replacing helpers supersedes every earlier
   * set (a higher sequence).
   */
  async chooseHelpers(chosen: readonly { readonly label: string; readonly enrolment: HelperEnrolment }[], need: number): Promise<RecoveryStatus> {
    const circle = await this.circle();
    const problems: string[] = [];
    if (chosen.length < HELPERS_MIN_NEED) problems.push(`choose at least ${HELPERS_MIN_NEED} people`);
    if (chosen.length > HELPERS_MAX) problems.push(`choose at most ${HELPERS_MAX} people`);
    if (!Number.isInteger(need) || need < HELPERS_MIN_NEED) problems.push(`at least ${HELPERS_MIN_NEED} must agree`);
    if (need > chosen.length) problems.push("more must agree than were chosen");
    if (need * 2 <= chosen.length) problems.push("more than half must agree, so two groups can never each claim your keys");
    const own = new Set((await this.core.keys.list()).map((k) => k.keyId));
    const seen = new Set<string>();
    for (const { enrolment } of chosen) {
      if (!isPlainObject(enrolment) || enrolment.format !== "kashscript-recovery-enrolment/1" || enrolment.circle !== circle) {
        problems.push("an answer is not for this phone's invitation");
        continue;
      }
      if (!Array.isArray(enrolment.keys) || enrolment.keys.length === 0) problems.push("an answer carries no keys");
      for (const k of enrolment.keys) {
        if (didKeyType(k) === null) problems.push("an answer carries something that is not a key");
        if (own.has(k)) problems.push("a helper key is one of your own — you cannot be your own helper");
        if (seen.has(k)) problems.push("two helpers share a key — one key is one vote");
        seen.add(k);
      }
    }
    if (problems.length > 0) throw new WalletError("RECOVERY_HELPERS_INVALID", [...new Set(problems)].join("; "));
    const before = await this.state();
    const state: HolderState = {
      circle,
      need,
      helpers: chosen.map((c) => ({ label: c.label, keys: [...c.enrolment.keys] })),
      nextSlot: 0,
      sequence: (before?.sequence ?? 0) + 1,
      sets: [],
    };
    await this.core.vault.put(RECOVERY, state);
    for (const r of await this.core.relationships.list()) if (r.keyId !== null) await this.cover(r as Relationship & { keyId: string });
    return this.status();
  }

  /** Name helpers for one place's key, from the next unused key in every helper's pool. */
  private async cover(r: Relationship & { keyId: string }): Promise<void> {
    const s = await this.state();
    if (s === null || s.helpers.length < HELPERS_MIN_NEED) return;
    if (s.sets.some((x) => x.keyId === r.keyId)) return;
    const slot = s.nextSlot;
    if (s.helpers.some((h) => h.keys.length <= slot)) return; // a pool is used up: the place waits, uncovered — a key is never reused
    const helperSet = await this.core.keys.withEventSigner(r.keyId, (signer) =>
      signHelperSet({ subject: signer, helpers: s.helpers.map((h) => h.keys[slot]!), need: s.need, sequence: s.sequence, issuedAtUnix: this.core.now() }),
    );
    await this.core.vault.put(RECOVERY, { ...s, nextSlot: slot + 1, sets: [...s.sets, { keyId: r.keyId, counterparty: r.counterparty, helperSet }] } satisfies HolderState);
  }

  /** The claims that show a place this is still you — oldest first. Showing them is your act, never automatic. */
  async successionFor(counterparty: string): Promise<readonly KeyClaim[]> {
    const r = await this.core.relationships.find(counterparty);
    if (r === null || r.keyId === null) return [];
    const claims = await storedClaims(this.core);
    const chain: KeyClaim[] = [];
    let current = r.keyId;
    for (;;) {
      const prior = claims.find((c) => c.body.successorDid === current && !chain.includes(c));
      if (prior === undefined) break;
      chain.unshift(prior);
      current = prior.body.priorDid;
    }
    return chain;
  }

  /* ── the helper ───────────────────────────────────────────────────────── */

  /** Answer an invitation: fresh keys for this person alone. One enrolment per person per phone. */
  async becomeHelper(invite: HelperInvite, label: string): Promise<HelperEnrolment> {
    if (!isPlainObject(invite) || invite.format !== "kashscript-recovery-invite/1" || typeof invite.circle !== "string" || invite.circle.length === 0) {
      throw new WalletError("REQUEST_INVALID", "not a helper invitation");
    }
    const helping = await this.core.vault.all<HelpingEntry>(PREFIX.helping);
    if (helping.some((h) => h.value.circle === invite.circle)) throw new WalletError("RECOVERY_ALREADY_HELPING");
    if (invite.circle === (await this.state())?.circle) throw new WalletError("RECOVERY_HELPERS_INVALID", "you cannot be your own helper");
    return this.enrol(invite.circle, label);
  }

  private async enrol(circle: string, label: string): Promise<HelperEnrolment> {
    const keys: string[] = [];
    for (let i = 0; i < HELPER_POOL_SIZE; i++) keys.push((await this.core.keys.create("helper")).keyId);
    await this.core.vault.put(PREFIX.helping + (await this.core.vault.newSlot()), { circle, label, keys } satisfies HelpingEntry);
    return { format: "kashscript-recovery-enrolment/1", circle, keys };
  }

  /** Read a request: whose it is, how many places, and the code to compare. Signs nothing. */
  async answer(request: RecoveryRequest): Promise<HelperView> {
    const entry = await this.helpingFor(request);
    return { code: await recoveryCode(request), places: request.claims.length, label: entry.label, request };
  }

  private async helpingFor(request: RecoveryRequest): Promise<HelpingEntry> {
    if (!isPlainObject(request) || request.format !== "kashscript-recovery-request/1" || !Array.isArray(request.claims) || request.claims.length === 0) {
      throw new WalletError("REQUEST_INVALID", "not a recovery request");
    }
    const helping = (await this.core.vault.all<HelpingEntry>(PREFIX.helping)).map((e) => e.value);
    const owners = new Set<HelpingEntry>();
    for (const claim of request.claims) {
      const named = Array.isArray(claim?.helperSet?.body?.helpers) ? claim.helperSet.body.helpers : [];
      const entry = helping.find((h) => h.keys.some((k) => named.includes(k)));
      if (entry === undefined) throw new WalletError("RECOVERY_NOT_YOURS");
      owners.add(entry);
    }
    if (owners.size !== 1) throw new WalletError("RECOVERY_NOT_YOURS", "the request mixes people");
    return [...owners][0]!;
  }

  /**
   * Say yes — after talking to the person and seeing the same code. Each claim
   * must be well formed and signed by its new key; each is signed with the one
   * pool key its set names. A fresh pool goes back for the new phone.
   */
  async approve(view: HelperView): Promise<RecoveryApproval> {
    const entry = await this.helpingFor(view.request);
    const approvals: { claimSha256: string; did: string; signature: KashEventSignature }[] = [];
    for (const claim of view.request.claims) {
      const check = await verifyKeyClaim(claim);
      if (!check.successorSignatureOk || (check.reason !== null && check.reason !== "BELOW_QUORUM") || !(await verifyHelperSet(claim.helperSet)).ok) {
        throw new WalletError("REQUEST_INVALID", `a claim does not check out: ${check.reason ?? "its helper set"}`);
      }
      const mine = entry.keys.filter((k) => claim.helperSet.body.helpers.includes(k));
      if (mine.length !== 1) throw new WalletError("RECOVERY_NOT_YOURS", "a claim names none, or more than one, of your keys");
      const a: HelperApproval = await this.core.keys.withEventSigner(mine[0]!, (signer) => approveKeyClaim(claim, signer));
      approvals.push({ claimSha256: await keyClaimSha256(claim), did: a.did, signature: a.signature });
    }
    const helping = await this.core.vault.all<HelpingEntry>(PREFIX.helping);
    if (helping.some((h) => h.value.circle === view.request.circle)) throw new WalletError("RECOVERY_ALREADY_HELPING");
    return { format: "kashscript-recovery-approval/1", approvals, enrolment: await this.enrol(view.request.circle, entry.label) };
  }

  /* ── the new phone ────────────────────────────────────────────────────── */

  /**
   * Begin on a new phone from the copy the person kept. Records come back from
   * it; each place's key gets a new key (in the secure chip where there is
   * one) and a drafted claim signed by that new key. Show the request to each
   * helper; read them the code.
   */
  async startOnNewPhone(savedCopy: string): Promise<{ readonly request: RecoveryRequest; readonly code: string }> {
    let value: unknown;
    try {
      value = JSON.parse(savedCopy);
    } catch {
      throw new WalletError("IMPORT_INVALID", "not JSON");
    }
    if (!isHolderExport(value)) throw new WalletError("IMPORT_INVALID", "not a holder export");
    const entries = value.recoveryHelpers ?? [];
    if (entries.length === 0) throw new WalletError("RECOVERY_NOTHING_TO_RECOVER");
    await this.importFile(savedCopy);
    const circle = await this.circle();
    const claims: PendingClaim[] = [];
    for (const e of entries) {
      const successor = await this.core.keys.create("relationship");
      const claim = await this.core.keys.withEventSigner(successor.keyId, (signer) =>
        draftHelperClaim({ helperSet: e.helperSet, successor: signer, claimedAtUnix: this.core.now() }),
      );
      claims.push({ counterparty: e.counterparty, successorKeyId: successor.keyId, claim });
    }
    await this.core.vault.put(RECOVERY_PENDING, { circle, claims } satisfies Pending);
    const request: RecoveryRequest = { format: "kashscript-recovery-request/1", circle, claims: claims.map((c) => c.claim) };
    return { request, code: await recoveryCode(request) };
  }

  /**
   * Bring in helpers' approvals. Each place whose claim now has a quorum moves
   * to its new key; one approval short, nothing changes and the approvals so
   * far are kept. Helpers who re-enrolled are chosen again, so the new keys
   * are covered at once.
   */
  async finish(answers: readonly { readonly label: string; readonly approval: RecoveryApproval }[]): Promise<FinishResult> {
    const pending = await this.core.vault.get<Pending>(RECOVERY_PENDING);
    if (pending === null) throw new WalletError("RECOVERY_NOT_STARTED");
    const merged: PendingClaim[] = [];
    for (const p of pending.claims) {
      const sha = await keyClaimSha256(p.claim);
      const add: HelperApproval[] = [];
      for (const { approval } of answers) for (const a of approval?.approvals ?? []) if (a.claimSha256 === sha) add.push({ did: a.did, signature: a.signature });
      merged.push({ ...p, claim: withApprovals(p.claim, add) });
    }
    const done: PendingClaim[] = [];
    const waiting: PendingClaim[] = [];
    for (const p of merged) ((await verifyKeyClaim(p.claim)).ok ? done : waiting).push(p);
    if (done.length === 0) {
      await this.core.vault.put(RECOVERY_PENDING, { ...pending, claims: merged } satisfies Pending);
      return { status: "waiting", recovered: 0, waiting: waiting.length };
    }
    for (const p of done) {
      const label = p.counterparty ?? p.claim.body.successorDid;
      const r = await this.core.relationships.ensure(label, label);
      await this.core.relationships.adoptKey(r, p.successorKeyId);
      await this.core.vault.put(PREFIX.succession + (await this.core.vault.newSlot()), { counterparty: p.counterparty, claim: p.claim } satisfies StoredClaim);
    }
    if (waiting.length === 0) await this.core.vault.remove(RECOVERY_PENDING);
    else await this.core.vault.put(RECOVERY_PENDING, { ...pending, claims: waiting } satisfies Pending);

    const again = answers.filter((a) => a.approval?.enrolment?.circle === pending.circle);
    let helpersAgain = 0;
    if (again.length >= HELPERS_MIN_NEED) {
      const need = Math.max(HELPERS_MIN_NEED, Math.floor(again.length / 2) + 1);
      await this.chooseHelpers(again.map((a) => ({ label: a.label, enrolment: a.approval.enrolment })), need);
      helpersAgain = again.length;
    }
    return { status: waiting.length === 0 ? "recovered" : "partly", recovered: done.length, waiting: waiting.length, helpersAgain };
  }
}
