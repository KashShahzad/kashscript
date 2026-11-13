// ============================================================================
// @kashscript/whiffin/mandate/lifecycle — ISSUE · DELIVER · REDEEM
// ----------------------------------------------------------------------------
// The mandate lifecycle use-cases + the ledger/nonce ports (interface + an
// in-memory reference adapter). ISSUE validates a request against the program's
// (policy-blind) SegmentPolicy, assembles + signs the grant, records ISSUED.
// REDEEM runs the config-driven policy gate (policy.ts), then burns the
// single-use nonce LAST + records REDEEMED. Reads policy FIELDS only — never
// branches on segmentTag. Ported from ks-adapters/{issue,redeem} (M4, ADR-0016);
// rejections are neutral `WhiffinPolicyError`s (the DD_* mapping stays venture-side).
// ============================================================================

import { WhiffinPolicyError } from "../errors";
import { assertPositivePaisa } from "../money";
import { DEFAULT_REDEEM_POLICY, runPolicy } from "../policy";
import type { PolicyCheck, RedeemRequest, RedeemResult } from "../policy";
import { ARRIVAL_CLAUSE, buildVendorAllowlist, forgeGrant, newGrantId, newSingleUseNonce } from "./grant";
import type {
  Grant,
  GrantRecord,
  GrantTransition,
  IssueRequest,
  IssueResult,
  Program,
  UnixSeconds,
} from "./types";

// ----------------------------------------------------------------------------
// Ports (interfaces) + in-memory reference adapters
// ----------------------------------------------------------------------------

/** The append-only store of issued grants + their lifecycle transitions. */
export interface GrantLedger {
  /** Persist a freshly issued grant. Rejects if its grantId already exists. */
  append(record: GrantRecord): Promise<void>;
  get(grantId: string): Promise<GrantRecord | undefined>;
  list(): Promise<readonly GrantRecord[]>;
  /** Append a lifecycle transition; returns the updated record. */
  recordTransition(grantId: string, transition: GrantTransition): Promise<GrantRecord>;
}

/** The single-use nonce-burn port. `burn` must return true EXACTLY once per
 *  nonce, atomically under concurrency (double-spend prevention). */
export interface NonceStore {
  burn(nonce: string): Promise<boolean>;
}

/** In-memory GrantLedger — for tests + local demos. Not durable. */
export class InMemoryGrantLedger implements GrantLedger {
  private readonly records = new Map<string, GrantRecord>();

  async append(record: GrantRecord): Promise<void> {
    const { grantId } = record.signed.grant;
    if (this.records.has(grantId)) {
      throw new WhiffinPolicyError("VALIDATION", `duplicate grantId ${grantId}`);
    }
    this.records.set(grantId, record);
  }

  async get(grantId: string): Promise<GrantRecord | undefined> {
    return this.records.get(grantId);
  }

  async list(): Promise<readonly GrantRecord[]> {
    return [...this.records.values()];
  }

  async recordTransition(grantId: string, transition: GrantTransition): Promise<GrantRecord> {
    const existing = this.records.get(grantId);
    if (existing === undefined) {
      throw new WhiffinPolicyError("NOT_FOUND", `grant ${grantId} not found`);
    }
    const updated: GrantRecord = {
      signed: existing.signed,
      state: transition.toState,
      transitions: [...existing.transitions, transition],
    };
    this.records.set(grantId, updated);
    return updated;
  }
}

/** In-memory NonceStore — single-process only. */
export class InMemoryNonceStore implements NonceStore {
  private readonly burned = new Set<string>();

  async burn(nonce: string): Promise<boolean> {
    if (this.burned.has(nonce)) return false;
    this.burned.add(nonce);
    return true;
  }
}

// ----------------------------------------------------------------------------
// ISSUE
// ----------------------------------------------------------------------------

export interface IssueOptions {
  readonly nowUnix?: UnixSeconds;
}

/** ISSUE one purpose-bound grant. Throws `WhiffinPolicyError` on any
 *  policy/validation failure; on success returns the signed grant + ledger
 *  record (state ISSUED). Reads program.policy FIELDS — never branches on segment.
 *
 *  The grant always carries an END DATE (d43: every rule expires) and the d41
 *  arrival clause. Issuing records a declaration; no value moves. */
export async function issueGrant(
  request: IssueRequest,
  program: Program,
  operatorPrivateKey: Uint8Array,
  ledger: GrantLedger,
  options: IssueOptions = {},
): Promise<IssueResult> {
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);

  if (program.status !== "ACTIVE") {
    throw new WhiffinPolicyError("VALIDATION", `program ${program.programId} is not ACTIVE (${program.status})`);
  }
  if (request.programId !== program.programId) {
    throw new WhiffinPolicyError("VALIDATION", "request.programId does not match the resolved program");
  }
  if (request.beneficiaryDid.trim() === "") {
    throw new WhiffinPolicyError("VALIDATION", "beneficiaryDid is required");
  }
  if (!program.policy.purposeCodes.includes(request.purposeTag)) {
    throw new WhiffinPolicyError(
      "PURPOSE_MISMATCH",
      `purpose "${request.purposeTag}" is not in program ${program.programId}`,
    );
  }
  assertPositivePaisa(request.amountPaisa);

  const expiryUnix = request.expiryUnix ?? nowUnix + program.defaultExpirySeconds;
  if (!Number.isInteger(expiryUnix) || expiryUnix <= nowUnix) {
    throw new WhiffinPolicyError(
      "VALIDATION",
      `expiryUnix must be an integer in the future (now=${nowUnix}, expiry=${expiryUnix})`,
    );
  }

  // Vendor set → Merkle root stored on the grant; per-vendor proofs used at REDEEM.
  const allowlist = await buildVendorAllowlist(program.approvedVendorDids);

  const grant: Grant = {
    grantId: newGrantId(),
    programId: program.programId,
    funderDid: program.funderDid,
    beneficiaryDid: request.beneficiaryDid,
    purposeTag: request.purposeTag,
    vendorAllowlistRoot: allowlist.rootHex,
    amountPaisa: request.amountPaisa,
    expiryUnix,
    singleUseNonce: newSingleUseNonce(),
    arrival: ARRIVAL_CLAUSE,
  };

  const signed = await forgeGrant(grant, operatorPrivateKey);
  const transition: GrantTransition = {
    grantId: grant.grantId,
    toState: "ISSUED",
    actorDid: program.funderDid,
    actorClass: "FUNDER",
    reason: "grant issued",
    code: null,
    atUnix: nowUnix,
  };
  const record: GrantRecord = { signed, state: "ISSUED", transitions: [transition] };
  await ledger.append(record);
  return { signed, record };
}

// ----------------------------------------------------------------------------
// DELIVER
// ----------------------------------------------------------------------------

export interface DeliverOptions {
  readonly nowUnix?: UnixSeconds;
}

/** Mark a grant DELIVERED. Allowed only from ISSUED (or DELIVERED, as a no-op);
 *  any other state is a typed rejection. No value moves. */
export async function markDelivered(
  grantId: string,
  ledger: GrantLedger,
  options: DeliverOptions = {},
): Promise<GrantRecord> {
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);
  const record = await ledger.get(grantId);
  if (record === undefined) {
    throw new WhiffinPolicyError("NOT_FOUND", `grant ${grantId} not found`);
  }
  if (record.state === "DELIVERED") return record;
  if (record.state !== "ISSUED") {
    throw new WhiffinPolicyError("VALIDATION", `grant ${grantId} cannot be delivered from state ${record.state}`);
  }
  const transition: GrantTransition = {
    grantId,
    toState: "DELIVERED",
    actorDid: record.signed.grant.funderDid,
    actorClass: "PROTOCOL",
    reason: "voucher delivered to beneficiary",
    code: null,
    atUnix: nowUnix,
  };
  return ledger.recordTransition(grantId, transition);
}

// ----------------------------------------------------------------------------
// REDEEM
// ----------------------------------------------------------------------------

export interface RedeemOptions {
  readonly nowUnix?: UnixSeconds;
  /** Override the ordered policy gate (defaults to DEFAULT_REDEEM_POLICY). */
  readonly policy?: readonly PolicyCheck[];
}

/**
 * REDEEM one grant. Gate order: exists → redeemable state → (policy gate:
 * signature · binding · purpose · expiry · vendor) → burn nonce (atomic, LAST) →
 * record REDEEMED. A failed check throws `WhiffinPolicyError` with a neutral
 * code and never consumes the nonce.
 */
export async function redeemGrant(
  request: RedeemRequest,
  operatorPublicKey: Uint8Array,
  ledger: GrantLedger,
  nonceStore: NonceStore,
  options: RedeemOptions = {},
): Promise<RedeemResult> {
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);

  const record = await ledger.get(request.grantId);
  if (record === undefined) {
    throw new WhiffinPolicyError("NOT_FOUND", `grant ${request.grantId} not found`);
  }
  const { grant } = record.signed;

  if (record.state === "REDEEMED") {
    throw new WhiffinPolicyError("NOT_REDEEMABLE", `grant ${grant.grantId} is already ${record.state}`);
  }
  if (record.state === "EXPIRED") {
    throw new WhiffinPolicyError("NOT_REDEEMABLE", `grant ${grant.grantId} is ${record.state}`);
  }

  const gate = await runPolicy(options.policy ?? DEFAULT_REDEEM_POLICY, {
    grant,
    record,
    request,
    operatorPublicKey,
    nowUnix,
  });
  if (!gate.ok) {
    throw new WhiffinPolicyError(gate.code, gate.detail);
  }

  // Burn the single-use nonce — atomically, only now that every rule has passed.
  if (!(await nonceStore.burn(grant.singleUseNonce))) {
    throw new WhiffinPolicyError("NONCE_SPENT", grant.grantId);
  }

  const transition: GrantTransition = {
    grantId: grant.grantId,
    toState: "REDEEMED",
    actorDid: request.vendorDid,
    actorClass: "VENDOR",
    reason: "voucher redeemed at approved vendor",
    code: null,
    atUnix: nowUnix,
  };
  const updated = await ledger.recordTransition(grant.grantId, transition);
  return { record: updated };
}
