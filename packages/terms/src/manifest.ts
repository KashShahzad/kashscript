/**
 * Manifest schema + deterministic compile.
 *
 * The byte-deterministic pipeline from a manifest draft to its sealed
 * `manifestId`. Wraps the identity-core canonical-JSON helper so the resulting
 * bytes are identical across runtimes.
 *
 * Properties:
 *   • compileManifest(draft) → { body, manifestId, jcsBytes } is pure.
 *   • Same draft always produces byte-identical jcsBytes.
 *   • Same body always produces the same manifestId.
 *   • Validates every invariant of the agreement up front, so a draft that
 *     compiles cleanly is a coherent agreement.
 *
 * Hashing note: `manifestId` is keccak-256 (not NIST SHA3-256) from
 * `@noble/hashes`, so it is the same on every runtime and a stranger can
 * recompute it with any keccak library.
 */

import { canonicalize } from "@kashscript/identity-core";
import { keccak_256 } from "@noble/hashes/sha3";

import { fail } from "./errors";
import { validateSplits } from "./splitter";
import {
  BPS_TOTAL,
  MAX_UNIX_SECONDS,
  MIN_LOCKOUT_SECONDS,
  isUnixSeconds,
  type BlueprintType,
  type ManifestId,
  type TermsManifest,
} from "./types";

/* ─────────────────────────────────────────────────────────────────
 *  Hashing
 * ─────────────────────────────────────────────────────────────────
 *
 * `manifestId = "kash-trade:" + "0x" + hexLowerCase(keccak256(JCS(body)))`.
 */

function toHexLower(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

/* ─────────────────────────────────────────────────────────────────
 *  Compile pipeline
 * ───────────────────────────────────────────────────────────────── */

/**
 * The `body` is the manifest minus the fields that change after sealing:
 *   • `manifestId`     (computed here)
 *   • `state`          (FSM-managed)
 *   • `committedAt`    (filled when the parties commit)
 *   • `openDisputeAt`  (filled when a dispute opens)
 *   • `signature`      (added by the buyer after compile)
 */
export type ManifestDraft = Omit<
  TermsManifest,
  "manifestId" | "state" | "committedAt" | "openDisputeAt" | "signature"
>;

export interface CompiledManifest {
  readonly body: ManifestDraft;
  readonly manifestId: ManifestId;
  readonly jcsBytes: Uint8Array;
}

const TEXT_ENCODER = new TextEncoder();

/**
 * Validate + JCS-canonicalise + compute `manifestId`. Throws TermsError on any
 * invariant violation.
 */
export async function compileManifest(draft: ManifestDraft): Promise<CompiledManifest> {
  validateManifestStatic(draft);

  const canonical = canonicalize(draft);                       // RFC 8785 JSON canonicalisation
  const bytes     = TEXT_ENCODER.encode(canonical);
  const digest    = keccak_256(bytes);
  const manifestId = `kash-trade:0x${toHexLower(digest)}` as ManifestId;

  return {
    body: draft,
    manifestId,
    jcsBytes: bytes,
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Static invariants (run BEFORE we touch the hasher)
 * ───────────────────────────────────────────────────────────────── */

const DECIMAL_RE = /^[0-9]+$/;

function validateManifestStatic(d: ManifestDraft): void {
  if (d.v !== 3) {
    fail("WRONG_VERSION", `Manifest.v must be 3 (got ${String(d.v)}).`);
  }
  if (!isBlueprintType(d.blueprint)) {
    fail("UNKNOWN_BLUEPRINT", `blueprint must be one of: otdc, subscription, milestone.`);
  }
  if (d.payload.kind !== d.blueprint) {
    fail("INVALID_BLUEPRINT_PAYLOAD", `payload.kind ("${d.payload.kind}") does not match blueprint ("${d.blueprint}").`);
  }

  /* ── The agreed price ────────────────────────────────────── */
  if (!d.price || typeof d.price.amount !== "string" || !DECIMAL_RE.test(d.price.amount)) {
    fail("INVALID_MANIFEST", "price.amount must be a decimal-stringified non-negative integer.");
  }
  if (typeof d.price.currency !== "string" || d.price.currency.length === 0) {
    fail("INVALID_MANIFEST", "price.currency must be a non-empty string.");
  }

  /* ── Dust-free split ─────────────────────────────────────── */
  validateSplits(d.splits, d.roundingHolder);

  /* ── Timeouts: Unix seconds, and a gap between soft and hard ── */
  for (const [name, at] of [
    ["softTimeoutAt", d.softTimeoutAt],
    ["hardTimeoutAt", d.hardTimeoutAt],
    ["disputeTimeoutAt", d.disputeTimeoutAt],
  ] as const) {
    if (!isUnixSeconds(at)) {
      fail("INVALID_MANIFEST", `${name} must be a Unix timestamp in seconds (an integer in [0, ${MAX_UNIX_SECONDS}]) — milliseconds are refused; got ${String(at)}.`);
    }
  }
  if (d.hardTimeoutAt <= d.softTimeoutAt) {
    fail("PRE_HARD_TIMEOUT", `hardTimeoutAt (${d.hardTimeoutAt}) must be > softTimeoutAt (${d.softTimeoutAt}).`);
  }
  if (d.hardTimeoutAt - d.softTimeoutAt < MIN_LOCKOUT_SECONDS) {
    fail("PRE_HARD_TIMEOUT", `Lockout gap ${d.hardTimeoutAt - d.softTimeoutAt} < MIN_LOCKOUT_SECONDS (${MIN_LOCKOUT_SECONDS}).`);
  }
  // disputeTimeoutAt is checked when a dispute opens (when it opens isn't known yet).

  /* ── Strict-majority quorum ──────────────────────────────── */
  if (!Number.isInteger(d.validation.threshold) || d.validation.threshold < 1) {
    fail("SUB_MAJORITY_QUORUM", `validation.threshold must be a positive integer.`);
  }
  const n = d.parties.attestors.length;
  if (d.validation.threshold * 2 <= n) {
    fail("SUB_MAJORITY_QUORUM", `attestor threshold ${d.validation.threshold}-of-${n} is sub-majority; needs ≥ ${Math.floor(n / 2) + 1}.`);
  }
  const dN = (d.validation.disputeArbitrators?.length ?? n);
  const dT = (d.validation.disputeThreshold ?? d.validation.threshold);
  if (dT * 2 <= dN) {
    fail("SUB_MAJORITY_QUORUM", `dispute-arbitrator threshold ${dT}-of-${dN} is sub-majority.`);
  }

  /* ── Class assignment cardinality ───────────────────────── */
  if (d.validation.priorityClasses.length !== n) {
    fail("INVALID_MANIFEST", `validation.priorityClasses (${d.validation.priorityClasses.length}) must match attestors.length (${n}).`);
  }

  /* ── Witness set sanity ─────────────────────────────────── */
  if (d.witnesses.threshold * 2 <= d.witnesses.set.length) {
    fail("SUB_MAJORITY_QUORUM", `witness threshold ${d.witnesses.threshold}-of-${d.witnesses.set.length} is sub-majority.`);
  }

  /* ── Subscription: periodRevertPolicy consistency ────────── */
  if (d.blueprint === "subscription" && d.payload.kind === "subscription") {
    const s = d.payload.subscription;
    if (s.periodRevertPolicy === "cascade-on-N-failures") {
      if (typeof s.maxSequentialFailedPeriods !== "number" || s.maxSequentialFailedPeriods < 1) {
        fail(
          "INVALID_BLUEPRINT_PAYLOAD",
          `subscription.maxSequentialFailedPeriods MUST be a positive integer when periodRevertPolicy="cascade-on-N-failures".`,
        );
      }
    }
  }

  /* ── Milestone: schedule integrity ───────────────────────── */
  if (d.blueprint === "milestone" && d.payload.kind === "milestone") {
    const steps = d.payload.milestone.steps;
    if (!Array.isArray(steps) || steps.length === 0) {
      fail("INVALID_BLUEPRINT_PAYLOAD", "milestone.steps MUST be a non-empty array.");
    }
    let stepBpsSum = 0;
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i]!;
      if (!Number.isInteger(step.bps) || step.bps < 1 || step.bps > BPS_TOTAL) {
        fail("INVALID_BLUEPRINT_PAYLOAD", `milestone.steps[${i}].bps must be an integer in [1, ${BPS_TOTAL}], got ${step.bps}.`);
      }
      stepBpsSum += step.bps;
      // Each step's own shares must be dust-free in their own right.
      validateSplits(step.recipients);
    }
    if (stepBpsSum !== BPS_TOTAL) {
      fail("BPS_SUM", `Σ milestone step bps = ${stepBpsSum}, expected ${BPS_TOTAL}.`);
    }
  }
}

function isBlueprintType(s: string): s is BlueprintType {
  return s === "otdc" || s === "subscription" || s === "milestone";
}
