/**
 * subscription-thread.ts — variable-amount subscriptions as a thread of OTDCs.
 *
 * The Subscription paradigm bills a FIXED `perPeriodAmount` every cycle. A
 * price-changing subscription — metered monthly billing, surge, tiered usage,
 * promotional cycles — is instead modelled as a SEQUENCE of independent OTDC
 * trades: one per billing cycle, each at that cycle's own price, linked by a
 * shared deterministic `threadId`.
 *
 * This module is the linkage layer: a stable threadId, the per-cycle link to
 * stamp into each cycle's OTDC manifest `metadata`, and a validator that a set
 * of cycles forms a coherent thread (same thread, contiguous, non-regressing).
 * Aggregating a thread's completion receipts by threadId yields the
 * subscription's full history. (A history is a record of what happened. This
 * module never turns it into a score of the people involved.)
 *
 * Pure + deterministic apart from WebCrypto (SHA-256 for the id). No I/O.
 */

import { canonicalizeBytes, encodeHex, isKashDid, type KashDid } from "@kashscript/identity-core";

import { fail } from "./errors";
import { isUnixSeconds, type ManifestId } from "./types";

export type ThreadId = `kash-thread:0x${string}`;

/** Stable per-subscription configuration the threadId is derived from. */
export interface SubscriptionThreadConfig {
  readonly subscriber: KashDid;
  readonly provider: KashDid;
  /**
   * Seconds between cycles (cadence) — a FIXED length such as a week or 30 days.
   * A calendar-month pass has no fixed length: give each cycle its own `dueAt`
   * through {@link cycleLink} instead of deriving it from the cadence.
   */
  readonly cadenceSeconds: number;
  /** When cycle 0 is due (Unix seconds). */
  readonly startAt: number;
  /** Optional cap on cycles; omit for open-ended. */
  readonly maxCycles?: number;
  /** Optional human label (part of the identity of the thread). */
  readonly label?: string;
}

/** Linkage stamped into each cycle's OTDC manifest `metadata`. */
export interface CycleLink {
  readonly kind: "subscription-cycle";
  readonly threadId: ThreadId;
  /** 0-based cycle index. */
  readonly cycleIndex: number;
  /** This cycle's price — VARIABLE per cycle (decimal-stringified bigint). */
  readonly amount: string;
  /** When this cycle is due (Unix seconds). */
  readonly dueAt: number;
  /** The prior cycle's settled trade id — absent for cycle 0. */
  readonly prevCycleManifestId?: ManifestId;
}

/** The key under which {@link cycleMetadata} nests the link in `manifest.metadata`. */
export const THREAD_META_KEY = "kash.subscription.thread" as const;

const DECIMAL_RE = /^[0-9]+$/;

/* ─────────────────────────────────────────────────────────────────
 *  Thread id
 * ───────────────────────────────────────────────────────────────── */

/** Derive the deterministic `kash-thread:` id for a subscription config. */
export async function deriveThreadId(config: SubscriptionThreadConfig): Promise<ThreadId> {
  validateThreadConfig(config);
  const bytes = canonicalizeBytes(stripUndefined(config));
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return `kash-thread:0x${encodeHex(new Uint8Array(digest))}`;
}

/** When `cycleIndex` is due (Unix seconds), per the config's fixed cadence. */
export function nextCycleDueAt(config: SubscriptionThreadConfig, cycleIndex: number): number {
  validateThreadConfig(config);
  if (!Number.isInteger(cycleIndex) || cycleIndex < 0) {
    fail("INVALID_MANIFEST", `cycleIndex must be a non-negative integer, got ${String(cycleIndex)}.`);
  }
  const due = config.startAt + cycleIndex * config.cadenceSeconds;
  if (!isUnixSeconds(due)) fail("INVALID_MANIFEST", `cycle ${cycleIndex} falls outside the Unix-seconds range (${String(due)}).`);
  return due;
}

/** True once `cycleIndex` has reached the config's `maxCycles` cap. */
export function isThreadComplete(config: SubscriptionThreadConfig, cycleIndex: number): boolean {
  return config.maxCycles !== undefined && cycleIndex >= config.maxCycles;
}

/* ─────────────────────────────────────────────────────────────────
 *  Cycle links
 * ───────────────────────────────────────────────────────────────── */

export interface CycleLinkInput {
  readonly threadId: ThreadId;
  readonly cycleIndex: number;
  readonly amount: string;
  readonly dueAt: number;
  readonly prevCycleManifestId?: ManifestId;
}

/** Construct + validate a cycle link. */
export function cycleLink(input: CycleLinkInput): CycleLink {
  if (typeof input.threadId !== "string" || !input.threadId.startsWith("kash-thread:")) {
    fail("INVALID_MANIFEST", "threadId must be a kash-thread: id.");
  }
  if (!Number.isInteger(input.cycleIndex) || input.cycleIndex < 0) {
    fail("INVALID_MANIFEST", `cycleIndex must be a non-negative integer, got ${String(input.cycleIndex)}.`);
  }
  if (typeof input.amount !== "string" || !DECIMAL_RE.test(input.amount)) {
    fail("INVALID_MANIFEST", `amount must be a decimal-stringified non-negative integer, got ${String(input.amount)}.`);
  }
  if (!isUnixSeconds(input.dueAt)) {
    fail("INVALID_MANIFEST", `dueAt must be a Unix timestamp in seconds — milliseconds are refused; got ${String(input.dueAt)}.`);
  }
  // Cycle 0 has no predecessor; every later cycle MUST chain to one.
  if (input.cycleIndex === 0 && input.prevCycleManifestId !== undefined) {
    fail("INVALID_MANIFEST", "cycle 0 must not carry a prevCycleManifestId.");
  }
  if (input.cycleIndex > 0 && (typeof input.prevCycleManifestId !== "string" || !input.prevCycleManifestId.startsWith("kash-trade:"))) {
    fail("INVALID_MANIFEST", `cycle ${input.cycleIndex} must chain to the prior cycle's kash-trade: id.`);
  }
  return {
    kind: "subscription-cycle",
    threadId: input.threadId,
    cycleIndex: input.cycleIndex,
    amount: input.amount,
    dueAt: input.dueAt,
    ...(input.prevCycleManifestId !== undefined ? { prevCycleManifestId: input.prevCycleManifestId } : {}),
  };
}

/** Nest a cycle link under {@link THREAD_META_KEY} for `manifest.metadata`. */
export function cycleMetadata(link: CycleLink): Readonly<Record<string, unknown>> {
  return { [THREAD_META_KEY]: link };
}

/** Recover a cycle link from a manifest's `metadata`, or null if it carries none. */
export function parseCycleLink(metadata: unknown): CycleLink | null {
  if (!metadata || typeof metadata !== "object") return null;
  const raw = (metadata as Record<string, unknown>)[THREAD_META_KEY];
  if (!raw || typeof raw !== "object") return null;
  const l = raw as Record<string, unknown>;
  if (l.kind !== "subscription-cycle" || typeof l.threadId !== "string" || typeof l.cycleIndex !== "number") return null;
  try {
    return cycleLink({
      threadId: l.threadId as ThreadId,
      cycleIndex: l.cycleIndex,
      amount: l.amount as string,
      dueAt: l.dueAt as number,
      ...(l.prevCycleManifestId !== undefined ? { prevCycleManifestId: l.prevCycleManifestId as ManifestId } : {}),
    });
  } catch {
    return null;
  }
}

/**
 * Validate that `links` form a coherent thread: all share `threadId`, the cycle
 * indices are exactly 0..n-1 (no gap, no duplicate), due times are
 * non-decreasing, and the prev-chain is structurally present. Throws on any
 * violation. (Pass a config to additionally enforce the `maxCycles` cap.)
 */
export function validateThreadSequence(
  threadId: ThreadId,
  links: readonly CycleLink[],
  config?: SubscriptionThreadConfig,
): void {
  const sorted = [...links].sort((a, b) => a.cycleIndex - b.cycleIndex);
  let prevDue = -1;
  for (let i = 0; i < sorted.length; i++) {
    const l = sorted[i]!;
    if (l.threadId !== threadId) fail("INVALID_MANIFEST", `cycle ${l.cycleIndex} belongs to a different thread.`);
    if (l.cycleIndex !== i) fail("INVALID_MANIFEST", `non-contiguous cycle indices: expected ${i}, got ${l.cycleIndex} (gap or duplicate).`);
    if (l.dueAt < prevDue) fail("INVALID_MANIFEST", `cycle ${l.cycleIndex} dueAt ${l.dueAt} regresses below ${prevDue}.`);
    prevDue = l.dueAt;
    if (i === 0 && l.prevCycleManifestId !== undefined) fail("INVALID_MANIFEST", "cycle 0 must not chain to a predecessor.");
    if (i > 0 && l.prevCycleManifestId === undefined) fail("INVALID_MANIFEST", `cycle ${l.cycleIndex} is missing its prev-chain.`);
  }
  if (config?.maxCycles !== undefined && sorted.length > config.maxCycles) {
    fail("INVALID_MANIFEST", `thread has ${sorted.length} cycles, exceeding maxCycles ${config.maxCycles}.`);
  }
}

/* ─────────────────────────────────────────────────────────────────
 *  Internals
 * ───────────────────────────────────────────────────────────────── */

function validateThreadConfig(c: SubscriptionThreadConfig): void {
  if (!c || typeof c !== "object") fail("INVALID_MANIFEST", "thread config must be an object.");
  if (!isKashDid(c.subscriber)) fail("WRONG_DID", "subscriber must be a did:kash.");
  if (!isKashDid(c.provider)) fail("WRONG_DID", "provider must be a did:kash.");
  if (!Number.isInteger(c.cadenceSeconds) || c.cadenceSeconds < 1) fail("INVALID_MANIFEST", "cadenceSeconds must be a positive integer.");
  if (!isUnixSeconds(c.startAt)) fail("INVALID_MANIFEST", `startAt must be a Unix timestamp in seconds — milliseconds are refused; got ${String(c.startAt)}.`);
  if (c.maxCycles !== undefined && (!Number.isInteger(c.maxCycles) || c.maxCycles < 1)) {
    fail("INVALID_MANIFEST", "maxCycles, when set, must be a positive integer.");
  }
}

function stripUndefined<T extends object>(o: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out as Partial<T>;
}
