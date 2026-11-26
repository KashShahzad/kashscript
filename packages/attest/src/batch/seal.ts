/**
 * The seal — what a batch fixes before its draw — and the batch object a `kash.attestation@1.1.0` receipt
 * carries (PY-5; `specs/attestation/batch.md` §2).
 *
 * The seal names the root over the items (`./items`), how many there are, the plan (how many are drawn, how
 * many short ones still allow acceptance, the chance, and the plan's limit) and, for a sampled batch, the
 * Bitcoin block whose hash will draw. Its digest is `SHA-256("kash-batch-seal-v1\n" ‖ JCS(seal))`; the stamp is
 * over that digest, and the receipt's reference names it.
 *
 * **A census** — every item checked, the draw taking all of them — needs no draw: it carries no `draw`, stamp or
 * blocks. A batch smaller than a plan's sample is checked whole, as a census.
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import { S, type ObjectSchema } from "@kashscript/lexicons/schema";
import { sha256Hex } from "../chain";
import { MAX_COINBASE_BYTES, MAX_COINBASE_PATH, MAX_DRAW_GAP, type DrawCoinbase } from "./beacon";
import { ALPHA_MAX_DEN, BATCH_MAX_SAMPLE, BATCH_MAX_SIZE, type Alpha } from "./chance";

export const SEAL_FORMAT = "kash-batch-seal/1";
export const SEAL_DOMAIN = "kash-batch-seal-v1\n";
/** The one draw source this version reads. */
export const DRAW_SOURCE_BITCOIN = "bitcoin/1";
/** The reason code a *not yet* carries when more were found short than the plan accepts. */
export const OVER_PLAN_REASON = "batch-over-plan";

export interface BatchPlan {
  /** How many items a person checks. Equal to the batch's size for a census. */
  readonly sample: number;
  /** The most short items among the drawn with which the batch may still be accepted. */
  readonly accept: number;
  /** The chance the plan accepts as its risk. */
  readonly alpha: Alpha;
  /** The plan's limit: if more than this many items fell short, the plan would pass the batch at most `alpha` of the time. */
  readonly limit: number;
}

export interface BatchDraw {
  readonly source: typeof DRAW_SOURCE_BITCOIN;
  /** The Bitcoin block whose hash draws the positions — named ahead of the chain's tip. */
  readonly height: number;
}

export interface BatchSeal {
  readonly format: typeof SEAL_FORMAT;
  /** The `kash-items/1` root, as 64 hex characters. */
  readonly root: string;
  readonly size: number;
  readonly plan: BatchPlan;
  /** A sampled batch's draw; never on a census. */
  readonly draw?: BatchDraw;
  /** A new draw of items drawn before names the earlier seal's digest, and its words say so. */
  readonly previous?: string;
}

export interface Batch {
  readonly seal: BatchSeal;
  /** The OpenTimestamps proof over the seal's digest, as base64. A sampled batch only. */
  readonly stamp?: string;
  /** The block headers from the block the stamp reached up to the draw block, as hex. A sampled batch only. */
  readonly blocks?: readonly string[];
  /**
   * The draw block's first transaction and its Merkle path, which name the block's height (BIP34) — a header carries
   * none. A sampled batch only (PY-5r).
   */
  readonly coinbase?: DrawCoinbase;
  /** The positions, among the drawn, that fell short of the agreed words — ascending. */
  readonly found: readonly number[];
  /** How many of the batch's items may fall short, at the plan's chance, given what was found. */
  readonly bound: number;
}

export const isCensus = (seal: BatchSeal): boolean => seal.plan.sample === seal.size;

const enc = new TextEncoder();

/** The seal's digest, as 64 hex characters: what the stamp is over and the receipt's reference names. */
export async function sealDigestOf(seal: BatchSeal): Promise<string> {
  const tag = enc.encode(SEAL_DOMAIN);
  const body = canonicalizeBytes(seal);
  const msg = new Uint8Array(tag.length + body.length);
  msg.set(tag, 0);
  msg.set(body, tag.length);
  return sha256Hex(msg);
}

const HEX64 = S.string({ pattern: /^[0-9a-f]{64}$/ });
const count = (min: number, max: number) => S.number({ integer: true, min, max });

export const BATCH_PLAN_SCHEMA: ObjectSchema = S.object(
  {
    sample: count(1, BATCH_MAX_SAMPLE),
    accept: count(0, BATCH_MAX_SAMPLE),
    alpha: S.object({ num: count(1, ALPHA_MAX_DEN), den: count(2, ALPHA_MAX_DEN) }, ["num", "den"]),
    limit: count(0, BATCH_MAX_SIZE),
  },
  ["sample", "accept", "alpha", "limit"],
);

export const BATCH_SEAL_SCHEMA: ObjectSchema = S.object(
  {
    format: S.literal(SEAL_FORMAT),
    root: HEX64,
    size: count(1, BATCH_MAX_SIZE),
    plan: BATCH_PLAN_SCHEMA,
    draw: S.optional(S.object({ source: S.literal(DRAW_SOURCE_BITCOIN), height: count(1, 100_000_000) }, ["source", "height"])),
    previous: S.optional(HEX64),
  },
  ["format", "root", "size", "plan"],
);

export const BATCH_SCHEMA: ObjectSchema = S.object(
  {
    seal: BATCH_SEAL_SCHEMA,
    stamp: S.optional(S.string({ minLength: 1, maxLength: 24_000, pattern: /^[A-Za-z0-9+/]+={0,2}$/ })),
    blocks: S.optional(S.array(S.string({ pattern: /^[0-9a-f]{160}$/ }), { minItems: 2, maxItems: MAX_DRAW_GAP + 1 })),
    coinbase: S.optional(
      S.object(
        {
          tx: S.string({ minLength: 2, maxLength: 2 * MAX_COINBASE_BYTES, pattern: /^(?:[0-9a-f]{2})+$/ }),
          path: S.array(HEX64, { maxItems: MAX_COINBASE_PATH }),
        },
        ["tx", "path"],
      ),
    ),
    found: S.array(count(0, BATCH_MAX_SIZE - 1), { maxItems: BATCH_MAX_SAMPLE }),
    bound: count(0, BATCH_MAX_SIZE),
  },
  ["seal", "found", "bound"],
);
