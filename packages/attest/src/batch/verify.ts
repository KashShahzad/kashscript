/**
 * The checks of a batch accepted on a sample that need hashing (PY-5; `specs/attestation/batch.md` §5) —
 * run by `verifyAttestationRecord` after the record's own checks, and by `attest verify`. Offline, never
 * throwing: every input gets a report, and what it could not decide is named, never passed by silence.
 *
 * - **the reference** names this seal's digest;
 * - **the draw** stands (`./beacon`): the stamp reached a block below the named height, the headers link, each
 *   meets the work floor, and the last names the seal's height in its first transaction (BIP34; PY-5r);
 * - **every position found short was drawn** — the draw recomputed from the seal and the draw block (`./draw`).
 *
 * `verifyBatchItems` takes the batch's items file and checks every item against the root.
 */

import { bytesToHex, hexToBytes } from "../chain";
import type { AttestationBody } from "../attestation/lexicon";
import { MAX_DRAW_GAP, SEED_MIN_WORK_BITS, checkDrawBlocks } from "./beacon";
import { drawPositions, drawSeed } from "./draw";
import { itemTree, type BatchItemsFile } from "./items";
import { isCensus, sealDigestOf, type Batch } from "./seal";

export type BatchProblemCode = "BATCH_REFERENCE" | "BATCH_DRAW" | "BATCH_FOUND";

export interface BatchCheck {
  readonly ok: boolean;
  readonly problems: readonly { readonly code: BatchProblemCode; readonly message: string }[];
  readonly notChecked: readonly string[];
  readonly sealDigest: string;
  readonly census: boolean;
  /** The positions the draw picks, recomputed; null for a census, or when no draw block could be read. */
  readonly drawn: readonly number[] | null;
  /** The draw block's hash, as Bitcoin displays it, read from the last header given. */
  readonly drawBlockHash: string | null;
  /** Whether the headers stand — linked, stamped below the draw, each above the floor. */
  readonly blocksStand: boolean;
  readonly stampHeight: number | null;
  readonly minWorkBits: number;
}

export interface BatchCheckOptions {
  /** Tests only: a lower work floor for headers they mine themselves. Reported when lowered. */
  readonly minWorkBits?: number;
}

/**
 * The line `verifyBatch` always adds to `notChecked`, since it never sees the items. A caller that does check
 * them with `verifyBatchItems` — `attest verify --batch` — drops this line, and says what the items check found.
 */
export const BATCH_ITEMS_NOT_CHECKED =
  "the items themselves — given the batch's items file, `verifyBatchItems` (attest verify --batch <file>) checks every item against the root";

async function displayHashOf(headerHex: string): Promise<string | null> {
  if (!/^[0-9a-f]{160}$/.test(headerHex)) return null;
  const once = await crypto.subtle.digest("SHA-256", hexToBytes(headerHex) as unknown as BufferSource);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", once)).reverse());
}

/** The hashing checks of a receipt's batch. The body's own checks (`checkAttestation`) are assumed run. */
export async function verifyBatch(body: AttestationBody, opts: BatchCheckOptions = {}): Promise<BatchCheck> {
  const batch = body.batch as Batch;
  const seal = batch.seal;
  const minWorkBits = opts.minWorkBits ?? SEED_MIN_WORK_BITS;
  const problems: { code: BatchProblemCode; message: string }[] = [];
  const notChecked: string[] = [];
  const sealDigest = await sealDigestOf(seal);
  if (body.reference.sha256 !== sealDigest) problems.push({ code: "BATCH_REFERENCE", message: "the receipt's reference does not name this seal's digest" });
  const census = isCensus(seal);
  if (census) {
    notChecked.push(BATCH_ITEMS_NOT_CHECKED);
    return { ok: problems.length === 0, problems, notChecked, sealDigest, census, drawn: null, drawBlockHash: null, blocksStand: true, stampHeight: null, minWorkBits };
  }

  const blocks = batch.blocks ?? [];
  const height = seal.draw?.height ?? 0;
  const standing = await checkDrawBlocks({ stamp: batch.stamp ?? "", sealDigest, blocks, ...(batch.coinbase !== undefined ? { coinbase: batch.coinbase } : {}), drawHeight: height, minWorkBits });
  for (const p of standing.problems) problems.push({ code: "BATCH_DRAW", message: p });
  // The draw is recomputed from the last header given even when the headers do not stand, so a reader sees it;
  // the problems above then say it does not count.
  const drawBlockHash = standing.drawBlockHash ?? (blocks.length > 0 && blocks.length <= MAX_DRAW_GAP + 1 ? await displayHashOf(blocks[blocks.length - 1]!) : null);
  let drawn: number[] | null = null;
  if (drawBlockHash !== null) {
    drawn = await drawPositions(await drawSeed(sealDigest, drawBlockHash), seal.size, seal.plan.sample);
    const picked = new Set(drawn);
    const stray = batch.found.filter((p) => !picked.has(p));
    if (stray.length > 0) problems.push({ code: "BATCH_FOUND", message: `${stray.length === 1 ? "a position" : `${stray.length} positions`} found short ${stray.length === 1 ? "was" : "were"} not drawn: ${stray.slice(0, 5).join(", ")}${stray.length > 5 ? ", …" : ""}` });
  }
  if (minWorkBits < SEED_MIN_WORK_BITS) notChecked.push(`the draw's headers were checked against a floor of ${minWorkBits} bits of work, below the ${SEED_MIN_WORK_BITS} a draw requires — a test's own floor`);
  notChecked.push(
    `that these headers are Bitcoin's own chain — each claims the floor's work and the last names height ${height} in its first transaction, but a costly private chain could do both; compare block ${height}'s hash${drawBlockHash !== null ? ` (${drawBlockHash})` : ""} with any copy of the chain`,
    `that the batch was put to the approver before block ${height} was mined, and that the asker sealed no other version of it first — the asker's own engine refuses an ask whose draw is already public; a stranger cannot see either`,
    BATCH_ITEMS_NOT_CHECKED,
  );
  return { ok: problems.length === 0, problems, notChecked, sealDigest, census, drawn, drawBlockHash, blocksStand: standing.ok, stampHeight: standing.stampHeight, minWorkBits };
}

/** Whether a batch's items file holds exactly the items its seal fixed: the same count, and the same root under the file's salt. */
export async function verifyBatchItems(batch: Batch, file: BatchItemsFile): Promise<{ readonly ok: boolean; readonly problems: readonly string[] }> {
  const problems: string[] = [];
  if (file.digests.length !== batch.seal.size) problems.push(`the file lists ${file.digests.length} items; the seal fixed ${batch.seal.size}`);
  else {
    try {
      const tree = await itemTree(file.salt, file.digests);
      if (tree.root !== batch.seal.root) problems.push("these items, under this salt, do not make the seal's root — an item was changed, swapped, added or left out");
    } catch (e) {
      problems.push(e instanceof Error ? e.message : String(e));
    }
  }
  return { ok: problems.length === 0, problems };
}
