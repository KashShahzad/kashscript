/**
 * A batch's words (PY-5; `specs/attestation/batch.md` §7) — the sentences the desk screen shows before the
 * person signs, and the checker prints for anyone reading the record. One function, so the two never differ.
 *
 * They follow the content standard (CONTENT-AND-FLOW-STANDARD-2026-11-09 §1): a first line a person would say
 * aloud; the parties named; counts, never percentages; what the record does **not** prove written in the body
 * beside what it proves (d51); the bound never called a guarantee; nothing said about who made the items (d43).
 * English here; Urdu and Roman Urdu are the screen's copy.
 */

import type { AttestationBody } from "../attestation/lexicon";
import { isCensus, type Batch } from "./seal";
import type { Alpha } from "./chance";

export interface BatchWordsOptions {
  /** Who asked, as the screen names them — "Acme". Default: "the asker". */
  readonly asker?: string;
  /** `approver` before signing (*you*); `reader` for anyone checking the record (*the approver*). Default: `reader`. */
  readonly voice?: "approver" | "reader";
}

export interface BatchWords {
  /** In order: what was checked, how it was drawn, what was found, the plan, the bound, its limit. */
  readonly lines: readonly string[];
  /** What the record does not prove — shown in the body, in the same type (d51). */
  readonly doesNotProve: readonly string[];
}

/** 10000 → "10,000": the same in every locale. */
export function grouped(n: number): string {
  const s = String(Math.trunc(Math.abs(n)));
  const out: string[] = [];
  for (let i = s.length; i > 0; i -= 3) out.unshift(s.slice(Math.max(0, i - 3), i));
  return (n < 0 ? "-" : "") + out.join(",");
}

/** {1, 20} → "1 time in 20"; {3, 100} → "3 times in 100". */
export const chanceWords = (a: Alpha): string => `${grouped(a.num)} ${a.num === 1 ? "time" : "times"} in ${grouped(a.den)}`;

/** The words of a receipt's batch. */
export function batchWords(body: AttestationBody, opts: BatchWordsOptions = {}): BatchWords {
  const batch = body.batch as Batch;
  const seal = batch.seal;
  const plan = seal.plan;
  const asker = opts.asker ?? "the asker";
  const you = opts.voice === "approver";
  const Subj = you ? "You" : "The approver";
  const subj = you ? "you" : "the approver";
  const N = grouped(seal.size);
  const n = grouped(plan.sample);
  const x = batch.found.length;
  const census = isCensus(seal);
  const lines: string[] = [];

  lines.push(census ? `${Subj} checked every one of the ${N} items in ${asker}'s batch.` : `${Subj} checked ${n} of the ${N} items in ${asker}'s batch.`);
  if (!census && seal.draw !== undefined) {
    lines.push(`They were chosen by Bitcoin block ${seal.draw.height}, mined after the batch was fixed, so ${you ? `neither you nor ${asker}` : "neither side"} picked them.`);
  }
  if (seal.previous !== undefined) lines.push(`This is a new draw: these items were sealed once before (seal ${seal.previous.slice(0, 12)}…).`);

  const seen = census ? N : n;
  if (x === 0) lines.push(`All ${seen} meet the agreed words.`);
  else if (x <= plan.accept) {
    lines.push(`${grouped(x)} of the ${seen} ${x === 1 ? "falls" : "fall"} short of the agreed words; the plan accepts up to ${grouped(plan.accept)}.`);
    if (body.outcome === "accepted") lines.push(`${you ? "Your" : "The"} acceptance does not cover ${x === 1 ? "that one" : `those ${grouped(x)}`}.`);
  } else {
    const allows = plan.accept === 0 ? "the plan accepts none" : `the plan accepts up to ${grouped(plan.accept)}`;
    lines.push(`${grouped(x)} of the ${seen} ${x === 1 ? "falls" : "fall"} short of the agreed words; ${allows}, so the batch can only be answered not yet.`);
    if (you) lines.push(`Tell ${asker} what to change — only ${asker} will see it. A new draw needs a new batch.`);
  }
  if (body.outcome === "not-yet" && x <= plan.accept) lines.push(`${Subj} answered not yet.`);

  const acceptIf = plan.accept === 0 ? "only if none fall short" : plan.accept === 1 ? "if at most 1 falls short" : `if at most ${grouped(plan.accept)} fall short`;
  if (census) {
    lines.push(`The plan accepts the batch ${acceptIf}.`);
    lines.push(`This says what was seen in these ${N} items, and nothing more.`);
  } else {
    const chance = chanceWords(plan.alpha);
    lines.push(`The plan: check ${n}, and accept the batch ${acceptIf}. If more than ${grouped(plan.limit)} of the ${N} fell short, this plan would pass the batch at most ${chance}.`);
    lines.push(`If more than ${grouped(batch.bound)} of the ${N} fell short, a draw of ${n} ${x === 0 ? "as clean as this one" : `with ${grouped(x)} or fewer short`} would come up at most ${chance}.`);
    lines.push(`This is not a guarantee: the other ${grouped(seal.size - plan.sample)} items were not seen.`);
  }

  const doesNotProve = [
    `It does not show that the items are good — only that ${subj} checked ${census ? "them" : `these ${n}`} and answered.`,
    ...(census ? [] : ["A draw finds only what a person can see in an item."]),
    "It says nothing about who made the items.",
  ];
  return { lines, doesNotProve };
}
