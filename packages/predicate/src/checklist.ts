/**
 * The checklist — a rule checked on the person's side first (ECOSYSTEM d84(a)),
 * against the receipts they hold, before anything is sent.
 *
 * For each criterion one row says, in plain words, whether it is **answered**
 * by these receipts, **missing** (and which issuers or lists the rule accepts
 * to supply it), stated on the person's **own word**, or **sealed** — a private
 * rule's row whose threshold only the desk can read.
 *
 * **Never a score or a percentage.** A row carries no number of any kind; a
 * test walks every output to keep it so. The receipt handles in a row are the
 * person's own and never leave their device.
 */

import type { Criterion, RuleBody1_1 as RuleBody } from "@kashscript/lexicons/extensions/door";
import { adoptedRead, type ReadAdoption } from "./adoption";
import { criterionQueries, matchQuery, PREDICATE_SUFFIX, OWN_WORD_SUFFIX, type MatchContext } from "./dcql";
import { asOfSeconds, evaluateCriterion, publicThresholds, type MatchedReceipt } from "./criteria";
import { readReceipts, type HeldReceipt, type ReadContext, type ReceiptView } from "./receipts";
import { ruleLive } from "./rule";
import { TA_ISSUER, TA_TRUST_LIST } from "./constants";

export type RowState = "answered" | "missing" | "own-word" | "sealed";

export interface Accepts {
  /** Issuers the rule names, with the names it gives them. */
  readonly issuers: readonly { readonly id: string; readonly name: string }[];
  /** Trust lists whose issuers the rule accepts. */
  readonly lists: readonly { readonly ref: string; readonly name: string }[];
  /** True when any issuer of the right kind of receipt will do (for example, any client who countersigns). */
  readonly anyIssuer: boolean;
}

export interface ChecklistRow {
  readonly criterion: string;
  readonly label: string;
  readonly purpose: string;
  readonly state: RowState;
  readonly via: "receipts" | "predicate" | "own-word" | null;
  /** The person's receipts this row rests on (their own handles) — minimal by default. */
  readonly receipts: readonly string[];
  /** Other receipts that also fit, which the person may add. */
  readonly more: readonly string[];
  readonly accepts: Accepts;
  /** Own word only: whether what the person stated meets the rule. Null until they state it. */
  readonly holds: boolean | null;
  /** One sentence for the row. */
  readonly words: string;
  readonly notes: readonly string[];
}

export interface Checklist {
  readonly rule: { readonly id: string; readonly version: number; readonly hash: string };
  /** The anchor whose adopted values this was checked against, when there is one. */
  readonly adoption: { readonly id: string; readonly anchor: string; readonly hash: string } | null;
  readonly live: boolean;
  readonly renewalDue: boolean;
  /** A draft is checked for practice; no door decides under it. */
  readonly draft: boolean;
  readonly rows: readonly ChecklistRow[];
  /** Every row is answered, sealed for the desk, or stated and holding — and the rule is in force and not a draft. */
  readonly ready: boolean;
}

export interface ChecklistOptions extends Omit<ReadContext, "nowSec"> {
  /** The evaluation time: an ISO date-time with an offset, or unix seconds. */
  readonly asOf: string | number;
  /** What the person states, by criterion, for the criteria the rule takes on their word. */
  readonly ownWord?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  /** The anchor's adoption the door decides under: its local values are the thresholds. */
  readonly adoption?: ReadAdoption;
}

export function acceptsOf(c: Criterion): Accepts {
  const issuers: { id: string; name: string }[] = [];
  const lists: { ref: string; name: string }[] = [];
  let anyIssuer = false;
  if (c.answer.by === "receipts") {
    const names = c.answer.names ?? {};
    for (const q of c.answer.query) {
      if (q.trusted_authorities === undefined) anyIssuer = true;
      for (const ta of q.trusted_authorities ?? []) {
        for (const v of ta.values) {
          if (ta.type === TA_ISSUER && !issuers.some((i) => i.id === v)) issuers.push({ id: v, name: names[v] ?? v });
          if (ta.type === TA_TRUST_LIST && !lists.some((l) => l.ref === v)) lists.push({ ref: v, name: names[v] ?? v });
        }
      }
    }
  }
  for (const i of c.predicate?.issuers ?? []) if (!issuers.some((x) => x.id === i.id)) issuers.push(i);
  return { issuers, lists, anyIssuer };
}

function acceptsWords(a: Accepts): string {
  const parts = [...a.issuers.map((i) => i.name), ...a.lists.map((l) => `an issuer on ${l.name}`)];
  if (a.anyIssuer) parts.push("any issuer of the receipt it names");
  return parts.length === 0 ? "" : ` The rule accepts it from ${parts.join(", or ")}.`;
}

/** Match one person's receipts to one criterion's queries. */
export function matchCriterion(rule: RuleBody, hash: string, c: Criterion, views: readonly ReceiptView[], ctx: MatchContext) {
  const { queries } = criterionQueries(rule, hash, c);
  const receipts: MatchedReceipt[] = [];
  const predicates: MatchedReceipt[] = [];
  const nearMisses: string[] = [];
  for (const q of queries) {
    if (q.id.endsWith(OWN_WORD_SUFFIX)) continue;
    for (const view of views) {
      const m = matchQuery(q, view, ctx);
      if (!m.ok) continue;
      const entry: MatchedReceipt = { queryId: q.id, view, values: m.values };
      if (q.id.endsWith(PREDICATE_SUFFIX)) predicates.push(entry);
      else if (!receipts.some((r) => r.view.contentId === view.contentId)) receipts.push(entry); // one record, one count (AU-3, A7-03)
      if (!view.counts) nearMisses.push(...view.problems);
    }
  }
  return { receipts, predicates, nearMisses };
}

/** Check a rule against the receipts a person holds. Pure; reads no clock. */
export async function checklist(rule: { readonly body: RuleBody; readonly hash: string }, held: readonly HeldReceipt[], opts: ChecklistOptions): Promise<Checklist> {
  const nowSec = asOfSeconds(opts.asOf);
  const ctx: ReadContext = { ...opts, nowSec };
  const views = await readReceipts(held, ctx);
  const thresholds = publicThresholds(rule.body, opts.adoption?.body.parameters);
  const rows: ChecklistRow[] = [];
  for (const c of rule.body.criteria) {
    const accepts = acceptsOf(c);
    if (c.answer.by === "own-word") {
      const word = opts.ownWord?.[c.id] ?? null;
      const r = evaluateCriterion(rule.body, c, { receipts: [], predicates: [], word }, { asOf: opts.asOf, thresholds });
      const holds = word === null ? null : r.met;
      rows.push({
        criterion: c.id,
        label: c.label,
        purpose: c.purpose,
        state: "own-word",
        via: "own-word",
        receipts: [],
        more: [],
        accepts,
        holds,
        words:
          holds === null
            ? `On your own word: ${c.answer.statement}`
            : holds
              ? `On your own word, and what you stated meets the rule: ${c.answer.statement}`
              : `On your own word — what you stated does not meet the rule yet: ${c.answer.statement}`,
        notes: r.sealed ? ["the rule's threshold for this is sealed, so the desk checks it"] : [],
      });
      continue;
    }
    const matched = matchCriterion(rule.body, rule.hash, c, views, { trustLists: opts.trustLists ?? [], nowSec });
    const { receipts, nearMisses } = matched;
    // An issuer's predicate was given under the rule's own values; where the anchor set one, the receipts are read.
    const anchorsOwn = adoptedRead(rule.body, c, opts.adoption).length > 0;
    const predicates = anchorsOwn ? [] : matched.predicates;
    const r = evaluateCriterion(rule.body, c, { receipts, predicates, word: null }, { asOf: opts.asOf, thresholds });
    const notes = [...new Set(nearMisses)].map((p) => `one of your receipts does not count: ${p}`);
    if (anchorsOwn && matched.predicates.length > 0) notes.push("an issuer's yes was given under the rule's own values — this door uses its own, so your receipts are read instead");
    if (r.exhausted) notes.push("this condition took too many steps to check here");
    let state: RowState;
    let words: string;
    if (r.sealed) {
      state = r.chosen.length > 0 ? "sealed" : "missing";
      words =
        state === "sealed"
          ? "The rule reads these receipts. Its threshold is sealed, so the desk checks it."
          : `Missing: ${c.label}.${acceptsWords(accepts)}`;
    } else if (r.met === true) {
      state = "answered";
      words = r.via === "predicate" ? `Answered by an issuer's yes under this rule's version: ${c.label}.` : `Answered by your receipts: ${c.label}.`;
    } else {
      state = "missing";
      words = `Missing: ${c.label}.${acceptsWords(accepts)}`;
      if (r.met === null && receipts.length > 0) notes.push("your receipts could not be checked against this here — the desk checks them");
    }
    rows.push({
      criterion: c.id,
      label: c.label,
      purpose: c.purpose,
      state,
      via: state === "missing" ? null : r.via,
      receipts: state === "missing" ? [] : r.chosen.map((m) => m.view.ref),
      more: r.more.map((m) => m.view.ref),
      accepts,
      holds: null,
      words,
      notes,
    });
  }
  const live = ruleLive(rule.body, nowSec);
  const draft = rule.body.draft === true;
  const a = opts.adoption;
  return {
    rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
    adoption: a === undefined ? null : { id: a.body.id, anchor: a.body.anchor, hash: a.hash },
    live: live.live,
    renewalDue: live.renewalDue,
    draft,
    rows,
    ready: live.live && !draft && rows.every((r) => r.state === "answered" || r.state === "sealed" || (r.state === "own-word" && r.holds === true)),
  };
}
