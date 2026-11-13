/**
 * Routing — for desks to reuse (ECOSYSTEM d84 (f) P3): a rule and a checked
 * packet in; `automatic-yes`, `not-yet` or `to-a-person` out, with the rows
 * that fired. **It never returns a refusal** — the type has no such member.
 *
 *   automatic-yes — every criterion is met, the outcome only grants, and the
 *                   author's signed rule carries the standing yes. Signed as
 *                   `standing:<author>`, citing the rows that fired.
 *   not-yet       — something is missing; the result says what, and who the
 *                   rule accepts to supply it.
 *   to-a-person   — everything else: an outcome that binds or touches
 *                   sensitive data, a rule with no standing yes, a row that
 *                   could not be read, a sealed threshold that would not open,
 *                   or the person asking for a person.
 *
 * Only fixed rules people wrote decide; there is no model anywhere in this
 * path. Every result carries the safeguards: the person is told whether it was
 * automatic, gets its reasons, may ask for a person, and may contest.
 */

import { adoptedRead, adoptedValues, adoptionInForce, type ReadAdoption } from "./adoption";
import { acceptsOf, type Accepts } from "./checklist";
import { asOfSeconds, evaluateCriterion, type Thresholds } from "./criteria";
import type { PacketCheck } from "./packet";
import { openThresholds, ruleLive, RuleError, type Openings, type ReadRule } from "./rule";

export type Route = "automatic-yes" | "not-yet" | "to-a-person";

export interface RouteRow {
  readonly criterion: string;
  /** true: met · false: not met · null: could not be read here. */
  readonly met: boolean | null;
  readonly via: "receipts" | "predicate" | "own-word";
  /** Hashes of the receipts the row rests on. Never their content. */
  readonly receipts: readonly string[];
}

export interface RouteResult {
  readonly route: Route;
  readonly rule: { readonly id: string; readonly version: number; readonly hash: string };
  readonly rows: readonly RouteRow[];
  /** The criteria met. */
  readonly fired: readonly string[];
  /** The criteria not met, with who the rule accepts to supply each. */
  readonly missing: readonly { readonly criterion: string; readonly label: string; readonly accepts: Accepts }[];
  /** The criteria that could not be read automatically. */
  readonly unread: readonly string[];
  /** Reason codes from the rule, for an automatic outcome. Empty when a person decides. */
  readonly reasons: readonly string[];
  /** Why it went this way, in plain words. */
  readonly why: string;
  readonly told: "automatic" | "a person decides";
  readonly mayAskForPerson: true;
  readonly contestWithinDays: number;
  /** Every receipt hash a decision on this packet would rely on. */
  readonly reliedOn: readonly string[];
  /** The adoption the door decided under — its anchor signs the decision. Null for the rule author's own door. */
  readonly adoption: { readonly id: string; readonly anchor: string; readonly hash: string } | null;
}

export async function route(
  rule: ReadRule,
  check: PacketCheck,
  opts: { readonly asOf: string | number; readonly openings?: Openings; readonly askedForPerson?: boolean; readonly adoption?: ReadAdoption },
): Promise<RouteResult> {
  const body = rule.body;
  if (check.rule.id !== body.id || check.rule.version !== body.version || check.rule.hash !== rule.hash) {
    throw new RuleError("RULE_INVALID", "the packet was checked against another rule or version");
  }
  if (body.draft === true) throw new RuleError("RULE_INVALID", "a draft is published for reading and comment — no door decides under it");
  if (!ruleLive(body, asOfSeconds(opts.asOf)).live) throw new RuleError("RULE_INVALID", "the rule is not in force — a door decides only under a rule in force");
  const a = opts.adoption;
  if (a !== undefined && (a.body.rule.id !== body.id || a.body.rule.version !== body.version || a.body.rule.hash !== rule.hash)) {
    throw new RuleError("RULE_INVALID", "the adoption is of another rule or version");
  }
  if (a !== undefined && !adoptionInForce(a, asOfSeconds(opts.asOf))) throw new RuleError("RULE_INVALID", "the adoption is not in force — an anchor's door decides only under an adoption in force");

  // A public rule's thresholds are in clear, with an anchor's adopted values over them; a private one's open only with
  // the desk's openings, checked against its commitments.
  const opened = body.visibility === "private" && opts.openings === undefined ? null : await openThresholds(body, opts.openings ?? {});
  const values = opened === null ? null : { ...opened, ...adoptedValues(body, a) };
  const thresholds: Thresholds | null = values === null ? null : { kind: "values", values };

  const rows: RouteRow[] = [];
  for (const c of body.criteria) {
    const held = check.byCriterion[c.id] ?? { receipts: [], predicates: [], word: null };
    // An issuer's predicate was given under the rule's own values, not the anchor's.
    const got = adoptedRead(body, c, a).length > 0 ? { ...held, predicates: [] } : held;
    if (thresholds === null) {
      rows.push({ criterion: c.id, met: null, via: c.answer.by === "own-word" ? "own-word" : "receipts", receipts: [] });
      continue;
    }
    const r = evaluateCriterion(body, c, got, { asOf: opts.asOf, thresholds });
    rows.push({ criterion: c.id, met: r.met, via: r.via, receipts: (r.via === "own-word" ? got.receipts : r.chosen).map((m) => m.view.id) });
  }

  const fired = rows.filter((r) => r.met === true).map((r) => r.criterion);
  const unread = rows.filter((r) => r.met === null).map((r) => r.criterion);
  const missing = rows
    .filter((r) => r.met === false)
    .map((r) => {
      const c = body.criteria.find((x) => x.id === r.criterion)!;
      return { criterion: c.id, label: c.label, accepts: acceptsOf(c) };
    });
  const reliedOn = [...new Set(rows.flatMap((r) => r.receipts))].sort();
  const base = {
    rule: check.rule,
    rows,
    fired,
    missing,
    unread,
    mayAskForPerson: true as const,
    contestWithinDays: body.contest.windowDays,
    reliedOn,
    adoption: a === undefined ? null : { id: a.body.id, anchor: a.body.anchor, hash: a.hash },
  };
  const firstReason = (outcome: "yes" | "not-yet"): string[] => body.reasons.filter((r) => r.outcome === outcome).slice(0, 1).map((r) => r.code);
  const toPerson = (why: string): RouteResult => ({ ...base, route: "to-a-person", reasons: [], why, told: "a person decides" });

  if (opts.askedForPerson === true) return toPerson("the person asked for a person");
  if (thresholds === null) return toPerson("the rule's sealed thresholds did not open — a person decides");
  if (unread.length > 0) return toPerson("a criterion could not be read automatically — a person decides");
  // d85(e): an automatic not yet is allowed on every rule, binding or not — it refuses nothing.
  if (missing.length > 0) {
    return { ...base, route: "not-yet", reasons: firstReason("not-yet"), why: "something the rule asks for is missing — the result says what, and who may supply it", told: "automatic" };
  }
  if (body.outcome.binds) return toPerson("every criterion is met, and the outcome binds the person — a named person decides (P3)");
  if (body.outcome.sensitive) return toPerson("every criterion is met, and the outcome touches sensitive data — a named person decides (P3)");
  if (!body.outcome.automaticYes) return toPerson("every criterion is met, and the rule's author keeps the yes for a person");
  const whose = a === undefined ? "the rule author's standing yes" : "the adopting anchor's standing yes";
  return { ...base, route: "automatic-yes", reasons: firstReason("yes"), why: `every criterion is met and the outcome only grants — ${whose}`, told: "automatic" };
}
