/**
 * The floor's rules, and the decisions each one enforces (ECOSYSTEM.md; RW-17 and its status note of 2026-11-12).
 *
 * Pure data: the runtime entry (`@kashscript/floor`) exports it, so nothing here may touch the file system or the
 * compiler. Every finding the scanner reports carries the cites of the decisions it rests on, and the report prints
 * them beside the finding — a failure always says which decision it enforces.
 */

export type RuleId =
  | "person-lookup"
  | "person-score"
  | "price-per-record"
  | "declined-state"
  | "unsuppressed-count"
  | "decision-without-rule"
  | "undeclared-route";

export interface RuleInfo {
  readonly id: RuleId;
  /** What the rule refuses, in one line. */
  readonly title: string;
  /** The decisions the rule enforces, as cited in the log. */
  readonly decisions: readonly string[];
}

/** One cite: the decision, and what it says that the finding rests on. */
export const CITE = {
  d27: "d27 (a yes, never a score)",
  d41Lookup: "d41 (presentation, never lookup; never built, at any price)",
  d41Scores: "d41 (never built: scores, rankings or comparisons between subjects)",
  d41Export: "d41 (never built: bulk export of subject records)",
  d41Report: "d41 (never built: a report naming individuals)",
  d42Standing: "d42 (a stored standing is a score with better manners)",
  d43Counts: "d43 (no conformance percentages, personal error counts or rankings)",
  d43Version: "d43 (every predicate names the rule version it was judged against)",
  d49a: "d49(a) (a decline leaves no trace: no declined flag, no list of refusers)",
  d50: "d50 (organisations pay for capacity and labour, never for volume)",
  d84c: "d84(c) as read by d96(b) (no fee for issuing, holding, presenting or checking a record)",
  d84P3: "d84 P3 (only a named person says no, and the decision is a receipt naming its rule's version)",
  d84P43: "d84 P4.3 (no door contacts a person who has not come to it)",
  d84Rule11: "d84 node rule 11 (every decision names its rule's version and reasons)",
  d85b2: "d85(b)2 (nothing looks a person up; there is no register of people)",
  d85b3: "d85(b)3 (no scores, rankings or watching of people)",
  d85b5: "d85(b)5 (every decision gives its reasons and can be contested)",
  d85b7: "d85(b)7 (rules are public: author, version, purpose, renewal date)",
  d85b11: "d85(b)11 (no total traces back to a person)",
  d85b12: "d85(b)12 (nothing takes a cut of what flows)",
  d91f: "d91(f) and its note of 2026-11-20 (small counts suppressed: noise first, then k as display)",
  d91hLookup: "d91(h) (no lookup endpoint; no directory or search of people)",
  d91hPush: "d91(h) (no push: a wallet hears only inside a session the person opened)",
  d91hRefusal: "d91(h) (no refusal query)",
  d91hExport: "d91(h) (no bulk export of people)",
  d91hAbsent: "d91(h) (the forbidden gateways are absent from the API, not merely unused)",
  d96a: "d96(a) (one fixed price on an accepted outcome, never a percentage)",
  d96d: "d96(d) (every number is the founder's, written where the price files hold it)",
  d97i: "d97(i) (k = 5 as the display rule for a count)",
  std27: "the standard §2.7 (a status never says declined)",
  std7: "the standard §7 (no stars, averages, rankings or all-time counts of a person)",
} as const;

export type CiteKey = keyof typeof CITE;

export const RULES: Readonly<Record<RuleId, RuleInfo>> = {
  "person-lookup": {
    id: "person-lookup",
    title: "No route lists, searches or looks up persons",
    decisions: ["d41", "d85(b)2", "d91(h)", "d84 P4.3"],
  },
  "person-score": {
    id: "person-score",
    title: "No field shaped as a score, rank, rating, average or count of a person",
    decisions: ["d27", "d41", "d42", "d43", "d85(b)3", "the standard §7"],
  },
  "price-per-record": {
    id: "price-per-record",
    title: "No price for issuing, holding, presenting or checking a record, and no percentage of anything",
    decisions: ["d50", "d84(c)", "d96(a)", "d96(b)", "d96(d)", "d85(b)12"],
  },
  "declined-state": {
    id: "declined-state",
    title: "No endpoint returns a per-person declined state",
    // d84 P3 is not listed: it is what allows a named person's refusal, so a waiver may cite it.
    decisions: ["d49(a)", "d91(h)", "d41", "d85(b)3", "the standard §2.7"],
  },
  "unsuppressed-count": {
    id: "unsuppressed-count",
    title: "Every exported count passes the floor's suppress, k = 5",
    decisions: ["d97(i)", "d85(b)11", "d91(f)"],
  },
  "decision-without-rule": {
    id: "decision-without-rule",
    title: "Every decision names a rule version",
    decisions: ["d43", "d84 P3", "d84", "d85(b)5", "d85(b)7"],
  },
  "undeclared-route": {
    id: "undeclared-route",
    title: "No mounted route is absent from the manifest",
    decisions: ["d91(h)"],
  },
};

/** The decision references in a piece of text: d41, d85(b)2, d91(h), d84 P4.3, d63(a) … normalised to lower case. */
export function decisionRefs(text: string): string[] {
  const out: string[] = [];
  const re = /\bd(\d{1,3})(\([a-z]\)(\d+)?)?(\s+p\d+(\.\d+)?)?/gi;
  for (const m of text.matchAll(re)) out.push(m[0].toLowerCase().replace(/\s+/g, ""));
  return out;
}

/**
 * Whether a waiver's cites are only the decisions its own rule enforces — a circular waiver, refused. A bare
 * decision number (d84) covers every part of it (d84(c), d84p3).
 */
export function circular(rule: RuleId, waiverDecision: string): boolean {
  const own = new Set(RULES[rule].decisions.flatMap((d) => decisionRefs(d)));
  const cited = decisionRefs(waiverDecision);
  if (cited.length === 0) return false;
  return cited.every((c) => {
    if (own.has(c)) return true;
    const bare = /^d\d+$/.test(c);
    return bare && [...own].some((o) => o === c || o.startsWith(`${c}(`) || o.startsWith(`${c}p`));
  });
}
