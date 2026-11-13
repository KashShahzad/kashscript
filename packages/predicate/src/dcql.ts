/**
 * DCQL — the Digital Credentials Query Language of OpenID for Verifiable
 * Presentations 1.0 (§6, §7). A rule's criteria carry credential queries
 * verbatim; this module reads them the way a wallet does: claims path
 * pointers, `values`, `claim_sets`, `trusted_authorities` and `meta`.
 *
 * Two extensions, each in a point the spec leaves open, and nothing else:
 *   - **the `kash-artifact` format** (the holder contract's OID4VCI profile),
 *     with `meta.dst_values`, `meta.attestation` and `meta.holder_path`;
 *   - **two `trusted_authorities` types**: `kash_issuer` (issuer DIDs) and
 *     `kash_trust_list` (`<publisher DID>#<list id>`: whoever that publisher's
 *     pinned list admits for this type).
 */

import { findListing, type TrustListReport } from "@kashscript/attest/holder";
import { PREDICATE_VCT } from "@kashscript/attest/exchange";
import type { ClaimPathElement, Criterion, DcqlClaimsQuery, DcqlCredentialQuery, RuleBody } from "@kashscript/lexicons/extensions/door";
import { KASH_ARTIFACT_FORMAT, OWN_WORD_VCT, READABLE_FORMATS, SD_JWT_FORMAT, TA_ISSUER, TA_TRUST_LIST } from "./constants";
import type { ReceiptView } from "./receipts";

export type { ClaimPathElement, DcqlClaimsQuery, DcqlCredentialQuery } from "@kashscript/lexicons/extensions/door";

export interface DcqlQuery {
  readonly credentials: readonly DcqlCredentialQuery[];
  readonly credential_sets: readonly { readonly options: readonly (readonly string[])[]; readonly required: boolean }[];
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * A claims path pointer (§7): a string selects a key, `null` every element of
 * an array, an integer one index. Null when the path selects nothing — the
 * claim is not present.
 */
export function selectClaim(root: unknown, path: readonly ClaimPathElement[]): { readonly value: unknown } | null {
  let selected: unknown[] = [root];
  let many = false;
  for (const el of path) {
    const next: unknown[] = [];
    for (const s of selected) {
      if (typeof el === "string") {
        if (!isPlainObject(s)) return null;
        if (Object.prototype.hasOwnProperty.call(s, el)) next.push(s[el]);
      } else if (el === null) {
        if (!Array.isArray(s)) return null;
        next.push(...s);
        many = true;
      } else {
        if (!Array.isArray(s)) return null;
        if (el < s.length) next.push(s[el]);
      }
    }
    if (next.length === 0 && !(el === null && selected.every(Array.isArray))) return null;
    selected = next;
  }
  return { value: many ? selected : selected[0] };
}

function valuesMatch(selected: unknown, values: readonly (string | number | boolean)[], many: boolean): boolean {
  const pool = many && Array.isArray(selected) ? selected : [selected];
  return pool.some((v) => values.some((w) => v === w));
}

export interface MatchContext {
  readonly trustLists?: readonly TrustListReport[];
  readonly nowSec: number;
}

export type MatchResult =
  | { readonly ok: true; readonly values: Readonly<Record<string, unknown>> }
  | { readonly ok: false; readonly why: string };

const stripFragment = (did: string): string => (did.includes("#") ? did.slice(0, did.indexOf("#")) : did);

/** Does this issuer satisfy the query's `trusted_authorities`? */
export function issuerAccepted(query: DcqlCredentialQuery, issuer: string | null, type: string | null, ctx: MatchContext): boolean {
  const tas = query.trusted_authorities;
  if (tas === undefined) return true;
  if (issuer === null) return false;
  return tas.some((ta) => {
    if (ta.type === TA_ISSUER) return ta.values.some((v) => stripFragment(v) === stripFragment(issuer));
    if (ta.type === TA_TRUST_LIST) {
      if (type === null) return false;
      const hit = findListing(issuer, type, ctx.trustLists ?? [], ctx.nowSec);
      return hit !== null && hit.pinned && ta.values.includes(`${hit.publisher}#${hit.listId}`);
    }
    return false;
  });
}

/** Does this receipt answer this credential query? On a match, the claims by id. */
export function matchQuery(query: DcqlCredentialQuery, view: ReceiptView, ctx: MatchContext): MatchResult {
  if (query.format !== view.format) return { ok: false, why: `a ${query.format} is asked for` };
  const meta = query.meta ?? {};
  if (view.format === SD_JWT_FORMAT && meta.vct_values !== undefined && (view.type === null || !meta.vct_values.includes(view.type))) {
    return { ok: false, why: "not the type asked for" };
  }
  if (view.format === KASH_ARTIFACT_FORMAT) {
    if (meta.dst_values !== undefined && (view.type === null || !meta.dst_values.includes(view.type))) return { ok: false, why: "not the type asked for" };
    if (meta.attestation === "countersigned" && view.attestation !== "countersigned") return { ok: false, why: "not countersigned by an independent party" };
  }
  if (!issuerAccepted(query, view.issuer, view.type, ctx)) return { ok: false, why: "not from an issuer the rule accepts" };
  const claims = query.claims ?? [];
  const present = new Map<string, unknown>();
  const failed = new Set<string>();
  for (const c of claims) {
    const sel = selectClaim(view.claims, c.path);
    if (sel === null) {
      failed.add(c.id);
      continue;
    }
    if (c.values !== undefined && !valuesMatch(sel.value, c.values, c.path.includes(null))) {
      failed.add(c.id);
      continue;
    }
    present.set(c.id, sel.value);
  }
  const sets = query.claim_sets ?? [claims.map((c) => c.id)];
  const satisfied = sets.find((set) => set.every((id) => present.has(id)));
  if (satisfied === undefined) return { ok: false, why: failed.size > 0 ? `it lacks ${[...failed].join(", ")}` : "it lacks a claim the rule reads" };
  return { ok: true, values: Object.fromEntries(present) };
}

/* ── the rule's DCQL query ────────────────────────────────────────────── */

export const PREDICATE_SUFFIX = "_predicate";
export const OWN_WORD_SUFFIX = "_word";

/** The credential query a predicate answering this criterion must satisfy. */
export function predicateQuery(rule: RuleBody, ruleHash: string, c: Criterion): DcqlCredentialQuery | null {
  if (c.predicate === undefined) return null;
  return {
    id: `${c.id}${PREDICATE_SUFFIX}`,
    format: SD_JWT_FORMAT,
    meta: { vct_values: [PREDICATE_VCT] },
    trusted_authorities: [{ type: TA_ISSUER, values: c.predicate.issuers.map((i) => i.id) }],
    claims: [
      { id: "kind", path: ["predicate", "kind"], values: [c.id] },
      { id: "answer", path: ["predicate", "answer"], values: [true] },
      { id: "rule", path: ["predicate", "rule", "id"], values: [rule.id] },
      { id: "version", path: ["predicate", "rule", "version"], values: [String(rule.version)] },
      { id: "hash", path: ["predicate", "rule", "hash"], values: [ruleHash] },
      { id: "windowTo", path: ["predicate", "window", "to"] },
    ],
  };
}

/** The credential query the person's own word answers: a self-issued statement pinned to this rule and criterion. */
export function ownWordQuery(rule: RuleBody, c: Criterion): DcqlCredentialQuery | null {
  if (c.answer.by !== "own-word") return null;
  const fields: DcqlClaimsQuery[] = Object.keys(c.answer.fields).map((f) => ({ id: f, path: ["word", "fields", f] }));
  return {
    id: `${c.id}${OWN_WORD_SUFFIX}`,
    format: SD_JWT_FORMAT,
    meta: { vct_values: [OWN_WORD_VCT] },
    claims: [
      { id: "rule", path: ["word", "rule", "id"], values: [rule.id] },
      { id: "version", path: ["word", "rule", "version"], values: [rule.version] },
      { id: "criterion", path: ["word", "criterion"], values: [c.id] },
      ...fields,
    ],
  };
}

/** Every credential query a criterion may be answered by, and its `credential_sets` options. */
export function criterionQueries(rule: RuleBody, ruleHash: string, c: Criterion): { queries: DcqlCredentialQuery[]; options: string[][] } {
  if (c.answer.by === "own-word") {
    const q = ownWordQuery(rule, c)!;
    return { queries: [q], options: [[q.id]] };
  }
  const queries = [...c.answer.query];
  const options = (c.answer.options ?? c.answer.query.map((q) => [q.id])).map((o) => [...o]);
  const p = predicateQuery(rule, ruleHash, c);
  if (p !== null) {
    queries.push(p);
    options.push([p.id]);
  }
  return { queries, options };
}

/** The rule's whole `dcql_query`: every criterion's queries, and one required credential set per criterion. */
export function ruleToDcql(rule: RuleBody, ruleHash: string): DcqlQuery {
  const credentials: DcqlCredentialQuery[] = [];
  const credential_sets: { options: string[][]; required: boolean }[] = [];
  for (const c of rule.criteria) {
    const { queries, options } = criterionQueries(rule, ruleHash, c);
    credentials.push(...queries);
    credential_sets.push({ options, required: true });
  }
  return { credentials, credential_sets };
}

/** Which criterion a credential query id belongs to: `<criterion>` or `<criterion>_<suffix>`. */
export function criterionOfQueryId(rule: RuleBody, queryId: string): Criterion | null {
  let best: Criterion | null = null;
  for (const c of rule.criteria) {
    if ((queryId === c.id || queryId.startsWith(`${c.id}_`)) && (best === null || c.id.length > best.id.length)) best = c;
  }
  return best;
}

/* ── structural checks beyond the schema ──────────────────────────────── */

export interface DcqlProblem {
  readonly code: "DCQL_MALFORMED" | "DCQL_FORMAT_UNREADABLE" | "DCQL_UNBOUND";
  readonly path: string;
  readonly message: string;
}

const TL_VALUE = /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}#[A-Za-z0-9._:-]{1,128}$/;

export function checkCriterionQueries(c: Criterion, at: string): DcqlProblem[] {
  const out: DcqlProblem[] = [];
  if (c.answer.by !== "receipts") return out;
  const ids = new Set<string>();
  c.answer.query.forEach((q, i) => {
    const p = `${at}.answer.query[${i}]`;
    const add = (code: DcqlProblem["code"], message: string, sub = ""): void => {
      out.push({ code, path: `${p}${sub}`, message });
    };
    if (ids.has(q.id)) add("DCQL_MALFORMED", `the query id ${q.id} is used twice`, ".id");
    ids.add(q.id);
    if (q.id !== c.id && !q.id.startsWith(`${c.id}_`)) add("DCQL_MALFORMED", `a query id is the criterion's id, or starts with "${c.id}_"`, ".id");
    if (q.id.endsWith(PREDICATE_SUFFIX) || q.id.endsWith(OWN_WORD_SUFFIX)) add("DCQL_MALFORMED", "the _predicate and _word suffixes are the evaluator's", ".id");
    if (!READABLE_FORMATS.includes(q.format)) {
      add("DCQL_FORMAT_UNREADABLE", `${q.format} is not readable by this version — it reads ${READABLE_FORMATS.join(" and ")}`, ".format");
      return;
    }
    const meta = q.meta ?? {};
    if (q.format === SD_JWT_FORMAT) {
      if (meta.vct_values === undefined) add("DCQL_MALFORMED", "an SD-JWT query names its vct_values", ".meta");
      if (meta.dst_values !== undefined || meta.attestation !== undefined || meta.holder_path !== undefined || meta.holder !== undefined) {
        add("DCQL_MALFORMED", "dst_values, attestation, holder_path and holder belong to kash-artifact", ".meta");
      }
    } else {
      if (meta.dst_values === undefined) add("DCQL_MALFORMED", "a kash-artifact query names its dst_values", ".meta");
      if (meta.vct_values !== undefined) add("DCQL_MALFORMED", "vct_values belongs to dc+sd-jwt", ".meta");
      // KS-Q11: one way to name the holder, and the countersigner only of a countersigned record.
      if (meta.holder !== undefined && meta.holder_path !== undefined) add("DCQL_MALFORMED", "a query names its holder one way — holder or holder_path, not both", ".meta");
      if (meta.holder === "countersigner" && meta.attestation !== "countersigned") add("DCQL_MALFORMED", "holder: countersigner reads a countersigned record — say attestation: countersigned", ".meta");
    }
    if (q.require_cryptographic_holder_binding === false) {
      add("DCQL_UNBOUND", "a presentation is always bound to the viewer's nonce and audience — holder binding cannot be switched off", ".require_cryptographic_holder_binding");
    }
    for (const [j, ta] of (q.trusted_authorities ?? []).entries()) {
      if (ta.type !== TA_ISSUER && ta.type !== TA_TRUST_LIST) add("DCQL_MALFORMED", `trusted_authorities type ${ta.type} is not readable — use ${TA_ISSUER} or ${TA_TRUST_LIST}`, `.trusted_authorities[${j}]`);
      if (ta.type === TA_TRUST_LIST && !ta.values.every((v) => TL_VALUE.test(v))) add("DCQL_MALFORMED", `a ${TA_TRUST_LIST} value is <publisher DID>#<list id>`, `.trusted_authorities[${j}]`);
      if (ta.type === TA_ISSUER && !ta.values.every((v) => /^did:(kash|key):/.test(v))) add("DCQL_MALFORMED", `a ${TA_ISSUER} value is an issuer's DID`, `.trusted_authorities[${j}]`);
    }
    const claimIds = new Set<string>();
    for (const [j, cl] of (q.claims ?? []).entries()) {
      if (claimIds.has(cl.id)) add("DCQL_MALFORMED", `the claim id ${cl.id} is used twice`, `.claims[${j}]`);
      claimIds.add(cl.id);
    }
    for (const set of q.claim_sets ?? []) {
      for (const id of set) if (!claimIds.has(id)) add("DCQL_MALFORMED", `claim_sets names ${id}, which is not a claim here`, ".claim_sets");
    }
  });
  for (const opt of c.answer.options ?? []) {
    for (const id of opt) if (!ids.has(id)) out.push({ code: "DCQL_MALFORMED", path: `${at}.answer.options`, message: `options name ${id}, which is not one of this criterion's queries` });
  }
  return out;
}
