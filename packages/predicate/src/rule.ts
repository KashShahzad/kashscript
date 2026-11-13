/**
 * The rule — `kash.rule@1.2.0`, reading 1.1.0 and 1.0.0 (`@kashscript/lexicons/extensions/door`) — its
 * validation, its hash, its signed form and the OpenID4VP request a door sends.
 *
 * **Validation refuses a rule that breaks the floor** (ECOSYSTEM d84 (f) P4's
 * second rule; node rules 10 and 11; d43):
 *   - an ask for a refusal, or a condition met by showing nothing;
 *   - a sensitive category (GDPR art. 9), an ascribed identity, a score;
 *   - a criterion with no stated purpose; a person's identity anywhere;
 *   - no renewal or end date, too long a life, no other way to show it;
 *   - an automatic yes on an outcome that binds or touches sensitive data;
 *   - a condition outside the FEEL subset, or one that is not a yes or no.
 * Known proxies raise warnings the author answers in writing; until every one
 * is answered the rule does not validate, and the answers publish with it.
 *
 * **Since KS-Q1b (`kash.rule@1.1.0`, d85(b)–(c)):** a rule may carry its
 * address. An addressed rule names each criterion's subject, which the
 * vocabulary reads (rule 1 binds when the subject is a person, or an
 * organisation's people); it is complete when all seven givens are answered,
 * and an incomplete one publishes only as a draft. Parameters may carry the
 * bounds an adopter sets within. A rule without an address is a 1.0.0 rule:
 * it validates as it did, with a warning that it has none.
 */

import { canonicalize, canonicalizeBytes } from "@kashscript/identity-core";
import { sha256Hex } from "@kashscript/attest/chain";
import { signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "@kashscript/attest/dsse";
import { base64ToBytes } from "@kashscript/attest/ed25519";
import { resolveVerificationKey } from "@kashscript/attest/signing";
import { validate } from "@kashscript/lexicons/schema";
import { KASH_RULE_1_2_BODY_SCHEMA, type Criterion1_1 as Criterion, type RuleBody1_1 as RuleBody, type Subject } from "@kashscript/lexicons/extensions/door";
import { addressTexts, checkAddress, completeness, type Completeness } from "./address";
import { boundsProblems } from "./bounds";
import { checkCriterionQueries, criterionQueries, ruleToDcql, type DcqlQuery } from "./dcql";
import { conditionScope, evaluateCriterion } from "./criteria";
import { checkFeel, fromJson, type FeelValue, type InputType } from "./feel";
import { CONTACT_PATTERNS, proxyTerms, refusedTerms, type RefusalCategory, type WarningCategory } from "./vocabulary";
import { DAY, DECISION_VCT, MAX_LIFE_DAYS, MAX_RENEW_DAYS, RESERVED_NAMES, RULE_PAYLOAD_TYPE, TA_ISSUER, TA_TRUST_LIST } from "./constants";
import { adoptionInForce, readAdoption, type ReadAdoption } from "./adoption";

/** The rule as `kash.rule@1.2.0` reads it — a 1.0.0 body is one with no address; a 1.1.0 body one whose queries name no `holder`. */
export type { RuleBody1_1 as RuleBody, Criterion1_1 as Criterion, RuleAddress, Subject } from "@kashscript/lexicons/extensions/door";

export type RefusalCode =
  | RefusalCategory
  | "SHAPE"
  | "PROVES_ABSENCE"
  | "NO_PURPOSE"
  | "PERSON_IDENTITY"
  | "AUTHOR_MISMATCH"
  | "DATES"
  | "NO_ANOTHER_WAY"
  | "AUTOMATIC_YES_ON_BINDING"
  | "AUTOMATIC_YES_ON_SENSITIVE"
  | "REASONS"
  | "CRITERIA"
  | "CONDITION"
  | "FEEL_OUTSIDE_SUBSET"
  | "FEEL_INVALID"
  | "DISCLOSURE_GAP"
  | "COUNTS_COPIES"
  | "SEALING"
  | "UNANSWERED_WARNING"
  | "DCQL_MALFORMED"
  | "DCQL_FORMAT_UNREADABLE"
  | "DCQL_UNBOUND"
  | "ADDRESS"
  | "INCOMPLETE_NOT_DRAFT"
  | "SUBJECT"
  | "BOUNDS";

/** `NO_ADDRESS` and `INCOMPLETE` say what a rule lacks; they are answered by completing it, never in writing. */
export type WarningCode = WarningCategory | "SINGLE_ISSUER" | "NO_ADDRESS" | "INCOMPLETE";

export interface Refusal {
  readonly code: RefusalCode;
  readonly path: string;
  readonly message: string;
}

export interface Warning {
  readonly code: WarningCode;
  readonly criterion: string;
  readonly path: string;
  readonly message: string;
  /** The author's written answer, when the rule carries one. */
  readonly answer: string | null;
  /** A proxy is answered in writing; a missing address or given is answered by completing the rule. */
  readonly answerable: boolean;
}

export interface RuleValidation {
  readonly ok: boolean;
  readonly refusals: readonly Refusal[];
  readonly warnings: readonly Warning[];
  readonly completeness: Completeness;
}

const MIN_TEXT = 12;

function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (typeof v === "object" && v !== null) for (const x of Object.values(v)) strings(x, out);
  return out;
}

/**
 * The parts of a criterion the floor's vocabulary reads, each with where it is.
 * `words` marks plain-language text (a label, a statement): refusals read it —
 * a "caste certificate" label asks for caste — but proxy warnings read only
 * what the criterion actually reads, so "a face-to-face interview" asks nothing.
 */
function machineParts(c: Criterion, at: string): { text: string; path: string; words?: true }[] {
  const parts: { text: string; path: string; words?: true }[] = [{ text: c.id, path: `${at}.id` }, { text: c.label, path: `${at}.label`, words: true }];
  if (c.answer.by === "own-word") {
    parts.push({ text: c.answer.statement, path: `${at}.answer.statement`, words: true });
    for (const f of Object.keys(c.answer.fields)) parts.push({ text: f, path: `${at}.answer.fields.${f}` });
  } else {
    c.answer.query.forEach((q, i) => {
      const p = `${at}.answer.query[${i}]`;
      for (const v of [...(q.meta?.vct_values ?? []), ...(q.meta?.dst_values ?? [])]) parts.push({ text: v.replace(/^https?:\/\/[^/]+/, ""), path: `${p}.meta` });
      (q.claims ?? []).forEach((cl, j) => {
        parts.push({ text: cl.id, path: `${p}.claims[${j}].id` });
        parts.push({ text: cl.path.filter((x): x is string => typeof x === "string").join(" "), path: `${p}.claims[${j}].path` });
        for (const v of cl.values ?? []) if (typeof v === "string") parts.push({ text: v, path: `${p}.claims[${j}].values` });
      });
    });
  }
  for (const t of Object.keys(c.condition?.types ?? {})) parts.push({ text: t, path: `${at}.condition.types.${t}` });
  return parts;
}

const PLAIN: Readonly<Record<RefusalCategory, string>> = {
  SENSITIVE_CATEGORY: "asks for a sensitive category (GDPR art. 9) — a rule asks only for what its purpose needs (P4)",
  ASCRIBED_IDENTITY: "asks for an ascribed identity — what someone was born into, never what they did (d85(b) rule 1, P4, d27, d36)",
  ASKS_FOR_A_REFUSAL: "asks for a refusal — no rule may (node rule 10)",
  READS_A_SCORE: "reads a score, a rank or a rating of a person — nothing here scores people (d85(b) rule 3, d43)",
};

const PROXY_PLAIN: Readonly<Record<WarningCode, string>> = {
  NO_ADDRESS: "has no address — a 1.0.0 rule; give it a sector, anchor family, authority, journey and the seven givens (d85(c))",
  INCOMPLETE: "does not answer every given yet — it publishes only as a draft until it does (d85(b) rule 7)",
  SINGLE_ISSUER: "accepts one issuer only — a single school, employer or neighbourhood body can stand in for who someone is; say why no other issuer can show the same thing",
  RESIDENCE_PROXY: "reads where someone lives — a known proxy for ethnicity, sect and class",
  NAME_PROXY: "reads a name — names carry caste, sect, gender and origin",
  LANGUAGE_ORIGIN_PROXY: "reads a first language — a known proxy for ethnicity and origin",
  AGE_PROXY: "reads a birth date — ask for an age predicate (age over N) if age is what the purpose needs",
  FAMILY_STATUS_PROXY: "reads family status — a known proxy for gender",
  APPEARANCE_PROXY: "reads a photo or an appearance — it shows ethnicity, gender and age",
  GRADE: "reads a grade — say why the purpose needs a grade and not the completion itself",
};

const iso = (s: string): number => Date.parse(s) / 1000;

/** Validate a rule body. Pure; reads no clock. */
export function validateRule(body: unknown): RuleValidation {
  const refusals: Refusal[] = [];
  const warnings: Omit<Warning, "answer">[] = [];
  const refuse = (code: RefusalCode, path: string, message: string): void => {
    refusals.push({ code, path, message });
  };

  const shape = validate<RuleBody>(KASH_RULE_1_2_BODY_SCHEMA, body);
  if (!shape.ok) {
    for (const e of shape.errors) refuse("SHAPE", `$.${e.path.join(".")}`, e.message);
    return { ok: false, refusals, warnings: [], completeness: { addressed: false, complete: false, missing: [] } };
  }
  const rule = shape.value;

  if (!rule.id.startsWith(`${rule.author}/rule/`)) refuse("AUTHOR_MISMATCH", "$.id", "a rule's id is its author's DID, then /rule/, then its slug");

  // d85(c): every rule has an address. One without is a 1.0.0 rule, which keeps validating.
  const complete = completeness(rule);
  if (rule.address === undefined) {
    warnings.push({ code: "NO_ADDRESS", criterion: "", path: "$.address", message: PROXY_PLAIN.NO_ADDRESS, answerable: false });
  } else {
    for (const p of checkAddress(rule.address)) refuse("ADDRESS", p.path, p.message);
    if (!complete.complete) {
      const message = `${PROXY_PLAIN.INCOMPLETE}: ${complete.missing.join(", ")}`;
      if (rule.draft === true) warnings.push({ code: "INCOMPLETE", criterion: "", path: "$.address.givens", message, answerable: false });
      else refuse("INCOMPLETE_NOT_DRAFT", "$.address.givens", `${message} — mark it draft: true, or answer every given`);
    }
  }

  // d43: it renews and ends.
  const pub = iso(rule.dates.published);
  const renew = iso(rule.dates.renewBy);
  const end = iso(rule.dates.endsAt);
  if (!(pub < renew)) refuse("DATES", "$.dates.renewBy", "the renewal date comes after publication");
  if (!(renew <= end)) refuse("DATES", "$.dates.renewBy", "a rule is renewed before it ends");
  if (renew - pub > MAX_RENEW_DAYS * DAY) refuse("DATES", "$.dates.renewBy", `a rule is reviewed within ${MAX_RENEW_DAYS} days of publication`);
  if (end - pub > MAX_LIFE_DAYS * DAY) refuse("DATES", "$.dates.endsAt", "a rule ends within three years — a standard that never expires is a cage (d43)");

  // P3: an automatic yes only grants.
  if (rule.outcome.automaticYes && rule.outcome.binds) refuse("AUTOMATIC_YES_ON_BINDING", "$.outcome", "an outcome that binds the person (credit, a contract, a debt) is a named person's decision — never automatic (P3)");
  if (rule.outcome.automaticYes && rule.outcome.sensitive) refuse("AUTOMATIC_YES_ON_SENSITIVE", "$.outcome", "an outcome touching sensitive data is a named person's decision — never automatic (P3)");

  // Node rule 11: decisions carry reasons from the rule's own list.
  const codes = new Set<string>();
  rule.reasons.forEach((r, i) => {
    if (codes.has(r.code)) refuse("REASONS", `$.reasons[${i}]`, `the reason ${r.code} is listed twice`);
    codes.add(r.code);
  });
  if (!rule.reasons.some((r) => r.outcome === "yes")) refuse("REASONS", "$.reasons", "a rule gives at least one reason for a yes");
  if (!rule.reasons.some((r) => r.outcome === "not-yet")) refuse("REASONS", "$.reasons", "a rule gives at least one reason for a not yet — what is missing, and who may supply it");

  // P4's first rule.
  if (rule.anotherWay.trim().length < MIN_TEXT) refuse("NO_ANOTHER_WAY", "$.anotherWay", "a door keeps another way to show the same thing (P4) — say what it is");

  // Thresholds: in clear on a public rule, sealed on a private one.
  for (const [name, p] of Object.entries(rule.parameters ?? {})) {
    const at = `$.parameters.${name}`;
    if (RESERVED_NAMES.includes(name)) refuse("SEALING", at, `${name} is a name the evaluator binds`);
    if (rule.visibility === "public") {
      if (p.sealed !== undefined || p.value === undefined) refuse("SEALING", at, "a public rule's thresholds are in clear");
      else if (fromJson(p.value, p.type as InputType) === null) refuse("SEALING", at, `the value does not read as a ${p.type}`);
    } else if (p.sealed === undefined || p.value !== undefined) {
      refuse("SEALING", at, "a private rule seals its thresholds and publishes only their commitments — its queries stay public");
    }
    // d85(b) rule 8: local parameters within stated bounds.
    if (p.bounds !== undefined) {
      if (rule.visibility === "private" || p.sealed !== undefined) refuse("SEALING", `${at}.bounds`, "a sealed threshold cannot be adopted — an adoption's values are public");
      else for (const problem of boundsProblems(p)) refuse("BOUNDS", `${at}.bounds`, problem);
    }
  }

  // Criteria.
  const ids = new Set<string>();
  const knownDids = new Set<string>([rule.author]);
  rule.criteria.forEach((c, i) => {
    const at = `$.criteria[${i}]`;
    if (ids.has(c.id)) refuse("CRITERIA", `${at}.id`, `the criterion ${c.id} is listed twice`);
    ids.add(c.id);
    if (c.purpose.trim().length < MIN_TEXT || c.purpose.trim().toLowerCase() === c.label.trim().toLowerCase()) {
      refuse("NO_PURPOSE", `${at}.purpose`, "every criterion says, in plain words, why the door needs it (P4) — and says more than its label");
    }
    for (const p of checkCriterionQueries(c, at)) refuse(p.code, p.path, p.message);
    for (const iss of c.predicate?.issuers ?? []) knownDids.add(iss.id);
    if (c.answer.by === "receipts") {
      for (const q of c.answer.query) for (const ta of q.trusted_authorities ?? []) for (const v of ta.values) knownDids.add(v.split("#")[0]!);
    }

    // The vocabulary, for what the criterion is about. A 1.0.0 criterion is about a person, the strictest reading.
    if (rule.address !== undefined && c.subject === undefined) refuse("SUBJECT", `${at}.subject`, "an addressed rule names each criterion's subject: person, organisation, product or place");
    const subject: Subject = c.subject ?? "person";
    for (const part of machineParts(c, at)) {
      for (const h of refusedTerms(part.text, subject)) refuse(h.category, part.path, `${PLAIN[h.category]}: "${h.term}"${subject === "person" ? "" : ` (subject: ${subject})`}`);
      if (part.words === true) continue;
      for (const h of proxyTerms(part.text, subject)) warnings.push({ code: h.category, criterion: c.id, path: part.path, message: `${PROXY_PLAIN[h.category]} ("${h.term}")`, answerable: true });
    }

    if (c.answer.by === "receipts") {
      // Unlinkable copies would count twice: a query for several SD-JWT receipts reads each one's record id.
      c.answer.query.forEach((q, j) => {
        if (q.format !== "dc+sd-jwt" || q.multiple !== true) return;
        const rec = (q.claims ?? []).find((cl) => cl.id === "record");
        if (rec === undefined) {
          refuse("COUNTS_COPIES", `${at}.answer.query[${j}].claims`, "a query for several SD-JWT receipts reads each one's record id (claim id \"record\") — one record shown in several unlinkable copies would otherwise count several times; an issuer's predicate avoids showing it");
        } else {
          for (const set of q.claim_sets ?? []) if (!set.includes("record")) refuse("DISCLOSURE_GAP", `${at}.answer.query[${j}].claim_sets`, "every claim_sets option includes record");
        }
      });
      // Node rule 10: a decision receipt is asked for only as a yes.
      c.answer.query.forEach((q, j) => {
        if (!(q.meta?.vct_values ?? []).includes(DECISION_VCT)) return;
        const outcome = (q.claims ?? []).find((cl) => cl.path.length === 2 && cl.path[0] === "decision" && cl.path[1] === "outcome");
        if (outcome === undefined || outcome.values === undefined || outcome.values.length !== 1 || outcome.values[0] !== "yes") {
          refuse("ASKS_FOR_A_REFUSAL", `${at}.answer.query[${j}]`, `${PLAIN.ASKS_FOR_A_REFUSAL}: a decision receipt is read only as a yes — its claim ["decision","outcome"] takes values ["yes"]`);
        }
      });
      // One issuer is a proxy risk.
      const issuers = new Set<string>();
      let lists = false;
      let open = false;
      for (const q of c.answer.query) {
        if (q.trusted_authorities === undefined) open = true;
        for (const ta of q.trusted_authorities ?? []) {
          if (ta.type === TA_TRUST_LIST) lists = true;
          if (ta.type === TA_ISSUER) for (const v of ta.values) issuers.add(v);
        }
      }
      for (const iss of c.predicate?.issuers ?? []) issuers.add(iss.id);
      if (!open && !lists && issuers.size === 1) warnings.push({ code: "SINGLE_ISSUER", criterion: c.id, path: `${at}.answer.query`, message: PROXY_PLAIN.SINGLE_ISSUER, answerable: true });
    }

    // The condition: in the subset, bound, a yes or a no, and never met by nothing.
    if (c.answer.by === "receipts" && c.condition === undefined) refuse("CONDITION", `${at}.condition`, "a criterion answered by receipts says, in FEEL, what about them counts");
    if (c.condition !== undefined) checkCondition(rule, c, at, refuse);
  });

  // A person's identity has no place in a rule.
  const free: { text: string; path: string }[] = [
    { text: rule.title, path: "$.title" },
    { text: rule.purpose, path: "$.purpose" },
    { text: rule.decider.role, path: "$.decider.role" },
    { text: rule.outcome.grants, path: "$.outcome.grants" },
    ...rule.reasons.map((r, i) => ({ text: r.text, path: `$.reasons[${i}].text` })),
    ...rule.criteria.flatMap((c, i) => [
      { text: c.label, path: `$.criteria[${i}].label` },
      { text: c.purpose, path: `$.criteria[${i}].purpose` },
      ...(c.answer.by === "own-word" ? [{ text: c.answer.statement, path: `$.criteria[${i}].answer.statement` }] : []),
    ]),
    ...(rule.answers ?? []).map((a, i) => ({ text: a.text, path: `$.answers[${i}].text` })),
    ...(rule.address !== undefined ? addressTexts(rule.address) : []),
  ];
  for (const { text, path } of free) {
    for (const { what, find } of CONTACT_PATTERNS) {
      const m = find(text);
      if (m === null) continue;
      if (what === "a DID" && knownDids.has(m.split("#")[0]!)) continue;
      refuse("PERSON_IDENTITY", path, `carries ${what} — a rule names roles and organisations, never a person (contact details belong in contest.how, as a role address)`);
    }
  }
  // A reason speaks of what the rule's criteria are about: refused if its words would be, for any of their subjects.
  const subjects = [...new Set(rule.criteria.map((c) => c.subject ?? "person"))];
  for (const [i, r] of rule.reasons.entries()) {
    const seen = new Set<string>();
    for (const h of subjects.flatMap((s) => refusedTerms(r.text, s))) {
      if (h.category === "ASKS_FOR_A_REFUSAL" || seen.has(`${h.category}:${h.term}`)) continue;
      seen.add(`${h.category}:${h.term}`);
      refuse(h.category, `$.reasons[${i}].text`, `a reason ${PLAIN[h.category].replace(/^asks for/, "names")}: "${h.term}"`);
    }
  }

  // Every proxy warning answered in writing. A missing address or given is answered by completing the rule.
  const answered = (w: Omit<Warning, "answer">): string | null => {
    if (!w.answerable) return null;
    const a = (rule.answers ?? []).find((x) => x.criterion === w.criterion && x.code === w.code);
    return a !== undefined && a.text.trim().length >= MIN_TEXT ? a.text : null;
  };
  const out = warnings
    .filter((w, i) => warnings.findIndex((x) => x.code === w.code && x.criterion === w.criterion) === i)
    .map((w) => ({ ...w, answer: answered(w) }));
  for (const w of out) {
    if (w.answerable && w.answer === null) refuse("UNANSWERED_WARNING", w.path, `${w.message} — answer it in writing in answers[] (criterion ${w.criterion}, code ${w.code})`);
  }
  return { ok: refusals.length === 0, refusals, warnings: out, completeness: complete };
}

function checkCondition(rule: RuleBody, c: Criterion, at: string, refuse: (code: RefusalCode, path: string, message: string) => void): void {
  const cond = c.condition!;
  const p = `${at}.condition`;
  for (const name of Object.keys(cond.types)) if (RESERVED_NAMES.includes(name)) refuse("CONDITION", `${p}.types.${name}`, `${name} is a name the evaluator binds`);
  // Inside a filter a receipt's claim would hide a threshold of the same name, so the two never share one.
  const params = Object.keys(rule.parameters ?? {});
  const read = c.answer.by === "own-word" ? Object.keys(c.answer.fields) : Object.keys(cond.types);
  for (const name of read) if (params.includes(name)) refuse("CONDITION", `${p}.types.${name}`, `${name} is both a claim and one of the rule's thresholds — rename one`);
  if (c.answer.by === "own-word" && Object.keys(cond.types).length > 0) refuse("CONDITION", `${p}.types`, "an own-word condition reads its fields, typed in answer.fields");
  const r = checkFeel(cond.feel, conditionScope(rule, c));
  for (const prob of r.problems) refuse(prob.outsideSubset ? "FEEL_OUTSIDE_SUBSET" : "FEEL_INVALID", `${p}.feel`, prob.message);
  if (!r.ok) return;

  if (c.answer.by === "receipts") {
    // Every claim the condition reads is one each query returns, in every disclosure option.
    for (const [j, q] of c.answer.query.entries()) {
      const claimIds = new Set((q.claims ?? []).map((cl) => cl.id));
      for (const t of Object.keys(cond.types)) {
        if (!claimIds.has(t)) refuse("CONDITION", `${at}.answer.query[${j}].claims`, `the condition types ${t}, which this query does not return`);
      }
      for (const f of r.fields) {
        if (!Object.prototype.hasOwnProperty.call(cond.types, f) && f !== "issuer") continue;
        for (const set of q.claim_sets ?? []) {
          if (f !== "issuer" && !set.includes(f)) refuse("DISCLOSURE_GAP", `${at}.answer.query[${j}].claim_sets`, `the condition reads ${f}, so every claim_sets option includes it`);
        }
      }
    }
    // Node rule 10: absence cannot be proven offline, and a condition met by showing nothing asks for exactly that.
    const empty = evaluateCriterion(rule, c, { receipts: [], predicates: [], word: null }, {
      asOf: rule.dates.published,
      thresholds: rule.visibility === "public" ? { kind: "values", values: Object.fromEntries(Object.entries(rule.parameters ?? {}).map(([n, prm]) => [n, fromJson(prm.value, prm.type as InputType)])) } : { kind: "sealed" },
    });
    if (empty.met === true) refuse("PROVES_ABSENCE", `${p}.feel`, "the condition holds when no receipt is shown — it asks someone to prove a thing did not happen, which only hiding a record can (node rule 10)");
  }
}

/* ── hash, signing, reading ───────────────────────────────────────────── */

/** SHA-256 hex over JCS of the body — the exact bytes the author signs. */
export function ruleHash(body: RuleBody): Promise<string> {
  return sha256Hex(canonicalizeBytes(body));
}

export class RuleError extends Error {
  constructor(
    readonly code: "RULE_INVALID" | "RULE_SIGNER" | "RULE_SIGNATURE" | "RULE_REQUEST",
    message: string,
    readonly refusals: readonly Refusal[] = [],
  ) {
    super(message);
    this.name = "RuleError";
  }
}

/** Sign a valid rule as its author (d62(d)2: an organisation signs as itself). */
export async function signRule(body: RuleBody, signer: DsseSigner): Promise<DsseEnvelope> {
  const v = validateRule(body);
  if (!v.ok) throw new RuleError("RULE_INVALID", `the rule does not validate: ${v.refusals.map((r) => r.code).join(", ")}`, v.refusals);
  if (signer.keyid.split("#")[0] !== body.author) throw new RuleError("RULE_SIGNER", "a rule is signed by its author's own key");
  return signEnvelope(body, RULE_PAYLOAD_TYPE, signer, { canonical: true });
}

export interface ReadRule {
  readonly body: RuleBody;
  readonly hash: string;
  readonly envelope: DsseEnvelope;
  readonly validation: RuleValidation;
}

/** Read a signed rule offline: its author's signature (the key is in its DID), its shape, its floor. Throws `RuleError`. */
export async function readRule(envelope: DsseEnvelope): Promise<ReadRule> {
  if (envelope?.payloadType !== RULE_PAYLOAD_TYPE) throw new RuleError("RULE_SIGNATURE", "not a door rule");
  let result;
  try {
    result = await verifyEnvelope(envelope, (keyid) => resolveVerificationKey(keyid));
  } catch {
    throw new RuleError("RULE_SIGNATURE", "the envelope does not read");
  }
  if (result.payloadJson === undefined) throw new RuleError("RULE_SIGNATURE", "the envelope does not read");
  const body = result.payloadJson as RuleBody;
  const author = typeof body?.author === "string" ? body.author : null;
  if (!result.ok || author === null || !result.verifiedKeyids.some((k) => k.split("#")[0] === author)) {
    throw new RuleError("RULE_SIGNATURE", "the rule is not signed by its author");
  }
  const bytes = base64ToBytes(envelope.payload);
  if (canonicalize(body) !== new TextDecoder().decode(bytes)) throw new RuleError("RULE_SIGNATURE", "the signed bytes are not the rule's canonical form");
  const validation = validateRule(body);
  if (!validation.ok) throw new RuleError("RULE_INVALID", `the rule does not validate: ${validation.refusals.map((r) => r.code).join(", ")}`, validation.refusals);
  return { body, hash: await sha256Hex(bytes), envelope, validation };
}

/** Is the rule in force at `nowSec`? Between publication and its end; past its renewal date it still holds, and says so. */
export function ruleLive(body: RuleBody, nowSec: number): { readonly live: boolean; readonly renewalDue: boolean } {
  return { live: iso(body.dates.published) <= nowSec && nowSec < iso(body.dates.endsAt), renewalDue: nowSec >= iso(body.dates.renewBy) };
}

/* ── private rules: sealed thresholds ─────────────────────────────────── */

export type Openings = Readonly<Record<string, { readonly value: string | number | boolean; readonly salt: string }>>;

/** The commitment a private rule publishes for one threshold. */
export function sealParameter(name: string, value: string | number | boolean, salt: string): Promise<string> {
  return sha256Hex(canonicalizeBytes({ name, value, salt }));
}

/** The desk's openings, checked against the rule's commitments. Null when any is missing or does not match. */
export async function openThresholds(body: RuleBody, openings: Openings): Promise<Record<string, FeelValue> | null> {
  const values: Record<string, FeelValue> = {};
  for (const [name, p] of Object.entries(body.parameters ?? {})) {
    if (p.sealed === undefined) {
      values[name] = fromJson(p.value, p.type as InputType);
      continue;
    }
    const o = openings[name];
    if (o === undefined || (await sealParameter(name, o.value, o.salt)) !== p.sealed) return null;
    const v = fromJson(o.value, p.type as InputType);
    if (v === null) return null;
    values[name] = v;
  }
  return values;
}

/* ── the request a door sends (OpenID4VP 1.0, direct_post) ────────────── */

export interface RuleRequest {
  readonly response_type: "vp_token";
  readonly response_mode: "direct_post";
  readonly client_id: string;
  readonly response_uri: string;
  readonly nonce: string;
  readonly state?: string;
  readonly dcql_query: DcqlQuery;
  /** The rule by value, so the person's side checks the rule itself before it shows anything. */
  readonly kash_rule: DsseEnvelope;
  readonly kash_rule_sha256: string;
  /** The anchor's adoption, when the door decides under one — its local values are what the person is checked against. */
  readonly kash_adoption?: DsseEnvelope;
  readonly kash_adoption_sha256?: string;
}

/**
 * The request a door sends. Under an adoption the door is the anchor: the
 * request comes from it, and every presentation binds its audience.
 */
export function ruleRequest(rule: ReadRule, opts: { readonly nonce: string; readonly responseUri: string; readonly state?: string; readonly adoption?: ReadAdoption }): RuleRequest {
  if (rule.body.draft === true) throw new RuleError("RULE_REQUEST", "a draft is published for reading and comment — no door decides under it");
  if (!opts.responseUri.startsWith("https://")) throw new RuleError("RULE_REQUEST", "a response goes to an https address");
  if (opts.nonce.length < 16) throw new RuleError("RULE_REQUEST", "a nonce is at least 16 characters of fresh randomness");
  const a = opts.adoption;
  if (a !== undefined && (a.body.rule.id !== rule.body.id || a.body.rule.version !== rule.body.version || a.body.rule.hash !== rule.hash)) {
    throw new RuleError("RULE_REQUEST", "the adoption is of another rule or version");
  }
  return {
    response_type: "vp_token",
    response_mode: "direct_post",
    client_id: a?.body.anchor ?? rule.body.author,
    response_uri: opts.responseUri,
    nonce: opts.nonce,
    ...(opts.state !== undefined ? { state: opts.state } : {}),
    dcql_query: ruleToDcql(rule.body, rule.hash),
    kash_rule: rule.envelope,
    kash_rule_sha256: rule.hash,
    ...(a !== undefined ? { kash_adoption: a.envelope, kash_adoption_sha256: a.hash } : {}),
  };
}

/**
 * Read a door's request on the person's side: the rule verifies and validates,
 * its digest matches, the request comes from its author — or from the anchor
 * whose adoption it carries, which verifies too — and the DCQL query is
 * exactly the rule's own, never more. A draft is never put to anyone. Throws
 * `RuleError`, or `AdoptionError` for an adoption that does not hold.
 */
export async function openRuleRequest(input: unknown, nowSec: number): Promise<{ readonly request: RuleRequest; readonly rule: ReadRule; readonly adoption?: ReadAdoption }> {
  const req = (typeof input === "string" ? JSON.parse(input) : input) as Partial<RuleRequest>;
  if (
    req === null ||
    typeof req !== "object" ||
    req.response_type !== "vp_token" ||
    req.response_mode !== "direct_post" ||
    typeof req.client_id !== "string" ||
    typeof req.response_uri !== "string" ||
    !req.response_uri.startsWith("https://") ||
    typeof req.nonce !== "string" ||
    req.nonce.length < 16 ||
    typeof req.kash_rule_sha256 !== "string" ||
    typeof req.kash_rule !== "object"
  ) {
    throw new RuleError("RULE_REQUEST", "not an OpenID4VP direct_post request carrying a rule");
  }
  const rule = await readRule(req.kash_rule as DsseEnvelope);
  if (rule.hash !== req.kash_rule_sha256) throw new RuleError("RULE_REQUEST", "the rule's digest does not match");
  if (rule.body.draft === true) throw new RuleError("RULE_REQUEST", "the rule is a draft — no door decides under it");
  let adoption: ReadAdoption | undefined;
  if (req.kash_adoption !== undefined) {
    adoption = await readAdoption(req.kash_adoption, rule);
    if (adoption.hash !== req.kash_adoption_sha256) throw new RuleError("RULE_REQUEST", "the adoption's digest does not match");
    if (req.client_id !== adoption.body.anchor) throw new RuleError("RULE_REQUEST", "the request is not from the anchor that adopted the rule");
    if (!adoptionInForce(adoption, nowSec)) throw new RuleError("RULE_REQUEST", "the adoption is not in force");
  } else if (req.client_id !== rule.body.author) {
    throw new RuleError("RULE_REQUEST", "the request is not from the rule's author");
  }
  if (canonicalize(req.dcql_query) !== canonicalize(ruleToDcql(rule.body, rule.hash))) throw new RuleError("RULE_REQUEST", "the query asks for more than the rule says");
  if (!ruleLive(rule.body, nowSec).live) throw new RuleError("RULE_REQUEST", "the rule is not in force");
  return { request: req as RuleRequest, rule, ...(adoption !== undefined ? { adoption } : {}) };
}

export { criterionQueries };
