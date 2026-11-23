/**
 * The decision receipt — `kash.decision@1.1.0` (its shape: `./decision-schema`)
 * — what comes back to the person (ECOSYSTEM d84(a): every decision is itself
 * a receipt the person keeps, naming the rule's version and its reasons).
 *
 * It is signed by the deciding organisation as itself (d62(d)2) — the rule's
 * author at its own door, or the anchor at a door it runs under its adoption
 * (d85(d)) — as an SD-JWT VC to the person's key for that desk. Visible: the
 * rule, the adoption if any, the outcome, and whether it was automatic.
 * Selectively disclosable: the reasons, the rows,
 * the receipt hashes, who decided and when — so the next door can read
 * "yes, under rule X version 3" and nothing more.
 *
 * **Validation refuses** (P3, node rules 10–11):
 *   - an automatic `no` or `partial` — only a person refuses;
 *   - an automatic `yes` on a rule that binds, touches sensitive data, or keeps
 *     its yes for a person;
 *   - a refusal that names no unmet criterion, or whose decider did not confirm
 *     reading the receipts (the desk never pre-fills a refusal);
 *   - a reason not in the rule; a mismatched rule; anything but hashes in
 *     `reliedOn` — the closed schema has no room for a receipt's content.
 */

import { canonicalize } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64Url } from "@kashscript/attest/ed25519";
import { verifyEnvelope, type DsseEnvelope } from "@kashscript/attest/dsse";
import { checkMandate, MANDATE_DST, payloadSha256 } from "@kashscript/attest/attestation";
import { decodeJws, issueSdJwt, jwkOf, signJws, verifySdJwt, verifyJws, type JwsSigner } from "@kashscript/attest/sd-jwt";
import { makeKeyResolver, type KeyResolver } from "@kashscript/attest/holder";
import { resolveVerificationKey, type VerifyKey } from "@kashscript/attest/signing";
import { validate } from "@kashscript/lexicons/schema";
import type { DecisionOutcome } from "@kashscript/lexicons/extensions/door";
import type { ReadAdoption } from "./adoption";
import { KASH_DECISION_1_2_BODY_SCHEMA, type DecisionBody, type MandateCitation } from "./decision-schema";
import type { ReadRule } from "./rule";
import type { RouteResult } from "./route";
import { DAY, DECISION_VCT } from "./constants";

export type { DecisionOutcome } from "@kashscript/lexicons/extensions/door";
export {
  KASH_DECISION_BODY_SCHEMA,
  KASH_DECISION_ID,
  KASH_DECISION_LEXICON,
  KASH_DECISION_NSID,
  KASH_DECISION_1_2_BODY_SCHEMA,
  KASH_DECISION_1_2_ID,
  KASH_DECISION_1_2_LEXICON,
  MANDATE_ID_PATTERN,
  type DecidedBy,
  type DecisionBody,
  type MandateCitation,
} from "./decision-schema";

export type DecisionRefusalCode =
  | "SHAPE"
  | "RULE_MISMATCH"
  | "ADOPTION_MISMATCH"
  | "AUTOMATIC_REFUSAL"
  | "AUTOMATIC_YES_ON_BINDING"
  | "AUTOMATIC_YES_ON_SENSITIVE"
  | "AUTOMATIC_YES_NOT_STANDING"
  | "STANDING_MISMATCH"
  | "SEAT_SIGNATURE"
  | "REFUSAL_UNEXPLAINED"
  | "REASON_NOT_IN_RULE"
  | "NOT_YET_NAMES_NOTHING"
  | "ROWS"
  | "CONTEST_WINDOW"
  | "MANDATE_MISMATCH";

export interface DecisionValidation {
  readonly ok: boolean;
  readonly refusals: readonly { readonly code: DecisionRefusalCode; readonly message: string }[];
  /** What could not be checked without more in hand — never a pass by silence (1.2.0: a cited mandate not presented). */
  readonly notChecked?: readonly string[];
}

/** A decision's outcome in d91's words, as a mandate's scope names outcomes. */
const OUTCOME_IN_D91: Readonly<Record<DecisionOutcome, "accepted" | "not-yet" | "refused">> = { yes: "accepted", "not-yet": "not-yet", no: "refused", partial: "refused" };

/** A cited mandate, presented beside the decision: the deciding organisation's, to this seat, covering this decision (d91(a), (f)). */
async function mandateProblems(envelope: DsseEnvelope, d: DecisionBody, decider: string): Promise<string[]> {
  const db = d.decidedBy;
  if (db.kind !== "person" || db.mandate === undefined) return ["a mandate is cited only by a person's decision"];
  const out: string[] = [];
  if (envelope.payloadType !== MANDATE_DST) out.push(`it is not a ${MANDATE_DST} envelope`);
  let json: unknown = null;
  try {
    json = JSON.parse(new TextDecoder().decode(base64ToBytes(envelope.payload)));
  } catch {
    return [...out, "its payload is not JSON"];
  }
  const m = checkMandate(json);
  if (!m.ok || m.body === null) return [...out, `it does not check: ${m.faults.map((f) => f.code).join(", ")}`];
  const mb = m.body;
  if (mb.id !== db.mandate.id || (await payloadSha256(envelope)) !== db.mandate.hash) out.push("it is not the mandate the decision cites — its id or its hash differs");
  if (mb.principal !== decider) out.push(`its principal is not the deciding organisation, ${decider}`);
  const v = await verifyEnvelope(envelope, resolveVerificationKey);
  if (!v.verifiedKeyids.some((k) => k.split("#")[0] === decider)) out.push("the deciding organisation's signature on it does not check");
  if (mb.delegate.key !== db.seat) out.push("its delegate is not the deciding seat");
  if (mb.delegate.kind !== "seat") out.push("a decision is a person's: its mandate is a seat's (d91(f): a refusal carries a person-role signature, never a machine mandate)");
  if (mb.scope.kinds !== undefined && !mb.scope.kinds.includes("decision")) out.push("its scope does not cover decisions");
  if (mb.scope.outcomes !== undefined && !mb.scope.outcomes.includes(OUTCOME_IN_D91[d.outcome])) out.push(`its scope does not cover ${OUTCOME_IN_D91[d.outcome]}`);
  const at = Date.parse(d.decidedAt);
  if (!(at >= Date.parse(mb.dates.from) && at < Date.parse(mb.dates.until))) out.push("the decision's time is outside its dates");
  return out;
}

export const SEAT_JWS_TYP = "kash-decision-seat+jwt" as const;

/**
 * Every decision copy's `_sd` holds this many digests, real or decoy (RW-15; `specs/attestation/README.md` §3
 * G1): a refusal hides one claim more than a yes (`refusal`), and the array's length must not say which.
 */
export const DECISION_SD_SLOTS = 8;

/** The bytes a seat signs: the body, with the signature itself left out, in JCS. A cited mandate (1.2.0) is signed with it; without one the bytes are 1.1.0's. */
function seatPayload(body: DecisionBody): Record<string, unknown> {
  const db = body.decidedBy;
  const unsigned = { ...body, decidedBy: db.kind === "person" ? { kind: db.kind, role: db.role, seat: db.seat, ...(db.mandate !== undefined ? { mandate: db.mandate } : {}) } : db };
  return JSON.parse(canonicalize(unsigned)) as Record<string, unknown>;
}

async function seatSignatureOk(body: DecisionBody): Promise<boolean> {
  const db = body.decidedBy;
  if (db.kind !== "person") return false;
  const [h, empty, s] = db.signature.split(".");
  if (h === undefined || empty !== "" || s === undefined) return false;
  const p = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(seatPayload(body))));
  const jws = decodeJws(`${h}.${p}.${s}`);
  if (jws === null || jws.header.typ !== SEAT_JWS_TYP || jws.header.kid !== db.seat) return false;
  const key = resolveVerificationKey(db.seat);
  return key !== null && (await verifyJws(jws, key));
}

/**
 * Validate a decision against the rule it names — and, at an anchor's door, the
 * adoption it was made under: then the anchor is the one who decided, and an
 * automatic outcome is the anchor's standing decision (d85(d)).
 */
export async function validateDecision(body: unknown, rule: ReadRule, adoption?: ReadAdoption, opts: { readonly mandate?: DsseEnvelope } = {}): Promise<DecisionValidation> {
  const refusals: { code: DecisionRefusalCode; message: string }[] = [];
  const refuse = (code: DecisionRefusalCode, message: string): void => {
    refusals.push({ code, message });
  };
  // 1.2.0's shape: every 1.1.0 body is a 1.2.0 body, so both validate here.
  const shape = validate<DecisionBody>(KASH_DECISION_1_2_BODY_SCHEMA, body);
  if (!shape.ok) {
    for (const e of shape.errors) refuse("SHAPE", `$.${e.path.join(".")}: ${e.message}`);
    return { ok: false, refusals };
  }
  const d = shape.value;
  const r = rule.body;
  if (d.rule.id !== r.id || d.rule.version !== r.version || d.rule.hash !== rule.hash) refuse("RULE_MISMATCH", "a decision names the exact rule, version and hash it was made under (node rule 11)");
  if (adoption === undefined && d.adoption !== undefined) refuse("ADOPTION_MISMATCH", "the decision names an adoption — check it against that adoption");
  if (adoption !== undefined && (d.adoption?.id !== adoption.body.id || d.adoption.hash !== adoption.hash)) refuse("ADOPTION_MISMATCH", "a decision at an anchor's door names the adoption it was made under, exactly");

  const standing = `standing:${adoption?.body.anchor ?? r.author}`;
  if (d.automatic) {
    if (d.outcome === "no" || d.outcome === "partial") refuse("AUTOMATIC_REFUSAL", "only a named person refuses or grants in part — a rule may say yes or not yet, never no (P3)");
    if (d.outcome === "yes" && r.outcome.binds) refuse("AUTOMATIC_YES_ON_BINDING", "a yes that binds the person is a named person's decision (P3)");
    if (d.outcome === "yes" && r.outcome.sensitive) refuse("AUTOMATIC_YES_ON_SENSITIVE", "a yes touching sensitive data is a named person's decision (P3)");
    if (d.outcome === "yes" && !r.outcome.automaticYes) refuse("AUTOMATIC_YES_NOT_STANDING", "the rule's author keeps the yes for a person — there is no standing yes to sign");
    if (d.decidedBy.kind !== "standing" || d.decidedBy.standing !== standing) refuse("STANDING_MISMATCH", `an automatic decision is signed as ${standing}`);
  } else {
    if (d.decidedBy.kind !== "person") refuse("STANDING_MISMATCH", "a decision a person made names their role and their seat's signature");
    else if (!(await seatSignatureOk(d))) refuse("SEAT_SIGNATURE", "the deciding seat's signature does not check");
  }
  // d91(a): a signature that is not the principal's own cites its mandate. The principal here is the
  // deciding organisation, so a cited mandate's id is under that DID. With the mandate presented beside the
  // decision, it is checked whole: the organisation's, to this seat, a seat's, covering this outcome, in force.
  // Without it, only the id is checked, and the result says so.
  const notChecked: string[] = [];
  const mandate = d.decidedBy.kind === "person" ? d.decidedBy.mandate : undefined;
  const decider = adoption?.body.anchor ?? r.author;
  if (mandate !== undefined && !mandate.id.startsWith(`${decider}/mandate/`)) refuse("MANDATE_MISMATCH", `a cited mandate is one the deciding organisation granted — its id is under ${decider}`);
  else if (mandate !== undefined && opts.mandate === undefined) notChecked.push("the cited mandate — not presented, so its delegate, scope and dates were not read");
  else if (mandate !== undefined && opts.mandate !== undefined) for (const p of await mandateProblems(opts.mandate, d, decider)) refuse("MANDATE_MISMATCH", `the cited mandate: ${p}`);

  if (d.outcome === "no" || d.outcome === "partial") {
    if (d.refusal === undefined || d.refusal.unmet.length === 0) refuse("REFUSAL_UNEXPLAINED", "a refusal or a partial grant names the criterion that was not met");
    if (d.refusal !== undefined && !d.refusal.unmet.every((u) => r.criteria.some((c) => c.id === u))) refuse("ROWS", "a refusal names criteria of this rule");
  } else if (d.refusal !== undefined) {
    refuse("ROWS", "only a refusal or a partial grant carries refusal");
  }

  for (const code of d.reasons) {
    const reason = r.reasons.find((x) => x.code === code);
    if (reason === undefined) refuse("REASON_NOT_IN_RULE", `${code} is not a reason this rule may give (node rule 11)`);
    else if (reason.outcome !== d.outcome) refuse("REASON_NOT_IN_RULE", `${code} is a reason for ${reason.outcome}, not ${d.outcome}`);
  }
  const known = new Set(r.criteria.map((c) => c.id));
  if (![...d.rows.fired, ...d.rows.missing].every((id) => known.has(id))) refuse("ROWS", "rows name criteria of this rule");
  if (d.outcome === "not-yet" && d.rows.missing.length === 0) refuse("NOT_YET_NAMES_NOTHING", "a not yet says what is missing");

  const window = Date.parse(d.contestUntil) - Date.parse(d.decidedAt);
  if (!(window >= r.contest.windowDays * DAY * 1000)) refuse("CONTEST_WINDOW", `the contest window is at least the rule's ${r.contest.windowDays} days`);
  return { ok: refusals.length === 0, refusals, ...(notChecked.length > 0 ? { notChecked } : {}) };
}

const isoOf = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Draft the receipt for an automatic outcome. A route to a person has none — a person decides with `decidePerson`. */
export function decisionFromRoute(r: RouteResult, rule: ReadRule, opts: { readonly decidedAt: string }): DecisionBody {
  if (r.route === "to-a-person") throw new Error("a person decides this one — see decidePerson");
  const at = Date.parse(opts.decidedAt);
  return {
    rule: { id: rule.body.id, version: rule.body.version, hash: rule.hash },
    ...(r.adoption !== null ? { adoption: { id: r.adoption.id, hash: r.adoption.hash } } : {}),
    outcome: r.route === "automatic-yes" ? "yes" : "not-yet",
    reasons: [...r.reasons],
    rows: { fired: [...r.fired], missing: r.missing.map((m) => m.criterion) },
    reliedOn: [...r.reliedOn],
    decidedBy: { kind: "standing", standing: `standing:${r.adoption?.anchor ?? rule.body.author}` },
    automatic: true,
    decidedAt: isoOf(at),
    contestUntil: isoOf(at + rule.body.contest.windowDays * DAY * 1000),
    ...(rule.body.practice === true ? { practice: true } : {}),
  };
}

export interface PersonDecisionInput {
  readonly rule: ReadRule;
  /** The anchor's adoption, at a door it runs. */
  readonly adoption?: ReadAdoption;
  readonly outcome: DecisionOutcome;
  readonly reasons: readonly string[];
  readonly fired: readonly string[];
  readonly missing: readonly string[];
  readonly reliedOn: readonly string[];
  /** For `no` and `partial`: the unmet criteria the decider chose, and their confirmation that they read the receipts. */
  readonly refusal?: { readonly unmet: readonly string[]; readonly receiptsRead: true };
  /** The deciding seat: its role and its own key. The receipt names the role, never the person. */
  readonly seat: { readonly role: string; readonly did: string; readonly signer: JwsSigner; readonly mandate?: MandateCitation };
  readonly decidedAt: string;
}

/** A named person's decision, signed by their seat's key. It is then validated like any other. */
export async function decidePerson(input: PersonDecisionInput): Promise<DecisionBody> {
  const at = Date.parse(input.decidedAt);
  const draft: DecisionBody = {
    rule: { id: input.rule.body.id, version: input.rule.body.version, hash: input.rule.hash },
    ...(input.adoption !== undefined ? { adoption: { id: input.adoption.body.id, hash: input.adoption.hash } } : {}),
    outcome: input.outcome,
    reasons: [...input.reasons],
    rows: { fired: [...input.fired], missing: [...input.missing] },
    reliedOn: [...input.reliedOn],
    decidedBy: { kind: "person", role: input.seat.role, seat: input.seat.did, signature: "", ...(input.seat.mandate !== undefined ? { mandate: input.seat.mandate } : {}) },
    automatic: false,
    ...(input.refusal !== undefined ? { refusal: { unmet: [...input.refusal.unmet], receiptsRead: input.refusal.receiptsRead } } : {}),
    decidedAt: isoOf(at),
    contestUntil: isoOf(at + input.rule.body.contest.windowDays * DAY * 1000),
    ...(input.rule.body.practice === true ? { practice: true } : {}),
  };
  const compact = await signJws({ typ: SEAT_JWS_TYP, kid: input.seat.did }, seatPayload(draft), input.seat.signer);
  const [h, , s] = compact.split(".");
  return { ...draft, decidedBy: { kind: "person", role: input.seat.role, seat: input.seat.did, signature: `${h}..${s}`, ...(input.seat.mandate !== undefined ? { mandate: input.seat.mandate } : {}) } };
}

export class DecisionError extends Error {
  constructor(
    message: string,
    readonly refusals: DecisionValidation["refusals"] = [],
  ) {
    super(message);
    this.name = "DecisionError";
  }
}

/**
 * Issue a valid decision to the person, as the deciding organisation — the
 * rule's author, or the anchor whose adoption the door ran. One copy per call;
 * ask for as many as the person needs.
 */
export async function issueDecision(input: {
  readonly body: DecisionBody;
  readonly rule: ReadRule;
  readonly adoption?: ReadAdoption;
  readonly issuer: JwsSigner & { readonly did: string };
  /** The person's key for this desk. */
  readonly holderPublicKey: VerifyKey;
  readonly iatUnix: number;
  readonly expUnix: number;
  /** Default: `_sd` padded to {@link DECISION_SD_SLOTS} digests, so a yes and a no have one shape (RW-15). */
  readonly decoys?: number;
}): Promise<string> {
  const v = await validateDecision(input.body, input.rule, input.adoption);
  if (!v.ok) throw new DecisionError(`the decision does not validate: ${v.refusals.map((r) => r.code).join(", ")}`, v.refusals);
  const decider = input.adoption?.body.anchor ?? input.rule.body.author;
  if (input.issuer.did !== decider) {
    throw new DecisionError(input.adoption === undefined ? "a decision is signed by the organisation whose rule it applies" : "a decision under an adoption is signed by the anchor that adopted the rule");
  }
  const b = input.body;
  const sdProperties = {
    reasons: b.reasons,
    rows: b.rows,
    reliedOn: b.reliedOn,
    decidedBy: b.decidedBy,
    decidedAt: b.decidedAt,
    contestUntil: b.contestUntil,
    ...(b.refusal !== undefined ? { refusal: b.refusal } : {}),
  };
  return issueSdJwt({
    header: { kid: input.issuer.did },
    claims: {
      iss: input.issuer.did,
      iat: input.iatUnix - (input.iatUnix % DAY),
      exp: input.expUnix,
      vct: DECISION_VCT,
      cnf: { jwk: jwkOf(input.holderPublicKey) },
      decision: { rule: b.rule, ...(b.adoption !== undefined ? { adoption: b.adoption } : {}), outcome: b.outcome, automatic: b.automatic, ...(b.practice === true ? { practice: true } : {}) },
    },
    sdProperties,
    decoys: input.decoys ?? Math.max(1, DECISION_SD_SLOTS - Object.keys(sdProperties).length),
    signer: input.issuer,
  });
}

export interface ReadDecision {
  readonly ok: boolean;
  readonly issuer: string | null;
  readonly holder: string | null;
  /** Always the rule, the adoption if any, the outcome and `automatic`; the rest only as far as the holder disclosed it. */
  readonly decision: Partial<DecisionBody> & Pick<DecisionBody, "rule" | "outcome" | "automatic">;
  readonly disclosed: readonly string[];
  readonly notes: readonly string[];
}

/** Read a decision receipt — held or presented — offline. */
export async function readDecision(sdJwt: string, opts: { readonly nowSec: number; readonly resolveKey?: KeyResolver; readonly presentedTo?: { readonly audience: string; readonly nonce: string } }): Promise<ReadDecision | null> {
  const resolveKey = opts.resolveKey ?? makeKeyResolver(new Map(), new Map());
  // Presented: bound to this verifier's audience and nonce, fresh (attest 0.3.0, KS-Q4). Held: as held.
  const sd =
    opts.presentedTo !== undefined
      ? await verifySdJwt(sdJwt, { resolveKey, requireKeyBinding: true, nowSec: opts.nowSec, audience: opts.presentedTo.audience, nonce: opts.presentedTo.nonce })
      : await verifySdJwt(sdJwt, { resolveKey, requireKeyBinding: false, nowSec: opts.nowSec });
  const c = sd.claims;
  const head = c?.decision as Pick<DecisionBody, "rule" | "outcome" | "automatic"> | undefined;
  if (sd.vct !== DECISION_VCT || c === null || head === undefined) return null;
  const disclosed = sd.disclosed.map((d) => String(d.path[0]));
  const decision: Record<string, unknown> = { ...head };
  for (const k of disclosed) decision[k] = c[k];
  return { ok: sd.ok, issuer: sd.issuer, holder: sd.holder, decision: decision as ReadDecision["decision"], disclosed, notes: sd.notes };
}
