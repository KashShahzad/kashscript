/**
 * The ask — a published request for evidence (ECOSYSTEM d42 §5; specs/presentation.md §1).
 *
 * An ask is answered with a yes, never with the data. `validateAsk` is the
 * reference validator for `specs/schemas/ask.schema.json` and enforces the
 * eight rules plus the forbidden needs; the constants below are the ones that
 * schema publishes, and a test keeps the two in step.
 *
 *   1 predicates only · 2 it says why · 3 a no is answerable · 4 it expires ·
 *   5 it is public · 6 no joining by default · 7 an excessive ask is
 *   recordable by whoever refused it · 8 it may not require the improvement item
 *
 * An ask never asks for origin, ethnicity, sect, caste or ancestry (d36).
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import { sha256Hex } from "../chain";
import { PREDICATE_VCT } from "./constants";

export const ASK_FORMAT = "kashscript-ask/1" as const;
/** Rule 4: an ask lives at most this long after it is published. */
export const ASK_MAX_LIFETIME_SEC = 366 * 86_400;
/** Rule 7: the stable key a holder's excessive-ask note names. */
export const ASK_KEY_PATTERN = "^ask:[a-z0-9][a-z0-9-]{1,62}$";
/** A predicate kind, as members publish them. */
export const PREDICATE_KIND_PATTERN = "^[a-z0-9]+(-[a-z0-9]+)*$";
/** Rule 8: the improvement item (d43) may never be required. */
export const IMPROVEMENT_PATTERN = "improv";
/** d36: no ask refers to origin, ethnicity, sect, caste or ancestry. Word-bounded, so "original" and "insect" pass. */
export const FORBIDDEN_NEED_PATTERN =
  "\\b(origins?|ethnic|ethnicity|ethnicities|sects?|sectarian|castes?|ancestry|ancestries|ancestral|ancestors?)\\b";
/** Rule 3: declining costs only what `goodFor` names. */
export const DECLINING_CONST = "costs-only-goodFor" as const;
/** Rule 6: one presentation per need unless the holder links them. */
export const LINKING_CONST = "separate" as const;
export const ASK_STATES = ["published", "withdrawn", "expired"] as const;

export const ASK_TOP_LEVEL_KEYS = [
  "format", "key", "version", "title", "who", "needs", "why", "answer", "goodFor",
  "declining", "linking", "published", "expiresAtUnix", "state",
] as const;
export const ASK_NEED_KEYS = ["id", "predicate", "withinDays", "issuers"] as const;

export interface AskNeed {
  readonly id: string;
  /** A predicate kind — never a record, a field or an attachment. */
  readonly predicate: string;
  /** How recent the predicate's window must be. */
  readonly withinDays: number;
  /** Optional: the issuers whose yes counts. */
  readonly issuers?: readonly string[];
}

export interface Ask {
  readonly format: typeof ASK_FORMAT;
  readonly key: string;
  readonly version: number;
  readonly title: string;
  readonly who: { readonly name: string; readonly id: string };
  readonly needs: readonly AskNeed[];
  readonly why: string;
  /** A yes, its window, and the issuers it rests on — never the records. */
  readonly answer: { readonly form: "yes"; readonly restsOn: "issuers" };
  /** What a yes gets the holder. Declining costs this and nothing more. */
  readonly goodFor: string;
  readonly declining: typeof DECLINING_CONST;
  readonly linking: typeof LINKING_CONST;
  readonly published: { readonly library: string; readonly atUnix: number };
  readonly expiresAtUnix: number;
  readonly state: (typeof ASK_STATES)[number];
}

export type AskRule =
  | "SHAPE"
  | "R1-predicates-only"
  | "R2-says-why"
  | "R3-no-is-answerable"
  | "R4-expires"
  | "R5-public"
  | "R6-no-joining"
  | "R7-excessive-recordable"
  | "R8-no-improvement-item"
  | "FORBIDDEN-NEED";

export interface AskViolation {
  readonly rule: AskRule;
  readonly path: string;
  readonly message: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

/** Validate an ask against the eight rules and the forbidden needs. */
export function validateAsk(ask: unknown): { readonly ok: boolean; readonly violations: readonly AskViolation[] } {
  const v: AskViolation[] = [];
  const add = (rule: AskRule, path: string, message: string): void => {
    v.push({ rule, path, message });
  };
  if (!isPlainObject(ask)) return { ok: false, violations: [{ rule: "SHAPE", path: "$", message: "an ask is an object" }] };

  // Anything outside the published shape could smuggle a demand in.
  for (const k of Object.keys(ask)) {
    if (!(ASK_TOP_LEVEL_KEYS as readonly string[]).includes(k)) {
      const rawDemand = /record|field|attach|raw|data|document|upload/i.test(k);
      add(rawDemand ? "R1-predicates-only" : "SHAPE", `$.${k}`, `"${k}" is not part of an ask`);
    }
  }
  if (ask.format !== ASK_FORMAT) add("SHAPE", "$.format", `format must be ${ASK_FORMAT}`);
  if (typeof ask.title !== "string" || ask.title.trim().length === 0) add("SHAPE", "$.title", "a title in plain words");
  if (!isPlainObject(ask.who) || typeof ask.who.name !== "string" || typeof ask.who.id !== "string" || ask.who.id.length === 0) {
    add("SHAPE", "$.who", "who asks: a name and an identifier");
  }
  if (!(ASK_STATES as readonly string[]).includes(ask.state as string)) add("SHAPE", "$.state", "state is published, withdrawn or expired");

  // Rule 1 — predicates only.
  const needs = ask.needs;
  if (!Array.isArray(needs) || needs.length === 0) {
    add("R1-predicates-only", "$.needs", "an ask needs at least one predicate");
  } else {
    const kinds = new Set<string>();
    needs.forEach((n, i) => {
      const p = `$.needs[${i}]`;
      if (!isPlainObject(n)) {
        add("R1-predicates-only", p, "a need is a predicate reference");
        return;
      }
      for (const k of Object.keys(n)) {
        if (!(ASK_NEED_KEYS as readonly string[]).includes(k)) add("R1-predicates-only", `${p}.${k}`, `a need names a predicate, never "${k}"`);
      }
      if (typeof n.id !== "string" || n.id.length === 0) add("SHAPE", `${p}.id`, "a need has an id");
      if (typeof n.predicate !== "string" || !new RegExp(PREDICATE_KIND_PATTERN).test(n.predicate)) {
        add("R1-predicates-only", `${p}.predicate`, "a predicate kind, such as cited-rule-in-force");
      } else {
        // Rule 6 — one presentation per kind.
        if (kinds.has(n.predicate)) add("R6-no-joining", `${p}.predicate`, "the same predicate twice would join presentations");
        kinds.add(n.predicate);
      }
      if (!isInt(n.withinDays) || n.withinDays < 1) add("SHAPE", `${p}.withinDays`, "a window in whole days");
      if (n.issuers !== undefined && (!Array.isArray(n.issuers) || n.issuers.some((x) => typeof x !== "string"))) {
        add("SHAPE", `${p}.issuers`, "issuers is a list of identifiers");
      }
      // Rule 8 and the forbidden needs look at every string in the need.
      const text = JSON.stringify(n);
      if (new RegExp(IMPROVEMENT_PATTERN, "i").test(text)) {
        add("R8-no-improvement-item", p, "an ask may never require the improvement item (d43) — it is offered, never demanded");
      }
      if (new RegExp(FORBIDDEN_NEED_PATTERN, "i").test(text)) {
        add("FORBIDDEN-NEED", p, "no ask refers to origin, ethnicity, sect, caste or ancestry (d36)");
      }
    });
  }
  if (!isPlainObject(ask.answer) || ask.answer.form !== "yes" || ask.answer.restsOn !== "issuers") {
    add("R1-predicates-only", "$.answer", "the answer is a yes resting on issuers — never on records");
  }

  // Rule 2 — it says why, on the request.
  if (typeof ask.why !== "string" || ask.why.trim().length < 12) add("R2-says-why", "$.why", "why, in plain words, on the request");
  else if (ask.why.trim() === String(ask.title).trim()) add("R2-says-why", "$.why", "why must say more than the title");

  // Rule 3 — a no is answerable and costs only the thing asked for.
  if (typeof ask.goodFor !== "string" || ask.goodFor.trim().length === 0) add("R3-no-is-answerable", "$.goodFor", "what a yes gets the holder");
  if (ask.declining !== DECLINING_CONST) add("R3-no-is-answerable", "$.declining", `declining ${DECLINING_CONST}`);

  // Rule 5 — it is public; rule 4 — it expires.
  const pub = ask.published;
  const pubOk = isPlainObject(pub) && typeof pub.library === "string" && /^https:\/\//.test(pub.library) && isInt(pub.atUnix);
  if (!pubOk) add("R5-public", "$.published", "published in a public library (https) with its date");
  if (!isInt(ask.expiresAtUnix)) {
    add("R4-expires", "$.expiresAtUnix", "an ask expires");
  } else if (pubOk) {
    const at = (pub as { atUnix: number }).atUnix;
    if (ask.expiresAtUnix <= at) add("R4-expires", "$.expiresAtUnix", "it expires after it is published");
    else if (ask.expiresAtUnix - at > ASK_MAX_LIFETIME_SEC) add("R4-expires", "$.expiresAtUnix", "an ask lives at most 366 days");
  }

  // Rule 6 — no joining by default.
  if (ask.linking !== LINKING_CONST) add("R6-no-joining", "$.linking", `linking is ${LINKING_CONST}; only the holder links presentations`);

  // Rule 7 — a stable identity a holder can name when they record it as excessive.
  if (typeof ask.key !== "string" || !new RegExp(ASK_KEY_PATTERN).test(ask.key)) add("R7-excessive-recordable", "$.key", "a stable key, ask:<slug>");
  if (!isInt(ask.version) || ask.version < 1) add("R7-excessive-recordable", "$.version", "a version number");

  return { ok: v.length === 0, violations: v };
}

/** SHA-256 over JCS of the ask — what a request binds and a holder's note names. */
export function askSha256(ask: Ask): Promise<string> {
  return sha256Hex(canonicalizeBytes(ask));
}

/** A DCQL query (OpenID4VP) for the ask: one credential query per need, predicate credentials only. */
export function askToDcql(ask: Ask): { readonly credentials: readonly Record<string, unknown>[] } {
  return {
    credentials: ask.needs.map((n) => ({
      id: n.id,
      format: "dc+sd-jwt",
      meta: { vct_values: [PREDICATE_VCT] },
      claims: [
        { path: ["predicate", "kind"], values: [n.predicate] },
        { path: ["predicate", "answer"], values: [true] },
        { path: ["predicate", "rule"] },
        { path: ["predicate", "window"] },
      ],
    })),
  };
}

/**
 * The OpenID4VP request an ask becomes: the DCQL query, the verifier's nonce,
 * and the ask itself by value (`kash_ask`) with its digest, so the wallet shows
 * the ask's `why` and can check it against its copy of the public library.
 */
export async function askRequest(
  ask: Ask,
  opts: { readonly nonce: string; readonly responseUri: string },
): Promise<Record<string, unknown>> {
  return {
    response_type: "vp_token",
    response_mode: "direct_post",
    client_id: ask.who.id,
    response_uri: opts.responseUri,
    nonce: opts.nonce,
    dcql_query: askToDcql(ask),
    kash_ask: ask,
    kash_ask_sha256: await askSha256(ask),
  };
}
