/**
 * Door Extension — the rule a door publishes, and the decision receipt it
 * gives back (ECOSYSTEM d84(a): rule · receipt · decision · recourse · renewal).
 *
 *   kash.rule@1.0.0
 *     A door's published rule: what it decides, why, who decides (a role),
 *     the reasons it may give, its contest window, its renewal and end dates,
 *     and its criteria. Each criterion is an OpenID4VP 1.0 DCQL query for the
 *     receipts that answer it (or the person's own word) plus a FEEL condition
 *     over what the query returns — DMN's literal expression. Public and
 *     organisation-authored. Signed by its author as a DSSE envelope
 *     (`application/vnd.kash.rule+json`).
 *
 *   kash.rule@1.1.0 (KS-Q1b; ECOSYSTEM d85(b)–(c))
 *     The same rule with its **address** — sector (ISIC Revision 5), anchor
 *     family, authority, journey and the seven givens — a **subject** on each
 *     criterion, **bounds** on the parameters an adopter may set, and `draft`.
 *     Every new field is optional, so every 1.0.0 body is a 1.1.0 body.
 *
 *   kash.rule@1.2.0 (KS-Q11)
 *     The same rule, with `meta.holder: "countersigner"` on a `kash-artifact`
 *     query: the presentation is bound to the one key whose acceptance in the
 *     countersign bundle verifies (a guest who accepted a host's receipt).
 *     Optional, so every 1.1.0 body is a 1.2.0 body; a 1.1.0 reader refuses a
 *     rule that names it, rather than binding it to the requester.
 *
 *   kash.adoption@1.0.0
 *     An anchor — an organisation — adopts one version of a rule with its own
 *     values for the parameters the rule bounds. Public, signed by the anchor
 *     as DSSE (`application/vnd.kash.adoption+json`). An adoption is the
 *     anchor's pact (d85(d)): rulebooks written once, executed locally.
 *
 * Every shape is closed: a field this schema does not name is refused, so none
 * can carry a score or a person's identity. Meaning — the floor's refusals, the
 * FEEL check, bounds, completeness — is checked by `@kashscript/predicate`;
 * this extension is the shape.
 *
 * **The decision receipt is not here** (since 0.3.0): it is the person's own
 * record, a credential they hold, so its schema lives with the package that
 * issues and checks it — `@kashscript/predicate/decision`. d59 makes lexicons
 * the home of public, organisation-authored records only.
 *
 * Import path: `@kashscript/lexicons/extensions/door`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema, type Schema } from "../schema";

/* ── shared pieces ─────────────────────────────────────────────────── */

const DID = S.string({ format: "did-ks" });
const ISO = S.string({ format: "iso8601" });
const HEX64 = S.string({ pattern: /^[0-9a-f]{64}$/ });
const SLUG = S.string({ pattern: /^[a-z0-9][a-z0-9-]{0,62}$/ });
/** DCQL ids: alphanumerics, `_` and `-` (OpenID4VP 1.0 §6.1). */
const DCQL_ID = S.string({ pattern: /^[A-Za-z0-9_-]{1,64}$/ });
const TEXT = (max: number): Schema => S.string({ minLength: 1, maxLength: max });

/** The DMN types a rule may give a value it reads — DMN's itemDefinition, in the FEEL subset. */
export const DOOR_INPUT_TYPES = [
  "string",
  "number",
  "boolean",
  "date",
  "date and time",
  "days and time duration",
  "years and months duration",
  "list of string",
  "list of number",
  "list of boolean",
  "list of date",
  "list of date and time",
  "list of days and time duration",
  "list of years and months duration",
] as const;
export type DoorInputType = (typeof DOOR_INPUT_TYPES)[number];
const INPUT_TYPE = S.enum(...DOOR_INPUT_TYPES);

export const DECISION_OUTCOMES = ["yes", "not-yet", "no", "partial"] as const;
export type DecisionOutcome = (typeof DECISION_OUTCOMES)[number];

/* ── DCQL (OpenID4VP 1.0 §6), as a rule carries it ─────────────────── */

export type ClaimPathElement = string | number | null;

export interface DcqlClaimsQuery {
  /** Required here: a claim's id is the name its criterion's condition reads. */
  readonly id: string;
  readonly path: readonly ClaimPathElement[];
  readonly values?: readonly (string | number | boolean)[];
}

export interface DcqlTrustedAuthoritiesQuery {
  /** `kash_issuer` (issuer DIDs) or `kash_trust_list` (`<publisher DID>#<list id>`), in the spec's extension point. */
  readonly type: string;
  readonly values: readonly string[];
}

export interface DcqlMeta {
  /** `dc+sd-jwt`: the accepted `vct` values. */
  readonly vct_values?: readonly string[];
  /** `kash-artifact`: the accepted registered DSTs (attest's registry). */
  readonly dst_values?: readonly string[];
  /** `kash-artifact`: `countersigned` asks for two independent signatures over the same bytes. */
  readonly attestation?: "countersigned" | "issuer-signed";
  /** `kash-artifact`: where in the signed payload the holder's key is named, for the presentation's binding. */
  readonly holder_path?: readonly ClaimPathElement[];
  /**
   * `kash-artifact`, **kash.rule@1.2.0** (KS-Q11): `countersigner` names the
   * holder as the one key whose acceptance in the countersign bundle verifies —
   * the party who countersigned these bytes, not the one who asked. Never with
   * `holder_path`; only with `attestation: countersigned`.
   */
  readonly holder?: "countersigner";
}

export interface DcqlCredentialQuery {
  readonly id: string;
  readonly format: string;
  readonly multiple?: boolean;
  readonly meta?: DcqlMeta;
  readonly trusted_authorities?: readonly DcqlTrustedAuthoritiesQuery[];
  readonly require_cryptographic_holder_binding?: boolean;
  readonly claims?: readonly DcqlClaimsQuery[];
  readonly claim_sets?: readonly (readonly string[])[];
}

const PATH = S.array(S.union(S.string({ minLength: 1, maxLength: 128 }), S.number({ integer: true, min: 0 }), S.literal(null)), { minItems: 1, maxItems: 16 });

export const DCQL_CLAIMS_QUERY_SCHEMA: ObjectSchema = S.object(
  {
    id: DCQL_ID,
    path: PATH,
    values: S.optional(S.array(S.union(S.string({ maxLength: 512 }), S.number({ integer: true }), S.boolean()), { minItems: 1, maxItems: 64 })),
  },
  ["id", "path"],
);

const DCQL_META_PROPERTIES = {
  vct_values: S.optional(S.array(S.string({ minLength: 1, maxLength: 256 }), { minItems: 1, maxItems: 16 })),
  dst_values: S.optional(S.array(S.string({ minLength: 1, maxLength: 256 }), { minItems: 1, maxItems: 16 })),
  attestation: S.optional(S.enum("countersigned", "issuer-signed")),
  holder_path: S.optional(PATH),
};

export const DCQL_CREDENTIAL_QUERY_SCHEMA: ObjectSchema = S.object(
  {
    id: DCQL_ID,
    format: S.string({ minLength: 1, maxLength: 64 }),
    multiple: S.optional(S.boolean()),
    meta: S.optional(S.object(DCQL_META_PROPERTIES)),
    trusted_authorities: S.optional(
      S.array(S.object({ type: S.string({ minLength: 1, maxLength: 64 }), values: S.array(S.string({ minLength: 1, maxLength: 256 }), { minItems: 1, maxItems: 64 }) }, ["type", "values"]), { minItems: 1, maxItems: 8 }),
    ),
    require_cryptographic_holder_binding: S.optional(S.boolean()),
    claims: S.optional(S.array(DCQL_CLAIMS_QUERY_SCHEMA, { minItems: 1, maxItems: 32 })),
    claim_sets: S.optional(S.array(S.array(DCQL_ID, { minItems: 1, maxItems: 32 }), { minItems: 1, maxItems: 16 })),
  },
  ["id", "format"],
);

/* ── kash.rule@1.0.0 ───────────────────────────────────────────────── */

export const KASH_RULE_NSID = "kash.rule" as const;
export const KASH_RULE_ID = "kash.rule@1.0.0" as const;

export interface RuleParameter {
  readonly type: DoorInputType;
  /** Public rules: the threshold in clear. */
  readonly value?: string | number | boolean;
  /** Private rules: SHA-256 hex of JCS({name, value, salt}); the desk holds the opening. */
  readonly sealed?: string;
}

export interface RuleReason {
  readonly code: string;
  readonly outcome: DecisionOutcome;
  readonly text: string;
}

export interface CriterionBasis {
  readonly title: string;
  readonly url?: string;
  readonly clause?: string;
  readonly page?: number;
  readonly quote?: string;
}

export type CriterionAnswer =
  | {
      readonly by: "receipts";
      /** DCQL credential queries, verbatim. Their ids are `<criterion>` or `<criterion>_<suffix>`. */
      readonly query: readonly DcqlCredentialQuery[];
      /** Which of them together answer the criterion (DCQL `credential_sets.options`). Default: each alone. */
      readonly options?: readonly (readonly string[])[];
      /** Display names for issuer DIDs and trust lists the queries name. */
      readonly names?: Readonly<Record<string, string>>;
    }
  | {
      readonly by: "own-word";
      /** What the person states, in plain words. */
      readonly statement: string;
      /** The values the person gives, by name and DMN type. */
      readonly fields: Readonly<Record<string, DoorInputType>>;
    };

export interface Criterion {
  readonly id: string;
  readonly label: string;
  /** Why the door needs it. Required: P4's second rule — a rule asks only for what its purpose needs. */
  readonly purpose: string;
  readonly answer: CriterionAnswer;
  /** An issuer's predicate (attest's predicate credential, `kind` = this criterion, `rule` = this rule) answers the row instead. */
  readonly predicate?: { readonly issuers: readonly { readonly id: string; readonly name: string }[]; readonly freshDays: number };
  /** A FEEL expression (the DMN subset) over what the query returns, with a DMN type for every claim it reads. */
  readonly condition?: { readonly feel: string; readonly types: Readonly<Record<string, DoorInputType>> };
  /** The clause it comes from, when a rule is drawn from a written policy. */
  readonly basis?: CriterionBasis;
}

export interface RuleBody {
  /** `did:kash:<author>/rule/<slug>` — the publisher's DID plus a path, as d60 identifies places. */
  readonly id: string;
  readonly version: number;
  /** The organisation that publishes it and answers for it. Never a person. */
  readonly author: string;
  readonly title: string;
  readonly purpose: string;
  readonly visibility: "public" | "private";
  readonly parameters?: Readonly<Record<string, RuleParameter>>;
  /** d43: every rule renews and ends. */
  readonly dates: { readonly published: string; readonly renewBy: string; readonly endsAt: string };
  /** Who decides: a role, never a named person. */
  readonly decider: { readonly role: string };
  readonly outcome: {
    /** What a yes grants, in plain words. */
    readonly grants: string;
    /** It binds the person — credit, a contract, a debt (P3): never automatic. */
    readonly binds: boolean;
    /** It touches sensitive data (GDPR art. 9): never automatic. */
    readonly sensitive: boolean;
    /** The author's standing decision: a yes is given when every criterion is met. Refused with `binds` or `sensitive`. */
    readonly automaticYes: boolean;
  };
  readonly reasons: readonly RuleReason[];
  readonly contest: { readonly windowDays: number; readonly answerDays: number; readonly how: string };
  /** P4's first rule: another way to show the same thing. Paper is the floor. */
  readonly anotherWay: string;
  readonly criteria: readonly Criterion[];
  /** The author's written answers to the warnings validation raised. Published with the rule. */
  readonly answers?: readonly { readonly criterion: string; readonly code: string; readonly text: string }[];
  /** Practice rules say so inside what is signed. */
  readonly practice?: boolean;
}

const OWN_WORD_ANSWER = S.object(
  { by: S.literal("own-word"), statement: TEXT(280), fields: S.record(INPUT_TYPE, S.string({ pattern: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/ })) },
  ["by", "statement", "fields"],
);

const RECEIPTS_ANSWER = S.object(
  {
    by: S.literal("receipts"),
    query: S.array(DCQL_CREDENTIAL_QUERY_SCHEMA, { minItems: 1, maxItems: 8 }),
    options: S.optional(S.array(S.array(DCQL_ID, { minItems: 1, maxItems: 8 }), { minItems: 1, maxItems: 8 })),
    names: S.optional(S.record(TEXT(120))),
  },
  ["by", "query"],
);

export const CRITERION_SCHEMA: ObjectSchema = S.object(
  {
    id: SLUG,
    label: TEXT(160),
    purpose: TEXT(600),
    answer: S.union(RECEIPTS_ANSWER, OWN_WORD_ANSWER),
    predicate: S.optional(
      S.object(
        {
          issuers: S.array(S.object({ id: DID, name: TEXT(120) }, ["id", "name"]), { minItems: 1, maxItems: 16 }),
          freshDays: S.number({ integer: true, min: 1, max: 366 }),
        },
        ["issuers", "freshDays"],
      ),
    ),
    condition: S.optional(
      S.object(
        { feel: S.string({ minLength: 1, maxLength: 2048 }), types: S.record(INPUT_TYPE, S.string({ pattern: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/ })) },
        ["feel", "types"],
      ),
    ),
    basis: S.optional(
      S.object(
        { title: TEXT(200), url: S.optional(S.string({ format: "url" })), clause: S.optional(TEXT(120)), page: S.optional(S.number({ integer: true, min: 1 })), quote: S.optional(TEXT(1000)) },
        ["title"],
      ),
    ),
  },
  ["id", "label", "purpose", "answer"],
);

export const KASH_RULE_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/rule\/[a-z0-9][a-z0-9-]{0,62}$/ }),
    version: S.number({ integer: true, min: 1 }),
    author: DID,
    title: TEXT(160),
    purpose: TEXT(1000),
    visibility: S.enum("public", "private"),
    parameters: S.optional(
      S.record(
        S.object({ type: INPUT_TYPE, value: S.optional(S.union(S.string({ maxLength: 256 }), S.number(), S.boolean())), sealed: S.optional(HEX64) }, ["type"]),
        S.string({ pattern: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/ }),
      ),
    ),
    dates: S.object({ published: ISO, renewBy: ISO, endsAt: ISO }, ["published", "renewBy", "endsAt"]),
    decider: S.object({ role: TEXT(64) }, ["role"]),
    outcome: S.object({ grants: TEXT(280), binds: S.boolean(), sensitive: S.boolean(), automaticYes: S.boolean() }, ["grants", "binds", "sensitive", "automaticYes"]),
    reasons: S.array(S.object({ code: SLUG, outcome: S.enum(...DECISION_OUTCOMES), text: TEXT(400) }, ["code", "outcome", "text"]), { minItems: 2, maxItems: 32 }),
    contest: S.object(
      { windowDays: S.number({ integer: true, min: 1, max: 366 }), answerDays: S.number({ integer: true, min: 1, max: 366 }), how: TEXT(400) },
      ["windowDays", "answerDays", "how"],
    ),
    anotherWay: TEXT(600),
    criteria: S.array(CRITERION_SCHEMA, { minItems: 1, maxItems: 32 }),
    answers: S.optional(S.array(S.object({ criterion: SLUG, code: S.string({ pattern: /^[A-Z][A-Z_]{1,63}$/ }), text: TEXT(1000) }, ["criterion", "code", "text"]), { maxItems: 64 })),
    practice: S.optional(S.boolean()),
  },
  ["id", "version", "author", "title", "purpose", "visibility", "dates", "decider", "outcome", "reasons", "contest", "anotherWay", "criteria"],
);

export const KASH_RULE_LEXICON: LexiconDef = {
  id: KASH_RULE_ID,
  nsid: KASH_RULE_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_RULE_BODY_SCHEMA,
  title: "A door's rule",
  description:
    "What a door decides, why, who decides, the reasons it may give, its contest window, renewal and end dates, and its criteria — each an OpenID4VP 1.0 DCQL query plus a FEEL condition. Public, organisation-authored, signed by its author.",
};

/* ── kash.rule@1.1.0 — the address, subjects, bounds, drafts ───────── */

export const KASH_RULE_1_1_ID = "kash.rule@1.1.0" as const;

/** What a criterion is about. d85(b) rule 1 binds when the subject is a person (or an organisation's people). */
export const SUBJECTS = ["person", "organisation", "product", "place"] as const;
export type Subject = (typeof SUBJECTS)[number];

export const ANCHOR_FAMILIES = ["movement", "knowledge", "work", "community"] as const;
export const AUTHORITY_KINDS = ["floor", "law", "standard", "institution", "community"] as const;
export const JOURNEYS = ["move", "learn", "earn-and-spend", "live", "leisure"] as const;
export const GIVENS = ["area", "spaces", "capitals", "culture", "economy", "time", "relations"] as const;
export type Given = (typeof GIVENS)[number];
export const SPACE_KINDS = ["premises", "workplace", "campus", "site", "vehicle", "home", "public-space", "online"] as const;
export const CAPITAL_KINDS = ["people", "systems", "resources"] as const;
export const ECONOMY_LEVELS = ["primary", "secondary", "tertiary", "quaternary", "quinary", "uncounted"] as const;

/** Bounds an adopter may set a parameter within: a range, or a list. */
export type ParameterBounds =
  | { readonly min?: string | number; readonly max?: string | number }
  | { readonly allowed: readonly (string | number | boolean)[] };

export interface RuleParameter1_1 extends RuleParameter {
  readonly bounds?: ParameterBounds;
}

export interface Criterion1_1 extends Criterion {
  readonly subject?: Subject;
}

export interface RuleRef {
  readonly rule: string;
  readonly version?: number;
}

export interface Givens {
  readonly area?: { readonly text: string; readonly anywhere?: boolean; readonly countries?: readonly string[]; readonly places?: readonly string[] };
  readonly spaces?: { readonly text: string; readonly kinds?: readonly (typeof SPACE_KINDS)[number][]; readonly places?: readonly string[] };
  readonly capitals?: { readonly text: string; readonly needs?: readonly { readonly kind: (typeof CAPITAL_KINDS)[number]; readonly what: string }[] };
  readonly culture?: { readonly text: string; readonly codes?: readonly { readonly title: string; readonly url?: string }[]; readonly languages?: readonly string[] };
  readonly economy?: { readonly text: string; readonly level?: (typeof ECONOMY_LEVELS)[number] };
  readonly time?: { readonly text: string; readonly lasts?: string; readonly renews?: string };
  readonly relations?: { readonly text: string; readonly recognises?: readonly RuleRef[]; readonly within?: readonly { readonly id: string }[] };
}

/** Every rule has an address (d85(c)). */
export interface RuleAddress {
  /** ISIC Revision 5: a section (A–V) or a two-digit division. */
  readonly sector: { readonly classification: "ISIC"; readonly revision: "5"; readonly code: string };
  readonly anchorFamily: (typeof ANCHOR_FAMILIES)[number];
  readonly authority: { readonly kind: (typeof AUTHORITY_KINDS)[number]; readonly name?: string; readonly url?: string };
  readonly journey: (typeof JOURNEYS)[number];
  /** The seven givens. A rule is complete when all seven are answered. */
  readonly givens: Givens;
}

export interface RuleBody1_1 extends Omit<RuleBody, "parameters" | "criteria"> {
  readonly parameters?: Readonly<Record<string, RuleParameter1_1>>;
  readonly criteria: readonly Criterion1_1[];
  readonly address?: RuleAddress;
  /** Published for reading and comment, never decided under. An incomplete rule publishes only as a draft. */
  readonly draft?: boolean;
}

const VALUE = S.union(S.string({ maxLength: 256 }), S.number(), S.boolean());
const PLACE_REF = S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/place\/[a-z0-9][a-z0-9-]{0,62}$/ });
const DURATION = S.string({ pattern: /^P(?=\d|T\d)(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$/ });
const RULE_ID = KASH_RULE_BODY_SCHEMA.properties.id!;
const GIVEN_TEXT = TEXT(600);

const PARAMETER_1_1 = S.object(
  {
    type: INPUT_TYPE,
    value: S.optional(VALUE),
    sealed: S.optional(HEX64),
    bounds: S.optional(
      S.union(
        S.object({ min: S.optional(S.union(S.string({ maxLength: 64 }), S.number())), max: S.optional(S.union(S.string({ maxLength: 64 }), S.number())) }),
        S.object({ allowed: S.array(VALUE, { minItems: 1, maxItems: 64 }) }, ["allowed"]),
      ),
    ),
  },
  ["type"],
);

const GIVENS_SCHEMA = S.object({
  area: S.optional(
    S.object(
      { text: GIVEN_TEXT, anywhere: S.optional(S.boolean()), countries: S.optional(S.array(S.string({ pattern: /^[A-Z]{2}$/ }), { minItems: 1, maxItems: 64 })), places: S.optional(S.array(PLACE_REF, { minItems: 1, maxItems: 64 })) },
      ["text"],
    ),
  ),
  spaces: S.optional(S.object({ text: GIVEN_TEXT, kinds: S.optional(S.array(S.enum(...SPACE_KINDS), { minItems: 1, maxItems: 8 })), places: S.optional(S.array(PLACE_REF, { minItems: 1, maxItems: 64 })) }, ["text"])),
  capitals: S.optional(S.object({ text: GIVEN_TEXT, needs: S.optional(S.array(S.object({ kind: S.enum(...CAPITAL_KINDS), what: TEXT(200) }, ["kind", "what"]), { minItems: 1, maxItems: 16 })) }, ["text"])),
  culture: S.optional(
    S.object(
      { text: GIVEN_TEXT, codes: S.optional(S.array(S.object({ title: TEXT(200), url: S.optional(S.string({ format: "url" })) }, ["title"]), { minItems: 1, maxItems: 16 })), languages: S.optional(S.array(S.string({ format: "bcp47" }), { minItems: 1, maxItems: 16 })) },
      ["text"],
    ),
  ),
  economy: S.optional(S.object({ text: GIVEN_TEXT, level: S.optional(S.enum(...ECONOMY_LEVELS)) }, ["text"])),
  time: S.optional(S.object({ text: GIVEN_TEXT, lasts: S.optional(DURATION), renews: S.optional(DURATION) }, ["text"])),
  relations: S.optional(
    S.object(
      { text: GIVEN_TEXT, recognises: S.optional(S.array(S.object({ rule: RULE_ID, version: S.optional(S.number({ integer: true, min: 1 })) }, ["rule"]), { minItems: 1, maxItems: 32 })), within: S.optional(S.array(S.object({ id: S.string({ minLength: 1, maxLength: 256 }) }, ["id"]), { minItems: 1, maxItems: 16 })) },
      ["text"],
    ),
  ),
});

export const RULE_ADDRESS_SCHEMA: ObjectSchema = S.object(
  {
    sector: S.object({ classification: S.literal("ISIC"), revision: S.literal("5"), code: S.string({ pattern: /^([A-V]|\d{2})$/ }) }, ["classification", "revision", "code"]),
    anchorFamily: S.enum(...ANCHOR_FAMILIES),
    authority: S.object({ kind: S.enum(...AUTHORITY_KINDS), name: S.optional(TEXT(120)), url: S.optional(S.string({ format: "url" })) }, ["kind"]),
    journey: S.enum(...JOURNEYS),
    givens: GIVENS_SCHEMA,
  },
  ["sector", "anchorFamily", "authority", "journey", "givens"],
);

export const CRITERION_1_1_SCHEMA: ObjectSchema = S.object({ ...CRITERION_SCHEMA.properties, subject: S.optional(S.enum(...SUBJECTS)) }, CRITERION_SCHEMA.required);

export const KASH_RULE_1_1_BODY_SCHEMA: ObjectSchema = S.object(
  {
    ...KASH_RULE_BODY_SCHEMA.properties,
    parameters: S.optional(S.record(PARAMETER_1_1, S.string({ pattern: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/ }))),
    criteria: S.array(CRITERION_1_1_SCHEMA, { minItems: 1, maxItems: 32 }),
    address: S.optional(RULE_ADDRESS_SCHEMA),
    draft: S.optional(S.boolean()),
  },
  KASH_RULE_BODY_SCHEMA.required,
);

export const KASH_RULE_1_1_LEXICON: LexiconDef = {
  id: KASH_RULE_1_1_ID,
  nsid: KASH_RULE_NSID,
  semver: { major: 1, minor: 1, patch: 0 },
  bodySchema: KASH_RULE_1_1_BODY_SCHEMA,
  title: "A door's rule, with its address",
  description:
    "kash.rule@1.0.0 plus the address (ISIC Rev. 5 sector, anchor family, authority, journey, the seven givens), each criterion's subject, parameter bounds for adopters, and draft. A 1.0.0 body is a 1.1.0 body.",
};

/* ── kash.rule@1.2.0 — the countersigner as holder ──────────────────── */

export const KASH_RULE_1_2_ID = "kash.rule@1.2.0" as const;

/** The DCQL credential query of 1.2.0: 1.1.0's, with `meta.holder`. */
export const DCQL_CREDENTIAL_QUERY_1_2_SCHEMA: ObjectSchema = S.object(
  {
    ...DCQL_CREDENTIAL_QUERY_SCHEMA.properties,
    meta: S.optional(S.object({ ...DCQL_META_PROPERTIES, holder: S.optional(S.enum("countersigner")) })),
  },
  DCQL_CREDENTIAL_QUERY_SCHEMA.required,
);

const RECEIPTS_ANSWER_1_2 = S.object({ ...RECEIPTS_ANSWER.properties, query: S.array(DCQL_CREDENTIAL_QUERY_1_2_SCHEMA, { minItems: 1, maxItems: 8 }) }, RECEIPTS_ANSWER.required);

export const CRITERION_1_2_SCHEMA: ObjectSchema = S.object({ ...CRITERION_1_1_SCHEMA.properties, answer: S.union(RECEIPTS_ANSWER_1_2, OWN_WORD_ANSWER) }, CRITERION_1_1_SCHEMA.required);

export const KASH_RULE_1_2_BODY_SCHEMA: ObjectSchema = S.object(
  { ...KASH_RULE_1_1_BODY_SCHEMA.properties, criteria: S.array(CRITERION_1_2_SCHEMA, { minItems: 1, maxItems: 32 }) },
  KASH_RULE_1_1_BODY_SCHEMA.required,
);

export const KASH_RULE_1_2_LEXICON: LexiconDef = {
  id: KASH_RULE_1_2_ID,
  nsid: KASH_RULE_NSID,
  semver: { major: 1, minor: 2, patch: 0 },
  bodySchema: KASH_RULE_1_2_BODY_SCHEMA,
  title: "A door's rule, with its address and the countersigner as holder",
  description:
    "kash.rule@1.1.0 plus meta.holder on a kash-artifact query: \"countersigner\" binds the presentation to the one key whose acceptance in the countersign bundle verifies. A 1.1.0 body is a 1.2.0 body.",
};

/* ── kash.adoption@1.0.0 ───────────────────────────────────────────── */

export const KASH_ADOPTION_NSID = "kash.adoption" as const;
export const KASH_ADOPTION_ID = "kash.adoption@1.0.0" as const;

export interface AdoptionBody {
  /** `did:kash:<anchor>/adoption/<slug>`. */
  readonly id: string;
  /** The adopting organisation — the anchor whose door decides under it. */
  readonly anchor: string;
  readonly rule: { readonly id: string; readonly version: number; readonly hash: string };
  /** Local values for the parameters the rule bounds — nothing else. */
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  /** It renews and ends, no later than the rule (d43). */
  readonly dates: { readonly adopted: string; readonly renewBy: string; readonly endsAt: string };
  readonly practice?: boolean;
}

export const KASH_ADOPTION_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: S.string({ pattern: /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/adoption\/[a-z0-9][a-z0-9-]{0,62}$/ }),
    anchor: DID,
    rule: S.object({ id: RULE_ID, version: S.number({ integer: true, min: 1 }), hash: HEX64 }, ["id", "version", "hash"]),
    parameters: S.record(VALUE, S.string({ pattern: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/ })),
    dates: S.object({ adopted: ISO, renewBy: ISO, endsAt: ISO }, ["adopted", "renewBy", "endsAt"]),
    practice: S.optional(S.boolean()),
  },
  ["id", "anchor", "rule", "parameters", "dates"],
);

export const KASH_ADOPTION_LEXICON: LexiconDef = {
  id: KASH_ADOPTION_ID,
  nsid: KASH_ADOPTION_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_ADOPTION_BODY_SCHEMA,
  title: "An anchor's adoption of a rule",
  description: "An organisation adopts one version of a rule with its own values for the parameters the rule bounds. Public, signed by the anchor.",
};

/* ── bundles ───────────────────────────────────────────────────────── */

/** Every door lexicon: the rule at 1.0.0, 1.1.0 and 1.2.0, and the adoption. All public and organisation-authored (d59). */
export const DOOR_LEXICONS: readonly LexiconDef[] = [KASH_RULE_LEXICON, KASH_RULE_1_1_LEXICON, KASH_RULE_1_2_LEXICON, KASH_ADOPTION_LEXICON];
