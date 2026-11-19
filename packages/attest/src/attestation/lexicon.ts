/**
 * `kash.attestation@1.0.0` and `kash.mandate@1.0.0` — d91(a)'s one record type and its mandate, as
 * closed shapes (RW-14; `specs/attestation/README.md` §1–§2).
 *
 * **Why here.** Both are held records — an attestation is kept by its holder and its issuer's book, a
 * mandate is presented beside what it authorised — never public, organisation-authored records, which
 * d59 makes the home of `@kashscript/lexicons` (the decision's precedent, d85(l)). They live with the
 * package every role shares: an issuer, a wallet and a desk all build on attest (d91(e): Issue · Hold ·
 * Verify), and none should need the desk's package to read its own record. Built with the lexicons'
 * schema DSL, never registered for publishing.
 *
 * The cross-field rules a shape cannot write are `./faults`. The three forms are `./forms`.
 */

import type { LexiconDef } from "@kashscript/lexicons/registry";
import { S, type ObjectSchema, type Schema } from "@kashscript/lexicons/schema";
import { STATUS_PURPOSES, type StatusListEntry } from "../holder/status-list";

/* ── the vocabulary (d91(a)) ───────────────────────────────────────── */

/**
 * The kinds of attestation this record carries. A **decision** — an attestation against a rule's version —
 * keeps its own record, `kash.decision` (`@kashscript/predicate/decision`), and is mapped, never duplicated.
 */
export const ATTESTATION_KINDS = ["receipt", "finding", "assurance", "contest"] as const;
export type AttestationKind = (typeof ATTESTATION_KINDS)[number];

/** d91(a)'s four outcomes. */
export const ATTESTATION_OUTCOMES = ["accepted", "not-yet", "refused", "finding"] as const;
export type AttestationOutcome = (typeof ATTESTATION_OUTCOMES)[number];

/** Every kind a mandate may scope: the four above, and the decision. */
export const SCOPED_KINDS = ["receipt", "decision", "finding", "assurance", "contest"] as const;
export type ScopedKind = (typeof SCOPED_KINDS)[number];

/**
 * d91(a): references are agreements and purposes (private, in books) and rules and standards (public, in
 * the library), each by hash and version. `artefact` (a delivered thing) and `attestation` (another
 * attestation, cited) are private too.
 */
export const REFERENCE_KINDS = ["agreement", "purpose", "artefact", "attestation", "rule", "standard"] as const;
export type ReferenceKind = (typeof REFERENCE_KINDS)[number];
/** Public references are shared by everyone who answers to them, so showing one links nobody. */
export const PUBLIC_REFERENCE_KINDS: readonly ReferenceKind[] = ["rule", "standard"];
export const isPublicReference = (kind: ReferenceKind): boolean => PUBLIC_REFERENCE_KINDS.includes(kind);

/** Who holds a mandate, by role — never by name. */
export const DELEGATE_KINDS = ["seat", "agent", "desk", "representative", "organisation"] as const;
export type DelegateKind = (typeof DELEGATE_KINDS)[number];

/* ── the pieces ────────────────────────────────────────────────────── */

const B58 = "[1-9A-HJ-NP-Za-km-z]{32,48}";
/** A `did:web` (W3C CCG): a host, an optional port written `%3A<port>`, and optional path segments. */
const WEB = "did:web:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?:%3A[0-9]{1,5})?(?::[A-Za-z0-9._-]{1,64}){0,8}";
const SLUG_SOURCE = "[a-z0-9][a-z0-9-]{0,62}";

/**
 * A party who answers: a self-certifying `did:kash`, or a `did:web` for an organisation on its own domain
 * (d91(e); d97(h): no method is registered, and a stranger resolves `did:web`). Opaque engine ids such as
 * `did:kash:org:<slug>` are not accepted — they resolve only through a list or a held key.
 */
export const PARTY_DID_PATTERN = new RegExp(`^(?:did:kash:${B58}|${WEB})$`);
/** A key: self-certifying, so a signature checks with no lookup (d28). */
export const KEY_DID_PATTERN = new RegExp(`^did:kash:${B58}$`);
/** A mandate's id: its principal's DID, then `/mandate/<slug>`. predicate's `MANDATE_ID_PATTERN` is the same; a test keeps them equal. */
export const MANDATE_ID_PATTERN = new RegExp(`^(?:did:kash:${B58}|${WEB})\\/mandate\\/${SLUG_SOURCE}$`);
/** A job's profile — `client-signoff/1`, `booking.delivered/1` (d91(a): conformity and flow are profiles). */
export const PROFILE_PATTERN = /^[a-z][a-z0-9.-]{0,62}\/[1-9][0-9]{0,3}$/;

const PARTY = S.string({ pattern: PARTY_DID_PATTERN });
const KEY = S.string({ pattern: KEY_DID_PATTERN });
const HEX64 = S.string({ pattern: /^[0-9a-f]{64}$/ });
const SLUG = S.string({ pattern: new RegExp(`^${SLUG_SOURCE}$`) });
const ISO = S.string({ format: "iso8601" });
const PROFILE = S.string({ pattern: PROFILE_PATTERN });
const text = (max: number): Schema => S.string({ minLength: 1, maxLength: max });

/** A content-addressed reference. */
export interface Reference {
  readonly kind: ReferenceKind;
  /** SHA-256 hex of the bytes the reference's own signer signed — or, unsigned, of its RFC 8785 canonical form. */
  readonly sha256: string;
  /** A public reference's library id (a rule's `did:kash:…/rule/<slug>`, a standard's clause). Never on a private one. */
  readonly id?: string;
  readonly version?: number;
}

export const REFERENCE_SCHEMA: ObjectSchema = S.object(
  { kind: S.enum(...REFERENCE_KINDS), sha256: HEX64, id: S.optional(text(256)), version: S.optional(S.number({ integer: true, min: 1 })) },
  ["kind", "sha256"],
);

/** A citation of the mandate a signature was made under, by id and the SHA-256 of its signed bytes. */
export interface MandateCitation {
  readonly id: string;
  readonly hash: string;
}

export const MANDATE_CITATION_SCHEMA: ObjectSchema = S.object({ id: S.string({ pattern: MANDATE_ID_PATTERN }), hash: HEX64 }, ["id", "hash"]);

/** W3C `BitstringStatusListEntry`, as attest's holder contract reads it (`statusEntryOf`). */
export const STATUS_ENTRY_SCHEMA: ObjectSchema = S.object(
  {
    type: S.literal("BitstringStatusListEntry"),
    statusPurpose: S.enum(...STATUS_PURPOSES),
    statusListIndex: S.string({ pattern: /^(0|[1-9][0-9]*)$/ }),
    statusListCredential: S.string({ format: "url" }),
  },
  ["type", "statusPurpose", "statusListIndex", "statusListCredential"],
);

/* ── kash.attestation@1.0.0 ────────────────────────────────────────── */

export const KASH_ATTESTATION_NSID = "kash.attestation" as const;
export const KASH_ATTESTATION_ID = "kash.attestation@1.0.0" as const;

export interface AttestationBody {
  /** The party who answers for it and whose book issues it — the principal, whoever's key signed for it. */
  readonly issuer: string;
  readonly kind: AttestationKind;
  readonly outcome: AttestationOutcome;
  readonly reference: Reference;
  /** Plain words: what was accepted, found or contested. Never a person's identity. */
  readonly statement: string;
  readonly profile?: string;
  /**
   * The other side, whose own signature over these same bytes completes the record — the client or guest who
   * accepts a receipt, the doer who countersigns a finding (d41: two signatures or it is not proof; d43). A
   * person's key for this one relationship, or an organisation signing as itself (a `did:web` only at grade 3).
   * Written when the counterparty answers, never before (§2.3). Never in a copy: `cnf` is.
   */
  readonly counterparty?: string;
  /** The mandate the issuer's signature was made under, when a delegate's key signed for it (d91(a)). */
  readonly mandate?: MandateCitation;
  /** The mandate the counterparty's signature was made under — a client company's employee, a person's agent (d91(a)). Never in a copy. */
  readonly counterpartyMandate?: MandateCitation;
  /** The counterparty's signing ceremony's grade, as the issuer's flow ran it (d91(d)): 0 practice only · 1 passkey on the issuer's approval domain · 2 device-bound · 3 the organisation itself. */
  readonly grade?: 0 | 1 | 2 | 3;
  /** A contest's: the content id of the decision copy it contests — SHA-256 hex of that copy's issuer-signed JWT, as `reliedOn` names an SD-JWT. */
  readonly contests?: string;
  /** The signer's own claim of when. A witness decides what stands (d91(a)). */
  readonly claimedAt: string;
  /** Every record can expire (d27.5). */
  readonly expiresAt: string;
  /** The content id of the attestation this one corrects; that one is then superseded (d91(a)). */
  readonly supersedes?: string;
  readonly credentialStatus?: StatusListEntry;
  /** Codes: what is missing for a not yet, the grounds of a contest, a finding's class. */
  readonly reasons?: readonly string[];
  readonly practice?: boolean;
}

export const KASH_ATTESTATION_BODY_SCHEMA: ObjectSchema = S.object(
  {
    issuer: PARTY,
    kind: S.enum(...ATTESTATION_KINDS),
    outcome: S.enum(...ATTESTATION_OUTCOMES),
    reference: REFERENCE_SCHEMA,
    statement: text(280),
    profile: S.optional(PROFILE),
    counterparty: S.optional(PARTY),
    mandate: S.optional(MANDATE_CITATION_SCHEMA),
    counterpartyMandate: S.optional(MANDATE_CITATION_SCHEMA),
    grade: S.optional(S.enum(0, 1, 2, 3)),
    contests: S.optional(HEX64),
    claimedAt: ISO,
    expiresAt: ISO,
    supersedes: S.optional(HEX64),
    credentialStatus: S.optional(STATUS_ENTRY_SCHEMA),
    reasons: S.optional(S.array(SLUG, { minItems: 1, maxItems: 16 })),
    practice: S.optional(S.boolean()),
  },
  ["issuer", "kind", "outcome", "reference", "statement", "claimedAt", "expiresAt"],
);

/** For JSON Schema export and tooling only — an attestation is a held record, never published. */
export const KASH_ATTESTATION_LEXICON: LexiconDef = {
  id: KASH_ATTESTATION_ID,
  nsid: KASH_ATTESTATION_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_ATTESTATION_BODY_SCHEMA,
  title: "An attestation",
  description:
    "A signed outcome — accepted, not yet, refused or finding — against a content-addressed reference, by a party who answers for it (d91(a)). A receipt, a finding, an assurance or a contest; a decision keeps kash.decision. Held by its holder and its issuer's book; never published.",
};

/* ── kash.mandate@1.0.0 ────────────────────────────────────────────── */

export const KASH_MANDATE_NSID = "kash.mandate" as const;
export const KASH_MANDATE_ID = "kash.mandate@1.0.0" as const;

export interface MandateScope {
  readonly kinds?: readonly ScopedKind[];
  /** In d91's words; a decision's `yes` is `accepted`, its `no` and `partial` are `refused`. */
  readonly outcomes?: readonly AttestationOutcome[];
  /** Exact registered tags the delegate may sign under. */
  readonly dsts?: readonly string[];
  readonly profiles?: readonly string[];
  readonly references?: readonly Reference[];
}

/**
 * One link: a principal grants one key. A chain — a seat's own agent — is not in this version (§4): with one
 * link the principal is always the issuer the record names, so nothing can widen a scope on the way down.
 */
export interface MandateBody {
  readonly id: string;
  /** Who answers for what the delegate signs. */
  readonly principal: string;
  /** The `kind` is the principal's own word: the format cannot tell a machine's key from a person's (§2.2). */
  readonly delegate: { readonly key: string; readonly kind: DelegateKind; readonly role?: string };
  readonly scope: MandateScope;
  readonly dates: { readonly from: string; readonly until: string };
  /** Required: a mandate can be revoked before it ends — a seat's holder leaves, an app is disconnected. */
  readonly credentialStatus: StatusListEntry;
  readonly practice?: boolean;
}

export const MANDATE_SCOPE_SCHEMA: ObjectSchema = S.object({
  kinds: S.optional(S.array(S.enum(...SCOPED_KINDS), { minItems: 1, maxItems: 5 })),
  outcomes: S.optional(S.array(S.enum(...ATTESTATION_OUTCOMES), { minItems: 1, maxItems: 4 })),
  dsts: S.optional(S.array(text(256), { minItems: 1, maxItems: 16 })),
  profiles: S.optional(S.array(PROFILE, { minItems: 1, maxItems: 16 })),
  references: S.optional(S.array(REFERENCE_SCHEMA, { minItems: 1, maxItems: 16 })),
});

export const KASH_MANDATE_BODY_SCHEMA: ObjectSchema = S.object(
  {
    id: S.string({ pattern: MANDATE_ID_PATTERN }),
    principal: PARTY,
    delegate: S.object({ key: KEY, kind: S.enum(...DELEGATE_KINDS), role: S.optional(text(64)) }, ["key", "kind"]),
    scope: MANDATE_SCOPE_SCHEMA,
    dates: S.object({ from: ISO, until: ISO }, ["from", "until"]),
    credentialStatus: STATUS_ENTRY_SCHEMA,
    practice: S.optional(S.boolean()),
  },
  ["id", "principal", "delegate", "scope", "dates", "credentialStatus"],
);

/** For JSON Schema export and tooling only — a mandate is presented beside what it authorised, never published. */
export const KASH_MANDATE_LEXICON: LexiconDef = {
  id: KASH_MANDATE_ID,
  nsid: KASH_MANDATE_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_MANDATE_BODY_SCHEMA,
  title: "A mandate",
  description:
    "A principal's signed grant to one key — a seat, an agent, a desk, a representative or another organisation — to sign within a scope until a date, revocable through its status entry (d91(a)). Every signature that is not the principal's own cites one. One link: no chain in this version. Presented beside what it authorised; never published.",
};
