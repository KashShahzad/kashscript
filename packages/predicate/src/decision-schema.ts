/**
 * `kash.decision@1.1.0` — the decision receipt's shape (moved here from
 * `@kashscript/lexicons` in KS-Q1b).
 *
 * **Why here.** A decision is the person's own record: a credential they hold,
 * issued to them and shown by their choice. d59 makes lexicons the home of
 * public, organisation-authored records — so the decision's shape lives with
 * the package that issues and checks it, as attest owns the predicate
 * credential's. It is built with the lexicons' schema DSL, and never published
 * as a record.
 *
 * 1.1.0 adds `adoption`: the anchor's adoption the decision was made under
 * (d85(d)). A 1.0.0 decision is a 1.1.0 decision without one.
 */

import type { LexiconDef } from "@kashscript/lexicons/registry";
import { S, type ObjectSchema } from "@kashscript/lexicons/schema";
import { DECISION_OUTCOMES, type DecisionOutcome } from "@kashscript/lexicons/extensions/door";

export const KASH_DECISION_NSID = "kash.decision" as const;
export const KASH_DECISION_ID = "kash.decision@1.1.0" as const;

export type DecidedBy =
  | { readonly kind: "standing"; readonly standing: string }
  | { readonly kind: "person"; readonly role: string; readonly seat: string; readonly signature: string };

export interface DecisionBody {
  readonly rule: { readonly id: string; readonly version: number; readonly hash: string };
  /** The anchor's adoption the door decided under. Absent at the rule author's own door. */
  readonly adoption?: { readonly id: string; readonly hash: string };
  readonly outcome: DecisionOutcome;
  /** Codes from the rule's reasons. At least one — node rule 11. */
  readonly reasons: readonly string[];
  readonly rows: { readonly fired: readonly string[]; readonly missing: readonly string[] };
  /** SHA-256 hex of each receipt relied on. Never the receipt. */
  readonly reliedOn: readonly string[];
  readonly decidedBy: DecidedBy;
  readonly automatic: boolean;
  /** A refusal or a partial grant names the unmet criterion and that the receipts were read (P3). */
  readonly refusal?: { readonly unmet: readonly string[]; readonly receiptsRead: true };
  readonly decidedAt: string;
  readonly contestUntil: string;
  readonly practice?: boolean;
}

const B58_DID = "did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}";
const HEX64 = S.string({ pattern: /^[0-9a-f]{64}$/ });
const SLUG = S.string({ pattern: /^[a-z0-9][a-z0-9-]{0,62}$/ });
const ISO = S.string({ format: "iso8601" });

export const KASH_DECISION_BODY_SCHEMA: ObjectSchema = S.object(
  {
    rule: S.object({ id: S.string({ pattern: new RegExp(`^${B58_DID}/rule/[a-z0-9][a-z0-9-]{0,62}$`) }), version: S.number({ integer: true, min: 1 }), hash: HEX64 }, ["id", "version", "hash"]),
    adoption: S.optional(S.object({ id: S.string({ pattern: new RegExp(`^${B58_DID}/adoption/[a-z0-9][a-z0-9-]{0,62}$`) }), hash: HEX64 }, ["id", "hash"])),
    outcome: S.enum(...DECISION_OUTCOMES),
    reasons: S.array(SLUG, { minItems: 1, maxItems: 32 }),
    rows: S.object({ fired: S.array(SLUG, { maxItems: 32 }), missing: S.array(SLUG, { maxItems: 32 }) }, ["fired", "missing"]),
    reliedOn: S.array(HEX64, { maxItems: 256 }),
    decidedBy: S.union(
      S.object({ kind: S.literal("standing"), standing: S.string({ pattern: new RegExp(`^standing:${B58_DID}$`) }) }, ["kind", "standing"]),
      S.object(
        { kind: S.literal("person"), role: S.string({ minLength: 1, maxLength: 64 }), seat: S.string({ format: "did-ks" }), signature: S.string({ pattern: /^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/, maxLength: 1024 }) },
        ["kind", "role", "seat", "signature"],
      ),
    ),
    automatic: S.boolean(),
    refusal: S.optional(S.object({ unmet: S.array(SLUG, { minItems: 1, maxItems: 32 }), receiptsRead: S.literal(true) }, ["unmet", "receiptsRead"])),
    decidedAt: ISO,
    contestUntil: ISO,
    practice: S.optional(S.boolean()),
  },
  ["rule", "outcome", "reasons", "rows", "reliedOn", "decidedBy", "automatic", "decidedAt", "contestUntil"],
);

/** For JSON Schema export and tooling only — a decision is never registered for publishing. */
export const KASH_DECISION_LEXICON: LexiconDef = {
  id: KASH_DECISION_ID,
  nsid: KASH_DECISION_NSID,
  semver: { major: 1, minor: 1, patch: 0 },
  bodySchema: KASH_DECISION_BODY_SCHEMA,
  title: "A decision receipt",
  description:
    "The outcome under one version of a rule (and the anchor's adoption it was made under), its reasons, the rows that fired and the hashes of the receipts relied on — never their content. The person's own record: signed to them, never published.",
};
