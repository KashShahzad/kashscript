/**
 * Lists Extension — the trust list and the status list as public records (ECOSYSTEM d47(e), d62(d)5,
 * d91(d), (f); KS-N1, folding in KS-R5's note: *their formats already exist in attest and the wallet, so
 * this is publishing them, not redesigning them*).
 *
 *   kash.trust-list@1.0.0
 *     A publisher's signed, versioned list of issuers: attest's `kashscript-trust-list/1` payload, in clear,
 *     with d91's three assertions written on it — **identity** (this key is this organisation, at a grade),
 *     **standing** (listed · suspended · removed) and **scope** (the exact registered tags it may issue, and
 *     the references it may attest against) — with **issuer classes** (self-issuer · counterparty · assessor ·
 *     accredited body · insurer) and the floor version it binds its issuers to. The `format` literal is
 *     unchanged, so attest's verifier and the wallet read a list of this shape today; teaching them standing,
 *     class and scope is KS-Q4's. A checker that reads windows only agrees with the standing, because a
 *     suspended or removed entry must end its window (see `trustListFaults`).
 *
 *   kash.status-list@1.0.0
 *     An issuer's revocation bitstring: attest's `kashscript-status-list/1` payload, aligned to W3C Bitstring
 *     Status List v1.0, in clear. Its three terminal states (expired · superseded · withdrawn, d91) are
 *     KS-Q4's, because the verifier must learn them too.
 *
 * **One document, two forms.** The muffler record is the clear payload; attest signs the same document
 * as a DSSE envelope (`signTrustList` / `signStatusList` with `{ canonical: true }`, as `kash trust sign`
 * does). Both canonicalise with RFC 8785, so the record's CID is the hash of the very bytes the envelope
 * signs, and a mirror serves the envelope beside the record (d28: checking needs no server of ours). Nothing
 * here verifies a signature — lexicons is zero-dependency; attest does.
 *
 * Import path: `@kashscript/lexicons/extensions/lists`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";
import { DID, HEX64, TEXT, fault, type RecordFault } from "./refs";

/* ── shared pieces ─────────────────────────────────────────────────── */

/** Mirrors `@kashscript/attest/holder`'s constants; a test in muffler keeps them equal. */
export const TRUST_LIST_FORMAT = "kashscript-trust-list/1" as const;
export const STATUS_LIST_FORMAT = "kashscript-status-list/1" as const;

const UNIX = S.number({ integer: true, min: 0 });

/** d91(f)'s issuer classes. An assurance carries the assessor's liability; Indorania carries none for a fact. */
export const ISSUER_CLASSES = ["self-issuer", "counterparty", "assessor", "accredited-body", "insurer"] as const;
export type IssuerClass = (typeof ISSUER_CLASSES)[number];

/** d91(f)'s standing. Only `listed` lists; the other two say why an entry is still written down. */
export const STANDINGS = ["listed", "suspended", "removed"] as const;
export type Standing = (typeof STANDINGS)[number];

/** The floor an entry conforms to (d91(f): every trust entry cites the version it conforms to). */
export interface FloorRef {
  /** The floor's version, as its publisher names it — a draft's name until the floor is a record (IN-N2). */
  readonly version: string;
  /** The floor record's hash, once there is one. */
  readonly hash?: string;
}

const FLOOR = S.object({ version: TEXT(64), hash: S.optional(HEX64) }, ["version"]);

/** A key for a signer whose identifier is not self-certifying (attest's `PublicKeyEntry`). */
export interface ListedKey {
  readonly keyid: string;
  readonly alg: "Ed25519" | "ES256";
  /** 64 hex (Ed25519) or 66 hex, a compressed point (ES256). */
  readonly publicKeyHex: string;
}

const KEY = S.object(
  { keyid: TEXT(256), alg: S.enum("Ed25519", "ES256"), publicKeyHex: S.string({ pattern: /^(?:[0-9a-f]{64}|0[23][0-9a-f]{64})$/ }) },
  ["keyid", "alg", "publicKeyHex"],
);

/* ── kash.trust-list@1.0.0 ─────────────────────────────────────────── */

export const KASH_TRUST_LIST_NSID = "kash.trust-list" as const;
export const KASH_TRUST_LIST_ID = "kash.trust-list@1.0.0" as const;

export interface TrustListIssuer {
  /** The issuer's identifier — a `did:kash`, or a stable id when its keys are listed below. */
  readonly issuerId: string;
  /** A plain name a person can read (d44). */
  readonly label: string;
  readonly keys: readonly ListedKey[];
  /** Scope, part one: the exact registered tags it may issue — never a family (attest's rule). */
  readonly dsts: readonly string[];
  readonly validFromUnix: number;
  readonly validUntilUnix: number;
  /** Identity: which class of issuer this is (d91(f)). */
  readonly class: IssuerClass;
  /** Standing: listed, suspended or removed. A suspended or removed entry ends its window. */
  readonly standing: Standing;
  /** Identity: the grade at which this key was shown to be this organisation's (d91(d)); 3 is the organisation signing as itself. */
  readonly grade?: 0 | 1 | 2 | 3;
  /** Scope, part two: the references — rules, standards' clauses — it may attest against, by id and hash. */
  readonly references?: readonly { readonly id: string; readonly hash?: string }[];
  /** This entry's floor, where it differs from the list's. */
  readonly floor?: FloorRef;
}

export interface TrustListBody {
  readonly format: typeof TRUST_LIST_FORMAT;
  readonly listId: string;
  /** Monotonic. A verifier holding several versions of one list uses the highest. */
  readonly version: number;
  /** The self-certifying `did:kash` that signs the envelope. */
  readonly publisher: string;
  readonly issuedAtUnix: number;
  readonly validFromUnix: number;
  readonly validUntilUnix: number;
  /** The floor every entry is bound to, unless its own says otherwise. */
  readonly floor: FloorRef;
  readonly issuers: readonly TrustListIssuer[];
  readonly practice?: boolean;
}

const TRUST_LIST_ISSUER: ObjectSchema = S.object(
  {
    issuerId: TEXT(256),
    label: TEXT(120),
    keys: S.array(KEY, { maxItems: 16 }),
    dsts: S.array(TEXT(256), { minItems: 1, maxItems: 64 }),
    validFromUnix: UNIX,
    validUntilUnix: UNIX,
    class: S.enum(...ISSUER_CLASSES),
    standing: S.enum(...STANDINGS),
    grade: S.optional(S.number({ integer: true, min: 0, max: 3 })),
    references: S.optional(S.array(S.object({ id: TEXT(256), hash: S.optional(HEX64) }, ["id"]), { minItems: 1, maxItems: 64 })),
    floor: S.optional(FLOOR),
  },
  ["issuerId", "label", "keys", "dsts", "validFromUnix", "validUntilUnix", "class", "standing"],
);

export const KASH_TRUST_LIST_BODY_SCHEMA: ObjectSchema = S.object(
  {
    format: S.literal(TRUST_LIST_FORMAT),
    listId: TEXT(128),
    version: S.number({ integer: true, min: 1 }),
    publisher: DID,
    issuedAtUnix: UNIX,
    validFromUnix: UNIX,
    validUntilUnix: UNIX,
    floor: FLOOR,
    issuers: S.array(TRUST_LIST_ISSUER, { maxItems: 4096 }),
    practice: S.optional(S.boolean()),
  },
  ["format", "listId", "version", "publisher", "issuedAtUnix", "validFromUnix", "validUntilUnix", "floor", "issuers"],
);

export const KASH_TRUST_LIST_LEXICON: LexiconDef = {
  id: KASH_TRUST_LIST_ID,
  nsid: KASH_TRUST_LIST_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_TRUST_LIST_BODY_SCHEMA,
  title: "A trust list",
  description:
    "A publisher's versioned list of issuers — attest's kashscript-trust-list/1 payload in clear — with d91's three assertions: identity (the key, its class and grade), standing (listed, suspended, removed) and scope (the exact tags and the references it may attest against), each entry bound to a floor version. Signed by its publisher as DSSE; any host may mirror it.",
};

/** The rules the shape cannot write. Call after the body has the shape. */
export function trustListFaults(body: TrustListBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (body.validFromUnix > body.validUntilUnix) out.push(fault("WINDOW", ["validUntilUnix"], "a list's window ends after it starts"));
  body.issuers.forEach((e, i) => {
    if (e.validFromUnix > e.validUntilUnix) out.push(fault("WINDOW", ["issuers", i, "validUntilUnix"], "an entry's window ends after it starts"));
    if (e.standing !== "listed" && e.validUntilUnix > body.issuedAtUnix) {
      out.push(
        fault(
          "STANDING_WINDOW",
          ["issuers", i, "validUntilUnix"],
          `a ${e.standing} entry ends its window no later than the list's issuedAtUnix, so a checker that reads windows only agrees with its standing`,
        ),
      );
    }
  });
  return out;
}

/* ── kash.status-list@1.0.0 ────────────────────────────────────────── */

export const KASH_STATUS_LIST_NSID = "kash.status-list" as const;
export const KASH_STATUS_LIST_ID = "kash.status-list@1.0.0" as const;

/** W3C Bitstring Status List's purposes attest reads today. The three terminal states of d91 are KS-Q4's. */
export const STATUS_PURPOSES = ["revocation", "suspension"] as const;
export type StatusPurpose = (typeof STATUS_PURPOSES)[number];

export interface StatusListBody {
  readonly format: typeof STATUS_LIST_FORMAT;
  readonly type: "BitstringStatusList";
  /** The https URL the list is served at; a record's `credentialStatus` points here. Shared by many records, never one per record. */
  readonly id: string;
  /** The keyid that signs the envelope. */
  readonly issuer: string;
  readonly statusPurpose: StatusPurpose;
  /** `u` + base64url(GZIP(bitstring)), at least 131,072 entries — attest enforces the floor when it signs. */
  readonly encodedList: string;
  /** The issuer's own claim of when this list was true. */
  readonly issuedAtUnix: number;
  readonly validUntilUnix: number | null;
  /** Milliseconds a verifier may cache it. */
  readonly ttl?: number;
  readonly practice?: boolean;
}

export const KASH_STATUS_LIST_BODY_SCHEMA: ObjectSchema = S.object(
  {
    format: S.literal(STATUS_LIST_FORMAT),
    type: S.literal("BitstringStatusList"),
    id: S.string({ pattern: /^https:\/\/[^\s]+$/, maxLength: 2048 }),
    issuer: TEXT(256),
    statusPurpose: S.enum(...STATUS_PURPOSES),
    encodedList: S.string({ pattern: /^u[A-Za-z0-9_-]+$/ }),
    issuedAtUnix: UNIX,
    validUntilUnix: S.union(UNIX, S.literal(null)),
    ttl: S.optional(S.number({ integer: true, min: 0 })),
    practice: S.optional(S.boolean()),
  },
  ["format", "type", "id", "issuer", "statusPurpose", "encodedList", "issuedAtUnix", "validUntilUnix"],
);

export const KASH_STATUS_LIST_LEXICON: LexiconDef = {
  id: KASH_STATUS_LIST_ID,
  nsid: KASH_STATUS_LIST_NSID,
  semver: { major: 1, minor: 0, patch: 0 },
  bodySchema: KASH_STATUS_LIST_BODY_SCHEMA,
  title: "A status list",
  description:
    "An issuer's revocation or suspension bitstring — attest's kashscript-status-list/1 payload in clear, aligned to W3C Bitstring Status List v1.0: the list's URL, its issuer, purpose, the encoded bitstring, and the time the issuer says it was true. Signed by its issuer as DSSE; any host may mirror it.",
};

export function statusListFaults(body: StatusListBody): readonly RecordFault[] {
  const out: RecordFault[] = [];
  if (body.validUntilUnix !== null && body.validUntilUnix < body.issuedAtUnix) {
    out.push(fault("VALID_UNTIL", ["validUntilUnix"], "a list is valid until after the time it was issued"));
  }
  return out;
}

/* ── bundle ────────────────────────────────────────────────────────── */

/** The two lists. Public, organisation-authored, mirrorable (d62(d)5). */
export const LIST_LEXICONS: readonly LexiconDef[] = [KASH_TRUST_LIST_LEXICON, KASH_STATUS_LIST_LEXICON];
