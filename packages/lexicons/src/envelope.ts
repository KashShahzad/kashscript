/**
 * The Kash-Event Envelope.
 *
 * Every record stored in a PDS conforms to this shape. The envelope is
 * lexicon-agnostic — only the `body` shape is governed by a specific lexicon.
 * Signatures are bound by a Domain-Separation Tag (DST) to prevent
 * cross-protocol replay (see Identity Protocol §5.5).
 */

import { S, type ObjectSchema, type Schema } from "./schema";
import {
  KASH_RECORD_DST,
  type CID,
  type DID,
  type Iso8601,
  type KashRecordDST,
  type LexiconId,
  type Multibase,
  type SignatureAlgorithm,
} from "./types";

/* ── interfaces ─────────────────────────────────────────────────── */

/** Cryptographic signature produced by a Signer under a `purpose: "active"` key. */
export interface KashSignature {
  /** verificationMethod id, e.g., "did:kash:5g7q…#sig-1". */
  readonly kid: string;
  /** Must match the verification method's `algorithm` field at verification time. */
  readonly alg: SignatureAlgorithm;
  /** Multibase-encoded signature bytes (z-prefix, base58-btc). */
  readonly sig: Multibase;
  /** Fixed DST: "kash-record-v1\n". Prevents cross-protocol replay. */
  readonly dst: KashRecordDST;
}

/** Header carried by every record, lexicon-agnostic. */
export interface KashHeader {
  /** Author DID. */
  readonly did: DID;
  /** Lexicon ID — <nsid>@<semver>. */
  readonly lexicon: LexiconId;
  /** Issued-at timestamp (ISO-8601 with offset). */
  readonly iat: Iso8601;
  /** Per-record nonce — 32-128 hex chars (≥128 bits of entropy). */
  readonly nonce: string;
  /** CID of the canonicalized body (computed at envelope-build time). */
  readonly cid: CID;
  /** Optional monotonic sequence within this (did, nsid) collection. */
  readonly seq?: number;
  /** Optional CID of the previous record in the same collection. */
  readonly prev?: CID;
  /** Optional record key — opaque, app-chosen. */
  readonly rkey?: string;
}

/** Standard Kash-Event envelope. Every PDS record IS a KashEvent<Body>. */
export interface KashEvent<Body = unknown> {
  readonly header: KashHeader;
  readonly body: Body;
  readonly signature: KashSignature;
}

/* ── runtime schemas ────────────────────────────────────────────── */

export const SIGNATURE_SCHEMA: ObjectSchema = S.object(
  {
    kid: S.string({ minLength: 1, maxLength: 256 }),
    alg: S.enum("ed25519", "es256", "bls12-381-g2"),
    sig: S.string({ format: "multibase" }),
    dst: S.literal(KASH_RECORD_DST),
  },
  ["kid", "alg", "sig", "dst"],
);

export const HEADER_SCHEMA: ObjectSchema = S.object(
  {
    did:     S.string({ format: "did-ks" }),
    lexicon: S.string({ format: "lexicon-id" }),
    iat:     S.string({ format: "iso8601" }),
    nonce:   S.string({ minLength: 32, maxLength: 128, pattern: /^[0-9a-f]+$/ }),
    cid:     S.string({ format: "cid" }),
    seq:     S.optional(S.number({ integer: true, min: 0 })),
    prev:    S.optional(S.string({ format: "cid" })),
    rkey:    S.optional(S.string({ minLength: 1, maxLength: 128 })),
  },
  ["did", "lexicon", "iat", "nonce", "cid"],
);

/** Envelope schema parameterised by the body's schema. */
export function envelopeSchema(body: Schema): ObjectSchema {
  return S.object(
    {
      header: HEADER_SCHEMA,
      body,
      signature: SIGNATURE_SCHEMA,
    },
    ["header", "body", "signature"],
  );
}

/** Envelope schema that accepts any body (used during pre-lexicon shape validation). */
export const BASE_ENVELOPE_SCHEMA: ObjectSchema = envelopeSchema(S.any());

/* ── shared record-reference shape ───────────────────────────────
 *
 * `RecordRef` points to another record by (CID, AT-URI). It is the
 * canonical cross-record link used by every lexicon that references
 * another record (e.g., social replies/reposts, trade receipts → offers,
 * trade.status → receipt, trade.receipt.linkedPost → social.post).
 *
 * Lives in the framework — not in any extension — so domain content
 * doesn't have to re-invent the shape.
 */

export interface RecordRef {
  readonly cid: CID;
  readonly uri: string;
}

export const AT_URI_PATTERN = /^at:\/\/did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}\/[a-z0-9.-]+\/[A-Za-z0-9_-]+$/;

export const RECORD_REF_SCHEMA: ObjectSchema = S.object(
  {
    cid: S.string({ format: "cid" }),
    uri: S.string({ pattern: AT_URI_PATTERN }),
  },
  ["cid", "uri"],
);
