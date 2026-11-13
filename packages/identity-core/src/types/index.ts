/**
 * @kashscript/identity-core/types — canonical protocol-type home.
 *
 * Single source of truth for the did:kash protocol's data shapes and
 * service SPIs. Two groups:
 *
 *   1. RUNTIME MODEL (re-exported from the modules that own the
 *      implementing code) — DID helpers, the DID Document, verification
 *      methods, service endpoints. These types travel with the functions
 *      that produce/consume them (`deriveDid`, `createDidDocument`,
 *      `verifyEventAgainstDocument`), so they're re-exported here rather
 *      than redefined.
 *
 *   2. PROTOCOL SPI (defined here) — the resolver, registrar, and Personal
 *      Data Store interfaces a hosted service would implement. No runtime
 *      code in identity-core implements these (resolution + PDS hosting are
 *      sovereign, out-of-package concerns); the interfaces live here so a
 *      `services/kash-resolver` or a third-party PDS can target one
 *      authoritative contract.
 *
 * This module absorbs the former standalone `@kashscript/identity`
 * package. That package now re-exports from here (back-compat shim).
 * Everything is `did:kash` — the legacy `did:ks` shapes are gone.
 */

/* ── Runtime model (owned by sibling modules) ─────────────────────── */

export type { KashDid } from "../did";
export { deriveDid, parseDid, isKashDid } from "../did";

export type {
  DidDocument,
  VerificationMethod,
  VerificationMethodType,
  ServiceEndpoint,
  PdsServiceType,
  CreateDidDocumentInput,
} from "../document";
export { createDidDocument, verifyEventAgainstDocument } from "../document";

import type { KashDid } from "../did";
import type { DidDocument, VerificationMethod } from "../document";

/**
 * Protocol version for the did:kash data model + service SPIs. Distinct
 * from the identity-core *package* version (`IDENTITY_CORE_VERSION`):
 * this tracks the wire-level protocol shape (DID format, DID Document,
 * PDS record shape). Formerly exported by the standalone
 * `@kashscript/identity` package, which has been removed.
 */
export const IDENTITY_PROTOCOL_VERSION = "1.0.0" as const;

/* ── Protocol SPI (defined here — no in-package implementation) ───── */

/**
 * Key algorithms the protocol recognises. `ed25519` is the only one the
 * core signer implements today; `secp256k1` is reserved for the
 * chain-settlement path (Trade) and EVM-account binding.
 */
export type KeyAlgorithm = "ed25519" | "secp256k1";

/**
 * Resolve a `did:kash` to its DID Document.
 *
 * For self-certifying single-key DIDs the document can be reconstructed
 * locally from the DID itself (the key IS the identifier) — no network
 * needed; see `createDidDocument`. A resolver is only required when the
 * DID has a *mutated* document (rotated keys, added services) whose
 * history lives off-DID. Implemented by a hosted `services/kash-resolver`,
 * never by identity-core.
 */
export interface DidResolver {
  resolve(did: KashDid): Promise<DidDocument | null>;
}

/**
 * Create / update / deactivate a DID Document. The mutation surface a
 * hosted registrar exposes. Pure-local single-key identities never need
 * this; multi-service or rotated identities do.
 */
export interface DidRegistrar {
  create(input: {
    readonly keys: readonly VerificationMethod[];
    readonly pds: string;
  }): Promise<DidDocument>;
  update(did: KashDid, patch: Partial<DidDocument>): Promise<DidDocument>;
  deactivate(did: KashDid): Promise<void>;
}

/* ── Personal Data Store (PDS) SPI ────────────────────────────────── */

/**
 * A single record in a user's PDS. `uri` is an AT-URI (`at://…`) so the
 * shape is interoperable with AT-Protocol tooling; `owner` is the did:kash
 * that signed it.
 */
export interface PdsRecord<T = unknown> {
  readonly cid: string;
  readonly uri: `at://${string}`;
  readonly collection: string;
  readonly rkey: string;
  readonly owner: KashDid;
  readonly value: T;
  readonly createdAt: string;
}

export interface PdsCollection {
  readonly nsid: string;
  readonly schema: string;
}

/**
 * A PDS host. The Foundry holds none of this — PDS nodes are sovereign,
 * run by the user or a host they choose. This is the contract a host
 * implements; identity-core never calls it.
 */
export interface PdsNode {
  readonly url: string;
  readonly operator: KashDid;
  list<T>(owner: KashDid, collection: string): Promise<readonly PdsRecord<T>[]>;
  get<T>(uri: string): Promise<PdsRecord<T> | null>;
  put<T>(input: {
    readonly owner: KashDid;
    readonly collection: string;
    readonly rkey?: string;
    readonly value: T;
  }): Promise<PdsRecord<T>>;
  delete(uri: string): Promise<void>;
}
