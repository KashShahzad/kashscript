// ============================================================================
// @kashscript/identity-server — store contracts, in-memory reference stores,
// and the IdentityServer composition root.
// ----------------------------------------------------------------------------
// The store-backed operations (issue/consume handshake, resolve/revoke DID,
// read/write PDS) take their durable dependency as an injected interface.
// `createIdentityServer(...)` composes them into one instance whose methods
// match the @duedale/identity-kernel surface. The venture injects Prisma/Redis
// (and muffler for the PDS) adapters that implement these interfaces; the
// `InMemory*` classes below are the reference impls that make the surface
// covered + testable without any infrastructure.
// ============================================================================

import type { SignedCountersignRequest, SignedCountersignWithdrawal } from "@kashscript/attest";

import {
  createCountersignRequest,
  decodeCrockford32,
  requestIdForCapability,
  withdrawCountersignRequest,
  type CreateCountersignRequestInput,
  type CreatedCountersignRequest,
} from "./countersign";
import { resolveDidPubkey, revokeGuestDid } from "./did";
import type { IdentityMetadataRecord, IdentityMetadataStore } from "./did";
import { issueGuestDid } from "./guest-did";
import { buildHandshakeChallenge, HANDSHAKE_CHALLENGE_TTL_SECONDS } from "./handshake";
import { assertDidWellFormed, nowUnix } from "./internal";
import { readPdsRecord, writePdsRecord } from "./pds";
import type { PdsStore, PdsStoredRecord } from "./pds";
import type {
  Did,
  GuestDidIssuanceRequest,
  HandshakeChallenge,
  IssueGuestDidResult,
  PdsCollection,
  PdsRecord,
  ReadPdsRecordResult,
  ResolveDidPubkeyResult,
  RevokeGuestDidResult,
  WritePdsRecordResult,
} from "./types";

// ----------------------------------------------------------------------------
// Challenge store contract
// ----------------------------------------------------------------------------

/**
 * Store contract for single-use handshake challenges. The venture injects a
 * Redis-backed adapter (with native key TTL); `InMemoryChallengeStore` is the
 * reference impl.
 */
export interface ChallengeStore {
  /** Persist `challenge` under its id with a `ttlSeconds` expiry. */
  put(challenge: HandshakeChallenge, ttlSeconds: number): Promise<void>;
  /** Atomically fetch-and-delete a challenge by id (one-time use). Returns null
   *  if unknown, already consumed, or expired at `nowSec`. */
  consume(challengeId: string, nowSec: number): Promise<HandshakeChallenge | null>;
}

// ----------------------------------------------------------------------------
// Countersign request store contract
// ----------------------------------------------------------------------------

/**
 * Store contract for countersign requests — the *hosted* delivery mode, where a
 * requester's own host exchanges a capability secret for the request it minted.
 * (The *carried* mode needs no store at all: the request travels as bytes.)
 *
 * **Two absences are the contract, not an oversight.**
 *
 * There is no `list`, no `find` and no query of any kind: the only way to reach
 * a request is to already hold the secret that addresses it. Presentation,
 * never lookup (ECOSYSTEM decision 41).
 *
 * And nothing here stores an *acceptance*. A countersignature is handed back to
 * the caller and never persisted by this package, so "what has this counterparty
 * signed" has no answer to give — which is a property of the schema rather than
 * a feature nobody has implemented yet.
 */
export interface CountersignRequestStore {
  /** Persist a minted request under its `requestId` with a `ttlSeconds` expiry. */
  put(request: SignedCountersignRequest, ttlSeconds: number): Promise<void>;
  /**
   * Fetch a request by id. Returns null when unknown, withdrawn or expired at
   * `nowSec`. **Not** fetch-and-delete: a request is answerable once but may be
   * read more than once — a counterparty who opens the link, reads it, and
   * closes the tab has to be able to come back.
   */
  get(requestId: string, nowSec: number): Promise<SignedCountersignRequest | null>;
  /** Mark a request answered, so a replayed link cannot produce a second
   *  signature. Returns false when it was already answered or is unknown. */
  markAnswered(requestId: string, nowSec: number): Promise<boolean>;
  /** Record that the requester withdrew it. Withdrawal is a signed artifact
   *  (`withdrawCountersignRequest`); this only stops the host serving it. */
  markWithdrawn(requestId: string, nowSec: number): Promise<void>;
}

// ----------------------------------------------------------------------------
// In-memory reference stores
// ----------------------------------------------------------------------------

/** In-memory single-use challenge store. Deletes on consume regardless of
 *  expiry, so a replayed id never verifies twice. */
export class InMemoryChallengeStore implements ChallengeStore {
  private readonly map = new Map<string, HandshakeChallenge>();

  async put(challenge: HandshakeChallenge, _ttlSeconds: number): Promise<void> {
    this.map.set(challenge.challengeId, challenge);
  }

  async consume(challengeId: string, nowSec: number): Promise<HandshakeChallenge | null> {
    const challenge = this.map.get(challengeId);
    if (challenge === undefined) return null;
    this.map.delete(challengeId); // one-time use: remove even if expired
    if (challenge.expiresAtUnix <= nowSec) return null;
    return challenge;
  }
}

/**
 * In-memory countersign request store. Reference impl — a venture injects a
 * durable adapter with the same two absences (no list, no acceptances).
 */
export class InMemoryCountersignRequestStore implements CountersignRequestStore {
  private readonly map = new Map<
    string,
    { request: SignedCountersignRequest; answered: boolean; withdrawn: boolean }
  >();

  async put(request: SignedCountersignRequest, _ttlSeconds: number): Promise<void> {
    this.map.set(request.body.requestId, { request, answered: false, withdrawn: false });
  }

  async get(requestId: string, nowSec: number): Promise<SignedCountersignRequest | null> {
    const entry = this.map.get(requestId);
    if (entry === undefined) return null;
    if (entry.withdrawn || entry.answered) return null;
    if (entry.request.body.expiresAtUnix <= nowSec) return null;
    return entry.request;
  }

  async markAnswered(requestId: string, nowSec: number): Promise<boolean> {
    const entry = this.map.get(requestId);
    if (entry === undefined || entry.answered || entry.withdrawn) return false;
    if (entry.request.body.expiresAtUnix <= nowSec) return false;
    entry.answered = true;
    return true;
  }

  async markWithdrawn(requestId: string, _nowSec: number): Promise<void> {
    const entry = this.map.get(requestId);
    if (entry !== undefined) entry.withdrawn = true;
  }

  /**
   * Test-only view of one entry's stored state, so a test can assert that
   * declining changed nothing. Takes an id the caller already holds and returns
   * a copy; it enumerates nothing and is not part of the store contract.
   */
  inspectForTest(requestId: string): { answered: boolean; withdrawn: boolean } | null {
    const entry = this.map.get(requestId);
    return entry === undefined ? null : { answered: entry.answered, withdrawn: entry.withdrawn };
  }
}

/** In-memory DID metadata store. */
export class InMemoryIdentityMetadataStore implements IdentityMetadataStore {
  private readonly map = new Map<Did, IdentityMetadataRecord>();

  async get(did: Did): Promise<IdentityMetadataRecord | null> {
    return this.map.get(did) ?? null;
  }

  async put(record: IdentityMetadataRecord): Promise<void> {
    this.map.set(record.did, record);
  }

  async revoke(did: Did, atUnix: number): Promise<IdentityMetadataRecord | null> {
    const prev = this.map.get(did);
    if (prev === undefined) return null;
    this.map.set(did, { ...prev, revokedAtUnix: atUnix });
    return prev;
  }
}

/** In-memory revisioned PDS store. The durable PDS is `@kashscript/muffler` (M3);
 *  this reference keeps the identity-server PDS contract covered + testable. */
export class InMemoryPdsStore implements PdsStore {
  private readonly provisioned = new Set<Did>();
  private readonly records = new Map<string, PdsStoredRecord>();

  private key(did: Did, collection: PdsCollection, recordKey: string): string {
    return `${did} ${collection} ${recordKey}`;
  }

  /** Reference-impl helper: mark a DID's PDS provisioned. */
  provision(did: Did): void {
    this.provisioned.add(did);
  }

  async isProvisioned(did: Did): Promise<boolean> {
    return this.provisioned.has(did);
  }

  async read(did: Did, collection: PdsCollection, recordKey: string): Promise<PdsStoredRecord | null> {
    return this.records.get(this.key(did, collection, recordKey)) ?? null;
  }

  async put(did: Did, stored: PdsStoredRecord): Promise<void> {
    this.records.set(this.key(did, stored.record.collection, stored.record.recordKey), stored);
  }
}

// ----------------------------------------------------------------------------
// The IdentityServer composition root
// ----------------------------------------------------------------------------

/** The stores an IdentityServer depends on. Any subset may be omitted; omitted
 *  stores default to the in-memory reference impl. */
export interface IdentityServerStores {
  readonly challengeStore: ChallengeStore;
  readonly metadataStore: IdentityMetadataStore;
  readonly pdsStore: PdsStore;
  readonly countersignStore: CountersignRequestStore;
}

/**
 * A configured identity authority. Its methods mirror the
 * @duedale/identity-kernel runtime surface; together with the storeless
 * exports (`verifyHandshakeSignature`, `issueGuestDid`, `sha256Hex*`, …) this
 * fully covers the kernel.
 */
export interface IdentityServer {
  /** Mint a guest DID AND persist its envelope so it resolves + can be revoked. */
  issueGuestDid(request: GuestDidIssuanceRequest): Promise<IssueGuestDidResult>;
  /** Issue a single-use, 300s handshake challenge for `did` and persist it. */
  issueHandshakeChallenge(did: Did): Promise<HandshakeChallenge>;
  /** Atomically consume a challenge by id (one-time). Null if unknown/expired. */
  consumeHandshakeChallenge(challengeId: string): Promise<HandshakeChallenge | null>;
  resolveDidPubkey(did: Did): Promise<ResolveDidPubkeyResult>;
  revokeGuestDid(did: Did): Promise<RevokeGuestDidResult>;
  writePdsRecord(did: Did, record: PdsRecord): Promise<WritePdsRecordResult>;
  readPdsRecord(did: Did, collection: PdsCollection, recordKey: string): Promise<ReadPdsRecordResult>;
  /** Mint a countersign request AND persist it so the *hosted* delivery mode
   *  can serve it. The capability secret comes back to the caller once and is
   *  never stored. */
  createCountersignRequest(input: CreateCountersignRequestInput): Promise<CreatedCountersignRequest>;
  /** Exchange a capability secret for the request it addresses. The ONLY way in:
   *  there is no listing, and the `requestId` alone opens nothing. */
  resolveCountersignRequest(capabilitySecretB32: string): Promise<SignedCountersignRequest | null>;
  /** Consume a request so a replayed link cannot produce a second signature. */
  markCountersignRequestAnswered(requestId: string): Promise<boolean>;
  /** Sign a withdrawal and stop serving the request. The signed artifact is what
   *  a stranger checks; the store change only affects this host. */
  withdrawCountersignRequest(
    request: SignedCountersignRequest,
    requesterPrivateKey: Uint8Array,
  ): Promise<SignedCountersignWithdrawal>;
}

/**
 * Composes the store-backed identity operations into one instance. Omitted
 * stores fall back to the in-memory reference impls, so `createIdentityServer()`
 * with no arguments yields a fully working (non-durable) authority for tests
 * and local development.
 */
export function createIdentityServer(stores: Partial<IdentityServerStores> = {}): IdentityServer {
  const challengeStore = stores.challengeStore ?? new InMemoryChallengeStore();
  const metadataStore = stores.metadataStore ?? new InMemoryIdentityMetadataStore();
  const pdsStore = stores.pdsStore ?? new InMemoryPdsStore();
  const countersignStore = stores.countersignStore ?? new InMemoryCountersignRequestStore();

  return {
    async issueGuestDid(request: GuestDidIssuanceRequest): Promise<IssueGuestDidResult> {
      const result = await issueGuestDid(request);
      if (result.ok) {
        await metadataStore.put({
          did: result.issuance.did,
          isGuestDid: true,
          issuedAtUnix: result.issuance.pubkey.issuedAtUnix,
          expiresAtUnix: result.issuance.expiresAtUnix,
          pdsEndpoint: null,
          revokedAtUnix: null,
        });
      }
      return result;
    },

    async issueHandshakeChallenge(did: Did): Promise<HandshakeChallenge> {
      assertDidWellFormed(did);
      const challenge = buildHandshakeChallenge(did);
      await challengeStore.put(challenge, HANDSHAKE_CHALLENGE_TTL_SECONDS);
      return challenge;
    },

    consumeHandshakeChallenge(challengeId: string): Promise<HandshakeChallenge | null> {
      return challengeStore.consume(challengeId, nowUnix());
    },

    resolveDidPubkey(did: Did): Promise<ResolveDidPubkeyResult> {
      return resolveDidPubkey(metadataStore, did);
    },

    revokeGuestDid(did: Did): Promise<RevokeGuestDidResult> {
      return revokeGuestDid(metadataStore, did);
    },

    writePdsRecord(did: Did, record: PdsRecord): Promise<WritePdsRecordResult> {
      return writePdsRecord(pdsStore, did, record);
    },

    readPdsRecord(did: Did, collection: PdsCollection, recordKey: string): Promise<ReadPdsRecordResult> {
      return readPdsRecord(pdsStore, did, collection, recordKey);
    },

    async createCountersignRequest(
      input: CreateCountersignRequestInput,
    ): Promise<CreatedCountersignRequest> {
      const created = await createCountersignRequest(input);
      const ttl = created.request.body.expiresAtUnix - created.request.body.issuedAtUnix;
      await countersignStore.put(created.request, ttl);
      return created;
    },

    async resolveCountersignRequest(
      capabilitySecretB32: string,
    ): Promise<SignedCountersignRequest | null> {
      // The secret is the address. Deriving the id from it here is what makes
      // holding an id — which is public, quotable and loggable — useless.
      const requestId = await requestIdForCapability(decodeCrockford32(capabilitySecretB32));
      return countersignStore.get(requestId, nowUnix());
    },

    markCountersignRequestAnswered(requestId: string): Promise<boolean> {
      return countersignStore.markAnswered(requestId, nowUnix());
    },

    async withdrawCountersignRequest(
      request: SignedCountersignRequest,
      requesterPrivateKey: Uint8Array,
    ): Promise<SignedCountersignWithdrawal> {
      const withdrawal = await withdrawCountersignRequest({ request, requesterPrivateKey });
      await countersignStore.markWithdrawn(request.body.requestId, nowUnix());
      return withdrawal;
    },
  };
}
