// ============================================================================
// @kashscript/identity-server — DID resolution + guest-DID revocation
// ----------------------------------------------------------------------------
// `did:kash` is self-certifying: the 32-byte Ed25519 public key is intrinsic
// to the identifier and extracted synchronously via identity-core's `parseDid`
// — the pubkey is NEVER sourced from client-supplied input. The identity
// metadata store supplies the *mutable* envelope (guest flag, issued/expiry
// timestamps, PDS endpoint, revocation status) and gates NOT_FOUND / REVOKED.
//
// The store is an injected dependency (interface below); the durable adapter
// (Prisma/Redis) stays venture-side. `stores.ts` ships an in-memory reference.
// ============================================================================

import { parseDid } from "@kashscript/identity-core";
import { assertDidWellFormed, bytesToBase64, newTraceId, nowUnix } from "./internal";
import type {
  Did,
  DidPubkey,
  ResolveDidPubkeyResult,
  RevokeGuestDidResult,
  UnixSeconds,
} from "./types";

/**
 * The mutable metadata envelope an identity authority holds for a DID. The
 * public key itself is NOT stored here — it is intrinsic to the self-certifying
 * `did:kash` and re-derived via `parseDid` on every resolution.
 */
export interface IdentityMetadataRecord {
  readonly did: Did;
  readonly isGuestDid: boolean;
  readonly issuedAtUnix: UnixSeconds;
  /** Null for permanent DIDs; populated for guest / time-bound DIDs. */
  readonly expiresAtUnix: UnixSeconds | null;
  readonly pdsEndpoint: string | null;
  /** Non-null once the DID has been explicitly revoked. */
  readonly revokedAtUnix: UnixSeconds | null;
}

/**
 * Store contract for DID metadata. The venture injects a Prisma/Redis-backed
 * adapter; `InMemoryIdentityMetadataStore` (stores.ts) is the reference impl.
 */
export interface IdentityMetadataStore {
  /** The metadata envelope for `did`, or null if the authority has no record. */
  get(did: Did): Promise<IdentityMetadataRecord | null>;
  /** Register / overwrite a DID's metadata envelope (e.g. at guest-DID mint). */
  put(record: IdentityMetadataRecord): Promise<void>;
  /** Mark `did` revoked at `atUnix`; returns the prior record, or null if the
   *  DID was unknown. */
  revoke(did: Did, atUnix: UnixSeconds): Promise<IdentityMetadataRecord | null>;
}

/** Extracts the self-certifying Ed25519 public key from a `did:kash`, as
 *  standard base64. Assumes `did` already passed `assertDidWellFormed`. */
function pubkeyB64FromDid(did: Did): string {
  return bytesToBase64(parseDid(did));
}

/**
 * Resolves a KashScript DID to its cryptographically anchored public-key
 * material + mutable envelope.
 *
 * State paths:
 *   - Happy          → { ok: true, pubkey }
 *   - Nil (unknown)  → { ok: false, reason: "NOT_FOUND" }
 *   - Revoked        → { ok: false, reason: "REVOKED" }
 *
 * @throws KashscriptIdentityMalformedDidError on a syntactically invalid DID
 *         (programmer error — distinct from the NOT_FOUND authentication path).
 */
export async function resolveDidPubkey(
  store: IdentityMetadataStore,
  did: Did,
): Promise<ResolveDidPubkeyResult> {
  assertDidWellFormed(did);
  const record = await store.get(did);
  if (record === null) {
    return { ok: false, reason: "NOT_FOUND", traceId: newTraceId() };
  }
  if (record.revokedAtUnix !== null) {
    return { ok: false, reason: "REVOKED", traceId: newTraceId() };
  }
  const pubkey: DidPubkey = {
    did,
    algorithm: "ed25519",
    publicKeyB64: pubkeyB64FromDid(did),
    issuedAtUnix: record.issuedAtUnix,
    expiresAtUnix: record.expiresAtUnix,
    isGuestDid: record.isGuestDid,
    pdsEndpoint: record.pdsEndpoint,
  };
  return { ok: true, pubkey };
}

/**
 * Explicitly revokes a guest DID before its natural expiry. Used by the
 * scheduled reap job and by ops in response to abuse signals.
 *
 * State paths:
 *   - Happy          → { ok: true, revokedAtUnix }
 *   - Nil (unknown)  → { ok: false, reason: "NOT_FOUND" }
 *   - Not a guest    → { ok: false, reason: "NOT_A_GUEST_DID" }
 *
 * @throws KashscriptIdentityMalformedDidError on a syntactically invalid DID.
 */
export async function revokeGuestDid(
  store: IdentityMetadataStore,
  did: Did,
  nowSec: UnixSeconds = nowUnix(),
): Promise<RevokeGuestDidResult> {
  assertDidWellFormed(did);
  const record = await store.get(did);
  if (record === null) {
    return { ok: false, reason: "NOT_FOUND", traceId: newTraceId() };
  }
  if (!record.isGuestDid) {
    return { ok: false, reason: "NOT_A_GUEST_DID", traceId: newTraceId() };
  }
  await store.revoke(did, nowSec);
  return { ok: true, revokedAtUnix: nowSec };
}
