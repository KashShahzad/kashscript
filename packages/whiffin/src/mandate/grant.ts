// ============================================================================
// @kashscript/whiffin/mandate/grant — grant signing + vendor allowlist
// ----------------------------------------------------------------------------
// The crypto of the ISSUE/REDEEM loop:
//   • signing   — @kashscript/identity-core (signEvent / verifyEvent, RFC 8785)
//   • allowlist — @kashscript/identity-zkp/merkle (binary Merkle tree + proofs)
//
// Grant signatures are scoped by a `kash-grant-v1` domain-separation tag, so a
// grant signature can never verify as any other Kash-Event (record / handshake
// / report). The grant amount is INTEGER paisa — no floating point. Ported from
// the ks-adapters/grant seed (M4, ADR-0016). `kash-grant-v1` and the header
// `typ` are wire: they sit inside signed bytes and never change.
// ============================================================================

import {
  generateKeyPair,
  importKey,
  signEvent,
  verifyEvent,
} from "@kashscript/identity-core";
import type { ExportedKey, KashKeyPair, SignedKashEvent } from "@kashscript/identity-core";
import {
  buildMerkleTreeWithPaths,
  bytesEqual,
  hashLeaf,
  recoverRoot,
} from "@kashscript/identity-zkp/merkle";
import type { MerkleInclusionProof } from "@kashscript/identity-zkp/merkle";

import type { ArrivalClause, Grant, SignedGrant } from "./types";

/** Domain-separation tag: scopes a grant signature so it can never verify as
 *  any other Kash-Event subprotocol. Trailing newline per the identity-core DST
 *  convention. */
export const GRANT_DST = "kash-grant-v1\n";

/**
 * The arrival clause every new mandate carries: the recipient confirms arrival,
 * and it takes two signatures to count as proof (d41). Fixed, not configurable —
 * a mandate cannot be issued that asks for fewer.
 */
export const ARRIVAL_CLAUSE: ArrivalClause = Object.freeze({ confirmedBy: "RECIPIENT", signatures: 2 });

/** True iff `x` is exactly the d41 arrival clause (recipient confirms; two signatures). */
export function isArrivalClause(x: unknown): x is ArrivalClause {
  if (typeof x !== "object" || x === null) return false;
  const c = x as Record<string, unknown>;
  return Object.keys(c).length === 2 && c.confirmedBy === "RECIPIENT" && c.signatures === 2;
}

/** The operator's grant-authority key pair ({ privateKey, publicKey }). */
export type GrantAuthorityKeyPair = KashKeyPair;

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const byte of b) out += byte.toString(16).padStart(2, "0");
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hexToBytes: odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ----------------------------------------------------------------------------
// Grant identifiers (WebCrypto random — edge/node/browser safe)
// ----------------------------------------------------------------------------

function randomHex(byteLength: number): string {
  const buffer = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(buffer);
  let hex = "";
  for (const byte of buffer) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** A unique grant id, e.g. `grant_9f2a1c…`. */
export function newGrantId(): string {
  return `grant_${randomHex(16)}`;
}

/** A single-use nonce (192-bit), burned atomically at REDEEM. */
export function newSingleUseNonce(): string {
  return randomHex(24);
}

// ----------------------------------------------------------------------------
// Grant signing (on @kashscript/identity-core)
// ----------------------------------------------------------------------------

/** Deterministic Kash-Event header bound to the grant. Rebuilt identically at
 *  verify time, so tampering the grant (incl. grantId) fails verification. */
function grantHeader(grant: Grant): Readonly<Record<string, unknown>> {
  return { typ: "kash/grant", v: 1, grantId: grant.grantId };
}

/** Sign a purpose-bound grant with the operator private key under the grant DST. */
export async function forgeGrant(grant: Grant, operatorPrivateKey: Uint8Array): Promise<SignedGrant> {
  const signature = await signEvent(grantHeader(grant), grant, operatorPrivateKey, { dst: GRANT_DST });
  return { grant, signature };
}

/** Verify a signed grant against the operator public key. Returns `false` on a
 *  real mismatch (tampered grant / wrong key); throws only on malformed input. */
export async function verifyGrant(signed: SignedGrant, operatorPublicKey: Uint8Array): Promise<boolean> {
  // audit r1 F3: PIN the DST. verifyEvent verifies under the signature's OWN
  // `dst` field, which is attacker-controlled wire data — so a Kash-Event signed
  // for a DIFFERENT domain whose {header,body} happened to match a grant's could
  // be accepted. Assert the embedded DST is exactly the grant DST first.
  if (signed.signature.dst !== GRANT_DST) return false;
  const event: SignedKashEvent = {
    header: grantHeader(signed.grant),
    body: signed.grant,
    signature: signed.signature,
  };
  return verifyEvent(event, operatorPublicKey);
}

/** Generate a fresh grant-authority Ed25519 key pair. */
export async function generateGrantAuthorityKeyPair(): Promise<GrantAuthorityKeyPair> {
  return generateKeyPair();
}

/** Re-hydrate the persistent grant-authority key from a base64-encoded JWK.
 *  `importKey` runs a sign+verify consistency probe, so a corrupt JWK throws. */
export async function loadGrantAuthorityKeyPair(jwkBase64: string): Promise<GrantAuthorityKeyPair> {
  const jwk = JSON.parse(atob(jwkBase64)) as ExportedKey;
  return importKey(jwk);
}

// ----------------------------------------------------------------------------
// Vendor allowlist (on @kashscript/identity-zkp/merkle)
// ----------------------------------------------------------------------------

const VENDOR_LEAF_KEY = "vendorDid";
/** Fixed, non-empty salt for vendor-allowlist leaves — satisfies identity-zkp's
 *  non-empty-salt rule and keeps these leaves non-collidable with other uses. */
const VENDOR_LEAF_SALT = utf8("kash-vendor-allowlist-v1");

async function vendorLeaf(vendorDid: string): Promise<Uint8Array> {
  return hashLeaf(VENDOR_LEAF_KEY, vendorDid, VENDOR_LEAF_SALT);
}

export interface VendorAllowlist {
  /** Hex Merkle root — stored in `Grant.vendorAllowlistRoot`. */
  readonly rootHex: string;
  /** Inclusion proof per approved vendor DID. */
  readonly proofByDid: ReadonlyMap<string, MerkleInclusionProof>;
}

/** Build the Merkle root + per-vendor inclusion proofs for an approved vendor
 *  set. DIDs are de-duplicated + sorted so the root is deterministic. */
export async function buildVendorAllowlist(vendorDids: readonly string[]): Promise<VendorAllowlist> {
  const sorted = [...new Set(vendorDids)].sort();
  if (sorted.length === 0) {
    throw new Error("buildVendorAllowlist: a program must have at least one approved vendor");
  }
  const leaves = await Promise.all(sorted.map(vendorLeaf));
  const { root, proofs } = await buildMerkleTreeWithPaths(leaves);
  const proofByDid = new Map<string, MerkleInclusionProof>();
  sorted.forEach((did, i) => {
    const proof = proofs[i];
    if (proof === undefined) throw new Error("buildVendorAllowlist: missing proof for leaf");
    proofByDid.set(did, proof);
  });
  return { rootHex: bytesToHex(root), proofByDid };
}

/** Check that `vendorDid` is in the allowlist whose root is `rootHex`, given its
 *  inclusion proof. Used by the REDEEM policy gate. */
/** Depth ceiling for a vendor-inclusion proof — 2^32 leaves, far beyond any real
 *  allowlist. audit r1 F5: bounds a crafted over-/under-long proof + the async-
 *  hash-per-level DoS surface. */
const MAX_MERKLE_PROOF_DEPTH = 32;

export async function verifyVendorInclusion(
  vendorDid: string,
  proof: MerkleInclusionProof,
  rootHex: string,
): Promise<boolean> {
  if (proof.siblings.length > MAX_MERKLE_PROOF_DEPTH) return false;
  const recovered = await recoverRoot(await vendorLeaf(vendorDid), proof);
  return bytesEqual(recovered, hexToBytes(rootHex));
}

export type { MerkleInclusionProof };
