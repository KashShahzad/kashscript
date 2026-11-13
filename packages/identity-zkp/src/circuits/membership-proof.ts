/**
 * Membership Proof — circuit spec + helper witness builder.
 *
 * Claim form:
 *   "I know `did` and a Merkle inclusion proof such that
 *      MerkleRoot(<my did, sibling chain>) == publicRegistryRoot"
 *
 * The verifier sees only:
 *   • the registry's Merkle root
 *   • (optionally) the registry id / namespace
 *
 * The holder's actual DID is never exposed.
 *
 * Standard instantiation:
 *   PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID
 */

import { KashZkpError } from "../errors";
import type { CircuitSpec, ProofSystem, VerificationKey } from "../types";

/**
 * Witness inputs. `siblings` and `pathBits` must have a length matching the
 * circuit's compiled tree depth (typically 20–32). Pad shallower trees by
 * duplicating leaves at the bottom; the circuit normalises depth.
 */
export interface MembershipProofWitness {
  /** PRIVATE — the holder's DID, serialised as a field element. */
  readonly didFE: bigint;
  /** PRIVATE — sibling hashes from leaf to root. */
  readonly siblings: readonly bigint[];
  /** PRIVATE — `0`/`1` bits indicating sibling position at each level. */
  readonly pathBits: readonly (0 | 1)[];
  /** PUBLIC — the registry's expected root. */
  readonly registryRoot: bigint;
  /** PUBLIC — namespace tag baked into the leaf hash (prevents cross-registry replay). */
  readonly namespaceTag: bigint;
}

export interface MembershipProofPublicSignals {
  readonly registryRoot: string;
  readonly namespaceTag: string;
}

export const PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID =
  "kash-proof-of-registry-membership-v1" as const;

export function buildMembershipProofSpec(opts: {
  readonly id: string;
  readonly system?: ProofSystem;
  readonly wasm: string | Uint8Array;
  readonly zkey: string | Uint8Array;
  readonly verificationKey: VerificationKey;
  readonly description?: string;
}): CircuitSpec {
  if (!opts.id)   throw new KashZkpError("buildMembershipProofSpec: `id` is required.",   "INVALID_CIRCUIT_SPEC");
  if (!opts.wasm) throw new KashZkpError("buildMembershipProofSpec: `wasm` is required.", "INVALID_CIRCUIT_SPEC");
  if (!opts.zkey) throw new KashZkpError("buildMembershipProofSpec: `zkey` is required.", "INVALID_CIRCUIT_SPEC");
  if (!opts.verificationKey) {
    throw new KashZkpError("buildMembershipProofSpec: `verificationKey` is required.", "INVALID_CIRCUIT_SPEC");
  }
  return {
    id:     opts.id,
    system: opts.system ?? "groth16",
    wasm:   opts.wasm,
    zkey:   opts.zkey,
    verificationKey: opts.verificationKey,
    ...(opts.description !== undefined ? { description: opts.description } : {}),
  };
}

export function toWitness(
  w: MembershipProofWitness,
): Readonly<Record<string, string | readonly string[]>> {
  if (typeof w.didFE          !== "bigint") throw witnessTypeError("didFE");
  if (typeof w.registryRoot   !== "bigint") throw witnessTypeError("registryRoot");
  if (typeof w.namespaceTag   !== "bigint") throw witnessTypeError("namespaceTag");
  if (!Array.isArray(w.siblings) || w.siblings.length === 0) {
    throw new KashZkpError(
      "MembershipProofWitness.siblings must be a non-empty array of bigints.",
      "INVALID_WITNESS",
    );
  }
  if (!Array.isArray(w.pathBits) || w.pathBits.length !== w.siblings.length) {
    throw new KashZkpError(
      `MembershipProofWitness.pathBits length (${w.pathBits.length}) must equal siblings length (${w.siblings.length}).`,
      "INVALID_WITNESS",
    );
  }
  for (const b of w.pathBits) {
    if (b !== 0 && b !== 1) {
      throw new KashZkpError("MembershipProofWitness.pathBits entries must be 0 or 1.", "INVALID_WITNESS");
    }
  }
  return {
    didFE:        w.didFE.toString(),
    siblings:     w.siblings.map((s) => s.toString()),
    pathBits:     w.pathBits.map((b) => b.toString()),
    registryRoot: w.registryRoot.toString(),
    namespaceTag: w.namespaceTag.toString(),
  };
}

function witnessTypeError(field: string): KashZkpError {
  return new KashZkpError(`MembershipProofWitness.${field} must be a bigint.`, "INVALID_WITNESS");
}
