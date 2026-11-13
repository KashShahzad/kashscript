/**
 * Circuit registry — type-only interfaces for the standard predicate proofs.
 *
 * The actual compiled artefacts (.wasm, .zkey, verificationKey) are NOT
 * bundled. Consumers fetch them from their own CDN or registry and pass
 * them to `buildRangeProofSpec` / `buildMembershipProofSpec`.
 *
 * Why no bundled artefacts: every compiled circuit is tied to a specific
 * trusted-setup ceremony output. Bundling would either centralise the
 * ceremony (anti-foundry-principle) or bloat the package with multi-MB
 * blobs users don't all need.
 *
 * Both circuits export a `toWitness` helper of the same name. They are
 * re-exported here as namespaces so the call site is unambiguous:
 *
 *   import { rangeProof, membershipProof } from "@kashscript/identity-zkp/circuits";
 *   const w = rangeProof.toWitness({ value, salt, threshold, commitment });
 */

export * as rangeProof      from "./range-proof";
export * as membershipProof from "./membership-proof";

/* Type re-exports so callers don't have to dive into a namespace just to
 * grab a type. Each namespace also still exposes its own copy. */
export type {
  RangeProofWitness,
  RangeProofPublicSignals,
  AttestedRangeProofWitness,
  AttestedRangeProofPublicSignals,
} from "./range-proof";
export {
  RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID,
  ATTESTED_RANGE_PROOF_CIRCUIT_ID,
  buildRangeProofSpec,
  toRangeWitness,
  toAttestedRangeWitness,
  // Deprecated aliases — kept so existing imports don't snap on rename:
  PROOF_OF_AGE_CIRCUIT_ID,
  PROOF_OF_BALANCE_CIRCUIT_ID,
} from "./range-proof";

export type {
  MembershipProofWitness,
  MembershipProofPublicSignals,
} from "./membership-proof";
export {
  PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID,
  buildMembershipProofSpec,
} from "./membership-proof";
