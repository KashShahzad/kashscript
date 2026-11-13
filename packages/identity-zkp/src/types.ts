/**
 * Shared types for the SNARK prover / verifier layer.
 *
 * The package is agnostic of the actual circuit toolchain — circom +
 * snarkjs is the reference path, but anything that produces a Groth16 /
 * PLONK proof object + verification key in the snarkjs JSON shape will
 * interoperate.
 *
 * Circuits are NOT shipped in this package. Consumers supply WASM and
 * zkey artifacts via URLs or `Uint8Array` blobs (see `CircuitSpec`).
 */

/** Underlying proof system. PLONK and FFLONK reuse the same JSON envelope. */
export type ProofSystem = "groth16" | "plonk" | "fflonk";

/** Stringified `bigint` (decimal). snarkjs emits everything as decimal strings. */
export type FieldElement = string;

/** snarkjs-compatible verification key. Shape varies per ProofSystem. */
export interface VerificationKey {
  readonly protocol: ProofSystem;
  readonly curve:    string;        // typically "bn128"
  readonly nPublic:  number;
  readonly [extra: string]: unknown;
}

/** snarkjs-compatible proof envelope. */
export interface ZkProof {
  readonly protocol: ProofSystem;
  readonly curve:    string;
  readonly [field: string]: unknown;
}

/** Public signals emitted alongside a proof. Ordered; matches the circuit. */
export type PublicSignals = readonly FieldElement[];

/**
 * Reference to a circuit's compiled artifacts.
 *
 * `wasm` and `zkey` may be:
 *   • a URL string (worker `fetch`es them)
 *   • a Uint8Array blob (transferred to the worker)
 *
 * `verificationKey` is REQUIRED at verification time and STRONGLY
 * RECOMMENDED at proof-generation time (lets the prover sanity-check
 * the witness shape before kicking off snarkjs).
 */
export interface CircuitSpec {
  /** Stable identifier, e.g., `"kash-proof-of-age-v1"`. */
  readonly id: string;
  /** Proof system the artifacts target. */
  readonly system: ProofSystem;
  /** Witness-generator WASM. */
  readonly wasm: string | Uint8Array;
  /** Proving key (.zkey). */
  readonly zkey: string | Uint8Array;
  /** Public verification key. */
  readonly verificationKey: VerificationKey;
  /** Human-readable description (used in error messages and UIs). */
  readonly description?: string;
}

/** Inputs to `createPrivacyProof`. Witness keys MUST match the circuit's
 *  input-signal names; values are decimal strings or `bigint`. */
export interface ProveRequest {
  readonly circuit: CircuitSpec;
  readonly witness: Readonly<Record<string, string | bigint | readonly (string | bigint)[]>>;
}

/** Result of `createPrivacyProof`. */
export interface ProveResult {
  readonly proof:         ZkProof;
  readonly publicSignals: PublicSignals;
  readonly elapsedMs:     number;
}

/** Inputs to `verifyPrivacyProof`. */
export interface VerifyRequest {
  readonly proof:           ZkProof;
  readonly publicSignals:   PublicSignals;
  readonly verificationKey: VerificationKey;
}
