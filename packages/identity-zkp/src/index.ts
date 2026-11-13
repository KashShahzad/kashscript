/**
 * @kashscript/identity-zkp — privacy primitives for did:kash.
 *
 *  • Selective disclosure (Merkle commitments + hash paths)  ← no peer deps
 *  • SNARK prover + verifier (Groth16 / PLONK via snarkjs)   ← peer dep: snarkjs
 *
 * Browser- and Node-compatible. Prover runs inside a Web Worker by default
 * so the main thread stays responsive during multi-second proof generation.
 */

export * from "./errors";
export * from "./types";
export * from "./merkle";
export * from "./disclosure";
export * from "./prover";
export * from "./verifier";
export * from "./circuits";

export const IDENTITY_ZKP_VERSION = "0.2.3" as const;
