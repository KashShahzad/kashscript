/**
 * Minimal ambient-module shim for the OPTIONAL `snarkjs` peer dependency.
 *
 * snarkjs ships no TypeScript declarations of its own. Without this shim,
 * users who never install snarkjs would see compile errors on the dynamic
 * `import("snarkjs")` calls scattered through prover.ts / verifier.ts /
 * worker.ts. Users who DO install snarkjs are not affected — TypeScript
 * resolves the real package first.
 *
 * Only the surface this package actually invokes is typed. Anything
 * snarkjs exposes beyond Groth16/PLONK/FFLONK fullProve+verify is opaque.
 */

declare module "snarkjs" {
  export interface SnarkjsSubsystem {
    fullProve(
      witness: Readonly<Record<string, unknown>>,
      wasm: string | Uint8Array,
      zkey: string | Uint8Array,
    ): Promise<{ proof: unknown; publicSignals: unknown }>;
    verify(
      verificationKey: unknown,
      publicSignals: unknown,
      proof: unknown,
    ): Promise<boolean>;
  }

  export const groth16: SnarkjsSubsystem;
  export const plonk:   SnarkjsSubsystem;
  export const fflonk:  SnarkjsSubsystem;
}
