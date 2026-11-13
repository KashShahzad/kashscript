/**
 * Range Proof — circuit spec + helper witness builder.
 *
 * ╔════════════════════════════════════════════════════════════════════╗
 * ║ F1 — CRITICAL SECURITY ADVISORY (READ BEFORE USING)                ║
 * ╠════════════════════════════════════════════════════════════════════╣
 * ║ The default circuit ID is now `kash-range-proof-on-commitment-v1`. ║
 * ║ This circuit proves:                                               ║
 * ║                                                                    ║
 * ║   "I know `value` and `salt` such that                             ║
 * ║      commitment == Poseidon(value, salt)                           ║
 * ║    AND                                                             ║
 * ║      value >= threshold"                                           ║
 * ║                                                                    ║
 * ║ Nothing in this proof binds `value` to an *issuer-attested fact*.  ║
 * ║ A prover can pick any `value` they like, compute a fresh           ║
 * ║ `commitment` for it, and produce a valid proof. The verifier sees  ║
 * ║ a cryptographically sound proof that the prover knows SOMETHING    ║
 * ║ ≥ threshold under SOME commitment they picked — NOT a proof that   ║
 * ║ a credentialed issuer ever attested to that value.                 ║
 * ║                                                                    ║
 * ║ Therefore THIS CIRCUIT IS NOT A "PROOF OF AGE", "PROOF OF KYC",    ║
 * ║ "PROOF OF SALARY", OR ANY OTHER ATTRIBUTE-LEVEL CLAIM. It is a     ║
 * ║ range proof over a self-issued commitment. Useful as a building    ║
 * ║ block (e.g., when the commitment was previously bound to an        ║
 * ║ issuer attestation by another protocol step), useless as an        ║
 * ║ end-to-end identity claim.                                         ║
 * ║                                                                    ║
 * ║ The forthcoming `kash-attested-range-proof-v1` circuit extends     ║
 * ║ the witness with `attestationSig`, `issuerPubkey`, `payloadCommit` ║
 * ║ — verifying inside the SNARK that the commitment is endorsed by a  ║
 * ║ trusted issuer's Ed25519 signature over the payload commit. Until  ║
 * ║ that circuit's artefacts ship, callers wanting real attribute      ║
 * ║ claims must compose this circuit with an out-of-band attestation   ║
 * ║ check (e.g., an issuer-signed Kash-Event that the verifier         ║
 * ║ separately validates and binds to `commitment` by some other       ║
 * ║ means — at which point selective disclosure is usually a simpler   ║
 * ║ choice).                                                           ║
 * ║                                                                    ║
 * ║ To enforce caller-acknowledgement, {@link toRangeWitness} requires ║
 * ║ the explicit `_acknowledgesSelfAttested: true` marker on the bare  ║
 * ║ witness. Witnesses without it raise `UNSAFE_WITNESS`.              ║
 * ╚════════════════════════════════════════════════════════════════════╝
 *
 * Consumers wire the actual circuit artifacts (wasm, zkey, verificationKey)
 * at runtime via {@link buildRangeProofSpec}.
 */

import { KashZkpError } from "../errors";
import type { CircuitSpec, ProofSystem, VerificationKey } from "../types";

/* ── circuit identifiers ──────────────────────────────────────────── */

/**
 * Bare range proof over a self-issued Poseidon commitment. See the
 * SECURITY ADVISORY above — this is NOT a proof of any real-world claim.
 */
export const RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID = "kash-range-proof-on-commitment-v1" as const;

/**
 * **Reserved** identifier for the forthcoming attested range proof. Witness
 * shape: see {@link AttestedRangeProofWitness}. Artefacts are NOT yet
 * published; consuming this id today will fail at proof-generation time.
 */
export const ATTESTED_RANGE_PROOF_CIRCUIT_ID = "kash-attested-range-proof-v1" as const;

/* ── witness shapes ───────────────────────────────────────────────── */

/**
 * Witness for the BARE range proof. Self-attestable — see SECURITY ADVISORY.
 */
export interface RangeProofWitness {
  /** PRIVATE — the holder's chosen value (NOT issuer-attested at this layer). */
  readonly value: bigint;
  /** PRIVATE — random scalar binding value to the commitment. */
  readonly salt: bigint;
  /** PUBLIC — the minimum value being claimed. */
  readonly threshold: bigint;
  /** PUBLIC — Poseidon(value, salt). The verifier sees this. */
  readonly commitment: bigint;
  /**
   * REQUIRED. Must be `true`. Callers acknowledge that this witness produces
   * a range proof over a SELF-ISSUED commitment with no issuer binding, and
   * therefore is NOT a substitute for a credentialed attribute claim. Set
   * deliberately each time the witness is built — never default it.
   */
  readonly _acknowledgesSelfAttested: true;
}

/**
 * **Phase-5 preview**: witness for the attested range proof. The
 * accompanying circuit verifies, INSIDE the SNARK, that:
 *
 *   1. `payloadCommit == Poseidon(value, salt)` — the holder knows the
 *      preimage of the public payload commit.
 *   2. `value >= threshold`.
 *   3. `Ed25519.verify(issuerPubkey, attestationSig, payloadCommit)` — an
 *      Ed25519-in-circuit gadget confirms a trusted issuer signed off on
 *      this exact `payloadCommit`.
 *
 * The verifier MUST anchor `issuerPubkey` to a known issuer DID's
 * verification method out-of-band; the SNARK proves the holder did not
 * substitute a self-issued key.
 *
 * Until the circuit artefacts ship, this interface is type-only — callers
 * can wire their TypeScript today against the shape, but proof generation
 * will throw `INVALID_CIRCUIT_SPEC` when the artefacts are absent.
 */
export interface AttestedRangeProofWitness {
  /** PRIVATE — the attested value. */
  readonly value: bigint;
  /** PRIVATE — random scalar binding value to the commitment. */
  readonly salt: bigint;
  /** PUBLIC — the minimum value being claimed. */
  readonly threshold: bigint;
  /** PUBLIC — Poseidon(value, salt). Equal to whatever the issuer signed. */
  readonly payloadCommit: bigint;
  /** PUBLIC — base58-encoded issuer Ed25519 public key. Anchored out-of-band. */
  readonly issuerPubkey: string;
  /** PUBLIC — base64url-encoded Ed25519 signature over `payloadCommit`. */
  readonly attestationSig: string;
}

/* ── public signals ───────────────────────────────────────────────── */

/** Public signals emitted by the bare circuit, in canonical order. */
export interface RangeProofPublicSignals {
  readonly commitment: string;
  readonly threshold:  string;
}

/** Public signals emitted by the attested circuit. */
export interface AttestedRangeProofPublicSignals {
  readonly payloadCommit:  string;
  readonly threshold:      string;
  readonly issuerPubkey:   string;
  readonly attestationSig: string;
}

/* ── spec builders ───────────────────────────────────────────────── */

/**
 * Build a `CircuitSpec` for a range proof. Defaults to the bare circuit id
 * with the matching SECURITY ADVISORY in its description so verifiers
 * inspecting the spec see the limitation in plaintext.
 */
export function buildRangeProofSpec(opts: {
  /** Defaults to {@link RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID}. */
  readonly id?: string;
  readonly system?: ProofSystem;
  readonly wasm: string | Uint8Array;
  readonly zkey: string | Uint8Array;
  readonly verificationKey: VerificationKey;
  readonly description?: string;
}): CircuitSpec {
  if (!opts.wasm) throw new KashZkpError("buildRangeProofSpec: `wasm` is required.", "INVALID_CIRCUIT_SPEC");
  if (!opts.zkey) throw new KashZkpError("buildRangeProofSpec: `zkey` is required.", "INVALID_CIRCUIT_SPEC");
  if (!opts.verificationKey) {
    throw new KashZkpError("buildRangeProofSpec: `verificationKey` is required.", "INVALID_CIRCUIT_SPEC");
  }
  const id = opts.id ?? RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID;
  const defaultDescription =
    id === RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID
      ? "Bare range proof over a Poseidon commitment. SELF-ATTESTABLE — see SECURITY ADVISORY in range-proof.ts."
      : id === ATTESTED_RANGE_PROOF_CIRCUIT_ID
        ? "Attested range proof — proves the commitment is endorsed by an issuer's Ed25519 signature in-circuit."
        : "Custom range-proof variant.";
  return {
    id,
    system: opts.system ?? "groth16",
    wasm:   opts.wasm,
    zkey:   opts.zkey,
    verificationKey: opts.verificationKey,
    description: opts.description ?? defaultDescription,
  };
}

/* ── witness builders ─────────────────────────────────────────────── */

/**
 * Convert a {@link RangeProofWitness} into the input map snarkjs expects.
 *
 * Throws `UNSAFE_WITNESS` when `_acknowledgesSelfAttested !== true`. This
 * is the F1 caller-acknowledgement gate: there is no way to build the bare
 * witness without affirmatively opting into its limited semantics.
 */
export function toRangeWitness(w: RangeProofWitness): Readonly<Record<string, string>> {
  if (w._acknowledgesSelfAttested !== true) {
    throw new KashZkpError(
      "Refusing to build a bare range-proof witness without `_acknowledgesSelfAttested: true`. " +
      "This circuit proves nothing about a real-world attribute (see SECURITY ADVISORY in range-proof.ts). " +
      "If you understand the limitation and want a self-issued commitment proof, set the flag explicitly. " +
      "If you want an attested proof, switch to AttestedRangeProofWitness / kash-attested-range-proof-v1.",
      "UNSAFE_WITNESS",
    );
  }
  if (typeof w.value      !== "bigint") throw witnessTypeError("value");
  if (typeof w.salt       !== "bigint") throw witnessTypeError("salt");
  if (typeof w.threshold  !== "bigint") throw witnessTypeError("threshold");
  if (typeof w.commitment !== "bigint") throw witnessTypeError("commitment");
  if (w.value < 0n || w.salt < 0n || w.threshold < 0n || w.commitment < 0n) {
    throw new KashZkpError("Range-proof witness values must be non-negative.", "INVALID_WITNESS");
  }
  return {
    value:      w.value.toString(),
    salt:       w.salt.toString(),
    threshold:  w.threshold.toString(),
    commitment: w.commitment.toString(),
  };
}

/**
 * Convert an {@link AttestedRangeProofWitness} into the input map snarkjs
 * expects. The corresponding circuit is NOT YET PUBLISHED — proof
 * generation will fail until the artefacts ship. The TypeScript shape is
 * exposed so callers can build their integration today.
 */
export function toAttestedRangeWitness(w: AttestedRangeProofWitness): Readonly<Record<string, string>> {
  if (typeof w.value         !== "bigint") throw witnessTypeError("value");
  if (typeof w.salt          !== "bigint") throw witnessTypeError("salt");
  if (typeof w.threshold     !== "bigint") throw witnessTypeError("threshold");
  if (typeof w.payloadCommit !== "bigint") throw witnessTypeError("payloadCommit");
  if (typeof w.issuerPubkey  !== "string" || w.issuerPubkey.length === 0) throw witnessTypeError("issuerPubkey");
  if (typeof w.attestationSig!== "string" || w.attestationSig.length === 0) throw witnessTypeError("attestationSig");
  if (w.value < 0n || w.salt < 0n || w.threshold < 0n || w.payloadCommit < 0n) {
    throw new KashZkpError("Attested range-proof witness values must be non-negative.", "INVALID_WITNESS");
  }
  return {
    value:          w.value.toString(),
    salt:           w.salt.toString(),
    threshold:      w.threshold.toString(),
    payloadCommit:  w.payloadCommit.toString(),
    issuerPubkey:   w.issuerPubkey,
    attestationSig: w.attestationSig,
  };
}

/* ── deprecated aliases (kept for grep-discoverability during the rename) ─ */

/** @deprecated Use {@link RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID}. Renamed to make the limited semantics explicit. */
export const PROOF_OF_AGE_CIRCUIT_ID = RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID;
/** @deprecated Use {@link RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID}. */
export const PROOF_OF_BALANCE_CIRCUIT_ID = RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID;
/** @deprecated Use {@link toRangeWitness} — the rename clarifies that this builds the WITNESS map, not the proof itself. */
export const toWitness = toRangeWitness;

/* ── internals ───────────────────────────────────────────────────── */

function witnessTypeError(field: string): KashZkpError {
  return new KashZkpError(`RangeProofWitness.${field} has the wrong type.`, "INVALID_WITNESS");
}
