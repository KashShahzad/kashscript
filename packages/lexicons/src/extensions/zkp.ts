/**
 * ZKP Extension — privacy-bearing proof submissions.
 *
 *   kash.zkp.proof-of-claim@1.0.0
 *     The on-the-wire shape a holder uses to submit a SNARK proof to a
 *     verifier. Pairs naturally with the {@link @kashscript/identity-zkp}
 *     prover surface but is transport-agnostic — verifiers can accept it
 *     over HTTP, Kafka, anywhere a Kash-Event flows.
 *
 * **F3 (audit) — one-shot-keypair pattern.** Every submission carries a
 * `submitWith` discriminator that names the keypair model the envelope
 * uses:
 *
 *   • `"ephemeral-keypair"` — the holder mints a FRESH keypair just for
 *     this submission. The envelope's `kid` is the ephemeral DID; the
 *     verifier learns nothing about the holder's persistent identity.
 *     This is the unlinkable mode. Cross-verifier correlation requires
 *     the verifiers to combine OUT-OF-BAND signals (network, billing) —
 *     the wire format itself reveals nothing.
 *
 *   • `"session-keypair"` — the holder uses a per-verifier session key
 *     (typically derived from a verifier-bound nonce). Submissions to
 *     the SAME verifier within the session are linkable; submissions
 *     across verifiers/sessions are not.
 *
 *   • `"persistent-keypair"` — the holder uses their long-lived DID key.
 *     All submissions are correlatable. Use only when correlation is
 *     desired (e.g., audit-trail flows; high-trust authenticated grants).
 *
 * The lexicon DOES NOT enforce which discriminator is used — that is a
 * holder choice — but verifiers MUST surface the chosen mode in their
 * UX and decision logic.
 *
 * Import path: `@kashscript/lexicons/extensions/zkp`.
 */

import type { LexiconDef } from "../registry";
import { S, type ObjectSchema } from "../schema";

/* ─────────────────────────────────────────────────────────────────
 *  kash.zkp.proof-of-claim@1.0.0
 * ───────────────────────────────────────────────────────────────── */

export const KASH_ZKP_PROOF_OF_CLAIM_NSID    = "kash.zkp.proof-of-claim" as const;
export const KASH_ZKP_PROOF_OF_CLAIM_VERSION = { major: 1, minor: 0, patch: 0 } as const;
export const KASH_ZKP_PROOF_OF_CLAIM_ID      = "kash.zkp.proof-of-claim@1.0.0" as const;

/** Keypair-model discriminator. See module docstring. */
export type SubmitWith = "ephemeral-keypair" | "session-keypair" | "persistent-keypair";

/** Supported SNARK envelopes. Mirrors `@kashscript/identity-zkp` `ProofSystem`. */
export type ZkpProofSystem = "groth16" | "plonk" | "fflonk";

export interface KashZkpProofOfClaimBody {
  /** The claim being proven, in plain language (display-only — never signed-into-circuit). */
  readonly claim: string;
  /** Stable circuit id (e.g., `"kash-range-proof-on-commitment-v1"`). */
  readonly circuitId: string;
  /** Proof system the envelope targets. */
  readonly system: ZkpProofSystem;
  /** The opaque proof envelope as emitted by snarkjs (any JSON shape). */
  readonly proof: Readonly<Record<string, unknown>>;
  /** Public signals — ordered, snarkjs decimal-string convention. */
  readonly publicSignals: readonly string[];
  /** Keypair model the holder used to submit. See module docstring. */
  readonly submitWith: SubmitWith;
  /**
   * OPTIONAL audience identifier when the holder bound the proof to a specific
   * verifier (typically the verifier's DID or origin URL). Verifiers SHOULD
   * reject submissions whose `audience` does not match their own identity.
   */
  readonly audience?: string;
  /** OPTIONAL ISO-8601 expiry. Verifiers SHOULD reject after this instant. */
  readonly expiresAt?: string;
  /** OPTIONAL base58btc-encoded SHA-256 over `{ proof, publicSignals, audience, expiresAt }`. */
  readonly bindingHashB58?: string;
}

export const KASH_ZKP_PROOF_OF_CLAIM_BODY_SCHEMA: ObjectSchema = S.object(
  {
    claim:          S.string({ minLength: 1, maxLength: 280 }),
    circuitId:      S.string({ minLength: 1, maxLength: 128, pattern: /^[a-z0-9][a-z0-9-]*$/ }),
    system:         S.enum("groth16", "plonk", "fflonk"),
    proof:          S.object({}, []),                // open shape — system-dependent
    publicSignals:  S.array(S.string({ maxLength: 96 }), { maxItems: 32 }),
    submitWith:     S.enum("ephemeral-keypair", "session-keypair", "persistent-keypair"),
    audience:       S.optional(S.string({ minLength: 1, maxLength: 512 })),
    expiresAt:      S.optional(S.string({ format: "iso8601" })),
    bindingHashB58: S.optional(S.string({ minLength: 32, maxLength: 64 })),
  },
  ["claim", "circuitId", "system", "proof", "publicSignals", "submitWith"],
);

/* ─────────────────────────────────────────────────────────────────
 *  Extension bundle
 * ───────────────────────────────────────────────────────────────── */

/** All ZKP-domain lexicons. Pass to `LexiconRegistry.registerAll()`. */
export const ZKP_EXTENSION: readonly LexiconDef[] = [
  {
    id: KASH_ZKP_PROOF_OF_CLAIM_ID,
    nsid: KASH_ZKP_PROOF_OF_CLAIM_NSID,
    semver: KASH_ZKP_PROOF_OF_CLAIM_VERSION,
    bodySchema: KASH_ZKP_PROOF_OF_CLAIM_BODY_SCHEMA,
    title: "ZKP Proof of Claim",
    description: "Wire envelope for submitting a SNARK proof to a verifier. Carries a submitWith discriminator that names the keypair-model the envelope uses, so verifiers can reason about linkability.",
  },
];
