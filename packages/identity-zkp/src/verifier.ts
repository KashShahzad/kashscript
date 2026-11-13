/**
 * Verifier — public-facing snarkjs.verify wrapper.
 *
 * Verification is cheap (milliseconds for Groth16). It runs on the main
 * thread by default. Apps that batch-verify can opt into the Worker path
 * by passing { useWorker: true }.
 *
 * This is the function Indusland / Duedale invoke on the server (or in
 * the browser) to check a holder-supplied proof. Never reveals or
 * accesses the holder's private witness.
 */

import { KashZkpError } from "./errors";
import type { VerifyRequest } from "./types";

/** Validate a SNARK proof against its public signals and verification key.
 *
 *  Verification is cheap (single-digit milliseconds for Groth16) and runs
 *  inline on the calling thread. Bulk-verify callers can batch via
 *  `Promise.all([...])` — snarkjs releases the event loop on each call.
 *
 *  Returns `true` if the proof verifies, `false` otherwise. Throws
 *  {@link KashZkpError} only when inputs are malformed (missing fields,
 *  wrong proof system) — a cryptographically-failed verify returns `false`. */
export async function verifyPrivacyProof(req: VerifyRequest): Promise<boolean> {
  validateVerifyRequest(req);

  let snarkjs: typeof import("snarkjs");
  try {
    snarkjs = await import("snarkjs");
  } catch (err) {
    throw new KashZkpError(
      "snarkjs is not installed. Add it as a peer dependency to use SNARK verification.",
      "SNARKJS_UNAVAILABLE",
      err,
    );
  }

  const system = req.proof.protocol;
  const subsystem = (snarkjs as unknown as Record<string, { verify?: Function }>)[system];
  if (!subsystem || typeof subsystem.verify !== "function") {
    throw new KashZkpError(
      `snarkjs.${system} is unavailable in this snarkjs version.`,
      "SNARKJS_UNAVAILABLE",
    );
  }

  try {
    const ok = await (subsystem.verify as (vk: unknown, pub: unknown, p: unknown) => Promise<boolean>)(
      req.verificationKey,
      req.publicSignals,
      req.proof,
    );
    return ok === true;
  } catch (err) {
    // A thrown error from snarkjs typically indicates malformed proof bytes
    // (wrong shape, wrong curve). Surface as INVALID_PROOF rather than `false`
    // so the caller can distinguish "wrong proof bytes" from "valid format,
    // failed verify".
    throw new KashZkpError(
      `snarkjs.${system}.verify threw: ${(err as Error)?.message ?? String(err)}.`,
      "INVALID_PROOF",
      err,
    );
  }
}

/* ── validation ─────────────────────────────────────────────────── */

function validateVerifyRequest(req: VerifyRequest): void {
  if (req === null || typeof req !== "object") {
    throw new KashZkpError("verify request must be an object.", "INVALID_INPUT");
  }
  if (!req.proof || typeof req.proof !== "object") {
    throw new KashZkpError("verify request: proof is required.", "INVALID_PROOF");
  }
  if (typeof (req.proof as { protocol?: unknown }).protocol !== "string") {
    throw new KashZkpError("verify request: proof.protocol is required.", "INVALID_PROOF");
  }
  if (!Array.isArray(req.publicSignals)) {
    throw new KashZkpError("verify request: publicSignals must be an array.", "INVALID_INPUT");
  }
  if (!req.verificationKey || typeof req.verificationKey !== "object") {
    throw new KashZkpError("verify request: verificationKey is required.", "INVALID_VERIFICATION_KEY");
  }
  if (req.verificationKey.protocol !== req.proof.protocol) {
    throw new KashZkpError(
      `Proof system mismatch — verificationKey.protocol="${req.verificationKey.protocol}" vs proof.protocol="${req.proof.protocol}".`,
      "INVALID_VERIFICATION_KEY",
    );
  }
}
