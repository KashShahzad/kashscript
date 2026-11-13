/**
 * Prover orchestrator.
 *
 * Holds a single Worker instance (lazy-constructed on first call) and
 * multiplexes prove/verify requests over `postMessage`. The main thread
 * never blocks: Web Workers run in parallel, so a 5-second Groth16
 * proof doesn't freeze the UI.
 *
 * **F2 — Studio-grade UX surface (v0.2+):**
 *   • `signal` — AbortSignal on the request. Cancels the caller's wait
 *     immediately; the worker is asked to abort but may continue running
 *     until its current snarkjs call returns (snarkjs is monolithic and
 *     has no internal abort hook). Setting the signal terminates pending
 *     promises with `PROVE_ABORTED`.
 *   • `onProgress` — called with `{ phase, fraction? }` as the worker
 *     emits phase markers ("loading-artifacts", "witness-gen", "proving").
 *   • `estimateProofCost(circuit)` — static heuristic, lets the caller
 *     decide whether to show a spinner or a full-page wait.
 *   • `configureProver({ idleTimeoutMs })` — terminates the worker after
 *     N ms with no pending requests. Reclaims the ~10 MB snarkjs heap
 *     when the user backs out of a flow.
 */

import { KashZkpError } from "./errors";
import { RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID, ATTESTED_RANGE_PROOF_CIRCUIT_ID } from "./circuits/range-proof";
import { PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID } from "./circuits/membership-proof";
import type {
  CircuitSpec,
  ProveRequest,
  ProveResult,
  PublicSignals,
  ZkProof,
} from "./types";

/* ── progress contract ───────────────────────────────────────────── */

export type ProverPhase =
  | "queued"
  | "loading-artifacts"
  | "witness-gen"
  | "proving"
  | "done"
  | "aborted"
  | "error";

export interface ProverProgressEvent {
  readonly phase: ProverPhase;
  /** 0..1 if a fraction is meaningful for this phase; otherwise omitted. */
  readonly fraction?: number;
  /** Optional human-readable note (e.g., "snarkjs.groth16.fullProve()"). */
  readonly note?: string;
}

export type ProverProgressCallback = (event: ProverProgressEvent) => void;

/* ── extended request shape ──────────────────────────────────────── */

export interface ExtendedProveRequest extends ProveRequest {
  /** F2: abort the wait when signaled. */
  readonly signal?: AbortSignal;
  /** F2: phase callback. Optional. */
  readonly onProgress?: ProverProgressCallback;
}

/* ── prover configuration ────────────────────────────────────────── */

export interface ProverConfig {
  /** Terminate the worker after this many ms of inactivity. `0` disables. */
  readonly idleTimeoutMs: number;
}

let proverConfig: ProverConfig = { idleTimeoutMs: 0 };

/** Mutate the prover configuration. Affects subsequent prove() calls. */
export function configureProver(partial: Partial<ProverConfig>): void {
  proverConfig = { ...proverConfig, ...partial };
  scheduleIdleTimer();
}

/* ── worker management ───────────────────────────────────────────── */

let workerInstance: Worker | null = null;
let workerFactory: (() => Worker) | null = null;
let nextId = 1;
let idleTimer: ReturnType<typeof setTimeout> | null = null;

interface PendingEntry {
  readonly resolve: (v: unknown) => void;
  readonly reject:  (e: unknown) => void;
  readonly onProgress?: ProverProgressCallback;
  aborted: boolean;
}
const pending = new Map<number, PendingEntry>();

/** Override the default worker factory. */
export function setProverWorker(factory: () => Worker): void {
  workerFactory = factory;
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
  }
}

/** Tear down the worker. Pending requests reject. */
export function teardownProver(): void {
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
  }
  for (const { reject } of pending.values()) {
    reject(new KashZkpError("Prover worker was torn down.", "WORKER_FAILED"));
  }
  pending.clear();
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
}

function scheduleIdleTimer(): void {
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  if (proverConfig.idleTimeoutMs <= 0) return;
  if (pending.size > 0) return;
  if (!workerInstance) return;
  idleTimer = setTimeout(() => {
    if (pending.size === 0 && workerInstance) {
      workerInstance.terminate();
      workerInstance = null;
    }
  }, proverConfig.idleTimeoutMs);
}

function getWorker(): Worker {
  if (workerInstance) return workerInstance;

  if (workerFactory) {
    workerInstance = workerFactory();
  } else if (typeof Worker === "undefined") {
    throw new KashZkpError(
      "Web Worker is not available in this environment. Call setProverWorker() to inject one.",
      "WORKER_UNAVAILABLE",
    );
  } else {
    try {
      workerInstance = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
    } catch (err) {
      throw new KashZkpError(
        "Failed to construct the default prover Worker. Configure one via setProverWorker().",
        "WORKER_UNAVAILABLE",
        err,
      );
    }
  }

  workerInstance.addEventListener("message", (e: MessageEvent) => {
    const msg = e.data as
      | {
          readonly id: number;
          readonly kind?: "progress";
          readonly phase: ProverPhase;
          readonly fraction?: number;
          readonly note?: string;
        }
      | {
          readonly id: number;
          readonly ok: boolean;
          readonly result?: unknown;
          readonly error?: { message: string; code?: string };
        };
    if (!msg || typeof msg.id !== "number") return;

    // Progress messages don't resolve the promise — just notify.
    if ("kind" in msg && msg.kind === "progress") {
      const handle = pending.get(msg.id);
      if (handle && !handle.aborted && handle.onProgress) {
        handle.onProgress({
          phase: msg.phase,
          ...(msg.fraction !== undefined ? { fraction: msg.fraction } : {}),
          ...(msg.note !== undefined ? { note: msg.note } : {}),
        });
      }
      return;
    }

    // Completion (ok or error).
    const handle = pending.get(msg.id);
    if (!handle) return;
    pending.delete(msg.id);

    if (handle.aborted) {
      handle.reject(new KashZkpError("Proof generation was aborted before completion.", "PROVE_ABORTED"));
    } else if ("ok" in msg && msg.ok) {
      handle.onProgress?.({ phase: "done" });
      handle.resolve(msg.result);
    } else if ("ok" in msg) {
      handle.onProgress?.({ phase: "error" });
      handle.reject(
        new KashZkpError(
          msg.error?.message ?? "Worker reported an error.",
          "WORKER_FAILED",
        ),
      );
    }
    scheduleIdleTimer();
  });

  workerInstance.addEventListener("error", (e: ErrorEvent) => {
    const err = new KashZkpError(`Worker fatal error: ${e.message}`, "WORKER_FAILED");
    for (const { reject } of pending.values()) reject(err);
    pending.clear();
  });

  return workerInstance;
}

/* ── public API ─────────────────────────────────────────────────── */

/**
 * Generate a SNARK proof off the main thread.
 *
 * The returned promise resolves with the proof + public signals + elapsed
 * time. See {@link ExtendedProveRequest} for abort + progress hooks.
 */
export async function createPrivacyProof(req: ExtendedProveRequest): Promise<ProveResult> {
  if (!req || typeof req !== "object") {
    throw new KashZkpError("createPrivacyProof: request is required.", "INVALID_INPUT");
  }
  const { circuit, witness, signal, onProgress } = req;
  if (!circuit || typeof circuit !== "object") {
    throw new KashZkpError("createPrivacyProof: circuit spec is required.", "INVALID_CIRCUIT_SPEC");
  }
  if (!circuit.wasm || !circuit.zkey) {
    throw new KashZkpError("createPrivacyProof: circuit.wasm and circuit.zkey are required.", "INVALID_CIRCUIT_SPEC");
  }
  if (!witness || typeof witness !== "object" || Array.isArray(witness)) {
    throw new KashZkpError("createPrivacyProof: witness must be a plain object.", "INVALID_WITNESS");
  }
  if (signal?.aborted) {
    throw new KashZkpError("Proof generation aborted before submission.", "PROVE_ABORTED");
  }

  const safeWitness: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(witness)) {
    safeWitness[k] = serialiseWitnessValue(v);
  }

  const worker = getWorker();
  const id = nextId++;
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }

  onProgress?.({ phase: "queued" });

  return new Promise<ProveResult>((resolve, reject) => {
    const entry: PendingEntry = {
      resolve: (r) => resolve(r as ProveResult),
      reject,
      aborted: false,
      ...(onProgress ? { onProgress } : {}),
    };
    pending.set(id, entry);

    // F2: abort plumbing. We can't kill snarkjs mid-proof, but we can
    // (a) return PROVE_ABORTED to the caller immediately, and (b) tell
    // the worker to discard its result when it eventually finishes.
    const onAbort = (): void => {
      const e = pending.get(id);
      if (!e || e.aborted) return;
      e.aborted = true;
      worker.postMessage({ id, kind: "abort" });
      pending.delete(id);
      reject(new KashZkpError("Proof generation aborted via AbortSignal.", "PROVE_ABORTED"));
    };
    if (signal) {
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener("abort", onAbort, { once: true });
    }

    worker.postMessage({
      id,
      kind: "prove",
      system: circuit.system,
      wasm:   circuit.wasm,
      zkey:   circuit.zkey,
      witness: safeWitness,
    });
  });
}

/** Convenience: just the proof + public signals (no timing). */
export async function createPrivacyProofSimple(
  req: ExtendedProveRequest,
): Promise<{ readonly proof: ZkProof; readonly publicSignals: PublicSignals }> {
  const { proof, publicSignals } = await createPrivacyProof(req);
  return { proof, publicSignals };
}

/* ── F2: cost estimator ─────────────────────────────────────────── */

export interface ProverCostEstimate {
  /** Expected elapsed wall-clock for the prove() call, in ms, on the given device class. */
  readonly estimatedMs: number;
  /** Confidence in the estimate. `"low"` for unknown circuits. */
  readonly confidence: "low" | "medium" | "high";
  /** Device class the estimate is calibrated to. */
  readonly deviceClass: "desktop" | "mobile";
  /** Per-phase breakdown when known. */
  readonly phases?: Readonly<{ loadArtifacts: number; witnessGen: number; prove: number }>;
}

/**
 * Heuristic cost estimate. Calibrated against the reference circuits at the
 * "studio-grade" capability rubric — desktop ≈ M1/Ryzen 5800X, mobile ≈
 * Snapdragon 6-series low end. Use it to decide between a spinner and a
 * full-page wait UI.
 */
export function estimateProofCost(circuit: CircuitSpec): ProverCostEstimate {
  const deviceClass: "desktop" | "mobile" =
    typeof navigator !== "undefined" && /Mobi|Android/i.test(navigator.userAgent)
      ? "mobile"
      : "desktop";

  // Static per-circuit calibration table. Numbers are wall-clock ms.
  const TABLE: Readonly<Record<string, { desktop: ProverCostEstimate["phases"]; mobile: ProverCostEstimate["phases"] }>> = {
    [RANGE_PROOF_ON_COMMITMENT_CIRCUIT_ID]: {
      desktop: { loadArtifacts: 250, witnessGen:  80, prove:  600 },
      mobile:  { loadArtifacts: 900, witnessGen: 300, prove: 4200 },
    },
    [ATTESTED_RANGE_PROOF_CIRCUIT_ID]: {
      // Ed25519-in-circuit is dominant; numbers are conservative — bump after benchmarking.
      desktop: { loadArtifacts: 600, witnessGen: 220, prove:  8000 },
      mobile:  { loadArtifacts: 2500, witnessGen: 900, prove: 55000 },
    },
    [PROOF_OF_REGISTRY_MEMBERSHIP_CIRCUIT_ID]: {
      desktop: { loadArtifacts: 320, witnessGen: 100, prove:  900 },
      mobile:  { loadArtifacts: 1200, witnessGen: 400, prove: 6800 },
    },
  };

  const row = TABLE[circuit.id];
  if (!row) {
    return { estimatedMs: 5000, confidence: "low", deviceClass };
  }
  const phases = row[deviceClass]!;
  const total = phases.loadArtifacts + phases.witnessGen + phases.prove;
  return { estimatedMs: total, confidence: "medium", deviceClass, phases };
}

/* ── helpers ────────────────────────────────────────────────────── */

function serialiseWitnessValue(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(serialiseWitnessValue);
  return v;
}
