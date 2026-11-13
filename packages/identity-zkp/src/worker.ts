/**
 * Web Worker module — runs snarkjs proof generation off the main thread.
 *
 * Hosts construct this worker via:
 *
 *   const worker = new Worker(
 *     new URL("@kashscript/identity-zkp/worker", import.meta.url),
 *     { type: "module" },
 *   );
 *
 * Modern bundlers (Bun, Vite, Webpack 5, esbuild) understand the
 * `new URL(..., import.meta.url)` pattern and emit the worker as its own
 * chunk automatically. SSR-rendered environments (Next.js App Router)
 * MUST construct the worker on the client only — wrap with `if (typeof
 * window !== "undefined")` inside a `useEffect` or click handler.
 *
 * snarkjs is dynamically imported the first time the worker handles a
 * `prove` or `verify` request. This way users who only need the
 * selective-disclosure layer never pay the bundle cost.
 */

/// <reference lib="webworker" />

import type { ProveResult, ZkProof, PublicSignals, VerificationKey } from "./types";

interface ProveMessage {
  readonly id: number;
  readonly kind: "prove";
  readonly wasm: string | Uint8Array;
  readonly zkey: string | Uint8Array;
  readonly system: "groth16" | "plonk" | "fflonk";
  readonly witness: Readonly<Record<string, unknown>>;
}

interface VerifyMessage {
  readonly id: number;
  readonly kind: "verify";
  readonly proof: ZkProof;
  readonly publicSignals: PublicSignals;
  readonly verificationKey: VerificationKey;
  readonly system: "groth16" | "plonk" | "fflonk";
}

/** F2: caller signals abort for an in-flight prove. snarkjs has no abort
 *  hook so we mark the id as aborted and swallow its result when it
 *  eventually completes. */
interface AbortMessage {
  readonly id: number;
  readonly kind: "abort";
}

type IncomingMessage = ProveMessage | VerifyMessage | AbortMessage;

/** Set of request ids the caller has aborted. The handler swallows the
 *  eventual snarkjs completion to avoid sending it across postMessage. */
const aborted = new Set<number>();

interface ProgressMessage {
  readonly id: number;
  readonly kind: "progress";
  readonly phase: "loading-artifacts" | "witness-gen" | "proving" | "done" | "aborted" | "error";
  readonly fraction?: number;
  readonly note?: string;
}

function emitProgress(msg: ProgressMessage): void { ctx.postMessage(msg); }

interface Response<T> {
  readonly id: number;
  readonly ok: true;
  readonly result: T;
}
interface ErrorResponse {
  readonly id: number;
  readonly ok: false;
  readonly error: { message: string; code?: string };
}

const ctx = self as unknown as DedicatedWorkerGlobalScope;

/* Dynamically load snarkjs once, cache the module. */
let snarkjsPromise: Promise<typeof import("snarkjs")> | null = null;
function loadSnarkjs(): Promise<typeof import("snarkjs")> {
  if (!snarkjsPromise) {
    snarkjsPromise = import("snarkjs").catch((err) => {
      snarkjsPromise = null;
      throw new Error(
        `snarkjs failed to load: ${(err as Error).message}. Install it as a peer dependency.`,
      );
    });
  }
  return snarkjsPromise;
}

ctx.addEventListener("message", (e: MessageEvent<IncomingMessage>) => {
  const msg = e.data;
  if (!msg || typeof msg.id !== "number") return;

  if (msg.kind === "abort") {
    // Mark the request as aborted; the eventual prove() completion will be
    // swallowed by runProve() and not posted back.
    aborted.add(msg.id);
    emitProgress({ id: msg.id, kind: "progress", phase: "aborted" });
    return;
  }

  void (async (): Promise<void> => {
    try {
      if (msg.kind === "prove") {
        const result = await runProve(msg);
        if (aborted.has(msg.id)) { aborted.delete(msg.id); return; }
        post<ProveResult>({ id: msg.id, ok: true, result });
      } else if (msg.kind === "verify") {
        const valid = await runVerify(msg);
        post<boolean>({ id: msg.id, ok: true, result: valid });
      } else {
        post<never>({
          id: (msg as { id: number }).id,
          ok: false,
          error: { message: `Unknown message kind` },
        } as unknown as ErrorResponse);
      }
    } catch (err) {
      if (aborted.has(msg.id)) { aborted.delete(msg.id); return; }
      const e2 = err as Error & { code?: string };
      const payload: ErrorResponse = {
        id: msg.id,
        ok: false,
        error: { message: e2?.message ?? String(err), ...(e2?.code ? { code: e2.code } : {}) },
      };
      post(payload);
    }
  })();
});

async function runProve(msg: ProveMessage): Promise<ProveResult> {
  emitProgress({ id: msg.id, kind: "progress", phase: "loading-artifacts" });
  const snarkjs = await loadSnarkjs();
  if (aborted.has(msg.id)) throw new Error("aborted");

  const start = performance.now();
  const sys = pickSystem(snarkjs, msg.system);

  // snarkjs.fullProve is monolithic; we can't observe its internal phases.
  // We emit "witness-gen" before calling and "proving" right before the
  // proof step inside fullProve happens to be the dominant cost — the two
  // markers are coarse but enough to drive a real progress UI.
  emitProgress({ id: msg.id, kind: "progress", phase: "witness-gen" });
  // No await yield needed before fullProve — runProve itself is async.
  emitProgress({ id: msg.id, kind: "progress", phase: "proving", note: `snarkjs.${msg.system}.fullProve()` });

  const { proof, publicSignals } = await sys.fullProve(msg.witness, msg.wasm, msg.zkey);
  return {
    proof: proof as ZkProof,
    publicSignals: publicSignals as PublicSignals,
    elapsedMs: Math.round(performance.now() - start),
  };
}

async function runVerify(msg: VerifyMessage): Promise<boolean> {
  const snarkjs = await loadSnarkjs();
  const sys = pickSystem(snarkjs, msg.system);
  return sys.verify(msg.verificationKey, msg.publicSignals, msg.proof);
}

interface SnarkjsSubsystem {
  fullProve(
    witness: Readonly<Record<string, unknown>>,
    wasm: string | Uint8Array,
    zkey: string | Uint8Array,
  ): Promise<{ proof: unknown; publicSignals: unknown }>;
  verify(
    vk: unknown,
    publicSignals: unknown,
    proof: unknown,
  ): Promise<boolean>;
}

function pickSystem(
  snarkjs: typeof import("snarkjs"),
  sys: "groth16" | "plonk" | "fflonk",
): SnarkjsSubsystem {
  const s = (snarkjs as unknown as Record<string, SnarkjsSubsystem | undefined>)[sys];
  if (!s) throw new Error(`snarkjs.${sys} is unavailable in this snarkjs version.`);
  return s;
}

function post<T>(message: Response<T> | ErrorResponse): void {
  ctx.postMessage(message);
}

/* The exported empty object satisfies "module" semantics — bundlers
 * sometimes balk at a file that only emits side-effect message handlers. */
export {};
