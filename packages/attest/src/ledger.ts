/**
 * Signed action-ledger — the VERIFY half.
 *
 * A ledger is an append-only, per-session hash-chain of signed rows. `attest`
 * ships the primitives to **verify** such a chain offline (`verifyLedgerSignature`
 * + `forensicConsistencyScan`) and to sign a single row (`signLedgerBlock`, the
 * co-located counterpart that keeps canonicalization from drifting). The
 * write-side service (append + session mutex + self-signing) is `@kashscript/hudhud`
 * (M5) — this module is the M1 "hash-chain helpers" verification surface.
 *
 * Ported from Oreoasis `ledger-signature.ts` + `did-registry.ts` +
 * `services/ledger-writer.ts` (forensic scan). The `@oreoasis/ks-bridge`
 * coupling is replaced with attest-owned errors. The registry deliberately does
 * NOT enforce a DID format — it is a pluggable resolver keyed on opaque DID
 * strings; canonical actor DIDs are base58btc `did:kash` (`KASH_DID_PATTERN`) and
 * format validation is the WRITE side's job (`@kashscript/hudhud`). audit r1 F5:
 * the earlier note here claiming colon-structured DIDs (`did:kash:oreoasis:…`)
 * was stale — the M5 ledger reconciled actor DIDs to base58 `did:kash`.
 */

import { signEvent, verifyEvent } from "@kashscript/identity-core";
import { AttestError, TamperError } from "./errors";
import { GENESIS_PREV_HASH, chainBlockHash } from "./chain";

/** Ledger-row DST — never collides with `kash-record-v1\n`. */
export const OREOASIS_LEDGER_DST = "oreoasis-ledger-v1\n" as const;

/* ── Row shapes (ported from ledger-store.ts) ──────────────────────────── */

export interface LedgerBlockInput {
  readonly sessionId: string;
  readonly stepIndex: number;
  readonly previousBlockHash: string;
  readonly currentTransactionBlockHash: string;
  readonly actorDid: string;
  readonly payloadMutation: Readonly<Record<string, unknown>>;
  /** `ed25519:<128-hex>` wire form. */
  readonly signature: string;
}

export interface LedgerBlockRecord extends LedgerBlockInput {
  readonly emittedAt: string;
  readonly localId: number;
}

/* ── DID registry (ported from did-registry.ts) ────────────────────────── */

export interface DidPublicKey {
  readonly did: string;
  readonly publicKeyBytes: Uint8Array;
  readonly algorithm: "ed25519";
}

export interface DidRegistry {
  resolve(did: string): Promise<DidPublicKey | null>;
}

/** In-memory registry — a legitimate dev/test backend (production resolves a
 *  DID's PDS document). Accepts any non-empty structured DID string. */
export class InMemoryDidRegistry implements DidRegistry {
  private readonly keys = new Map<string, DidPublicKey>();

  public register(entry: DidPublicKey): void {
    if (typeof entry.did !== "string" || entry.did.length === 0) {
      throw new AttestError("INVALID_INPUT", "DID must be a non-empty string");
    }
    if (entry.publicKeyBytes.byteLength !== 32) {
      throw new AttestError(
        "INVALID_INPUT",
        `Public key for ${entry.did} must be 32 bytes (got ${entry.publicKeyBytes.byteLength})`,
      );
    }
    this.keys.set(entry.did, {
      did: entry.did,
      publicKeyBytes: new Uint8Array(entry.publicKeyBytes),
      algorithm: entry.algorithm,
    });
  }

  public async resolve(did: string): Promise<DidPublicKey | null> {
    const entry = this.keys.get(did);
    if (entry === undefined) return null;
    return {
      did: entry.did,
      publicKeyBytes: new Uint8Array(entry.publicKeyBytes),
      algorithm: entry.algorithm,
    };
  }

  public size(): number {
    return this.keys.size;
  }
}

/* ── Ledger-row sign / verify (ported from ledger-signature.ts) ────────── */

export class LedgerSignatureError extends Error {
  public readonly reason:
    | "MALFORMED_HEX"
    | "BAD_SIGNATURE_FORMAT"
    | "UNKNOWN_ACTOR"
    | "VERIFY_FALSE"
    | "VERIFY_THREW";
  constructor(reason: LedgerSignatureError["reason"], message: string) {
    super(message);
    this.name = "LedgerSignatureError";
    this.reason = reason;
  }
}

export interface LedgerSignaturePayload {
  readonly sessionId: string;
  readonly stepIndex: number;
  readonly actorDid: string;
  readonly previousBlockHash: string;
  readonly payloadMutation: Readonly<Record<string, unknown>>;
}

const HEX_128 = /^[0-9a-f]{128}$/;

/** Verify a ledger row's Ed25519 signature over the `{header,body}` envelope
 *  under `oreoasis-ledger-v1\n`. Returns `true` or throws {@link LedgerSignatureError}. */
export async function verifyLedgerSignature(input: {
  readonly signatureWire: string;
  readonly payload: LedgerSignaturePayload;
  readonly didRegistry: DidRegistry;
}): Promise<true> {
  if (!input.signatureWire.startsWith("ed25519:")) {
    throw new LedgerSignatureError(
      "BAD_SIGNATURE_FORMAT",
      `Signature must start with 'ed25519:' (got '${input.signatureWire.slice(0, 8)}')`,
    );
  }
  const sigHex = input.signatureWire.slice("ed25519:".length);
  if (!HEX_128.test(sigHex)) {
    throw new LedgerSignatureError(
      "BAD_SIGNATURE_FORMAT",
      `Ed25519 signature must be 128 lowercase hex chars (got length ${sigHex.length})`,
    );
  }

  const actor = await input.didRegistry.resolve(input.payload.actorDid);
  if (actor === null) {
    throw new LedgerSignatureError(
      "UNKNOWN_ACTOR",
      `DID registry has no entry for ${input.payload.actorDid}`,
    );
  }

  const event = {
    header: {
      sessionId: input.payload.sessionId,
      stepIndex: input.payload.stepIndex,
      actorDid: input.payload.actorDid,
      previousBlockHash: input.payload.previousBlockHash,
    },
    body: input.payload.payloadMutation,
    signature: {
      alg: "ed25519" as const,
      sig: sigHex,
      dst: OREOASIS_LEDGER_DST,
      encoding: "hex" as const,
      kid: input.payload.actorDid,
    },
  };

  let ok: boolean;
  try {
    ok = await verifyEvent(event, actor.publicKeyBytes);
  } catch (err) {
    throw new LedgerSignatureError(
      "VERIFY_THREW",
      `verifyEvent raised: ${err instanceof Error ? err.message : "unknown"}`,
    );
  }
  if (!ok) {
    throw new LedgerSignatureError(
      "VERIFY_FALSE",
      "Ed25519 signature failed verification under the actor's public key",
    );
  }
  return true;
}

/** Sign a ledger-row payload → `ed25519:<128-hex>`. Co-located with verify so
 *  the canonicalization can never drift (the seed's #1 silent-VERIFY_FALSE risk). */
export async function signLedgerBlock(
  payload: LedgerSignaturePayload,
  privateKey: Uint8Array,
): Promise<string> {
  const signed = await signEvent(
    {
      sessionId: payload.sessionId,
      stepIndex: payload.stepIndex,
      actorDid: payload.actorDid,
      previousBlockHash: payload.previousBlockHash,
    },
    payload.payloadMutation,
    privateKey,
    { dst: OREOASIS_LEDGER_DST, encoding: "hex", kid: payload.actorDid },
  );
  return `ed25519:${signed.sig}`;
}

/* ── Forensic consistency scan (ported from services/ledger-writer.ts) ─── */

export interface ForensicScanReport {
  readonly sessionId: string;
  readonly rowCount: number;
  readonly verifiedAt: string;
  readonly chainHashes: ReadonlyArray<string>;
  /** Always `true` on return — the scan THROWS {@link TamperError} on tamper. */
  readonly ok: true;
}

/**
 * Walk a session's rows in order and verify, per row (throwing {@link TamperError}
 * on the first failure):
 *   1. STEP_INDEX_GAP        — stepIndex === row position
 *   2. PREVIOUS_HASH_MISMATCH — previousBlockHash === prior row's currentHash (genesis = GENESIS_PREV_HASH)
 *   3. PAYLOAD_HASH_VARIANCE  — recomputed chainBlockHash === currentTransactionBlockHash
 *   4. SIGNATURE_VERIFY_FAILED — the row's Ed25519 signature verifies
 *
 * The recomputed payload is exactly `{ sessionId, stepIndex, actorDid,
 * payloadMutation, signature }` (the signature IS folded into the chain hash).
 * `nowIso` is injectable so callers can keep the report deterministic.
 */
export async function forensicConsistencyScan(
  sessionId: string,
  rows: ReadonlyArray<LedgerBlockRecord>,
  didRegistry: DidRegistry,
  nowIso: string = new Date().toISOString(),
): Promise<ForensicScanReport> {
  const ordered = [...rows].sort((a, b) => a.stepIndex - b.stepIndex);
  const chainHashes: string[] = [];
  let priorHash = GENESIS_PREV_HASH;

  for (let i = 0; i < ordered.length; i++) {
    const block = ordered[i]!;

    if (block.stepIndex !== i) {
      throw new TamperError("STEP_INDEX_GAP", i, `expected stepIndex ${i}, got ${block.stepIndex}`);
    }
    if (block.previousBlockHash !== priorHash) {
      throw new TamperError("PREVIOUS_HASH_MISMATCH", i, `previousBlockHash does not chain to the prior row`);
    }

    const recomputed = await chainBlockHash(
      {
        sessionId: block.sessionId,
        stepIndex: block.stepIndex,
        actorDid: block.actorDid,
        payloadMutation: block.payloadMutation,
        signature: block.signature,
      },
      block.previousBlockHash,
    );
    if (recomputed !== block.currentTransactionBlockHash) {
      throw new TamperError("PAYLOAD_HASH_VARIANCE", i, `recomputed block hash does not match currentTransactionBlockHash`);
    }

    try {
      await verifyLedgerSignature({
        signatureWire: block.signature,
        payload: {
          sessionId: block.sessionId,
          stepIndex: block.stepIndex,
          actorDid: block.actorDid,
          previousBlockHash: block.previousBlockHash,
          payloadMutation: block.payloadMutation,
        },
        didRegistry,
      });
    } catch (err) {
      const reason = err instanceof LedgerSignatureError ? err.reason : "VERIFY_THREW";
      throw new TamperError("SIGNATURE_VERIFY_FAILED", i, `row signature failed (${reason})`);
    }

    chainHashes.push(block.currentTransactionBlockHash);
    priorHash = block.currentTransactionBlockHash;
  }

  return { sessionId, rowCount: ordered.length, verifiedAt: nowIso, chainHashes, ok: true };
}
