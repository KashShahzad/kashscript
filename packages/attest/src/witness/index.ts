/**
 * Public-witness client + chain anchor + receipt store.
 *
 * Submits an anchor's Merkle root to a public transparency log so a third party
 * can prove the artifact existed no later than the witness time. **Rekor**
 * (Sigstore) is primary; **OpenTimestamps** is the fallback; offline / all-
 * unreachable degrades honestly to `backend: "none"` (locally tamper-evident,
 * not publicly provable — never a fabricated receipt). The client **never
 * throws** — a witness failure must not fail the artifact it witnesses.
 *
 * Full inclusion/timestamp verification is delegated to public tooling
 * (`rekor-cli` / `ots verify`); this client submits + captures the receipt.
 *
 * Ported from Oreoasis `services/witness-client.ts` + `chain-anchor.ts` +
 * `anchor-receipt-store.ts` (app-specific stderr telemetry dropped for library
 * cleanliness; offline env → `KASH_ATTEST_WITNESS_OFFLINE=1`).
 */

import { bytesToBase64, ed25519PublicKeyToSpkiPem, signRawEd25519, type RawEd25519Signer } from "../ed25519";
import { bytesToHex, hexToBytes } from "../chain";

/** RFC 6962's tree: a batch where each member proves its place with its own path (GP-6). */
export * from "./rfc6962";

/* ── Anchor shapes ─────────────────────────────────────────────────────── */

export interface ChainTip {
  readonly sessionId: string;
  readonly latestHash: string;
  readonly latestStepIndex: number;
}

export type AnchorWitnessBackend = "rekor" | "opentimestamps" | "none";

export interface AnchorWitness {
  readonly backend: AnchorWitnessBackend;
  /** Backend-specific proof, embedded verbatim for offline export. */
  readonly receipt: Readonly<Record<string, unknown>>;
  readonly witnessedAt: string | null;
}

export interface AnchorRecord {
  readonly publishedAt: string;
  readonly merkleRoot: string;
  readonly tipCount: number;
  readonly tips: ReadonlyArray<ChainTip>;
  readonly witness?: AnchorWitness;
}

/** Deterministic SHA-256 over sorted `sessionId\nlatestHash\nlatestStepIndex\n`
 *  segments — the anchor's role is to be an unrewritable external witness, so a
 *  flat digest suffices; the per-session chain hash is what proves tamper.
 *
 *  ⚠️ audit r1 F1 (KNOWN, deferred): this newline join is NOT injective — a tip
 *  whose `sessionId`/`latestHash` contains a `\n` can collide with a different
 *  tip-set. The injective fix (canonical-JSON / length-prefixed encoding) is a
 *  WIRE-FORMAT change that would invalidate every anchor already witnessed by a
 *  real venture, so it MUST land behind an anchor-format version bump coordinated
 *  with re-anchoring — see `specs/attest-audit-r1.md`. Mitigation today: the
 *  single-session `verifyAuditBundle` path independently binds
 *  `tip.latestHash === tail.currentTransactionBlockHash` (a 64-hex string that
 *  cannot hold `\n`), so a forged multi-field collision does not verify there. */
export async function computeAnchorMerkleRoot(
  tips: ReadonlyArray<ChainTip>,
): Promise<string> {
  const sorted = [...tips].sort((a, b) => (a.sessionId < b.sessionId ? -1 : 1));
  let acc = new Uint8Array(0);
  const enc = new TextEncoder();
  for (const t of sorted) {
    const segment = enc.encode(`${t.sessionId}\n${t.latestHash}\n${t.latestStepIndex}\n`);
    const next = new Uint8Array(acc.length + segment.length);
    next.set(acc);
    next.set(segment, acc.length);
    acc = next;
  }
  const digest = await crypto.subtle.digest("SHA-256", acc as unknown as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/* ── Witness client ────────────────────────────────────────────────────── */

const DEFAULT_REKOR_BASE_URL = "https://rekor.sigstore.dev";
const DEFAULT_OTS_CALENDARS: ReadonlyArray<string> = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
];
const DEFAULT_TIMEOUT_MS = 10_000;

export interface WitnessPayload {
  /** 64-char sha256 hex — the anchor's Merkle root over the chain tips. */
  readonly merkleRootHex: string;
  /** Host signing material — the Rekor `hashedrekord` records a signature over the root.
   *  Ed25519: the entry carries the key as an Ed25519 SPKI PEM. */
  readonly signer: RawEd25519Signer;
}

export interface WitnessClientOptions {
  readonly offline?: boolean;
  readonly rekorBaseUrl?: string;
  readonly otsCalendarUrls?: ReadonlyArray<string>;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

function noneWitness(reason: string, merkleRoot: string): AnchorWitness {
  return { backend: "none", receipt: { witnessed: false, reason, merkleRoot }, witnessedAt: null };
}
function numberOrNull(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
function envOffline(): boolean {
  return typeof process !== "undefined" && process.env?.KASH_ATTEST_WITNESS_OFFLINE === "1";
}

export class WitnessClient {
  private readonly offline: boolean;
  private readonly rekorBaseUrl: string;
  private readonly otsCalendarUrls: ReadonlyArray<string>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: WitnessClientOptions = {}) {
    this.offline = options.offline ?? envOffline();
    this.rekorBaseUrl = (options.rekorBaseUrl ?? DEFAULT_REKOR_BASE_URL).replace(/\/+$/, "");
    this.otsCalendarUrls = options.otsCalendarUrls ?? DEFAULT_OTS_CALENDARS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /** Witness `payload.merkleRootHex`: Rekor → OpenTimestamps → `none`. Never throws. */
  public async witness(payload: WitnessPayload): Promise<AnchorWitness> {
    if (this.offline) return noneWitness("offline", payload.merkleRootHex);
    try {
      return await this.submitToRekor(payload);
    } catch {
      try {
        return await this.submitToOpenTimestamps(payload);
      } catch {
        return noneWitness("witness-unreachable", payload.merkleRootHex);
      }
    }
  }

  private async submitToRekor(payload: WitnessPayload): Promise<AnchorWitness> {
    const rootBytes = hexToBytes(payload.merkleRootHex);
    const signatureB64 = await signRawEd25519(rootBytes, payload.signer);
    const publicKeyPem = ed25519PublicKeyToSpkiPem(payload.signer.publicKey);
    const proposedEntry = {
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: { hash: { algorithm: "sha256", value: payload.merkleRootHex } },
        signature: {
          content: signatureB64,
          publicKey: { content: bytesToBase64(new TextEncoder().encode(publicKeyPem)) },
        },
      },
    };
    const res = await this.fetchWithTimeout(`${this.rekorBaseUrl}/api/v1/log/entries`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(proposedEntry),
    });
    if (!res.ok) throw new Error(`Rekor HTTP ${res.status}`);
    const json = (await res.json()) as Record<string, unknown>;
    const uuid = Object.keys(json)[0];
    if (uuid === undefined) throw new Error("Rekor returned an empty entry map");
    const entry = json[uuid] as Record<string, unknown> | undefined;
    const verification = (entry?.verification ?? {}) as Record<string, unknown>;
    const integratedTime = numberOrNull(entry?.integratedTime);
    return {
      backend: "rekor",
      receipt: {
        rekorBaseUrl: this.rekorBaseUrl,
        uuid,
        logIndex: numberOrNull(entry?.logIndex),
        logID: typeof entry?.logID === "string" ? entry.logID : null,
        integratedTime,
        signedEntryTimestamp:
          typeof verification.signedEntryTimestamp === "string" ? verification.signedEntryTimestamp : null,
        inclusionProof: verification.inclusionProof ?? null,
        merkleRoot: payload.merkleRootHex,
      },
      witnessedAt: integratedTime !== null ? new Date(integratedTime * 1000).toISOString() : null,
    };
  }

  private async submitToOpenTimestamps(payload: WitnessPayload): Promise<AnchorWitness> {
    const digest = hexToBytes(payload.merkleRootHex); // 32 bytes
    const errors: string[] = [];
    for (const cal of this.otsCalendarUrls) {
      const base = cal.replace(/\/+$/, "");
      try {
        const res = await this.fetchWithTimeout(`${base}/digest`, {
          method: "POST",
          headers: { "Content-Type": "application/octet-stream", Accept: "application/octet-stream" },
          body: digest as unknown as BodyInit,
        });
        if (!res.ok) {
          errors.push(`${base}: HTTP ${res.status}`);
          continue;
        }
        const proof = new Uint8Array(await res.arrayBuffer());
        return {
          backend: "opentimestamps",
          receipt: {
            calendar: base,
            digestAlgorithm: "sha256",
            digest: payload.merkleRootHex,
            proofBase64: bytesToBase64(proof),
            note: "Incomplete calendar proof — run `ots upgrade` to anchor to Bitcoin, then `ots verify`.",
          },
          witnessedAt: null,
        };
      } catch (e) {
        errors.push(`${base}: ${errMsg(e)}`);
      }
    }
    throw new Error(`All OpenTimestamps calendars failed: ${errors.join("; ")}`);
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(new Error(`WITNESS_TIMEOUT_${this.timeoutMs}MS`)),
      this.timeoutMs,
    );
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}

/* ── Receipt store ─────────────────────────────────────────────────────── */

export interface AnchorReceiptRecord extends AnchorRecord {
  readonly id: string;
  readonly createdAt: string;
}

export interface AnchorReceiptStore {
  append(record: AnchorRecord): Promise<AnchorReceiptRecord>;
  latest(): Promise<AnchorReceiptRecord | null>;
  history(): Promise<ReadonlyArray<AnchorReceiptRecord>>;
  latestForRoot(merkleRoot: string): Promise<AnchorReceiptRecord | null>;
}

/** In-memory backend — the no-DB / test profile (Prisma backend stays venture-side). */
export class InMemoryAnchorReceiptStore implements AnchorReceiptStore {
  private readonly rows: AnchorReceiptRecord[] = [];

  public async append(record: AnchorRecord): Promise<AnchorReceiptRecord> {
    const stored: AnchorReceiptRecord = Object.freeze({
      ...record,
      tips: Object.freeze(record.tips.map((t) => Object.freeze({ ...t }))),
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    });
    this.rows.push(stored);
    return stored;
  }

  public async latest(): Promise<AnchorReceiptRecord | null> {
    return this.rows.length === 0 ? null : (this.rows[this.rows.length - 1] ?? null);
  }

  public async history(): Promise<ReadonlyArray<AnchorReceiptRecord>> {
    return [...this.rows];
  }

  public async latestForRoot(merkleRoot: string): Promise<AnchorReceiptRecord | null> {
    for (let i = this.rows.length - 1; i >= 0; i--) {
      const row = this.rows[i]!;
      if (row.merkleRoot === merkleRoot) return row;
    }
    return null;
  }
}
