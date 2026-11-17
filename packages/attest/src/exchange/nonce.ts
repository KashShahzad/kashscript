/**
 * Issue each nonce once and accept it once (KS-Q4; d84 P6: nonce bound into
 * every presentation). The key binding's window bounds how long a captured
 * presentation stays fresh; this is the rest of the replay defence — a
 * presentation is accepted at most once, for a nonce this verifier issued,
 * inside the nonce's lifetime.
 *
 * In memory, bounded, and knowing nothing about who asked: a nonce is random
 * bytes and an expiry, never tied to a person, a device or a request's origin.
 * A verifier that runs several processes keeps its nonces in its own store and
 * keeps this contract: `issue` remembers, `consume` answers once.
 */

import { bytesToBase64Url } from "../ed25519";
import { AttestError } from "../errors";
import { verifySdJwt, type SdJwtReport, type VerifyPresentedSdJwtOptions } from "../sd-jwt/sd-jwt";

/** Five minutes: long enough to scan a code and answer, short enough that an unused nonce soon means nothing. */
export const DEFAULT_NONCE_TTL_SEC = 300;
/** The most nonces held at once; past it the oldest is forgotten, so a flood of requests costs its own requests, never memory. */
export const DEFAULT_NONCE_MAX = 10_000;

export type NonceAnswer = "accepted" | "unknown" | "expired" | "used";

export interface NonceRegistry {
  /** A fresh nonce, remembered until it is used or expires. */
  issue(nowSec?: number): string;
  /** Accept a nonce once: `accepted` the first time inside its lifetime; `used` after that; `unknown` for one never issued here (or forgotten); `expired` past its lifetime. */
  consume(nonce: string, nowSec?: number): NonceAnswer;
  /** How many nonces are waiting. */
  readonly size: number;
}

export interface NonceRegistryOptions {
  readonly ttlSec?: number;
  readonly max?: number;
  readonly now?: () => number;
}

export function createNonceRegistry(opts: NonceRegistryOptions = {}): NonceRegistry {
  const ttl = opts.ttlSec ?? DEFAULT_NONCE_TTL_SEC;
  const max = opts.max ?? DEFAULT_NONCE_MAX;
  if (!Number.isSafeInteger(ttl) || ttl < 1) throw new AttestError("INVALID_INPUT", "a nonce lives at least one second");
  if (!Number.isSafeInteger(max) || max < 1) throw new AttestError("INVALID_INPUT", "a registry holds at least one nonce");
  const clock = opts.now ?? (() => Math.floor(Date.now() / 1000));
  /** nonce → expiry; a used nonce is kept, marked, until its expiry, so a replay inside the lifetime reads `used`. */
  const live = new Map<string, { exp: number; used: boolean }>();
  const prune = (now: number): void => {
    for (const [n, v] of live) if (v.exp <= now) live.delete(n);
  };
  return {
    issue(nowSec) {
      const now = nowSec ?? clock();
      prune(now);
      while (live.size >= max) {
        const oldest = live.keys().next();
        if (oldest.done === true) break;
        live.delete(oldest.value);
      }
      const nonce = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
      live.set(nonce, { exp: now + ttl, used: false });
      return nonce;
    },
    consume(nonce, nowSec) {
      const now = nowSec ?? clock();
      const v = typeof nonce === "string" ? live.get(nonce) : undefined;
      if (v === undefined) return "unknown";
      if (v.exp <= now) {
        live.delete(nonce);
        return "expired";
      }
      if (v.used) return "used";
      v.used = true;
      return "accepted";
    },
    get size() {
      return live.size;
    },
  };
}

export type AcceptPresentationFailure = "NONCE_REPLAYED" | "NONCE_UNKNOWN";

export interface AcceptedPresentation {
  readonly ok: boolean;
  /** The SD-JWT's own reason, or the registry's. */
  readonly reason: SdJwtReport["reason"] | AcceptPresentationFailure;
  readonly report: SdJwtReport;
  readonly nonce: NonceAnswer | null;
}

/**
 * Verify a presentation against the nonce this verifier issued, and accept it
 * once. The nonce is consumed only after the presentation verifies, so a
 * malformed or forged answer never burns a nonce its real holder is about to
 * use. `consume` is synchronous, so two copies racing in one process cannot
 * both be accepted.
 */
export async function acceptPresentationOnce(
  presentation: string,
  registry: NonceRegistry,
  opts: VerifyPresentedSdJwtOptions,
): Promise<AcceptedPresentation> {
  const report = await verifySdJwt(presentation, opts);
  if (!report.ok) return { ok: false, reason: report.reason, report, nonce: null };
  const answer = registry.consume(opts.nonce, opts.nowSec);
  if (answer === "accepted") return { ok: true, reason: null, report, nonce: answer };
  return { ok: false, reason: answer === "used" ? "NONCE_REPLAYED" : "NONCE_UNKNOWN", report, nonce: answer };
}
