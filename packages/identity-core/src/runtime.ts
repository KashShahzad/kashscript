/**
 * What this runtime's WebCrypto can do. Ed25519 arrived in browsers late
 * (Chrome 137, Firefox 129, Safari 17) and some WebViews still lack it, while
 * P-256 is everywhere. A verifier that cannot run an algorithm must say so —
 * "not checked here" — and never report the signature as invalid (d11).
 */

import { KashCryptoError } from "./errors";

/** True for the error WebCrypto throws when it does not know an algorithm at all. */
export function isAlgorithmUnsupported(err: unknown): boolean {
  if (err instanceof KashCryptoError) return err.code === "ALG_UNAVAILABLE";
  const name = typeof err === "object" && err !== null ? (err as { name?: unknown }).name : undefined;
  return name === "NotSupportedError";
}

let ed25519Probe: Promise<boolean> | null = null;

/** Whether this runtime's WebCrypto can verify Ed25519. Probed once. */
export function ed25519Available(): Promise<boolean> {
  ed25519Probe ??= (async () => {
    try {
      // RFC 8032 test 1's public key — any valid point works.
      const pub = Uint8Array.of(
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
      );
      await crypto.subtle.importKey("raw", pub as unknown as BufferSource, { name: "Ed25519" }, false, ["verify"]);
      return true;
    } catch {
      return false;
    }
  })();
  return ed25519Probe;
}

/** Re-throw an "algorithm unavailable" failure as the typed error; otherwise do nothing. */
export function rethrowIfUnavailable(err: unknown, alg: string): void {
  if (isAlgorithmUnsupported(err)) {
    if (err instanceof KashCryptoError) throw err;
    throw new KashCryptoError(`This runtime's WebCrypto cannot run ${alg}; nothing was judged.`, "ALG_UNAVAILABLE", err);
  }
}
