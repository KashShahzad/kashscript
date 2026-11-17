/**
 * A public witness's verdict over a digest (KS-Q4; ECOSYSTEM d5, d89(a),
 * d91(a)). The trust log is one witness; the second is public — OpenTimestamps
 * (Bitcoin, through calendars) or an RFC 3161 authority — and the two fail
 * differently, which is the point. Each verdict says what stands behind it and
 * what was not checked; `final` with `digestOk` is the only state that gives a
 * time.
 */

import { base64ToBytes } from "../ed25519";
import { verifyOpenTimestamps, type BitcoinHeader } from "./ots";
import { verifyRfc3161Digest } from "./rfc3161";

export type { BitcoinHeader } from "./ots";

export type WitnessKind = "opentimestamps" | "rfc3161";

export type WitnessState =
  /** A time stands: the proof reaches a block header the checker holds, or the authority's token stamps this digest and its signature was verified. */
  | "final"
  /** The witness was asked and has not answered — an OpenTimestamps proof the calendars have not yet committed. */
  | "pending"
  /** The proof is read and names its attestation, but this checker could not finish — a block header not supplied, a signature chain left to openssl. */
  | "unchecked"
  | "invalid";

export interface WitnessVerdict {
  readonly kind: WitnessKind;
  readonly state: WitnessState;
  /** The attested time, when `final`. */
  readonly timeUnix: number | null;
  /** The proof is over the digest asked about. False means it stamps something else. */
  readonly digestOk: boolean;
  /** Who stands behind the time, in words: `Bitcoin block 974281`, `DigiCert … (RFC 3161)`. */
  readonly by: string;
  readonly detail: string;
}

/** A witness as a proof carries it: the file's bytes, base64. */
export interface LogWitness {
  readonly kind: WitnessKind;
  readonly proofBase64: string;
}

export interface WitnessVerdictOptions {
  /** Bitcoin block headers the checker holds, for OpenTimestamps proofs that reached a block. */
  readonly headers?: readonly BitcoinHeader[];
  /** Verifies an RFC 3161 token's CMS signature and chain over this digest — the CLI's openssl. Without it a token's time is read, never relied on. */
  readonly verifyRfc3161Signature?: Rfc3161SignatureCheck;
}

/** Checks a token's CMS signature, its chain to a root the caller trusts, and that it stamps `digestHex`. */
export type Rfc3161SignatureCheck = (tsr: Uint8Array, digestHex: string) => Promise<boolean>;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The verdict of every witness carried, in order, each over `digestHex`. Junk is `invalid`, never a throw. */
export async function witnessVerdictsFor(witnesses: readonly unknown[], digestHex: string, opts: WitnessVerdictOptions = {}): Promise<WitnessVerdict[]> {
  const out: WitnessVerdict[] = [];
  for (const w of witnesses) {
    if (!isPlainObject(w) || (w.kind !== "opentimestamps" && w.kind !== "rfc3161") || typeof w.proofBase64 !== "string") {
      out.push({ kind: "opentimestamps", state: "invalid", timeUnix: null, digestOk: false, by: "nobody", detail: "a witness is {kind, proofBase64}" });
      continue;
    }
    let bytes: Uint8Array;
    try {
      bytes = base64ToBytes(w.proofBase64);
    } catch {
      out.push({ kind: w.kind, state: "invalid", timeUnix: null, digestOk: false, by: "nobody", detail: "the proof is not base64" });
      continue;
    }
    if (w.kind === "opentimestamps") {
      out.push(await verifyOpenTimestamps(bytes, digestHex, opts.headers !== undefined ? { headers: opts.headers } : {}));
      continue;
    }
    let signatureVerified = false;
    if (opts.verifyRfc3161Signature !== undefined) {
      try {
        signatureVerified = await opts.verifyRfc3161Signature(bytes, digestHex);
      } catch {
        signatureVerified = false;
      }
    }
    out.push(await verifyRfc3161Digest(bytes, digestHex, { signatureVerified }));
  }
  return out;
}
