/**
 * Signing a DSSE record — the holder's own signature on a record they author
 * (a work record, a request for their own history), with the key they hold
 * for that one place and no other.
 *
 * Narrow on purpose:
 * - **one key**: the relationship key for the counterparty. Never the root
 *   (which signs nothing, d47(g)(1)), never a copy or helper key. It signs in
 *   the hardware where the hardware holds it, and is never handed back;
 * - **one list of record types**: only what a holder authors. A session line
 *   has `sessions.cosign`'s checks; a trust or status list is a publisher's or
 *   an issuer's act; nothing else is signed from here;
 * - **the switch decides first** (d49(a)): unset or off, and nothing is signed
 *   and nothing is left behind.
 */

import { signEnvelope, type DsseEnvelope } from "@kashscript/attest/dsse";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";

/**
 * The payload types a holder signs through the wallet. Each is a `dsse-type`
 * row in attest's registry (a test holds that true). Adding one is a change to
 * this file, made on purpose.
 */
export const HOLDER_SIGNABLE_PAYLOAD_TYPES: readonly string[] = [
  "application/vnd.oreoasis.work-record+json",
  "application/vnd.oreoasis.holder-export-request+json",
  "application/vnd.oreoasis.improvement-statement-request+json",
];

/** A record is a document, not a file: refuse anything that large before signing it. */
export const MAX_SIGNED_PAYLOAD_BYTES = 256 * 1024;

export type SignDsseResult =
  | { readonly status: "signed"; readonly envelope: DsseEnvelope }
  | { readonly status: "needs-choice"; readonly counterparty: string }
  | { readonly status: "off" };

export interface SignDsseOptions {
  /** JCS-canonicalize the payload before signing. Default: the payload's own `JSON.stringify` bytes. */
  readonly canonical?: boolean;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

export class Signing {
  constructor(private readonly core: WalletCore) {}

  /**
   * Sign `payload` as `payloadType` with the person's key for `counterparty`.
   * The type and the payload are checked first, so a refused record changes
   * nothing — not even a key made for a place.
   */
  async dsse(counterparty: string, payloadType: string, payload: unknown, opts: SignDsseOptions = {}): Promise<SignDsseResult> {
    if (!HOLDER_SIGNABLE_PAYLOAD_TYPES.includes(payloadType)) {
      throw new WalletError("SIGN_REFUSED", `${JSON.stringify(payloadType)} is not a record a holder signs here`);
    }
    if (!isPlainObject(payload)) throw new WalletError("SIGN_REFUSED", "the payload must be a plain JSON object");
    let size: number;
    try {
      size = new TextEncoder().encode(JSON.stringify(payload)).length;
    } catch {
      throw new WalletError("SIGN_REFUSED", "the payload is not JSON");
    }
    if (size > MAX_SIGNED_PAYLOAD_BYTES) throw new WalletError("SIGN_REFUSED", `the payload is ${size} bytes; the limit is ${MAX_SIGNED_PAYLOAD_BYTES}`);

    const proof = await this.core.relationships.proof(counterparty);
    if (proof === "unset") return { status: "needs-choice", counterparty };
    if (proof === "off") return { status: "off" };
    const r = await this.core.relationships.ensureKey(await this.core.relationships.ensure(counterparty));
    const envelope = await this.core.keys.withSigner(r.keyId, (s) =>
      signEnvelope(payload, payloadType, s, opts.canonical === true ? { canonical: true } : undefined),
    );
    return { status: "signed", envelope };
  }
}
