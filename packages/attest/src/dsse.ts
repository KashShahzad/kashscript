/**
 * DSSE (Dead Simple Signing Envelope) + PAE — Sigstore-compatible.
 *
 *   Envelope: { payloadType, payload: base64(bytes), signatures: [{ keyid, sig }] }
 *   Signed:   Ed25519 (raw, 64 bytes) or ES256 (strict DER, low-S) over
 *             PAE(payloadType, payloadBytes)
 *   PAE:      "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 *
 * A DSSE signature names no algorithm, so **the key decides** (PL-2,
 * ADR-0020): a resolver returns a bare 32-byte key (Ed25519, as before) or a
 * typed key, and the signature is checked under that key's algorithm only.
 * ES256 is DER because that is what Sigstore tooling verifies.
 *
 * Domain separation is carried by `payloadType` (the DSSE-native mechanism) — no
 * DST is prepended, so signatures verify with any standard DSSE tool (cosign,
 * sigstore) as well as attest's own verifier. Ported from Oreoasis
 * `apps/oreoasis-core-host/src/dsse.ts`.
 *
 * `signEnvelope` defaults to **faithful DSSE** (payload = verbatim
 * `JSON.stringify` bytes, preserved byte-for-byte) so it round-trips the
 * ventures' existing bundles. Pass `{ canonical: true }` for new attest
 * artifacts to JCS-canonicalize the payload first (ROADMAP "JCS + DSSE").
 */

import { canonicalizeBytes } from "@kashscript/identity-core";
import { AttestError } from "./errors";
import { bytesToBase64, base64ToBytes } from "./ed25519";
import { signBytes, verifyBytes, type RawSigner, type VerifyKey } from "./signing";

/** Media type for a signed audit-trail bundle (also its DSSE separation label). */
export const DSSE_PAYLOAD_TYPE_AUDIT_BUNDLE =
  "application/vnd.oreoasis.audit-bundle+json" as const;

export interface DsseSignature {
  /** Verification-method id — the signer's DID. */
  readonly keyid: string;
  /** Standard base64 of the signature over the PAE: raw 64 bytes for Ed25519,
   *  strict DER for ES256. */
  readonly sig: string;
}

export interface DsseEnvelope {
  readonly payloadType: string;
  /** Standard base64 of the payload bytes. */
  readonly payload: string;
  readonly signatures: ReadonlyArray<DsseSignature>;
}

/** A signer whose DID becomes the `keyid`: an Ed25519 key pair (as before),
 *  a software P-256 key, or a key held in hardware. */
export type DsseSigner = RawSigner & { readonly keyid: string };

export interface DsseVerifyResult {
  /** True iff ≥1 signature verified under a resolvable key. */
  readonly ok: boolean;
  readonly payloadType: string;
  /** Decoded + JSON-parsed payload (bytes preserved from signing) — `undefined`
   *  when the signed bytes are not JSON. The signatures were judged over the
   *  bytes either way (AU-3, A7-04). */
  readonly payloadJson: unknown;
  /** The keyids whose signatures verified, as the envelope spells them —
   *  callers enforce the expected signer, and count by the key a keyid resolves
   *  to (`canonicalSignerOf`), never by the spelling. */
  readonly verifiedKeyids: ReadonlyArray<string>;
}

export interface SignEnvelopeOptions {
  /** JCS-canonicalize the payload before signing (attest-canonical). Default
   *  `false` = faithful DSSE (verbatim `JSON.stringify`, seed-compatible). */
  readonly canonical?: boolean;
}

/** PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body. LEN is
 *  the ASCII-decimal UTF-8 byte length; SP is a single 0x20. */
export function pae(payloadType: string, payload: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  const typeBytes = enc.encode(payloadType);
  const prefix = enc.encode(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${payload.length} `,
  );
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix, 0);
  out.set(payload, prefix.length);
  return out;
}

/** Wrap `payloadObject` in a signed DSSE envelope. */
export async function signEnvelope(
  payloadObject: unknown,
  payloadType: string,
  signer: DsseSigner,
  opts?: SignEnvelopeOptions,
): Promise<DsseEnvelope> {
  const payloadBytes = opts?.canonical
    ? canonicalizeBytes(payloadObject)
    : new TextEncoder().encode(JSON.stringify(payloadObject));
  const sig = await signBytes(signer, pae(payloadType, payloadBytes), "der");
  return {
    payloadType,
    payload: bytesToBase64(payloadBytes),
    signatures: [{ keyid: signer.keyid, sig: bytesToBase64(sig) }],
  };
}

/**
 * Verify a DSSE envelope. `resolvePublicKey` maps a signature `keyid` to its
 * key — a bare 32-byte Ed25519 key, or a typed key — or null if unknown.
 * Returns `ok: true` when ≥1 signature verifies. A sibling signature that is
 * not base64 is skipped like any other junk entry, and a payload that is not
 * JSON is reported as `payloadJson: undefined` — neither is thrown, because
 * anyone can append either to a record somebody else signed (AU-3, A7-04).
 * Throws {@link AttestError} only on a structurally malformed envelope (no
 * string `payloadType` or `payload`, no `signatures` array, a payload that is
 * not base64), and identity-core's `ALG_UNAVAILABLE` when this runtime cannot
 * run a key's algorithm at all.
 */
export async function verifyEnvelope(
  envelope: DsseEnvelope,
  resolvePublicKey: (keyid: string) => VerifyKey | null,
): Promise<DsseVerifyResult> {
  if (
    envelope === null ||
    typeof envelope !== "object" ||
    typeof envelope.payloadType !== "string" ||
    typeof envelope.payload !== "string" ||
    !Array.isArray(envelope.signatures)
  ) {
    throw new AttestError(
      "MALFORMED_ENVELOPE",
      "envelope must have string payloadType, string payload, and a signatures array",
    );
  }

  const payloadBytes = base64ToBytes(envelope.payload);
  const paeBytes = pae(envelope.payloadType, payloadBytes);

  const verifiedKeyids: string[] = [];
  for (const s of envelope.signatures) {
    if (
      s === null ||
      typeof s !== "object" ||
      typeof s.keyid !== "string" ||
      typeof s.sig !== "string"
    ) {
      // audit r1 F2: a malformed SIBLING signature must not deny verification of
      // an otherwise-valid envelope. DSSE is "≥1 signature verifies" — skip the
      // junk entry (it simply never contributes a verified keyid) instead of
      // throwing away every valid signature alongside it.
      continue;
    }
    const pub = resolvePublicKey(s.keyid);
    if (pub === null) continue;
    let sigBytes: Uint8Array;
    try {
      sigBytes = base64ToBytes(s.sig);
    } catch {
      continue; // a sibling that is not base64 contributes nothing, and denies nothing (AU-3, A7-04)
    }
    if (await verifyBytes(sigBytes, paeBytes, pub, "der")) {
      verifiedKeyids.push(s.keyid);
    }
  }

  // The payload as JSON when it is JSON. Bytes that are not JSON are `undefined`, never
  // a throw: the signatures above were judged over the bytes (AU-3, A7-04).
  let payloadJson: unknown;
  try {
    payloadJson = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    payloadJson = undefined;
  }

  return {
    ok: verifiedKeyids.length > 0,
    payloadType: envelope.payloadType,
    payloadJson,
    verifiedKeyids,
  };
}
