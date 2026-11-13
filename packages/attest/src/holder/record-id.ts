import { canonicalizeBytes } from "@kashscript/identity-core";
import { sha256Hex } from "../chain";
import { base64ToBytes } from "../ed25519";
import { pae } from "../dsse";

/** How a held artifact is carried: a JSON value, or a string (an Indus token, an SD-JWT). */
export interface HeldArtifactValue {
  readonly kind: string;
  readonly value: unknown;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The record id a wallet computes: SHA-256 hex over the UTF-8 of a string
 * artifact, or over RFC 8785 JCS of a JSON one. Local to the wallet — never
 * sent anywhere unless the holder discloses it.
 */
export async function recordIdOf(artifact: HeldArtifactValue): Promise<string> {
  if (typeof artifact.value === "string") return sha256Hex(new TextEncoder().encode(artifact.value.trim()));
  return sha256Hex(canonicalizeBytes(artifact.value));
}

/**
 * The identity a verifier counts by: what the issuer signed, never the wrapping
 * around it (AU-3, A7-03). A re-wrapped copy — an extra field, a junk sibling
 * signature, a bare envelope beside its countersigned form — has a new record
 * id and the same content id, so a threshold is met by records, not encodings.
 *
 *   - `dsse`, `countersign-bundle`: SHA-256 over PAE(payloadType, payload bytes)
 *     of the envelope (the bundle's subject) — the bytes every signer signed;
 *   - `kash-event`: SHA-256 over JCS({header, body}) — the bytes its signer signed;
 *   - `sd-jwt`: SHA-256 over the issuer-signed JWT, the first `~`-segment;
 *   - anything else, or a value without its kind's shape: the record id.
 */
export async function contentIdOf(artifact: HeldArtifactValue): Promise<string> {
  const v = artifact.value;
  const envelope = artifact.kind === "countersign-bundle" ? (isPlainObject(v) ? v.subject : null) : artifact.kind === "dsse" ? v : null;
  if (isPlainObject(envelope) && typeof envelope.payloadType === "string" && typeof envelope.payload === "string") {
    try {
      return await sha256Hex(pae(envelope.payloadType, base64ToBytes(envelope.payload)));
    } catch {
      // not base64: no signed bytes to name — fall through to the record id
    }
  }
  if (artifact.kind === "kash-event" && isPlainObject(v) && isPlainObject(v.header) && isPlainObject(v.body)) {
    try {
      return await sha256Hex(canonicalizeBytes({ header: v.header, body: v.body }));
    } catch {
      // not canonicalisable — fall through
    }
  }
  if (artifact.kind === "sd-jwt" && typeof v === "string") {
    return sha256Hex(new TextEncoder().encode(v.trim().split("~")[0]!));
  }
  return recordIdOf(artifact);
}
