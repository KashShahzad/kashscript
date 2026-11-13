/**
 * One signing seam and one verifying seam, for every family attest signs raw
 * bytes in (DSSE, JWS). PL-2 adds ES256 beside Ed25519 (d47(g)(3)); the rule
 * this file exists to enforce is that **the algorithm comes from the key,
 * never from the envelope**:
 *
 *   • a key is either a bare 32-byte `Uint8Array` — Ed25519, the shape every
 *     caller already passes — or a typed {@link KashPublicKey};
 *   • a `did:kash` declares its own key type ({@link resolveDidKey});
 *   • nothing here reads an algorithm out of a signature or a header.
 *
 * ES256 is signed low-S and verified only low-S. Its encoding follows each
 * family's own standard: raw `r ‖ s` for JWS (RFC 7518), strict DER for DSSE
 * (what Sigstore tooling verifies). A hardware key never hands over its
 * private bytes; it signs through a callback. So does an Ed25519 key held
 * elsewhere — a key service, a KMS, a non-extractable CryptoKey (GP-6) — and
 * its signature is checked under its public key before anything uses it.
 */

import {
  compressP256PublicKey,
  decodeBase58,
  deriveDidForKey,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  es256RawSignature,
  parseDidKey,
  signP256,
  verifyP256,
  type ExternalSignature,
  type KashKeyType,
  type KashPublicKey,
} from "@kashscript/identity-core";
import { AttestError } from "./errors";
import { signRaw, verifyRaw } from "./ed25519";

export type { KashKeyType, KashPublicKey, ExternalSignature };

/** An Ed25519 key that never leaves where it lives: it signs the exact message and returns the 64-byte signature. */
export interface ExternalEd25519Signer {
  readonly alg: "Ed25519";
  readonly publicKey: Uint8Array;
  readonly sign: (message: Uint8Array) => Promise<Uint8Array>;
}

/**
 * Who signs. The first shape is the one every caller already passes and means
 * Ed25519; the two ES256 shapes are a software P-256 key and a key held in
 * hardware, which signs over the exact message bytes (hashing with SHA-256
 * itself, as ES256 requires). The last is an Ed25519 key held elsewhere, so a
 * server signs without its seed in the caller (d47(f)).
 */
export type RawSigner =
  | { readonly alg?: "Ed25519"; readonly privateKey: Uint8Array; readonly publicKey: Uint8Array }
  | { readonly alg: "ES256"; readonly privateKey: Uint8Array; readonly publicKey: Uint8Array }
  | { readonly alg: "ES256"; readonly publicKey: Uint8Array; readonly sign: (message: Uint8Array) => Promise<ExternalSignature> }
  | ExternalEd25519Signer;

/** A verification key: bare bytes are Ed25519 (the pre-PL-2 shape); anything else says its type. */
export type VerifyKey = Uint8Array | KashPublicKey;

/** How an ES256 signature is written: raw for JWS, DER for DSSE. Ed25519 is always raw. */
export type EcdsaForm = "raw" | "der";

export function typedKey(key: VerifyKey): KashPublicKey {
  return key instanceof Uint8Array ? { type: "Ed25519", publicKey: key } : key;
}

/** The typed public key of a signer. */
export function signerKey(signer: RawSigner): KashPublicKey {
  return signer.alg === "ES256"
    ? { type: "P-256", publicKey: compressP256PublicKey(signer.publicKey) }
    : { type: "Ed25519", publicKey: signer.publicKey };
}

/** The self-certifying `did:kash` of a signer's key. */
export function signerDid(signer: RawSigner): string {
  return deriveDidForKey(signerKey(signer));
}

/** The JOSE `alg` a key implies — the only `alg` a JWS signed by it may carry. */
export function joseAlgOf(type: KashKeyType): "EdDSA" | "ES256" {
  return type === "P-256" ? "ES256" : "EdDSA";
}

/**
 * An Ed25519 signature from a key held elsewhere, checked before it is used: a
 * key service that answers with another key — a rotation, a wrong reference —
 * fails here, not later in a stranger's verifier.
 */
async function signEd25519Through(signer: ExternalEd25519Signer, message: Uint8Array): Promise<Uint8Array> {
  // A malformed public key is the caller's mistake, said as such — not a signature that "does not verify".
  if (!(signer.publicKey instanceof Uint8Array) || signer.publicKey.length !== 32) {
    throw new AttestError("INVALID_INPUT", "an external Ed25519 signer's publicKey is 32 bytes");
  }
  const sig: unknown = await signer.sign(message);
  if (!(sig instanceof Uint8Array) || sig.length !== 64 || !(await verifyRaw(sig, message, signer.publicKey))) {
    throw new AttestError("MALFORMED_SIGNATURE", "the external Ed25519 signer returned a signature that does not verify under its public key");
  }
  return new Uint8Array(sig);
}

/** Sign raw bytes. ES256 comes back low-S, in the form the family asks for. */
export async function signBytes(signer: RawSigner, message: Uint8Array, form: EcdsaForm): Promise<Uint8Array> {
  if (signer.alg !== "ES256") return "sign" in signer ? signEd25519Through(signer, message) : signRaw(message, signer.privateKey, signer.publicKey);
  const raw =
    "sign" in signer
      ? es256RawSignature(await signer.sign(message))
      : await signP256(message, signer.privateKey, signer.publicKey);
  return form === "der" ? ecdsaRawToDer(raw) : raw;
}

/**
 * Verify raw bytes under a key whose type is known. `false` for anything that
 * does not verify — a wrong signature, a high-S twin, a signature written for
 * the other algorithm, a malformed DER. A runtime that cannot run the key's
 * algorithm at all throws `ALG_UNAVAILABLE`: nothing was judged.
 */
export async function verifyBytes(signature: Uint8Array, message: Uint8Array, key: VerifyKey, form: EcdsaForm): Promise<boolean> {
  const k = typedKey(key);
  if (k.type === "Ed25519") return verifyRaw(signature, message, k.publicKey);
  let raw: Uint8Array;
  if (form === "der") {
    try {
      raw = ecdsaDerToRaw(signature);
    } catch {
      return false;
    }
  } else {
    raw = signature;
  }
  try {
    return await verifyP256(raw, message, k.publicKey);
  } catch {
    return false; // a malformed P-256 key verifies nothing
  }
}

/** The key a `did:kash` (with or without a `#fragment`) declares, or null. Never throws. */
export function resolveDidKey(keyid: string): KashPublicKey | null {
  if (typeof keyid !== "string") return null;
  const i = keyid.indexOf("#");
  try {
    return parseDidKey(i === -1 ? keyid : keyid.slice(0, i));
  } catch {
    return null;
  }
}

const DID_KEY_PREFIX = "did:key:z";
/** Multicodec varints: `ed25519-pub` (0xed) and `p256-pub` (0x1200). */
const MULTICODEC_ED25519 = [0xed, 0x01] as const;
const MULTICODEC_P256 = [0x80, 0x24] as const;

/** The key a `did:key:z…` (base58btc multibase) declares — Ed25519 or compressed P-256 — or null. */
function resolveDidKeyMethod(did: string): KashPublicKey | null {
  let bytes: Uint8Array;
  try {
    bytes = decodeBase58(did.slice(DID_KEY_PREFIX.length));
  } catch {
    return null;
  }
  const hasPrefix = (p: readonly number[]): boolean => p.every((b, n) => bytes[n] === b);
  try {
    if (bytes.length === 2 + 32 && hasPrefix(MULTICODEC_ED25519)) return { type: "Ed25519", publicKey: bytes.slice(2) };
    if (bytes.length === 2 + 33 && hasPrefix(MULTICODEC_P256)) return { type: "P-256", publicKey: compressP256PublicKey(bytes.slice(2)) };
  } catch {
    return null; // a point that is not on the curve names no key
  }
  return null;
}

/**
 * The key any DSSE `keyid` this ecosystem accepts declares: a `did:kash` of
 * either type, or a `did:key` of either type (with or without a `#fragment`).
 * Hand it to {@link verifyBytes}' callers as the resolver — it returns a *typed*
 * key, so an ES256 signature is judged as ES256. A resolver that returns a bare
 * 32-byte key can only ever verify Ed25519. Never throws; null for anything else.
 * {@link resolveDidKey} keeps its `did:kash`-only meaning.
 */
export function resolveVerificationKey(keyid: string): KashPublicKey | null {
  if (typeof keyid !== "string") return null;
  const i = keyid.indexOf("#");
  const did = i === -1 ? keyid : keyid.slice(0, i);
  return did.startsWith(DID_KEY_PREFIX) ? resolveDidKeyMethod(did) : resolveDidKey(did);
}

/**
 * The one name of a signer: the `did:kash` of the key a keyid resolves to — a
 * `did:kash` of either type or a `did:key`, with or without a `#fragment`. Two
 * spellings of one key give one name; a keyid that names no key gives null.
 * Every count of signers and every independence check compares this, never the
 * string a signer wrote (AU-3, A7-02: `did:kash:X` and `did:kash:X#c` are one key).
 */
export function canonicalSignerOf(keyid: string): string | null {
  const key = resolveVerificationKey(keyid);
  return key === null ? null : deriveDidForKey(key);
}
