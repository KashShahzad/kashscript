/**
 * Sign / verify primitives for Kash-Events.
 *
 * Implements the Identity-Bible §5.5 signature shape:
 *
 *   sig = Ed25519.sign( sk, DST_bytes || JCS({ header, body }) )
 *
 * The DST (Domain-Separation Tag) is a literal byte prefix that scopes a
 * signature to a specific subprotocol — preventing a record signature from
 * being replayed as, say, a trade-attestor or handshake signature. Default
 * DST is `kash-record-v1\n` for record-tier events (the Kash-Event envelope
 * used by @kashscript/lexicons).
 *
 * Hardened against malleability through deterministic RFC 8785
 * canonicalisation (see `./canonical.ts`'s Security Advisory). Ed25519 itself
 * is non-malleable by construction (RFC 8032 §8.4: signatures are unique per
 * (message, key) pair under correct implementations).
 *
 * Side-effect free. No console, no fetch, no globals beyond `globalThis.crypto`.
 */

import { canonicalizeBytes } from "./canonical";
import { decodeBase58, encodeBase58 } from "./base58";
import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { decodeHex, encodeHex } from "./hex";
import { KashCryptoError } from "./errors";
import type { KashPublicKey } from "./did";
import { ecdsaDerToRaw, normaliseLowS, P256_SIGNATURE_BYTES, signP256, verifyP256 } from "./p256";
import { rethrowIfUnavailable } from "./runtime";
import { ed25519Precheck } from "./ed25519-strict";

const ED25519_PRIVATE_KEY_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES  = 32;
const ED25519_SIGNATURE_BYTES   = 64;

/** Default Domain-Separation Tag for Kash-Event records.
 *  Matches the `signature.dst` literal used by `@kashscript/lexicons`. */
export const DEFAULT_KASH_RECORD_DST = "kash-record-v1\n" as const;

/**
 * Byte-level encoding for the signature string.
 *
 *   • `"multibase"` (DEFAULT) — `z`-prefix + base58btc. Matches the
 *     `@kashscript/lexicons` envelope schema (`format: "multibase"`).
 *     Recommended for new code; emitted with NO `encoding` field on
 *     the resulting `KashEventSignature` so the output is byte-identical
 *     to the lexicons wire format.
 *   • `"base64url"` — historical default. Signatures emitted with this
 *     encoding carry an explicit `encoding: "base64url"` field so
 *     verifyEvent knows to decode them; they do NOT match the lexicons
 *     envelope schema and require a bridge for cross-package use.
 *   • `"hex"` — convenience for log-line debugging. Same `encoding` field
 *     posture as base64url.
 */
export type SignatureEncoding = "multibase" | "base64url" | "hex";

/**
 * Algorithm identifier register (§5.5 of identity-protocol-v1.md).
 *
 * `ed25519` and `es256` are implemented. `es256` (PL-2, ADR-0020) is ECDSA
 * P-256 with SHA-256, signed low-S and carried as raw `r ‖ s`; a high-S twin
 * is rejected. `bls12-381` stays reserved and throws `UNSUPPORTED_ALG`.
 *
 * The `alg` on a signature is never trusted alone: {@link verifyEventForKey}
 * takes the algorithm from the key's declared type, and `verifyEvent` refuses
 * a key whose length belongs to the other algorithm.
 */
export type KashSignatureAlg = "ed25519" | "es256" | "bls12-381";

/** Signature object embedded in a SignedKashEvent. */
export interface KashEventSignature {
  /** Algorithm identifier — see {@link KashSignatureAlg}. */
  readonly alg: KashSignatureAlg;
  /** Signature bytes, encoded per `encoding` (or multibase by default). */
  readonly sig: string;
  /** Domain-Separation Tag that was prepended to the canonical payload before signing. */
  readonly dst: string;
  /**
   * Encoding chosen for `sig`. Optional — when omitted, `sig` is multibase
   * (z-prefix base58btc) per the lexicons envelope schema. Explicit values
   * (`"base64url"` / `"hex"`) are emitted only when the caller passes
   * `SignEventOptions.encoding` explicitly.
   */
  readonly encoding?: SignatureEncoding;
  /** Optional verification-method id (e.g., `did:kash:<pub>#sig-1`). */
  readonly kid?: string;
}

/** Minimal shape `signEvent` operates on. */
export interface SignableKashEvent {
  readonly header: Readonly<Record<string, unknown>>;
  readonly body:   unknown;
}

/** Minimal shape `verifyEvent` operates on. */
export interface SignedKashEvent extends SignableKashEvent {
  readonly signature: KashEventSignature;
}

/** Options accepted by `signEvent` and `Signer.sign`. */
export interface SignEventOptions {
  /** Override the default `kash-record-v1\n` DST. */
  readonly dst?: string;
  /** Signature encoding. Default `"base64url"`. */
  readonly encoding?: SignatureEncoding;
  /** Verification-method id to embed in the returned signature object. */
  readonly kid?: string;
}

/* ── Ed25519 PKCS8 prefix ─────────────────────────────────────────
 * Constant 16-byte ASN.1 DER prefix that wraps a 32-byte Ed25519 seed
 * into a PKCS8 PrivateKeyInfo (RFC 8410). Lets us import a raw seed
 * via `crypto.subtle.importKey("pkcs8", …)` without depending on any
 * third-party DER encoder. */
const PKCS8_ED25519_PREFIX = Uint8Array.of(
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
);

const TEXT_ENCODER = new TextEncoder();

/** No-op cast: Uint8Array is a valid `ArrayBufferView` at runtime, but newer
 *  `@types/bun` declarations type `Uint8Array<ArrayBufferLike>` whose `buffer`
 *  no longer satisfies the strict `ArrayBuffer` shape expected by WebCrypto's
 *  `BufferSource`. This helper centralises the type-only widening. */
function bufferIn(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

/* ──────────────────────────────────────────────────────────────────
 * signEvent
 * ────────────────────────────────────────────────────────────────── */

/**
 * Sign a Kash-Event.
 *
 *  1. Canonicalise `{ header, body }` (RFC 8785).
 *  2. Prepend the DST as UTF-8 bytes.
 *  3. Sign with Ed25519 using `privateKey`.
 *
 * @returns A {@link KashEventSignature} ready to embed in the event envelope.
 */
export async function signEvent(
  header: Readonly<Record<string, unknown>>,
  body: unknown,
  privateKey: Uint8Array,
  opts?: SignEventOptions,
): Promise<KashEventSignature> {
  assertPrivateKey(privateKey);
  const dst = opts?.dst ?? DEFAULT_KASH_RECORD_DST;
  // Default to multibase — matches the lexicons envelope schema. Callers that
  // explicitly opt into "base64url" or "hex" get the historical shape with
  // an `encoding` field on the output (so verifyEvent knows how to decode).
  const encoding: SignatureEncoding = opts?.encoding ?? "multibase";

  const payloadBytes = buildSignablePayload(header, body, dst);

  const cryptoKey = await importEd25519PrivateKey(privateKey);

  let sigBytes: Uint8Array;
  try {
    const buf = await crypto.subtle.sign({ name: "Ed25519" }, cryptoKey, bufferIn(payloadBytes));
    sigBytes = new Uint8Array(buf);
  } catch (err) {
    throw new KashCryptoError("WebCrypto Ed25519 sign() failed.", "SIGN_FAILED", err);
  }

  if (sigBytes.length !== ED25519_SIGNATURE_BYTES) {
    throw new KashCryptoError(
      `Ed25519 signature must be ${ED25519_SIGNATURE_BYTES} bytes (got ${sigBytes.length}).`,
      "SIGN_FAILED",
    );
  }

  // When encoding is the default ("multibase"), omit the `encoding` field
  // entirely — the output is then byte-identical to the lexicons envelope
  // schema's `KashSignature` shape and round-trips through validateEvent
  // without a bridge. Explicit "base64url"/"hex" callers retain the field
  // so verifyEvent on the receiving side knows the wire format.
  return {
    alg: "ed25519",
    sig: encodeSignatureBytes(sigBytes, encoding),
    dst,
    ...(encoding === "multibase" ? {} : { encoding }),
    ...(opts?.kid !== undefined ? { kid: opts.kid } : {}),
  };
}

/* ──────────────────────────────────────────────────────────────────
 * verifyEvent
 * ────────────────────────────────────────────────────────────────── */

/**
 * Verify a signed Kash-Event.
 *
 * Returns `true` if the signature is mathematically valid under `publicKey`
 * for the re-canonicalised `{ header, body }` of `event`. Returns `false`
 * for a wrong-but-syntactically-valid signature.
 *
 * Throws {@link KashCryptoError} when the inputs themselves are malformed
 * (bad public-key length, missing signature fields, unsupported algorithm,
 * malformed base64url/hex). A `false` return is reserved for "bytes are well
 * formed but do not validate" — i.e., a real signature mismatch.
 *
 * ⚠️ **Threat-model note:** this function trusts the caller to supply the
 * correct `publicKey` for the claimed signer. It does NOT consult any DID
 * Document and does NOT enforce that `event.signature.kid` corresponds to
 * `publicKey`. A wrong-but-real key still produces a `true` result if it
 * happens to verify (which only happens for forged events). To authenticate
 * an event against a known DID Document, use
 * {@link verifyEventAgainstDocument} from `./document` (which resolves
 * `kid` → `verificationMethod.publicKey` before delegating here).
 */
export async function verifyEvent(
  event: SignedKashEvent,
  publicKey: Uint8Array,
): Promise<boolean> {
  validateSignatureShape(event);

  // Dispatch on alg — and each branch asserts a key of ITS algorithm's length,
  // so a 32-byte Ed25519 key can never be read as P-256 or the reverse. The
  // switch is exhaustive so adding a new alg becomes a compile error here.
  const alg = event.signature.alg;
  switch (alg) {
    case "ed25519":
      return verifyEd25519(event, publicKey);
    case "es256":
      return verifyEs256(event, publicKey);
    case "bls12-381":
      throw new KashCryptoError(
        `Signature alg "${alg}" is reserved (§5.5) but not implemented in this build.`,
        "UNSUPPORTED_ALG",
      );
    default: {
      const _exhaust: never = alg;
      throw new KashCryptoError(
        `Unknown signature alg: ${JSON.stringify(_exhaust)}.`,
        "UNSUPPORTED_ALG",
      );
    }
  }
}

async function verifyEd25519(
  event: SignedKashEvent,
  publicKey: Uint8Array,
): Promise<boolean> {
  assertPublicKey(publicKey);

  const sig = event.signature;
  // Decode by inspecting the explicit `encoding` field when present;
  // otherwise default to multibase (which is what signEvent now emits by
  // default and what the lexicons envelope schema requires).
  const encoding: SignatureEncoding =
    sig.encoding === "hex"        ? "hex" :
    sig.encoding === "base64url"  ? "base64url" :
                                    "multibase";

  let sigBytes: Uint8Array;
  try {
    sigBytes = decodeSignatureBytes(sig.sig, encoding);
  } catch (err) {
    throw new KashCryptoError(
      `Malformed signature encoding (${encoding}).`,
      "INVALID_ENCODING",
      err,
    );
  }

  if (sigBytes.length !== ED25519_SIGNATURE_BYTES) {
    // Wrong-length signature is a non-match, not a host-failure.
    return false;
  }
  // AU-3 (A7-07): the acceptance rule before any engine is asked — S < L, a canonical
  // A and R, neither of small order (./ed25519-strict). Engines differ at these
  // edges; the rule makes Bun, Node and every browser answer alike.
  if (ed25519Precheck(publicKey, sigBytes) !== "ok") return false;

  const payloadBytes = buildSignablePayload(event.header, event.body, sig.dst);

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      bufferIn(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (err) {
    rethrowIfUnavailable(err, "Ed25519");
    throw new KashCryptoError(
      "WebCrypto rejected the public key for verification.",
      "INVALID_KEY_BYTES",
      err,
    );
  }

  return crypto.subtle.verify(
    { name: "Ed25519" },
    cryptoKey,
    bufferIn(sigBytes),
    bufferIn(payloadBytes),
  );
}

async function verifyEs256(
  event: SignedKashEvent,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!(publicKey instanceof Uint8Array) || (publicKey.length !== 33 && publicKey.length !== 65)) {
    throw new KashCryptoError(
      "An es256 signature needs a P-256 public key (33 or 65 bytes).",
      "INVALID_KEY_BYTES",
    );
  }
  const sig = event.signature;
  const encoding: SignatureEncoding =
    sig.encoding === "hex"        ? "hex" :
    sig.encoding === "base64url"  ? "base64url" :
                                    "multibase";
  let sigBytes: Uint8Array;
  try {
    sigBytes = decodeSignatureBytes(sig.sig, encoding);
  } catch (err) {
    throw new KashCryptoError(`Malformed signature encoding (${encoding}).`, "INVALID_ENCODING", err);
  }
  // Raw r ‖ s only; anything else — including a DER blob — is a non-match.
  if (sigBytes.length !== P256_SIGNATURE_BYTES) return false;
  const payloadBytes = buildSignablePayload(event.header, event.body, sig.dst);
  return verifyP256(sigBytes, payloadBytes, publicKey);
}

/* ──────────────────────────────────────────────────────────────────
 * Typed keys and external signers (PL-2)
 * ────────────────────────────────────────────────────────────────── */

/**
 * Verify a Kash-Event against a key whose TYPE is known — from the `did:kash`
 * that names it ({@link parseDidKey}). The algorithm comes from the key: an
 * `es256` signature against an Ed25519 key, or the reverse, is `false`
 * whatever the signature claims.
 */
export async function verifyEventForKey(
  event: SignedKashEvent,
  key: KashPublicKey,
): Promise<boolean> {
  validateSignatureShape(event);
  const expected: KashSignatureAlg = key.type === "P-256" ? "es256" : "ed25519";
  if (event.signature.alg !== expected) return false;
  return verifyEvent(event, key.publicKey);
}

/** A raw signature from somewhere the key never leaves — a phone's secure chip. */
export interface ExternalSignature {
  readonly signature: Uint8Array;
  /** Hardware usually returns DER; say which, because a DER blob can be 64 bytes too. */
  readonly format: "raw" | "der";
}

/**
 * Who signs. Ed25519 and P-256 software keys carry their private bytes; a
 * hardware key carries only a `sign` callback over the exact payload bytes
 * (the chip hashes them with SHA-256 itself, as ES256 requires).
 */
export type EventSigner =
  | { readonly alg: "ed25519"; readonly privateKey: Uint8Array }
  | { readonly alg: "es256"; readonly privateKey: Uint8Array; readonly publicKey: Uint8Array }
  | { readonly alg: "es256"; readonly sign: (payload: Uint8Array) => Promise<ExternalSignature> };

/** Normalise an ES256 signature from any source to raw, low-S `r ‖ s`. */
export function es256RawSignature(sig: ExternalSignature): Uint8Array {
  const raw = sig.format === "der" ? ecdsaDerToRaw(sig.signature) : sig.signature;
  if (raw.length !== P256_SIGNATURE_BYTES) {
    throw new KashCryptoError(`An ES256 signature is ${P256_SIGNATURE_BYTES} bytes (got ${raw.length}).`, "SIGN_FAILED");
  }
  return normaliseLowS(raw);
}

/** Sign a Kash-Event with any signer — software Ed25519, software P-256 or hardware. */
export async function signEventWith(
  header: Readonly<Record<string, unknown>>,
  body: unknown,
  signer: EventSigner,
  opts?: SignEventOptions,
): Promise<KashEventSignature> {
  if (signer.alg === "ed25519") return signEvent(header, body, signer.privateKey, opts);
  if (signer.alg !== "es256") {
    throw new KashCryptoError(`Unknown signer alg ${JSON.stringify((signer as { alg?: unknown }).alg)}.`, "UNSUPPORTED_ALG");
  }
  const dst = opts?.dst ?? DEFAULT_KASH_RECORD_DST;
  const encoding: SignatureEncoding = opts?.encoding ?? "multibase";
  const payloadBytes = buildSignablePayload(header, body, dst);
  let raw: Uint8Array;
  if ("sign" in signer) {
    try {
      raw = es256RawSignature(await signer.sign(payloadBytes));
    } catch (err) {
      if (err instanceof KashCryptoError) throw err;
      throw new KashCryptoError("The external ES256 signer failed.", "SIGN_FAILED", err);
    }
  } else {
    raw = await signP256(payloadBytes, signer.privateKey, signer.publicKey);
  }
  return {
    alg: "es256",
    sig: encodeSignatureBytes(raw, encoding),
    dst,
    ...(encoding === "multibase" ? {} : { encoding }),
    ...(opts?.kid !== undefined ? { kid: opts.kid } : {}),
  };
}

/** Sign a Kash-Event with a software P-256 key. */
export function signEventEs256(
  header: Readonly<Record<string, unknown>>,
  body: unknown,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  opts?: SignEventOptions,
): Promise<KashEventSignature> {
  return signEventWith(header, body, { alg: "es256", privateKey, publicKey }, opts);
}

/** The exact bytes a Kash-Event signature covers: `DST ‖ JCS({header, body})`. */
export function kashEventSigningInput(
  header: Readonly<Record<string, unknown>>,
  body: unknown,
  dst: string,
): Uint8Array {
  return buildSignablePayload(header, body, dst);
}

/* ──────────────────────────────────────────────────────────────────
 * verifyBatch — parallel-verification helper for Oreoasis
 * ──────────────────────────────────────────────────────────────────
 *
 * Concurrent verification via Promise.all. WebCrypto operations release the
 * event loop, so a Promise.all over N events is dispatched in parallel and
 * is materially faster than serial verification at high N.
 *
 * NOTE — true Ed25519 batch verification (RFC 8032 §8.2 batched-equation
 * form) is asymptotically faster than per-signature verify but requires
 * direct access to curve scalar multiplication, which WebCrypto does not
 * expose. A future @kashscript/identity-batch package may layer that on
 * top of @noble/ed25519. For now, parallel-per-sig is the optimisation.
 */
export async function verifyBatch(
  events: readonly SignedKashEvent[],
  publicKeys: readonly Uint8Array[],
): Promise<readonly boolean[]> {
  if (events.length !== publicKeys.length) {
    throw new KashCryptoError(
      `verifyBatch length mismatch (events=${events.length}, publicKeys=${publicKeys.length}).`,
      "INVALID_INPUT",
    );
  }
  return Promise.all(events.map((e, i) => safeVerify(e, publicKeys[i]!)));
}

/** Internal: per-entry verifier that swallows ALL exceptions and reports `false`.
 *  Used by `verifyBatch` so a single malformed entry doesn't kill the batch. */
async function safeVerify(event: SignedKashEvent, publicKey: Uint8Array): Promise<boolean> {
  try {
    return await verifyEvent(event, publicKey);
  } catch {
    return false;
  }
}

/* ──────────────────────────────────────────────────────────────────
 * Internal helpers
 * ────────────────────────────────────────────────────────────────── */

function buildSignablePayload(
  header: Readonly<Record<string, unknown>>,
  body: unknown,
  dst: string,
): Uint8Array {
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new KashCryptoError("header must be a plain object.", "INVALID_INPUT");
  }
  if (typeof dst !== "string" || dst.length === 0) {
    throw new KashCryptoError("dst must be a non-empty string.", "INVALID_INPUT");
  }
  const dstBytes = TEXT_ENCODER.encode(dst);
  const payloadBytes = canonicalizeBytes({ header, body });
  const out = new Uint8Array(dstBytes.length + payloadBytes.length);
  out.set(dstBytes, 0);
  out.set(payloadBytes, dstBytes.length);
  return out;
}

async function importEd25519PrivateKey(seed: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);

  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      bufferIn(pkcs8),
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  } catch (err) {
    rethrowIfUnavailable(err, "Ed25519");
    throw new KashCryptoError(
      "WebCrypto rejected the Ed25519 private key (seed bytes do not form a valid key).",
      "INVALID_KEY_BYTES",
      err,
    );
  }
}

function encodeSignatureBytes(bytes: Uint8Array, encoding: SignatureEncoding): string {
  if (encoding === "multibase") return `z${encodeBase58(bytes)}`;
  if (encoding === "hex") return encodeHex(bytes);
  return encodeBase64Url(bytes);
}

function decodeSignatureBytes(s: string, encoding: SignatureEncoding): Uint8Array {
  if (encoding === "multibase") {
    if (!s.startsWith("z")) {
      throw new KashCryptoError(
        `multibase signature must start with "z" (base58btc prefix); got ${JSON.stringify(s.slice(0, 1))}.`,
        "INVALID_INPUT",
      );
    }
    return decodeBase58(s.slice(1));
  }
  if (encoding === "hex") return decodeHex(s);
  return decodeBase64Url(s);
}

function assertPrivateKey(privateKey: Uint8Array): void {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== ED25519_PRIVATE_KEY_BYTES) {
    throw new KashCryptoError(
      `privateKey must be a ${ED25519_PRIVATE_KEY_BYTES}-byte Uint8Array.`,
      "INVALID_KEY_BYTES",
    );
  }
}

function assertPublicKey(publicKey: Uint8Array): void {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new KashCryptoError(
      `publicKey must be a ${ED25519_PUBLIC_KEY_BYTES}-byte Uint8Array.`,
      "INVALID_KEY_BYTES",
    );
  }
}

const KNOWN_ALGS: ReadonlySet<KashSignatureAlg> = new Set(["ed25519", "es256", "bls12-381"]);

function validateSignatureShape(event: SignedKashEvent): void {
  if (event === null || typeof event !== "object") {
    throw new KashCryptoError("event must be an object.", "INVALID_INPUT");
  }
  const sig: unknown = (event as { signature?: unknown }).signature;
  if (sig === null || typeof sig !== "object") {
    throw new KashCryptoError("event.signature must be an object.", "INVALID_INPUT");
  }
  const s = sig as Record<string, unknown>;
  if (typeof s.alg !== "string" || !KNOWN_ALGS.has(s.alg as KashSignatureAlg)) {
    throw new KashCryptoError(
      `Unknown signature algorithm: ${JSON.stringify(s.alg)} (known: ${[...KNOWN_ALGS].join(", ")}).`,
      "INVALID_INPUT",
    );
  }
  if (typeof s.sig !== "string" || s.sig.length === 0) {
    throw new KashCryptoError("event.signature.sig must be a non-empty string.", "INVALID_INPUT");
  }
  if (typeof s.dst !== "string" || s.dst.length === 0) {
    throw new KashCryptoError("event.signature.dst must be a non-empty string.", "INVALID_INPUT");
  }
}
