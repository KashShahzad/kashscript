/**
 * DID Document formatter for did:kash.
 *
 * Produces a W3C DID Core 1.0 compliant JSON-LD document. Verification
 * methods use the W3C `Multikey` type (a single `publicKeyMultibase` string
 * carrying the codec prefix + raw key bytes, base58btc encoded with a `z`
 * tag per Multibase).
 *
 * The single verification method emitted by this formatter authorises the
 * holder of the corresponding private key to sign Kash-Events — it is
 * registered under `authentication`, `assertionMethod`, and
 * `capabilityInvocation` so the same key can transact across the protocol's
 * three first-class signing relationships.
 *
 * Pure deterministic logic — no clocks, no IDs, no I/O.
 */

import { decodeBase58, encodeBase58 } from "./base58";
import { didKeyType, isKashDid, parseDidKey, type KashDid, type KashPublicKey } from "./did";
import { KashCryptoError } from "./errors";
import { compressP256PublicKey } from "./p256";
import { verifyEventForKey, type SignedKashEvent } from "./signatures";

const ED25519_KEY_BYTES = 32;
const P256_KEY_BYTES = 33;
/** W3C Multikey codec prefix for Ed25519 public keys (varint 0xed01). */
const ED25519_MULTIKEY_PREFIX = Uint8Array.of(0xed, 0x01);
/** W3C Multikey codec prefix for compressed P-256 public keys (varint 0x1200). */
const P256_MULTIKEY_PREFIX = Uint8Array.of(0x80, 0x24);

/** Service-endpoint type for a user's Personal Data Store. */
export type PdsServiceType = "PersonalDataStore";

/** Verification-method type. Today only `Multikey`; reserved for Phase-4 Passkeys. */
export type VerificationMethodType = "Multikey";

export interface VerificationMethod {
  /** Fragment-suffixed DID, e.g., `did:kash:abc…#sig-1`. */
  readonly id: string;
  readonly type: VerificationMethodType;
  /** DID that controls this key — always equal to the parent document's `id`. */
  readonly controller: KashDid;
  /**
   * Base58btc-encoded `0xed01 || <32-byte Ed25519 key>` or
   * `0x8024 || <33-byte compressed P-256 key>`, prefixed with the multibase
   * `z` tag per W3C Multibase.
   */
  readonly publicKeyMultibase: `z${string}`;
}

export interface ServiceEndpoint {
  readonly id: string;
  readonly type: PdsServiceType;
  readonly serviceEndpoint: string;
}

export interface DidDocument {
  readonly "@context": readonly [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://kashscript.com/ns/did/v1",
  ];
  readonly id: KashDid;
  readonly verificationMethod: readonly VerificationMethod[];
  readonly authentication: readonly string[];
  readonly assertionMethod: readonly string[];
  readonly capabilityInvocation: readonly string[];
  readonly service: readonly ServiceEndpoint[];
  /** W3C DID Core §5 `alsoKnownAs`. Omitted in the v1.0 single-key shape. */
  readonly alsoKnownAs?: readonly string[];
}

/* ── createDidDocument — input shapes ───────────────────────────── */

/**
 * Structured input for {@link createDidDocument}. Preferred over the
 * positional signature for Phase-3 callers that need multi-PDS, extra
 * services, or `alsoKnownAs`.
 */
export interface CreateDidDocumentInput {
  /** The fully-qualified DID — must already match `publicKey`. */
  readonly did: KashDid | string;
  /** The public key `did` names: 32-byte Ed25519, or P-256 (33 or 65 bytes). */
  readonly publicKey: Uint8Array;
  /**
   * HTTPS URL of the user's Personal Data Store, or an array thereof for
   * multi-PDS deployments (spec §3.3). The first endpoint is canonical; the
   * rest are registered as `#pds-2`, `#pds-3`, ...
   */
  readonly pdsEndpoint: string | readonly string[];
  /** Service endpoints beyond PDS (e.g., witness, dwn). Appended verbatim. */
  readonly additionalServices?: readonly ServiceEndpoint[];
  /** Optional W3C `alsoKnownAs` array (handles, web URLs, alt DIDs). */
  readonly alsoKnownAs?: readonly string[];
}

/**
 * Build a W3C-compliant DID Document for a `did:kash` identity.
 *
 * **Positional form (back-compat with v0.2):**
 * ```ts
 * createDidDocument(did, publicKey, pdsEndpoint)
 * ```
 *
 * **Options-object form (preferred, v0.3+):**
 * ```ts
 * createDidDocument({
 *   did, publicKey,
 *   pdsEndpoint: ["https://pds.example", "https://backup.example"],
 *   alsoKnownAs: ["https://alice.kashscript.com"],
 * })
 * ```
 */
export function createDidDocument(
  did: KashDid | string,
  publicKey: Uint8Array,
  pdsEndpoint: string,
): DidDocument;
export function createDidDocument(input: CreateDidDocumentInput): DidDocument;
export function createDidDocument(
  arg1: KashDid | string | CreateDidDocumentInput,
  publicKey?: Uint8Array,
  pdsEndpoint?: string,
): DidDocument {
  const input: CreateDidDocumentInput = isCreateInput(arg1)
    ? arg1
    : { did: arg1, publicKey: publicKey as Uint8Array, pdsEndpoint: pdsEndpoint as string };

  // —— validate `did` — either type; the Ed25519 path is exactly as before PL-2
  const declared = typeof input.did === "string" ? didKeyType(input.did) : null;
  if (typeof input.did !== "string" || declared === null || (declared === "Ed25519" && !isKashDid(input.did))) {
    throw new KashCryptoError(
      `did must be a valid did:kash identifier (got ${JSON.stringify(input.did)}).`,
      "INVALID_DID",
    );
  }

  // —— validate `publicKey`
  if (!(input.publicKey instanceof Uint8Array)) {
    throw new KashCryptoError("publicKey must be a Uint8Array.", "INVALID_KEY_BYTES");
  }
  let multikey: `z${string}`;
  if (declared === "Ed25519") {
    if (input.publicKey.length !== ED25519_KEY_BYTES) {
      throw new KashCryptoError(
        `publicKey must be ${ED25519_KEY_BYTES} bytes (got ${input.publicKey.length}).`,
        "INVALID_KEY_BYTES",
      );
    }
    multikey = encodeMultikey(ED25519_MULTIKEY_PREFIX, input.publicKey);
  } else {
    // A P-256 DID carries its key; the one passed in must be the same point.
    const named = parseDidKey(input.did).publicKey;
    const given = compressP256PublicKey(input.publicKey);
    if (named.length !== given.length || named.some((b, i) => b !== given[i])) {
      throw new KashCryptoError("publicKey is not the key the P-256 did:kash names.", "INVALID_KEY_BYTES");
    }
    multikey = encodeMultikey(P256_MULTIKEY_PREFIX, named);
  }

  // —— validate `pdsEndpoint`(s)
  const pdsEndpoints: readonly string[] = Array.isArray(input.pdsEndpoint)
    ? input.pdsEndpoint
    : [input.pdsEndpoint as string];
  if (pdsEndpoints.length === 0) {
    throw new KashCryptoError("pdsEndpoint must contain at least one URL.", "INVALID_INPUT");
  }
  for (const ep of pdsEndpoints) {
    if (typeof ep !== "string" || ep.length === 0) {
      throw new KashCryptoError("pdsEndpoint entries must be non-empty strings.", "INVALID_INPUT");
    }
    if (!/^https?:\/\/[^\s]+$/.test(ep)) {
      throw new KashCryptoError(
        `pdsEndpoint must be an http(s) URL (got ${JSON.stringify(ep)}).`,
        "INVALID_INPUT",
      );
    }
  }

  // —— compose the verification method
  const did = input.did as KashDid;
  const sigId = `${did}#sig-1`;

  const services: ServiceEndpoint[] = pdsEndpoints.map((ep, i) => ({
    id: i === 0 ? `${did}#pds` : `${did}#pds-${i + 1}`,
    type: "PersonalDataStore",
    serviceEndpoint: ep,
  }));
  if (input.additionalServices) services.push(...input.additionalServices);

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1",
      "https://kashscript.com/ns/did/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: sigId,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: multikey,
      },
    ],
    authentication: [sigId],
    assertionMethod: [sigId],
    capabilityInvocation: [sigId],
    service: services,
    ...(input.alsoKnownAs && input.alsoKnownAs.length > 0 ? { alsoKnownAs: input.alsoKnownAs } : {}),
  };
}

/* ── F4: verify a Kash-Event against a resolved DID Document ────── */

/**
 * Verify a Kash-Event using the verification method named by
 * `event.signature.kid` of the supplied DID Document. The safe complement
 * to {@link verifyEvent} — resolves `kid` → `publicKey` via the document
 * before delegating, so the caller cannot accidentally verify under a
 * wrong-but-real public key.
 *
 * Throws:
 * - `INVALID_INPUT` — `event.signature.kid` is missing.
 * - `KID_NOT_RESOLVED` — no verificationMethod with that id exists in the doc,
 *   or its controller does not match the doc's `id`.
 * - `INVALID_KEY_FORMAT` — `publicKeyMultibase` is malformed.
 *
 * Returns `false` (not an error) when the signature is well-formed but does
 * not validate — i.e., a real cryptographic mismatch. Use this for routine
 * acceptance gating; reserve thrown errors for shape / config bugs.
 */
export async function verifyEventAgainstDocument(
  event: SignedKashEvent,
  document: DidDocument,
): Promise<boolean> {
  const kid = event.signature.kid;
  if (typeof kid !== "string" || kid.length === 0) {
    throw new KashCryptoError(
      "event.signature.kid is required for document-bound verification.",
      "INVALID_INPUT",
    );
  }
  const vm = document.verificationMethod.find((m) => m.id === kid);
  if (vm === undefined) {
    throw new KashCryptoError(
      `verificationMethod ${JSON.stringify(kid)} not found in DID Document ${document.id}.`,
      "KID_NOT_RESOLVED",
    );
  }
  if (vm.controller !== document.id) {
    throw new KashCryptoError(
      `verificationMethod ${JSON.stringify(kid)} has controller ${JSON.stringify(vm.controller)}, expected ${JSON.stringify(document.id)}.`,
      "KID_NOT_RESOLVED",
    );
  }
  // The algorithm comes from the key's codec, never from the event's own `alg`.
  return verifyEventForKey(event, decodeMultikey(vm.publicKeyMultibase));
}

/* ── internal helpers ─────────────────────────────────────────────── */

function isCreateInput(v: unknown): v is CreateDidDocumentInput {
  return typeof v === "object" && v !== null && "publicKey" in (v as Record<string, unknown>);
}

function encodeMultikey(prefix: Uint8Array, publicKey: Uint8Array): `z${string}` {
  const buf = new Uint8Array(prefix.length + publicKey.length);
  buf.set(prefix, 0);
  buf.set(publicKey, prefix.length);
  return `z${encodeBase58(buf)}`;
}

/** Inverse of {@link encodeMultikey}. Strips the `z` tag, base58-decodes, and
 *  reads the codec: 0xed01 → a 32-byte Ed25519 key, 0x8024 → a 33-byte
 *  compressed P-256 key (validated). Any other codec is refused. */
export function decodeMultikey(multibase: string): KashPublicKey {
  if (typeof multibase !== "string" || multibase.length === 0 || multibase[0] !== "z") {
    throw new KashCryptoError(
      `publicKeyMultibase must begin with "z" (base58btc multibase tag), got ${JSON.stringify(multibase)}.`,
      "INVALID_KEY_FORMAT",
    );
  }
  let raw: Uint8Array;
  try {
    raw = decodeBase58(multibase.slice(1));
  } catch (err) {
    throw new KashCryptoError("publicKeyMultibase contains invalid base58 characters.", "INVALID_ENCODING", err);
  }
  if (raw[0] === ED25519_MULTIKEY_PREFIX[0] && raw[1] === ED25519_MULTIKEY_PREFIX[1]) {
    if (raw.length !== ED25519_MULTIKEY_PREFIX.length + ED25519_KEY_BYTES) {
      throw new KashCryptoError(
        `publicKeyMultibase decoded to ${raw.length} bytes, expected ${ED25519_MULTIKEY_PREFIX.length + ED25519_KEY_BYTES}.`,
        "INVALID_KEY_BYTES",
      );
    }
    return { type: "Ed25519", publicKey: raw.subarray(ED25519_MULTIKEY_PREFIX.length) };
  }
  if (raw[0] === P256_MULTIKEY_PREFIX[0] && raw[1] === P256_MULTIKEY_PREFIX[1]) {
    if (raw.length !== P256_MULTIKEY_PREFIX.length + P256_KEY_BYTES) {
      throw new KashCryptoError(
        `publicKeyMultibase decoded to ${raw.length} bytes, expected ${P256_MULTIKEY_PREFIX.length + P256_KEY_BYTES}.`,
        "INVALID_KEY_BYTES",
      );
    }
    return { type: "P-256", publicKey: compressP256PublicKey(raw.subarray(P256_MULTIKEY_PREFIX.length)) };
  }
  throw new KashCryptoError(
    `publicKeyMultibase codec prefix is neither Ed25519 (0xed01) nor P-256 (0x8024); got 0x${(raw[0] ?? 0).toString(16).padStart(2, "0")}${(raw[1] ?? 0).toString(16).padStart(2, "0")}.`,
    "INVALID_KEY_FORMAT",
  );
}
