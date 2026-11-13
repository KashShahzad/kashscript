/**
 * Key resolution for held records — one order, stated once.
 *
 * The ecosystem's signers are not uniformly self-certifying: countersign and
 * Indusland's Kash-Events sign as `did:kash:<base58>`, but Oreoasis agent
 * receipts sign as `did:kash:agent:<hex>`, work records as an opaque actor id,
 * and Indus tokens by JWKS `kid`. So a wallet resolves a signing key in this
 * order, and every report says which step answered:
 *
 *   1. **self-certifying** — the key is inside the identifier (`parseDidKey`),
 *      and so is its type: Ed25519 or P-256 (PL-2).
 *   2. **trust-list** — a key named by a verified trust list whose publisher
 *      the verifier pinned. From an unpinned list it is reported as
 *      `unpinned-trust-list`: the binding is only that publisher's word.
 *   3. **held-key** — a public key the holder kept. It verifies a signature;
 *      it never makes the signer a listed issuer.
 *
 * Every resolved key carries its TYPE, and the verifiers take the algorithm
 * from it — never from the envelope.
 */

import { compressP256PublicKey, parseDid, type KashKeyType, type KashPublicKey } from "@kashscript/identity-core";
import { hexToBytes } from "../chain";
import { resolveDidKey } from "../signing";

export type KeySource = "self-certifying" | "trust-list" | "unpinned-trust-list" | "held-key";

export interface ResolvedKey {
  readonly keyid: string;
  readonly publicKey: Uint8Array;
  readonly source: KeySource;
  /** The key's type — and so the only algorithm it verifies. */
  readonly type: KashKeyType;
}

export type KeyResolver = (keyid: string) => ResolvedKey | null;

/** A public key carried in a trust list or kept by the holder: Ed25519 as 32
 *  bytes of hex, or ES256 as the 33-byte compressed P-256 point in hex. */
export interface PublicKeyEntry {
  readonly keyid: string;
  readonly alg: "Ed25519" | "ES256";
  readonly publicKeyHex: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX66 = /^0[23][0-9a-f]{64}$/;

/** The identifier with any `#fragment` removed (`did:kash:z…#sig-1` → `did:kash:z…`). */
export function stripFragment(keyid: string): string {
  const i = keyid.indexOf("#");
  return i === -1 ? keyid : keyid.slice(0, i);
}

/** The Ed25519 key inside a self-certifying `did:kash`, or null — Ed25519 only,
 *  as before PL-2. Never throws. Use {@link selfCertifyingTypedKey} for either type. */
export function selfCertifyingKey(keyid: string): Uint8Array | null {
  try {
    return parseDid(stripFragment(keyid));
  } catch {
    return null;
  }
}

/** The key, with its declared type, inside a self-certifying `did:kash`. Never throws. */
export function selfCertifyingTypedKey(keyid: string): KashPublicKey | null {
  return resolveDidKey(keyid);
}

/** Decode a well-formed Ed25519 entry; null for anything else (including ES256). Pre-PL-2 shape. */
export function publicKeyOf(entry: PublicKeyEntry): Uint8Array | null {
  const k = typedKeyOf(entry);
  return k !== null && k.type === "Ed25519" ? k.publicKey : null;
}

/** Decode a well-formed entry of either algorithm, typed; null for anything malformed. */
export function typedKeyOf(entry: PublicKeyEntry): KashPublicKey | null {
  if (entry === null || typeof entry !== "object" || typeof entry.publicKeyHex !== "string") return null;
  const hex = entry.publicKeyHex.toLowerCase();
  if (entry.alg === "Ed25519") return HEX64.test(hex) ? { type: "Ed25519", publicKey: hexToBytes(hex) } : null;
  if (entry.alg === "ES256") {
    if (!HEX66.test(hex)) return null;
    try {
      return { type: "P-256", publicKey: compressP256PublicKey(hexToBytes(hex)) };
    } catch {
      return null;
    }
  }
  return null;
}

/** A trust-list key, with whether its list's publisher was pinned. `type` defaults to Ed25519. */
export interface ListedKey {
  readonly publicKey: Uint8Array;
  readonly pinned: boolean;
  readonly type?: KashKeyType;
}

/** Resolve in the order above. `trustListKeys` and `heldKeys` are keyed by keyid;
 *  a held key given as bare bytes is Ed25519. */
export function makeKeyResolver(
  trustListKeys: ReadonlyMap<string, ListedKey>,
  heldKeys: ReadonlyMap<string, Uint8Array | KashPublicKey>,
): KeyResolver {
  return (keyid: string) => {
    if (typeof keyid !== "string" || keyid.length === 0) return null;
    const self = selfCertifyingTypedKey(keyid);
    if (self !== null) return { keyid, publicKey: self.publicKey, type: self.type, source: "self-certifying" };
    const listed = trustListKeys.get(keyid);
    if (listed !== undefined) {
      return { keyid, publicKey: listed.publicKey, type: listed.type ?? "Ed25519", source: listed.pinned ? "trust-list" : "unpinned-trust-list" };
    }
    const held = heldKeys.get(keyid);
    if (held !== undefined) {
      const k = held instanceof Uint8Array ? { type: "Ed25519" as const, publicKey: held } : held;
      return { keyid, publicKey: k.publicKey, type: k.type, source: "held-key" };
    }
    return null;
  };
}

/** The typed key a resolver returned — what `verifyEnvelope` and `verifyJws` take. */
export function keyOfResolved(r: ResolvedKey): KashPublicKey {
  return { type: r.type, publicKey: r.publicKey };
}

/**
 * One name for a resolved key's material, `<type>:<hex>`, so two keyids that
 * resolve to one key — a `did:kash` and its `#fragment` alias, or a listed key
 * under two ids — count once wherever signers are counted (AU-3, A7-02).
 */
export function keyIdentityOf(r: Pick<ResolvedKey, "type" | "publicKey">): string {
  let hex = "";
  for (let i = 0; i < r.publicKey.length; i++) hex += r.publicKey[i]!.toString(16).padStart(2, "0");
  return `${r.type}:${hex}`;
}
