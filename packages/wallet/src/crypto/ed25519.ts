/**
 * Ed25519 relationship keys from a 32-byte seed — the same seed format the
 * kernel signs with (identity-core, attest). The public key is read back
 * through WebCrypto's PKCS8 import (RFC 8410), so no curve code lives here.
 * A key's name is its self-certifying `did:kash`.
 */

import { deriveDid } from "@kashscript/identity-core";
import { base64UrlToBytes, buf, concat } from "./bytes";

const PKCS8_ED25519_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

export async function ed25519PublicKeyOf(seed: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  const key = await crypto.subtle.importKey("pkcs8", buf(concat(PKCS8_ED25519_PREFIX, seed)), { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  if (typeof jwk.x !== "string") throw new Error("the runtime did not return the Ed25519 public key");
  return base64UrlToBytes(jwk.x);
}

/** An Ed25519 signer in the shape attest's signing functions take. Keys in
 *  hardware sign through `KeyRegistry.withSigner` instead (PL-2). */
export interface RelationshipSigner {
  readonly keyid: string;
  readonly did: string;
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export function signerOf(seed: Uint8Array, publicKey: Uint8Array): RelationshipSigner {
  const did = deriveDid(publicKey);
  return { keyid: did, did, privateKey: seed, publicKey };
}
