/**
 * High-level Signer — bundles an Ed25519 key pair with the convenience
 * methods most callers actually need: DID derivation, DID Document
 * formatting, sign/verify against the bundled key.
 *
 * Side-effect free. Holds the private seed in memory; never writes it,
 * logs it, or transmits it. To persist, call {@link Signer.exportJwk}
 * and hand the result to your secure-enclave / OS keychain layer.
 */

import { createDidDocument, type DidDocument } from "./document";
import { deriveDid, type KashDid } from "./did";
import {
  exportKey,
  generateKeyPair,
  importKey,
  type ExportedKey,
  type KashKeyPair,
} from "./keys";
import {
  signEvent,
  verifyEvent,
  type KashEventSignature,
  type SignedKashEvent,
  type SignEventOptions,
} from "./signatures";

export class Signer {
  /** Public DID derived from the key pair. Stable for the lifetime of the Signer. */
  readonly did: KashDid;

  private readonly keyPair: KashKeyPair;

  private constructor(keyPair: KashKeyPair) {
    this.keyPair = keyPair;
    this.did = deriveDid(keyPair.publicKey);
  }

  /** Generate a fresh Ed25519 identity. */
  static async generate(): Promise<Signer> {
    return new Signer(await generateKeyPair());
  }

  /** Re-hydrate a Signer from a JWK (e.g., loaded out of secure-enclave storage). */
  static async fromJwk(jwk: ExportedKey | JsonWebKey): Promise<Signer> {
    return new Signer(await importKey(jwk));
  }

  /** Wrap an already-constructed key pair. Synchronous; performs no I/O. */
  static fromKeyPair(keyPair: KashKeyPair): Signer {
    return new Signer(keyPair);
  }

  /** Raw 32-byte Ed25519 public key. */
  get publicKey(): Uint8Array {
    return this.keyPair.publicKey;
  }

  /** Serialise the key pair (both halves) as a JWK suitable for secure storage. */
  exportJwk(): ExportedKey {
    return exportKey(this.keyPair);
  }

  /** Format the W3C DID Document for this identity bound to a PDS endpoint. */
  createDidDocument(pdsEndpoint: string): DidDocument {
    return createDidDocument(this.did, this.keyPair.publicKey, pdsEndpoint);
  }

  /**
   * Sign a Kash-Event. `kid` defaults to `<this.did>#sig-1` to match the
   * verification method emitted by {@link createDidDocument}.
   */
  async sign(
    header: Readonly<Record<string, unknown>>,
    body: unknown,
    opts?: SignEventOptions,
  ): Promise<KashEventSignature> {
    const merged: SignEventOptions = {
      ...opts,
      kid: opts?.kid ?? `${this.did}#sig-1`,
    };
    return signEvent(header, body, this.keyPair.privateKey, merged);
  }

  /** Verify an event against THIS Signer's public key. */
  async verify(event: SignedKashEvent): Promise<boolean> {
    return verifyEvent(event, this.keyPair.publicKey);
  }
}
