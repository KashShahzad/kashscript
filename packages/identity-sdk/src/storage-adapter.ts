/**
 * Identity-storage adapter interface + headless implementation.
 *
 * Why this exists:
 *   The original `./storage` module is hard-wired to the browser
 *   (`window.localStorage` + `IndexedDB`). It works fine inside a React
 *   app but cannot be used from Node / Bun / Deno / Cloudflare Workers /
 *   the `kash` CLI / any other headless runtime. Every non-browser
 *   consumer was forced to rewrite the same in-memory adapter from
 *   scratch.
 *
 * This file:
 *   • Defines `IdentityStorageAdapter` — the abstraction over "where do
 *     I keep the user's identity envelope + private key material?"
 *   • Ships `HeadlessIdentityStorage` — a runtime-agnostic in-memory
 *     implementation. Suitable for tests, scripts, the `kash` binary's
 *     short-lived sessions, and as the base class for a file-backed
 *     adapter (which would override `write/clear` to also write JSON).
 *
 * The existing browser primitives (`readStoredIdentity`,
 * `writeStoredIdentity`, `storeSignerKey`, …) stay as-is for backward
 * compatibility. A future `BrowserIdentityStorage` class implementing
 * this interface would wrap them; not done in this pass to keep the
 * change-surface minimal.
 */

import type { ExportedKey } from "@kashscript/identity-core/keys";
import { decodeBase58, encodeBase58 } from "@kashscript/identity-core/base58";
import { decodeBase64Url, encodeBase64Url } from "@kashscript/identity-core/base64url";
import type { KashDid } from "@kashscript/identity-core";
import type { KashIdentity, StoredKashIdentity } from "./types";

/**
 * Storage abstraction the SDK promises to any host.
 *
 * Two layers per device:
 *   • the **public envelope** (`KashIdentity`) — DID, pubkey,
 *     credential id, optional handle. Safe to log, safe to inspect.
 *   • the **private key** (`ExportedKey` JWK or, in browser, a
 *     non-extractable `CryptoKey` reference) — never logged, never
 *     transmitted off-device unsupervised. The headless adapter holds
 *     it as a JWK; a real `BrowserIdentityStorage` would hold a
 *     CryptoKey reference and skip the JWK round-trip entirely.
 *
 * Adapters MAY return `null` from any read when nothing has been
 * written. They MUST NOT throw on "empty" — only on actual I/O
 * failures (out of disk, permission denied, etc).
 */
export interface IdentityStorageAdapter {
  /** Read the public identity envelope. */
  readEnvelope(): KashIdentity | null;
  /** Read the private-key material (when the adapter stores it as JWK). */
  readKeyJwk(): ExportedKey | null;
  /**
   * Write both layers. Atomic per-call — never half-written. Replaces any
   * prior state for this device.
   */
  write(identity: KashIdentity, jwk: ExportedKey, handle?: string): void;
  /** Wipe both layers (sign-out). Idempotent. */
  clear(): void;
  /** Whether the adapter has a complete identity ready to load. */
  hasIdentity(): boolean;
  /**
   * Export both layers as a portable bundle. Used by the cross-device
   * transfer flow (the bundle is what gets handed to the platform's key
   * sync — iCloud Keychain, Google Password Manager, WebAuthn cross-device).
   * Returns `null` for empty adapters.
   */
  exportBundle(): IdentityBundle | null;
  /**
   * Import a previously-exported bundle. Replaces any existing local state.
   */
  importBundle(bundle: IdentityBundle): void;
}

/** Wire shape of a portable identity bundle. Stable across SDK minor versions. */
export interface IdentityBundle {
  readonly envelope: StoredKashIdentity;
  readonly keyJwk: ExportedKey;
}

/**
 * Headless in-memory implementation. Runs in Node, Bun, Deno, Cloudflare
 * Workers, plain browsers — any runtime where `globalThis` exists. State
 * is in-memory only; the caller is responsible for persistence if they
 * need it (subclass and override `write`/`clear` to also write to disk).
 */
export class HeadlessIdentityStorage implements IdentityStorageAdapter {
  private state: IdentityBundle | null = null;

  readEnvelope(): KashIdentity | null {
    if (!this.state) return null;
    const { envelope } = this.state;
    return {
      did:          envelope.did as KashDid,
      publicKey:    decodeBase58(envelope.publicKeyB58),
      credentialId: decodeBase64Url(envelope.credentialIdB64u),
      ...(envelope.handle !== undefined ? { handle: envelope.handle } : {}),
    };
  }

  readKeyJwk(): ExportedKey | null {
    return this.state ? this.state.keyJwk : null;
  }

  write(identity: KashIdentity, jwk: ExportedKey, handle?: string): void {
    const envelope: StoredKashIdentity = {
      did:              identity.did,
      publicKeyB58:     encodeBase58(identity.publicKey),
      credentialIdB64u: encodeBase64Url(identity.credentialId),
      updatedAt:        new Date().toISOString(),
      ...(handle !== undefined ? { handle } : {}),
    };
    this.state = { envelope, keyJwk: jwk };
  }

  clear(): void {
    this.state = null;
  }

  hasIdentity(): boolean {
    return this.state !== null;
  }

  exportBundle(): IdentityBundle | null {
    if (!this.state) return null;
    return {
      envelope: this.state.envelope,
      keyJwk:   this.state.keyJwk,
    };
  }

  importBundle(bundle: IdentityBundle): void {
    this.state = { envelope: bundle.envelope, keyJwk: bundle.keyJwk };
  }
}
