/**
 * Shared types for the React SDK.
 */

import type { KashDid, KashEventSignature, SignEventOptions } from "@kashscript/identity-core";

/** Coarse lifecycle status surfaced to UI components. */
export type KashAuthStatus =
  | "loading"             // hydrating from storage; initial mount
  | "unauthenticated"     // no active session (with or without stored identity)
  | "authenticating"      // a register/login/sign operation is in flight
  | "authenticated"       // session active; signer ready
  | "recovery-required"   // F3: registered identity exists but its Passkey is orphaned on this device
  | "error";              // last operation failed; see `error`

/** Outcome shape returned by {@link KashAuthContextValue.recover}. */
export type KashRecoveryStatus =
  | "not-required"        // no recovery state detected — usual happy path
  | "guardian-needed"     // user must reach their guardians to co-sign a quorum-recover op
  | "in-progress"         // recovery flow has been initiated; awaiting guardian sigs
  | "unsupported";        // protocol Phase-3 is required and not yet shipped

/** Public-facing identity record exposed via context + hooks. */
export interface KashIdentity {
  readonly did: KashDid;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** Opaque WebAuthn credential id. */
  readonly credentialId: Uint8Array;
  /** Optional user-supplied handle (display only). */
  readonly handle?: string;
}

/** Persisted identity envelope (localStorage shape). */
export interface StoredKashIdentity {
  readonly did: KashDid;
  /** Base58btc-encoded public key. */
  readonly publicKeyB58: string;
  /** Base64url-encoded credential id. */
  readonly credentialIdB64u: string;
  readonly handle?: string;
  /** ISO-8601 timestamp of last register/auth ceremony. */
  readonly updatedAt: string;
}

/** Argument bundle for {@link KashAuthContextValue.register}. */
export interface RegisterOptions {
  /** User-facing handle. Used as `user.name` in the WebAuthn ceremony. */
  readonly handle: string;
  /** Display name shown in the OS prompt. Defaults to `handle`. */
  readonly displayName?: string;
  /**
   * F3 escape hatch: skip the discoverable-credential probe that refuses
   * to mint a duplicate when an orphaned Passkey is detected. Set this
   * ONLY in tests or when the caller has authoritative knowledge that
   * the user genuinely wants a fresh identity (e.g., they just clicked
   * "Start over" in your UI).
   */
  readonly skipExistingCheck?: boolean;
}

/** Context surface exposed by `<KashAuthProvider>`. */
export interface KashAuthContextValue {
  readonly status: KashAuthStatus;
  readonly identity: KashIdentity | null;
  readonly error: Error | null;

  /** Run the full registration ceremony — generate Ed25519 + create Passkey + persist. */
  readonly register: (opts: RegisterOptions) => Promise<KashIdentity>;

  /** Run the assertion ceremony to prove device ownership and unlock signing. */
  readonly authenticate: () => Promise<KashIdentity>;

  /** Clear in-memory session state. Persistent identity stays in storage. */
  readonly logout: () => Promise<void>;

  /** Wipe persistent identity AND in-memory session. Irreversible. */
  readonly resetStorage: () => Promise<void>;

  /**
   * Sign a Kash-Event. Triggers a Passkey assertion (biometric prompt) bound
   * to the SHA-256 of the canonicalised payload — MITM and replay defences
   * are built in. Returns the {@link KashEventSignature} ready to embed in
   * the event envelope.
   */
  readonly sign: (
    header: Readonly<Record<string, unknown>>,
    body: unknown,
    opts?: SignEventOptions,
  ) => Promise<KashEventSignature>;

  /**
   * Probe the authenticator for an existing credential for this RP. Used at
   * registration time to refuse silently overwriting a Passkey that the
   * SDK is no longer aware of (cache cleared / cookie-management extension
   * wiped localStorage but left the OS Keychain entry).
   *
   * Returns the discovered `credentialId` bytes, or `null` if no credential
   * is reachable or the user cancelled the probe.
   */
  readonly detectExistingCredential: () => Promise<Uint8Array | null>;

  /**
   * Initiate the Quorum-recovery flow (§4.4 of identity-protocol-v1.md).
   *
   * **Phase-3 status:** the underlying op-log resolver does not exist yet,
   * so this returns `"unsupported"` today. Once the resolver lands, the
   * implementation will:
   *
   *   1. Discover the user's `set-recovery-quorum` op from their PDS or a
   *      witness mirror.
   *   2. Contact each guardian DID and request an attestation (§4.4.1).
   *   3. Once threshold is met, publish a `quorum-recover` op with the new
   *      Active/Management/Recovery key set.
   *   4. Re-register the local Passkey against the new Active key.
   */
  readonly recover: () => Promise<KashRecoveryStatus>;
}
