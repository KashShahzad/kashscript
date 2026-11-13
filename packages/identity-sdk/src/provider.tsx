"use client";

/**
 * ╔════════════════════════════════════════════════════════════════════╗
 * ║                     DEVELOPER QUICKSTART                           ║
 * ║                                                                    ║
 * ║ Wrap your Next.js (or any React) app in <KashAuthProvider> once,   ║
 * ║ then call the hooks anywhere below it.                             ║
 * ║                                                                    ║
 * ║   // app/layout.tsx (Next.js App Router)                           ║
 * ║   import { KashAuthProvider } from "@kashscript/identity-sdk";     ║
 * ║                                                                    ║
 * ║   export default function RootLayout({ children }) {               ║
 * ║     return (                                                       ║
 * ║       <html lang="en">                                             ║
 * ║         <body>                                                     ║
 * ║           <KashAuthProvider rpName="Indusland">                    ║
 * ║             {children}                                             ║
 * ║           </KashAuthProvider>                                      ║
 * ║         </body>                                                    ║
 * ║       </html>                                                      ║
 * ║     );                                                             ║
 * ║   }                                                                ║
 * ║                                                                    ║
 * ║   // app/components/LoginButton.tsx                                ║
 * ║   "use client";                                                    ║
 * ║   import { useKashAuth } from "@kashscript/identity-sdk";          ║
 * ║                                                                    ║
 * ║   export function LoginButton() {                                  ║
 * ║     const { status, identity, register, authenticate } =           ║
 * ║       useKashAuth();                                               ║
 * ║                                                                    ║
 * ║     if (status === "loading") return <Spinner />;                  ║
 * ║     if (identity) return <button onClick={authenticate}>           ║
 * ║       Log in as {identity.handle ?? identity.did.slice(0, 18)}     ║
 * ║     </button>;                                                     ║
 * ║     return <button onClick={() => register({ handle: "kashif" })}> ║
 * ║       Create identity                                              ║
 * ║     </button>;                                                     ║
 * ║   }                                                                ║
 * ║                                                                    ║
 * ║   // app/components/PublishButton.tsx                              ║
 * ║   "use client";                                                    ║
 * ║   import { useSigner } from "@kashscript/identity-sdk";            ║
 * ║                                                                    ║
 * ║   export function PublishButton({ header, body }) {                ║
 * ║     const { sign, status } = useSigner();                          ║
 * ║     async function onPublish() {                                   ║
 * ║       const sig = await sign(header, body);                        ║
 * ║       // POST { header, body, signature: sig } to your PDS         ║
 * ║     }                                                              ║
 * ║     return <button disabled={status !== "authenticated"}           ║
 * ║                    onClick={onPublish}>Publish</button>;           ║
 * ║   }                                                                ║
 * ╚════════════════════════════════════════════════════════════════════╝
 *
 * SECURITY MODEL
 * ──────────────────────────────────────────────────────────────────
 * The SDK never touches a private-key byte buffer. On registration we
 * generate a non-extractable Ed25519 CryptoKey via WebCrypto and persist
 * it as a structured-clone reference in IndexedDB. The OS-level secure
 * store backs the actual key material; JS only ever holds an opaque
 * handle that can sign but cannot export.
 *
 * Every sign() call:
 *   1. Builds the canonical payload (RFC 8785 JCS via identity-core).
 *   2. SHA-256s the canonical bytes — this is the Passkey assertion challenge.
 *   3. Triggers `navigator.credentials.get()` (biometric prompt).
 *   4. Verifies `clientDataJSON.origin === window.location.origin` and
 *      `clientDataJSON.challenge === expected`. Origin mismatch and
 *      challenge mismatch are both hard-fail errors. This is the
 *      MITM-defence cited in the Phase-4 critical instruction.
 *   5. Signs the canonical payload with the non-extractable Ed25519 key.
 *
 * ╔════════════════════════════════════════════════════════════════════╗
 * ║ F4 — THREAT BOUNDARY                                               ║
 * ╠════════════════════════════════════════════════════════════════════╣
 * ║ WHAT THIS SDK DEFENDS AGAINST                                      ║
 * ║   • MITM / replay (origin + challenge bound to payload bytes)      ║
 * ║   • Origin substitution (clientDataJSON.origin check)              ║
 * ║   • Iframe phishing (clientDataJSON.crossOrigin refused — F2)      ║
 * ║   • Blind signing (modal always shows full body — Trust-UX)        ║
 * ║   • CSS-injection attacks against the modal (Shadow DOM — F1)      ║
 * ║   • Bidi / zero-width text spoofing in displayed strings (F5)      ║
 * ║   • Orphaned-credential silent overwrite (excludeCredentials — F3) ║
 * ║   • Private-key extraction (non-extractable CryptoKey)             ║
 * ║                                                                    ║
 * ║ WHAT THIS SDK DOES *NOT* DEFEND AGAINST                            ║
 * ║   • Compromise of the host page's JavaScript context. Anything     ║
 * ║     running in the same realm can call sign() with attacker-       ║
 * ║     chosen bytes — the user still sees the modal, but they         ║
 * ║     may approve a hostile request whose origin appears             ║
 * ║     legitimate. Mitigation: ship sensitive flows from a separate   ║
 * ║     origin under an iframe with `allow="publickey-credentials-get  ║
 * ║     publickey-credentials-create"` *INVERTED* (i.e., DON'T iframe  ║
 * ║     the signer; have the host iframe USERS into the signer).      ║
 * ║   • OS-level malware that intercepts WebCrypto calls.              ║
 * ║   • A malicious browser extension with `<all_urls>` access.        ║
 * ║   • A user who blindly approves every modal without reading it.    ║
 * ║                                                                    ║
 * ║ PHASE-4 MIGRATION PLAN (F4 ARCHITECTURE NOTE)                      ║
 * ║   The current shape uses the Passkey as an "unlock factor" for     ║
 * ║   the in-browser Ed25519 key (the actual signing key). Phase-4     ║
 * ║   replaces this with ES256-as-identity: the Passkey ITSELF is the  ║
 * ║   signing key, the Ed25519 CryptoKey goes away, and `signature.alg ║
 * ║   = "es256"`. The cutover triggers when identity-core's `es256`    ║
 * ║   slot (§5.5) is implemented. Until then, sign() embeds the        ║
 * ║   Passkey assertion (authenticatorData + clientDataJSON + sig)     ║
 * ║   inside `signature.userPresenceProof` so verifiers can audit the  ║
 * ║   ceremony chain even today.                                       ║
 * ╚════════════════════════════════════════════════════════════════════╝
 */

import {
  canonicalizeBytes,
  decodeBase58,
  deriveDid,
  encodeBase64Url,
  type KashDid,
  type KashEventSignature,
  type SignEventOptions,
} from "@kashscript/identity-core";
import * as React from "react";
import { KashSdkError } from "./errors";
import {
  clearStoredIdentity,
  loadSignerKey,
  readStoredIdentity,
  removeSignerKey,
  storeSignerKey,
  writeStoredIdentity,
} from "./storage";
import type {
  KashAuthContextValue,
  KashAuthStatus,
  KashIdentity,
  KashRecoveryStatus,
  RegisterOptions,
} from "./types";
import { assertPasskey, createPasskey, discoverExistingCredential } from "./webauthn";

/* ─────────────────────────────────────────────────────────────────
 * Context
 * ───────────────────────────────────────────────────────────────── */

export const KashAuthContext = React.createContext<KashAuthContextValue | null>(null);

export interface KashAuthProviderProps {
  readonly children: React.ReactNode;
  /** WebAuthn RP id. Defaults to `window.location.hostname`. */
  readonly rpId?: string;
  /** WebAuthn RP name shown in OS prompts. Defaults to `"Kash"`. */
  readonly rpName?: string;
}

/* ─────────────────────────────────────────────────────────────────
 * Internal reducer state
 * ───────────────────────────────────────────────────────────────── */

interface SdkState {
  readonly status: KashAuthStatus;
  readonly identity: KashIdentity | null;
  readonly error: Error | null;
}

const INITIAL_STATE: SdkState = { status: "loading", identity: null, error: null };

/* ─────────────────────────────────────────────────────────────────
 * Default Domain-Separation Tag (matches @kashscript/lexicons records).
 * Kept local rather than imported so this file has zero deps beyond
 * identity-core. Replace via SignEventOptions.dst if needed.
 * ───────────────────────────────────────────────────────────────── */

const DEFAULT_KASH_RECORD_DST = "kash-record-v1\n";

const TEXT_ENCODER = new TextEncoder();

/* ─────────────────────────────────────────────────────────────────
 * Provider
 * ───────────────────────────────────────────────────────────────── */

export function KashAuthProvider({
  children,
  rpId,
  rpName,
}: KashAuthProviderProps): React.ReactElement {
  const [state, setState] = React.useState<SdkState>(INITIAL_STATE);

  // In-memory non-extractable CryptoKey for the current session. Cleared on logout.
  const signerKeyRef = React.useRef<CryptoKey | null>(null);
  const identityRef  = React.useRef<KashIdentity | null>(null);
  React.useEffect((): void => { identityRef.current = state.identity; }, [state.identity]);

  /* Hydrate from storage once on mount. */
  React.useEffect(() => {
    try {
      const stored = readStoredIdentity();
      setState({ status: "unauthenticated", identity: stored, error: null });
    } catch (err) {
      setState({ status: "error", identity: null, error: err as Error });
    }
  }, []);

  /* ── register ───────────────────────────────────────────────── */
  const register = React.useCallback(
    async (opts: RegisterOptions): Promise<KashIdentity> => {
      // Refuse to overwrite an existing identity silently.
      const existing = identityRef.current;
      if (existing) {
        throw new KashSdkError(
          `An identity (${existing.did}) is already registered. Call resetStorage() first.`,
          "ALREADY_REGISTERED",
        );
      }
      if (!opts.handle || typeof opts.handle !== "string") {
        throw new KashSdkError("RegisterOptions.handle is required.", "INVALID_INPUT");
      }

      setState((s) => ({ ...s, status: "authenticating", error: null }));
      try {
        // F3: discoverability probe. If the authenticator already holds a
        // credential for this RP that we lost track of (cleared storage /
        // cookie-management extension wipe), refuse to mint a duplicate.
        // The probe is best-effort — if the user cancels it, we treat that
        // as "no existing credential" and proceed.
        let preExisting: Uint8Array | null = null;
        try {
          preExisting = await discoverExistingCredential({
            ...(rpId !== undefined ? { rpId } : {}),
            timeoutMs: opts.skipExistingCheck ? 1 : 15_000,
          });
        } catch { /* probe failures are non-fatal */ }
        if (preExisting && !opts.skipExistingCheck) {
          throw new KashSdkError(
            "A Passkey for this site already exists on this device but is not registered with the SDK. " +
            "Use authenticate() to resume it, or call recover() if it cannot be unlocked.",
            "WEBAUTHN_ORPHANED_CREDENTIAL",
          );
        }

        // 1. Generate an in-browser Ed25519 key pair. We export the public key bytes
        //    and re-import the private half as non-extractable, so once stored in
        //    IndexedDB only the browser knows the underlying bytes.
        const seedPair = (await crypto.subtle.generateKey(
          { name: "Ed25519" },
          true,
          ["sign", "verify"],
        )) as CryptoKeyPair;
        const publicKey = new Uint8Array(
          await crypto.subtle.exportKey("raw", seedPair.publicKey),
        );
        const pkcs8 = new Uint8Array(
          await crypto.subtle.exportKey("pkcs8", seedPair.privateKey),
        );
        const nonExtractablePrivate = await crypto.subtle.importKey(
          "pkcs8",
          pkcs8 as unknown as BufferSource,
          { name: "Ed25519" },
          false, // <- non-extractable
          ["sign"],
        );
        // Best-effort: wipe the transient pkcs8 buffer.
        pkcs8.fill(0);

        const did: KashDid = deriveDid(publicKey);

        // 2. Create the Passkey, binding it to the freshly minted DID's pubkey bytes
        //    so the credential is durably linked to this identity in the OS prompt.
        //    F3: also pass any preExisting credential id to excludeCredentials —
        //    if the probe yielded one, the OS refuses to mint a duplicate.
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const passkey = await createPasskey({
          challenge,
          userId:          publicKey,   // pubkey doubles as the WebAuthn user id
          userName:        opts.handle,
          userDisplayName: opts.displayName ?? opts.handle,
          ...(rpId   !== undefined ? { rpId }   : {}),
          ...(rpName !== undefined ? { rpName } : {}),
          ...(preExisting ? { excludeCredentialIds: [preExisting] } : {}),
        });

        // 3. Persist. CryptoKey → IndexedDB. Public envelope → localStorage.
        await storeSignerKey(did, nonExtractablePrivate);
        const identity: KashIdentity = {
          did,
          publicKey,
          credentialId: passkey.credentialId,
          ...(opts.handle !== undefined ? { handle: opts.handle } : {}),
        };
        writeStoredIdentity(identity);

        signerKeyRef.current = nonExtractablePrivate;
        setState({ status: "authenticated", identity, error: null });
        return identity;
      } catch (err) {
        const wrapped = err instanceof Error ? err : new Error(String(err));
        setState((s) => ({ ...s, status: "error", error: wrapped }));
        throw err;
      }
    },
    [rpId, rpName],
  );

  /* ── authenticate ──────────────────────────────────────────── */
  const authenticate = React.useCallback(async (): Promise<KashIdentity> => {
    const stored = identityRef.current ?? readStoredIdentity();
    if (!stored) {
      throw new KashSdkError(
        "No registered identity found. Call register() first.",
        "NOT_AUTHENTICATED",
      );
    }

    setState((s) => ({ ...s, status: "authenticating", error: null }));
    try {
      // Plain login ceremony: random 32-byte challenge, biometric prompt,
      // clientDataJSON validation. We do NOT bind the challenge to any
      // event here — `sign()` does that on each per-event ceremony.
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await assertPasskey({
        challenge,
        credentialId: stored.credentialId,
        ...(rpId !== undefined ? { rpId } : {}),
      });

      const key = await loadSignerKey(stored.did);
      if (!key) {
        // F3: localStorage knows about the identity but IndexedDB doesn't —
        // partial-wipe state. Indistinguishable from "device was wiped"
        // from the user's perspective; surface as recovery-required.
        const orphan = new KashSdkError(
          "The signing key for this identity is missing on this device. Recovery is required.",
          "WEBAUTHN_ORPHANED_CREDENTIAL",
        );
        setState({ status: "recovery-required", identity: stored, error: orphan });
        throw orphan;
      }
      signerKeyRef.current = key;
      setState({ status: "authenticated", identity: stored, error: null });
      return stored;
    } catch (err) {
      const wrapped = err instanceof Error ? err : new Error(String(err));
      // F3: route orphan errors to the recovery-required state so the
      // host UI can render the Quorum-recovery CTA instead of a generic error.
      const isOrphan = wrapped instanceof KashSdkError && wrapped.code === "WEBAUTHN_ORPHANED_CREDENTIAL";
      setState((s) => ({
        ...s,
        status: isOrphan ? "recovery-required" : "error",
        identity: stored,
        error: wrapped,
      }));
      throw err;
    }
  }, [rpId]);

  /* ── logout ────────────────────────────────────────────────── */
  const logout = React.useCallback(async (): Promise<void> => {
    signerKeyRef.current = null;
    setState((s) => ({ ...s, status: "unauthenticated", error: null }));
  }, []);

  /* ── resetStorage ─────────────────────────────────────────── */
  const resetStorage = React.useCallback(async (): Promise<void> => {
    const stored = identityRef.current ?? readStoredIdentity();
    if (stored) await removeSignerKey(stored.did);
    clearStoredIdentity();
    signerKeyRef.current = null;
    setState({ status: "unauthenticated", identity: null, error: null });
  }, []);

  /* ── sign ──────────────────────────────────────────────────── */
  const sign = React.useCallback(
    async (
      header: Readonly<Record<string, unknown>>,
      body: unknown,
      opts?: SignEventOptions,
    ): Promise<KashEventSignature> => {
      const identity = identityRef.current;
      if (!identity) {
        throw new KashSdkError(
          "Cannot sign without a registered identity.",
          "NOT_AUTHENTICATED",
        );
      }

      // 1. Build the canonical payload — exactly what identity-core does.
      const dst = opts?.dst ?? DEFAULT_KASH_RECORD_DST;
      const canonicalBytes = canonicalizeBytes({ header, body });
      const dstBytes = TEXT_ENCODER.encode(dst);
      const payloadBytes = new Uint8Array(dstBytes.length + canonicalBytes.length);
      payloadBytes.set(dstBytes, 0);
      payloadBytes.set(canonicalBytes, dstBytes.length);

      // 2. SHA-256 of the canonical (DST-prefixed) payload IS the WebAuthn challenge.
      //    Binding the assertion's challenge to the exact bytes we're about to sign
      //    means the biometric prompt is provably about THIS event — a captured
      //    assertion can't be replayed against a different event.
      const challenge = new Uint8Array(
        await crypto.subtle.digest("SHA-256", payloadBytes as unknown as BufferSource),
      );

      // 3. Trigger the biometric prompt. Origin + challenge validation inside.
      try {
        await assertPasskey({
          challenge,
          credentialId: identity.credentialId,
          ...(rpId !== undefined ? { rpId } : {}),
        });
      } catch (err) {
        // F3: a NotFoundError from the authenticator means the credential is
        // orphaned. Surface a recovery-required state in addition to throwing.
        if (err instanceof KashSdkError && err.code === "WEBAUTHN_ORPHANED_CREDENTIAL") {
          setState((s) => ({ ...s, status: "recovery-required", error: err }));
        }
        throw err;
      }

      // 4. Load the Ed25519 CryptoKey if not in memory (e.g., post-reload sign).
      let key = signerKeyRef.current;
      if (!key) {
        key = await loadSignerKey(identity.did);
        if (!key) {
          throw new KashSdkError(
            "No signing key for this DID in IndexedDB.",
            "STORAGE_CORRUPT",
          );
        }
        signerKeyRef.current = key;
        // Confirm authenticated state if we were called from a "stored but not logged-in" pose.
        setState((s) =>
          s.status === "authenticated" ? s : { ...s, status: "authenticated", identity, error: null },
        );
      }

      // 5. Sign with the non-extractable Ed25519 key.
      const sigBytes = new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          key,
          payloadBytes as unknown as BufferSource,
        ),
      );

      return {
        alg: "ed25519",
        sig: encodeBase64Url(sigBytes),
        dst,
        encoding: opts?.encoding ?? "base64url",
        kid: opts?.kid ?? `${identity.did}#sig-1`,
      };
    },
    [rpId],
  );

  /* ── detectExistingCredential — F3 probe surface ──────────── */
  const detectExistingCredential = React.useCallback(async (): Promise<Uint8Array | null> => {
    try {
      return await discoverExistingCredential({
        ...(rpId !== undefined ? { rpId } : {}),
        timeoutMs: 15_000,
      });
    } catch {
      return null;
    }
  }, [rpId]);

  /* ── recover — Quorum recovery flow (F3 scaffold) ─────────── */
  const recover = React.useCallback(async (): Promise<KashRecoveryStatus> => {
    // Phase-3 op-log + witness resolver is the prerequisite for the
    // discovery side of recover() (locate the user's `set-recovery-quorum`
    // op and contact the guardians for attestations per §4.4.1). Until
    // that lands, surface "unsupported" so host UIs can render the
    // "coming soon" copy and offer a manual support path.
    //
    // When Phase-3 ships, the implementation becomes:
    //   1. Read the user's DID from state.identity (if known) or prompt for
    //      it (display-only — recovery is keyless on the local side).
    //   2. Fetch the latest finalized `set-recovery-quorum` op from the
    //      witness mirror.
    //   3. Iterate guardians; request each to sign the §4.4.1 payload.
    //   4. Once threshold attestations are collected, mint a new local
    //      Ed25519 keypair + Passkey, then publish `quorum-recover` with
    //      the new keys.
    //   5. Replace storage and signal "authenticated".
    return "unsupported";
  }, []);

  /* ── memoise the context value ─────────────────────────────── */
  const value = React.useMemo<KashAuthContextValue>(
    () => ({
      status: state.status,
      identity: state.identity,
      error: state.error,
      register,
      authenticate,
      logout,
      resetStorage,
      detectExistingCredential,
      recover,
      sign,
    }),
    [state.status, state.identity, state.error, register, authenticate, logout, resetStorage, sign, detectExistingCredential, recover],
  );

  return (
    <KashAuthContext.Provider value={value}>{children}</KashAuthContext.Provider>
  );
}

/* ─────────────────────────────────────────────────────────────────
 * Internal — used by the hooks module via the exported context.
 * Throws when called outside a <KashAuthProvider>.
 * ───────────────────────────────────────────────────────────────── */
export function useKashAuthContext(): KashAuthContextValue {
  const ctx = React.useContext(KashAuthContext);
  if (!ctx) {
    throw new KashSdkError(
      "Hook called outside <KashAuthProvider>. Wrap your app once at the root.",
      "PROVIDER_MISSING",
    );
  }
  return ctx;
}

/* re-export decodeBase58 so it's reachable for advanced consumers
 * working with the public identity bytes (kept un-namespaced for ergonomics). */
export { decodeBase58 };
