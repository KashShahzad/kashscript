"use client";

/**
 * Headless hooks — logic-only. No JSX, no HTML, no CSS.
 *
 *   useKashAuth()      → full provider value (register, authenticate, sign, …)
 *   useKashIdentity()  → just the identity + status
 *   useSigner()        → just the sign function + status (+ kid helpers)
 *
 * Each hook throws {@link KashSdkError} (`PROVIDER_MISSING`) if called outside
 * a `<KashAuthProvider>`.
 */

import type {
  KashEventSignature,
  SignEventOptions,
} from "@kashscript/identity-core";
import * as React from "react";
import { KashSdkError } from "./errors";
import { useKashAuthContext } from "./provider";
import type {
  KashAuthContextValue,
  KashAuthStatus,
  KashIdentity,
} from "./types";

/** The complete provider surface. */
export function useKashAuth(): KashAuthContextValue {
  return useKashAuthContext();
}

/** The current user's identity (or `null`) plus session status.
 *  Stable across re-renders for the same identity. */
export function useKashIdentity(): {
  readonly identity: KashIdentity | null;
  readonly status: KashAuthStatus;
  readonly error: Error | null;
} {
  const ctx = useKashAuthContext();
  return React.useMemo(
    () => ({ identity: ctx.identity, status: ctx.status, error: ctx.error }),
    [ctx.identity, ctx.status, ctx.error],
  );
}

/** Subset of the context surface scoped to signing.
 *
 *  `sign` triggers the OS biometric prompt and returns a {@link KashEventSignature}
 *  ready to attach to a Kash-Event envelope. The prompt's challenge is bound to
 *  the SHA-256 of the canonical payload — see provider.tsx §SECURITY MODEL. */
export function useSigner(): {
  readonly sign: (
    header: Readonly<Record<string, unknown>>,
    body: unknown,
    opts?: SignEventOptions,
  ) => Promise<KashEventSignature>;
  readonly status: KashAuthStatus;
  readonly identity: KashIdentity | null;
  /** `<did>#sig-1` fragment id matching the DID Document's verification method. */
  readonly defaultKid: string | null;
} {
  const ctx = useKashAuthContext();
  return React.useMemo(
    () => ({
      sign: ctx.sign,
      status: ctx.status,
      identity: ctx.identity,
      defaultKid: ctx.identity ? `${ctx.identity.did}#sig-1` : null,
    }),
    [ctx.sign, ctx.status, ctx.identity],
  );
}

/* Re-exported for downstream `instanceof` checks. */
export { KashSdkError };
