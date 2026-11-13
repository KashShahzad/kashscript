"use client";

/**
 * <SignInGate /> — render-gating wrapper for protected UI.
 *
 *   <SignInGate fallback={<MarketingLanding />}>
 *     <Dashboard />
 *   </SignInGate>
 *
 * Behaviour:
 *
 *   loading             → renders `loadingFallback` (defaults to a neutral pulse)
 *   authenticated       → renders `children`
 *   error               → renders `errorFallback` if provided, else `fallback`
 *   recovery-required   → renders `recoveryFallback` if provided, else `fallback`
 *   unauthenticated /   → renders `fallback`
 *   authenticating
 *
 * The component is intentionally pure-presentation. It does NOT trigger
 * authenticate() — pair it with a <KashConnect /> in the fallback to let
 * the user start the ceremony themselves. This separation keeps the gate
 * race-free across React 19 concurrent renders.
 *
 * For server-side rendering (Next.js App Router), the gate respects the
 * `"use client"` boundary — every render decision happens client-side
 * after hydration. The first paint shows `loadingFallback`.
 *
 * For component-level guarding inside an already-mounted tree, prefer
 * the sister <RequireAuth /> wrapper at the same path.
 */

import * as React from "react";
import { useKashAuthContext } from "../provider";
import type { KashAuthStatus, KashIdentity } from "../types";

export interface SignInGateProps {
  /** Rendered when the user is authenticated. */
  readonly children: React.ReactNode;
  /** Rendered when the user is NOT authenticated (default state). */
  readonly fallback: React.ReactNode;
  /** Rendered while the provider is hydrating its initial session. Defaults to a neutral pulse. */
  readonly loadingFallback?: React.ReactNode;
  /** Rendered when status is `"error"`. Falls back to `fallback`. */
  readonly errorFallback?: React.ReactNode;
  /** Rendered when status is `"recovery-required"` (orphaned credential). Falls back to `fallback`. */
  readonly recoveryFallback?: React.ReactNode;
  /**
   * Optional render-prop override. When supplied, the gate hands control
   * to the caller for every branch — useful when you need access to the
   * identity / status inside the gated tree without an extra hook call.
   */
  readonly render?: (state: SignInGateState) => React.ReactNode;
}

export interface SignInGateState {
  readonly status: KashAuthStatus;
  readonly identity: KashIdentity | null;
  readonly error: Error | null;
}

export function SignInGate({
  children,
  fallback,
  loadingFallback,
  errorFallback,
  recoveryFallback,
  render,
}: SignInGateProps): React.ReactElement | null {
  const ctx = useKashAuthContext();

  if (render) {
    return <>{render({ status: ctx.status, identity: ctx.identity, error: ctx.error })}</>;
  }

  if (ctx.status === "loading") {
    return <>{loadingFallback ?? <DefaultLoadingPulse />}</>;
  }
  if (ctx.status === "authenticated") {
    return <>{children}</>;
  }
  if (ctx.status === "error") {
    return <>{errorFallback ?? fallback}</>;
  }
  if (ctx.status === "recovery-required") {
    return <>{recoveryFallback ?? fallback}</>;
  }
  // "unauthenticated" + "authenticating" — same UX (show the entry surface)
  return <>{fallback}</>;
}

/* ─────────────────────────────────────────────────────────────────
 *  <RequireAuth /> — silent inverse of SignInGate
 *
 *  Render-blocks until authenticated. Calls onUnauthorized once per
 *  status transition INTO an unauthenticated state — typical use:
 *
 *    <RequireAuth onUnauthorized={() => router.push("/login")}>
 *      <ProtectedRoute />
 *    </RequireAuth>
 * ───────────────────────────────────────────────────────────────── */

export interface RequireAuthProps {
  readonly children: React.ReactNode;
  /** Fired exactly once when status transitions to a non-authenticated state. */
  readonly onUnauthorized?: (status: KashAuthStatus) => void;
  /** Placeholder while the provider hydrates. Defaults to `null`. */
  readonly loadingFallback?: React.ReactNode;
}

export function RequireAuth({
  children,
  onUnauthorized,
  loadingFallback = null,
}: RequireAuthProps): React.ReactElement | null {
  const ctx = useKashAuthContext();
  const last = React.useRef<KashAuthStatus | null>(null);

  React.useEffect(() => {
    const isUnauthorized =
      ctx.status === "unauthenticated" ||
      ctx.status === "error" ||
      ctx.status === "recovery-required";
    if (isUnauthorized && last.current !== ctx.status) {
      onUnauthorized?.(ctx.status);
    }
    last.current = ctx.status;
  }, [ctx.status, onUnauthorized]);

  if (ctx.status === "loading") return <>{loadingFallback}</>;
  if (ctx.status === "authenticated") return <>{children}</>;
  return null;
}

/* ─────────────────────────────────────────────────────────────────
 *  Default loading pulse — neutral, framework-agnostic
 * ───────────────────────────────────────────────────────────────── */

function DefaultLoadingPulse(): React.ReactElement {
  return (
    <div
      role="status"
      aria-busy
      aria-label="Loading session"
      className="
        flex w-full items-center justify-center py-12
        text-sm text-neutral-400 dark:text-neutral-500
        animate-pulse select-none
      "
    >
      <span className="font-mono uppercase tracking-[0.22em] text-[10px]">loading…</span>
    </div>
  );
}
