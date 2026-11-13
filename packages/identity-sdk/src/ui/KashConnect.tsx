"use client";

/**
 * <KashConnect /> — a single button that drives the entire WebAuthn lifecycle.
 *
 *   • idle / no stored identity  →  "Create identity" — prompts for a handle, runs register()
 *   • idle / stored, no session  →  "Connect" — runs authenticate()
 *   • authenticating             →  spinner, "Verifying…"
 *   • authenticated              →  connected pill with truncated DID; click → popover with copy / disconnect
 *   • error                      →  amber-toned "Try again"
 *
 * Tailwind-only styling. `className` + `style` overrides on the root. White-labellers
 * can also wrap with their own components — every visual choice here is opinionated
 * but neutral enough to drop into most product palettes.
 */

import * as React from "react";
import { useKashAuth } from "../hooks";
import type { KashIdentity } from "../types";
import { ChevronDownIcon, CopyIcon, CheckIcon, FingerprintIcon, SpinnerIcon } from "./icons";

export interface KashConnectProps {
  readonly className?: string;
  readonly style?: React.CSSProperties;
  /** Override the default `window.prompt("Choose a handle")` flow. Return null to abort. */
  readonly getHandle?: () => Promise<string | null>;
  /** Called after successful register/authenticate. */
  readonly onConnect?: (identity: KashIdentity) => void;
  /** Called after the user explicitly disconnects from the popover. */
  readonly onDisconnect?: () => void;
  /**
   * Compact mode — icon-only when authenticated, single-word ("Sign in") otherwise.
   * Designed for tight headers, dense sidebars, and floating-island toolbars.
   * Avatar + popover behaviour are preserved; the visible label shrinks.
   */
  readonly compact?: boolean;
  /**
   * Visual variant for the IDLE state (the "create / connect" button).
   *   "solid"   (default) — dark filled pill, high-contrast
   *   "outline"           — bordered, transparent fill, blends with the host
   *   "ghost"             — text-only, no background; for inline placement
   */
  readonly variant?: "solid" | "outline" | "ghost";
}

const PILL_BASE =
  "inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium " +
  "transition focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 " +
  "focus-visible:ring-offset-neutral-900 focus-visible:ring-emerald-400";

export function KashConnect({
  className,
  style,
  getHandle,
  onConnect,
  onDisconnect,
  compact = false,
  variant = "solid",
}: KashConnectProps): React.ReactElement | null {
  const { status, identity, error, register, authenticate, logout } = useKashAuth();

  if (status === "loading") {
    return (
      <div
        className={`${PILL_BASE} bg-neutral-200/70 dark:bg-neutral-800/70 text-transparent select-none animate-pulse ${className ?? ""}`.trim()}
        style={style}
        aria-hidden
      >
        connecting&nbsp;identity
      </div>
    );
  }

  // ── authenticating state ──────────────────────────────────────
  if (status === "authenticating") {
    return (
      <button
        type="button"
        disabled
        className={`${PILL_BASE} bg-neutral-900 text-neutral-200 dark:bg-neutral-100 dark:text-neutral-900 cursor-progress ${className ?? ""}`.trim()}
        style={style}
        aria-busy
      >
        <SpinnerIcon className="h-4 w-4" />
        Verifying…
      </button>
    );
  }

  // ── connected state ───────────────────────────────────────────
  if (status === "authenticated" && identity) {
    return (
      <ConnectedPill
        identity={identity}
        onLogout={async () => { await logout(); onDisconnect?.(); }}
        compact={compact}
        {...(className !== undefined ? { className } : {})}
        {...(style !== undefined ? { style } : {})}
      />
    );
  }

  // ── default: idle / unauthenticated / error ───────────────────
  const hasStored = identity !== null;
  const handleClick = async (): Promise<void> => {
    try {
      let result: KashIdentity;
      if (hasStored) {
        result = await authenticate();
      } else {
        const handle = await (getHandle ? getHandle() : promptForHandle());
        if (handle === null || handle === "") return;
        result = await register({ handle });
      }
      onConnect?.(result);
    } catch {
      // error state is already surfaced via the context; swallow the throw at the UI edge.
    }
  };

  const isError = status === "error";
  const label = isError
    ? compact ? "Retry" : "Try again"
    : hasStored
      ? compact ? "Sign in" : "Connect with Kash"
      : compact ? "Create" : "Create identity";
  return (
    <button
      type="button"
      onClick={handleClick}
      className={
        `${PILL_BASE} ${idleVariantClasses(variant, isError)} shadow-sm ${className ?? ""}`.trim()
      }
      style={style}
      aria-label={isError ? "Retry connecting with Kash" : hasStored ? "Connect with Kash" : "Create Kash identity"}
      title={isError && error?.message ? error.message : undefined}
    >
      <FingerprintIcon className="h-4 w-4" />
      {label}
    </button>
  );
}

/* ── variant resolver — pure ────────────────────────────────────── */

function idleVariantClasses(variant: "solid" | "outline" | "ghost", isError: boolean): string {
  if (isError) {
    // Error state ignores the variant; amber is the universal "something went wrong" cue.
    return "bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/40 hover:bg-amber-500/25";
  }
  if (variant === "outline") {
    return (
      "bg-transparent text-neutral-900 dark:text-neutral-50 " +
      "border border-neutral-300 dark:border-neutral-700 " +
      "hover:bg-neutral-100 dark:hover:bg-neutral-800"
    );
  }
  if (variant === "ghost") {
    return (
      "bg-transparent text-neutral-900 dark:text-neutral-50 " +
      "hover:bg-neutral-100 dark:hover:bg-neutral-800"
    );
  }
  // solid (default)
  return (
    "bg-neutral-900 text-neutral-50 hover:bg-neutral-700 " +
    "dark:bg-neutral-50 dark:text-neutral-900 dark:hover:bg-white"
  );
}

/* ── connected pill + popover ──────────────────────────────────── */

function ConnectedPill({
  identity,
  onLogout,
  compact = false,
  className,
  style,
}: {
  readonly identity: KashIdentity;
  readonly onLogout: () => Promise<void>;
  readonly compact?: boolean;
  readonly className?: string;
  readonly style?: React.CSSProperties;
}): React.ReactElement {
  const [open, setOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const ref = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onEsc = (e: KeyboardEvent): void => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return (): void => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(identity.did);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch { /* swallow */ }
  };

  const short = truncateDid(identity.did);
  const label = identity.handle ?? short;

  return (
    <div ref={ref} className={`relative inline-block ${className ?? ""}`.trim()} style={style}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={
          `${PILL_BASE} bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100 ` +
          `hover:bg-neutral-200 dark:hover:bg-neutral-700 border border-neutral-200 dark:border-neutral-700 shadow-sm ` +
          (compact ? "!px-2" : "")
        }
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={compact ? `Signed in as ${label}` : undefined}
        title={compact ? label : undefined}
      >
        <Avatar publicKey={identity.publicKey} />
        {!compact ? (
          <>
            <span className="max-w-[12rem] truncate">{label}</span>
            <ChevronDownIcon className={`h-3.5 w-3.5 opacity-60 transition-transform ${open ? "rotate-180" : ""}`} />
          </>
        ) : null}
      </button>

      {open ? (
        <div
          role="menu"
          className="
            absolute right-0 top-full mt-2 w-72 origin-top-right
            rounded-2xl border border-neutral-200 dark:border-neutral-800
            bg-white dark:bg-neutral-900 shadow-lg shadow-black/10
            p-3 z-50
          "
        >
          <div className="flex items-center gap-3 px-1 py-1">
            <Avatar publicKey={identity.publicKey} size={36} />
            <div className="min-w-0">
              <div className="text-sm font-medium text-neutral-900 dark:text-neutral-100 truncate">
                {identity.handle ?? "—"}
              </div>
              <div className="font-mono text-[11px] text-neutral-500 truncate">{short}</div>
            </div>
          </div>
          <div className="my-2 h-px bg-neutral-200 dark:bg-neutral-800" />
          <button
            type="button"
            onClick={copy}
            role="menuitem"
            className="
              w-full flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm
              text-neutral-700 dark:text-neutral-200
              hover:bg-neutral-100 dark:hover:bg-neutral-800 transition
            "
          >
            {copied ? <CheckIcon className="h-4 w-4 text-emerald-500" /> : <CopyIcon className="h-4 w-4" />}
            {copied ? "Copied" : "Copy DID"}
          </button>
          <button
            type="button"
            onClick={() => { void onLogout(); setOpen(false); }}
            role="menuitem"
            className="
              mt-0.5 w-full flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm
              text-rose-600 dark:text-rose-400
              hover:bg-rose-500/10 transition
            "
          >
            Disconnect
          </button>
        </div>
      ) : null}
    </div>
  );
}

/* ── avatar from DID bytes — deterministic gradient ──────────── */

function Avatar({ publicKey, size = 22 }: { readonly publicKey: Uint8Array; readonly size?: number }): React.ReactElement {
  const a = publicKey[0] ?? 0;
  const b = publicKey[1] ?? 0;
  const c = publicKey[2] ?? 0;
  const hue1 = (a * 360) / 255;
  const hue2 = (b * 360) / 255;
  const sat  = 55 + ((c * 30) / 255);
  return (
    <span
      aria-hidden
      className="inline-block rounded-full ring-1 ring-inset ring-black/10 dark:ring-white/10"
      style={{
        width: size,
        height: size,
        background: `linear-gradient(135deg, hsl(${hue1} ${sat}% 60%), hsl(${hue2} ${sat}% 45%))`,
      }}
    />
  );
}

/* ── helpers ─────────────────────────────────────────────────── */

function truncateDid(did: string): string {
  if (did.length <= 22) return did;
  return `${did.slice(0, 14)}…${did.slice(-6)}`;
}

async function promptForHandle(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  const v = window.prompt("Choose a handle for your Kash identity:");
  return v ? v.trim() : null;
}
