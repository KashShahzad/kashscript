"use client";

/**
 * <IdentityWidget /> — the "Identity Bento Box" dashboard tile.
 *
 * Standalone widget for app dashboards (Indusland, Duedale, third-party apps).
 * Renders:
 *
 *   • A deterministic avatar derived from the public key.
 *   • Truncated DID with a one-click copy affordance.
 *   • Optional PDS endpoint indicator.
 *   • "Key Health" row — three checks: identity / Passkey / session.
 *
 * Tailwind + currentColor. `className` and `style` overrides flow to the root
 * tile. Subparts are styled with neutral classes so the component drops cleanly
 * into either light or dark themes.
 */

import * as React from "react";
import { useKashIdentity } from "../hooks";
import { CheckIcon, CopyIcon, FingerprintIcon, ServerIcon, ShieldCheckIcon } from "./icons";

export interface IdentityWidgetProps {
  readonly className?: string;
  readonly style?: React.CSSProperties;
  /** PDS endpoint URL to display. Optional — falls back to "not configured". */
  readonly pdsEndpoint?: string;
  /** Eyebrow text shown above the title. Default `"sovereign identity"`. */
  readonly eyebrow?: string;
  /** Render-prop override for the action row at the bottom (e.g., a "Manage" link). */
  readonly footer?: React.ReactNode;
}

export function IdentityWidget({
  className,
  style,
  pdsEndpoint,
  eyebrow = "sovereign identity",
  footer,
}: IdentityWidgetProps): React.ReactElement {
  const { identity, status } = useKashIdentity();
  const [copied, setCopied] = React.useState(false);

  const copy = async (): Promise<void> => {
    if (!identity) return;
    try {
      await navigator.clipboard.writeText(identity.did);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch { /* swallow */ }
  };

  const isAuth     = status === "authenticated";
  const hasPasskey = identity !== null;
  const ready      = identity !== null;

  return (
    <article
      className={
        "relative isolate overflow-hidden rounded-3xl " +
        "border border-neutral-200/70 dark:border-neutral-800 " +
        "bg-white dark:bg-neutral-900 " +
        "shadow-[0_1px_2px_rgba(0,0,0,0.04),0_8px_24px_-12px_rgba(0,0,0,0.18)] " +
        `p-6 lg:p-7 text-neutral-900 dark:text-neutral-100 ${className ?? ""}`
      }
      style={style}
    >
      {/* eyebrow + headline */}
      <header className="flex items-start justify-between gap-3">
        <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-neutral-500 inline-flex items-center gap-2">
          <span className="relative inline-flex h-1.5 w-1.5">
            {isAuth ? (
              <>
                <span className="absolute inset-0 animate-ping rounded-full bg-emerald-500/70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
              </>
            ) : (
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neutral-400" />
            )}
          </span>
          {eyebrow}
        </p>
        <Avatar publicKey={identity?.publicKey} />
      </header>

      {/* DID */}
      <div className="mt-5">
        <p className="text-xs text-neutral-500 mb-1">Decentralized identifier</p>
        <button
          type="button"
          disabled={!identity}
          onClick={copy}
          className="
            group inline-flex max-w-full items-center gap-2 rounded-xl
            border border-neutral-200/70 dark:border-neutral-800
            bg-neutral-50 dark:bg-neutral-950/40
            px-3 py-2 font-mono text-[13px] text-neutral-700 dark:text-neutral-300
            hover:bg-neutral-100 dark:hover:bg-neutral-800/60
            disabled:opacity-50 disabled:cursor-not-allowed transition
          "
          aria-label="Copy DID to clipboard"
        >
          <span className="truncate">{identity ? truncateDid(identity.did) : "did:kash:—"}</span>
          {copied ? (
            <CheckIcon className="h-3.5 w-3.5 text-emerald-500" />
          ) : (
            <CopyIcon className="h-3.5 w-3.5 text-neutral-500 group-hover:text-neutral-700 dark:group-hover:text-neutral-200 transition" />
          )}
        </button>
      </div>

      {/* PDS endpoint */}
      <div className="mt-4">
        <p className="text-xs text-neutral-500 mb-1">Personal Data Store</p>
        <div className="
          flex items-center gap-2 rounded-xl
          border border-neutral-200/70 dark:border-neutral-800
          bg-neutral-50 dark:bg-neutral-950/40
          px-3 py-2 text-[13px]
        ">
          <ServerIcon className="h-3.5 w-3.5 text-neutral-500" />
          <span className="truncate text-neutral-700 dark:text-neutral-300">
            {pdsEndpoint ?? <span className="italic text-neutral-500">not configured</span>}
          </span>
        </div>
      </div>

      {/* Key Health */}
      <div className="mt-5">
        <p className="text-xs text-neutral-500 mb-2 uppercase tracking-wider">Key health</p>
        <ul className="grid grid-cols-3 gap-2">
          <HealthBadge
            label="Identity"
            ok={ready}
            icon={<ShieldCheckIcon className="h-3.5 w-3.5" />}
          />
          <HealthBadge
            label="Passkey"
            ok={hasPasskey}
            icon={<FingerprintIcon className="h-3.5 w-3.5" />}
          />
          <HealthBadge
            label="Session"
            ok={isAuth}
            warning={!isAuth && ready}
            icon={<span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-current" />}
          />
        </ul>
      </div>

      {/* optional footer slot */}
      {footer ? (
        <div className="mt-5 pt-4 border-t border-neutral-200/70 dark:border-neutral-800/70">
          {footer}
        </div>
      ) : null}
    </article>
  );
}

/* ── subparts ────────────────────────────────────────────────── */

function HealthBadge({
  label,
  ok,
  warning,
  icon,
}: {
  readonly label: string;
  readonly ok: boolean;
  readonly warning?: boolean;
  readonly icon?: React.ReactNode;
}): React.ReactElement {
  const tone =
    ok
      ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 ring-1 ring-inset ring-emerald-500/30"
      : warning
        ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-1 ring-inset ring-amber-500/30"
        : "bg-neutral-500/10 text-neutral-500 ring-1 ring-inset ring-neutral-500/20";

  return (
    <li className={`flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-[11px] font-medium ${tone}`}>
      {icon}
      <span className="truncate">{label}</span>
    </li>
  );
}

function Avatar({ publicKey }: { readonly publicKey: Uint8Array | undefined }): React.ReactElement {
  if (!publicKey) {
    return (
      <span
        className="h-9 w-9 rounded-2xl bg-neutral-200 dark:bg-neutral-800 ring-1 ring-inset ring-black/5 dark:ring-white/5"
        aria-hidden
      />
    );
  }
  const a = publicKey[0] ?? 0;
  const b = publicKey[1] ?? 0;
  const c = publicKey[2] ?? 0;
  const d = publicKey[3] ?? 0;
  const h1 = (a * 360) / 255;
  const h2 = (b * 360) / 255;
  const h3 = (c * 360) / 255;
  const s  = 55 + ((d * 30) / 255);
  return (
    <span
      aria-hidden
      className="h-9 w-9 rounded-2xl ring-1 ring-inset ring-black/10 dark:ring-white/10"
      style={{
        background:
          `radial-gradient(at 25% 25%, hsl(${h1} ${s}% 65%) 0%, transparent 60%),` +
          `radial-gradient(at 80% 30%, hsl(${h2} ${s}% 55%) 0%, transparent 55%),` +
          `radial-gradient(at 50% 90%, hsl(${h3} ${s}% 45%) 0%, transparent 60%)`,
      }}
    />
  );
}

function truncateDid(did: string): string {
  if (did.length <= 28) return did;
  return `${did.slice(0, 16)}…${did.slice(-8)}`;
}
