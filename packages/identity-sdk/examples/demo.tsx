"use client";

/**
 * Demo page — drops the three Phase-4.2 UI components onto a dark-mode canvas.
 *
 *   • Top-right          → <KashConnect />          (auth lifecycle)
 *   • Left column        → <IdentityWidget />       (Bento dashboard tile)
 *   • Right column       → "Publish listing" CTA   (opens the modal)
 *   • Overlay (on click) → <SignTransactionModal /> (signs a kash.trade.offer)
 *
 * This file lives under `packages/identity-sdk/examples/` and is excluded from
 * the build (the tsconfig include glob targets `src/**\/*` only). Copy it into
 * any Next.js / Vite / Astro app's page tree to see it live.
 *
 * Tailwind must be configured on the host (it ships with apps/kashscript already).
 */

import * as React from "react";
import { KashAuthProvider } from "../src/provider";
import {
  IdentityWidget,
  KashConnect,
  SignTransactionModal,
} from "../src/ui";

/* ──────────────────────────────────────────────────────────────────
 * Root export — wraps the demo in the provider.
 * In a Next.js App-Router app this would live in app/layout.tsx instead.
 * ────────────────────────────────────────────────────────────────── */

export default function DemoPage(): React.ReactElement {
  return (
    <KashAuthProvider rpName="Kash Demo">
      <DemoShell />
    </KashAuthProvider>
  );
}

/* ──────────────────────────────────────────────────────────────────
 * Demo shell — dark-mode canvas with a foundry-ish bento layout
 * ────────────────────────────────────────────────────────────────── */

function DemoShell(): React.ReactElement {
  const [modalOpen, setModalOpen] = React.useState(false);
  const [lastSig, setLastSig] = React.useState<string | null>(null);

  /* A representative kash.trade.offer body. */
  const body = React.useMemo(
    () => ({
      title:       "Karachi rooftop apartment — 2BR sea view",
      description: "Two bedrooms, fully furnished, walking distance to Clifton beach.",
      category:    "rentals" as const,
      price:       { amount: "85000.00", currency: "PKR", unit: "per-month" },
      location:    { region: "PK-SD", handler: "pickup" as const },
      status:      "open" as const,
    }),
    [],
  );

  /* A typical Kash-Event header (in a real app the CID would be SHA-256(body)). */
  const header = React.useMemo(
    () => ({
      did:     "did:kash:5g7q2hvh3xkvjnq7tzaaymzfeswftxnnyya",
      lexicon: "kash.trade.offer@1.0.0",
      iat:     "2026-05-11T12:34:56Z",
      nonce:   "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      cid:     "bafyreidemo0000000000000000000000000000000000000000000000",
      rkey:    "self",
    }),
    [],
  );

  return (
    <div className="dark min-h-screen bg-neutral-950 text-neutral-100 selection:bg-emerald-500/30">
      {/* subtle radial backdrop */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 -z-10"
        style={{
          backgroundImage:
            "radial-gradient(60rem 40rem at 20% -10%, rgba(16,185,129,0.10) 0%, transparent 60%)," +
            "radial-gradient(40rem 30rem at 95% 10%, rgba(56,189,248,0.10) 0%, transparent 60%)",
        }}
      />

      <header className="mx-auto max-w-6xl px-6 lg:px-8 pt-10 pb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span
            aria-hidden
            className="grid h-9 w-9 place-items-center rounded-2xl bg-emerald-500/15 text-emerald-400 ring-1 ring-inset ring-emerald-500/30 font-mono text-sm"
          >
            ks
          </span>
          <div className="font-mono text-xs uppercase tracking-[0.22em] text-neutral-400">
            kashscript · identity demo
          </div>
        </div>
        <KashConnect />
      </header>

      <main className="mx-auto max-w-6xl px-6 lg:px-8 pb-20">
        <section className="pt-8 pb-12">
          <h1
            className="text-4xl lg:text-5xl tracking-tight font-medium leading-[1.04] max-w-2xl"
            style={{ fontFamily: "var(--font-serif, ui-serif)" }}
          >
            A sovereign identity, ready to sign anything.
          </h1>
          <p className="mt-3 text-neutral-400 max-w-xl text-sm">
            Drop these three components into any React app to give your users a
            DID, a Passkey, and a transparent biometric prompt for every signature.
          </p>
        </section>

        <section className="grid grid-cols-12 gap-4 lg:gap-5">
          {/* IDENTITY WIDGET — left column */}
          <div className="col-span-12 md:col-span-5">
            <IdentityWidget
              pdsEndpoint="https://pds.kashscript.com"
              footer={
                <a
                  href="#"
                  className="
                    inline-flex items-center gap-1.5 text-xs font-medium
                    text-emerald-400 hover:text-emerald-300 transition
                  "
                  onClick={(e) => e.preventDefault()}
                >
                  Manage identity →
                </a>
              }
            />
          </div>

          {/* PUBLISH PANEL — right column, triggers modal */}
          <div className="col-span-12 md:col-span-7">
            <article
              className="
                h-full rounded-3xl border border-neutral-800
                bg-neutral-900 p-6 lg:p-7
                shadow-[0_8px_24px_-12px_rgba(0,0,0,0.6)]
              "
            >
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-neutral-400">
                duedale · marketplace
              </p>
              <h2 className="mt-2 text-2xl font-medium tracking-tight">
                Publish a listing
              </h2>
              <p className="mt-2 text-sm text-neutral-400 max-w-md">
                Tap publish to sign a <code className="font-mono text-emerald-300">kash.trade.offer</code> record.
                The biometric prompt will be bound to the canonical bytes of THIS listing.
              </p>

              <div className="mt-5 grid grid-cols-3 gap-2 text-[11px]">
                <Pill label="title"    value={body.title.slice(0, 22) + "…"} />
                <Pill label="price"    value={`₨ ${body.price.amount} ${body.price.currency}`} />
                <Pill label="category" value={body.category} />
              </div>

              <button
                type="button"
                onClick={() => setModalOpen(true)}
                className="
                  mt-6 inline-flex items-center gap-2 rounded-full
                  bg-emerald-500 hover:bg-emerald-400 text-emerald-950
                  px-4 py-2 text-sm font-semibold transition
                  focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400
                  focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-900
                "
              >
                Publish listing
              </button>

              {lastSig ? (
                <p className="mt-4 text-[11px] text-emerald-400 font-mono break-all">
                  ✓ signed · sig: {lastSig.slice(0, 32)}…
                </p>
              ) : null}
            </article>
          </div>
        </section>

        <section className="mt-12 grid grid-cols-12 gap-4 lg:gap-5 text-sm">
          <NoteCard className="col-span-12 md:col-span-4" title="1 · Connect">
            <code>{"<KashConnect />"}</code> creates or unlocks the user's identity.
            State surfaces via the <code>useKashAuth()</code> hook.
          </NoteCard>
          <NoteCard className="col-span-12 md:col-span-4" title="2 · Inspect">
            <code>{"<IdentityWidget />"}</code> shows DID, PDS, and key health.
            White-label-ready via <code>className</code> / <code>style</code> and a footer slot.
          </NoteCard>
          <NoteCard className="col-span-12 md:col-span-4" title="3 · Sign">
            <code>{"<SignTransactionModal />"}</code> breaks down every field before the
            prompt. Blind signing is structurally impossible.
          </NoteCard>
        </section>
      </main>

      <SignTransactionModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        requestedBy="duedale.app"
        lexiconId="kash.trade.offer@1.0.0"
        action="Create marketplace listing"
        description="Publishing this listing to your PDS. Buyers will be able to view, like, and trade against it."
        header={header}
        body={body}
        onSigned={(sig) => setLastSig(sig.sig)}
      />
    </div>
  );
}

/* ── tiny demo helpers (NOT part of the SDK surface) ────────── */

function Pill({ label, value }: { readonly label: string; readonly value: string }): React.ReactElement {
  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-950/60 px-3 py-2">
      <div className="font-mono text-[9px] uppercase tracking-[0.22em] text-neutral-500">{label}</div>
      <div className="mt-1 truncate text-neutral-200">{value}</div>
    </div>
  );
}

function NoteCard({
  className,
  title,
  children,
}: {
  readonly className?: string;
  readonly title: string;
  readonly children: React.ReactNode;
}): React.ReactElement {
  return (
    <article
      className={
        "rounded-3xl border border-neutral-800 bg-neutral-900/60 p-5 backdrop-blur " +
        (className ?? "")
      }
    >
      <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-neutral-500">{title}</p>
      <p className="mt-2 text-sm text-neutral-300 leading-relaxed">{children}</p>
    </article>
  );
}
