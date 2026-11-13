"use client";

/**
 * <SignTransactionModal /> — pre-sign confirmation dialog with Trust-UX
 * isolation.
 *
 * Trust-UX is the load-bearing concern. The modal visually segregates THREE
 * distinct zones so a user can never confuse who is asking, what is being
 * asked, and what data the request actually contains:
 *
 *   1. REQUESTED BY  — origin / app name. Tinted "trust" panel with an
 *                       origin-verified badge.
 *   2. ACTION        — a single human-readable line plus the lexicon ID.
 *   3. DATA BEING SIGNED — recursive key/value rendering of `body` so the
 *                       user can audit each field before approving.
 *
 * **F1 isolation contract.** The modal renders inside a CLOSED Shadow DOM
 * via `<ShadowFrame>`, with a self-contained stylesheet bundled inside the
 * shadow root. Host-page CSS cannot reach the modal's tree — `display:
 * none` rules, `opacity: 0` overlays, off-screen translations, and other
 * CSS-injection attacks against the Approve / Cancel buttons are foreclosed
 * at the browser boundary. After mount, a `getComputedStyle` integrity
 * check verifies that the three critical elements (title, approve, cancel)
 * are present, opaque, and inside the viewport; if any check fails the
 * modal renders a fail-state and refuses to allow signing.
 *
 * **F5 sanitisation.** Every user-facing string (requestedBy, lexiconId,
 * action, description, header/body field names and string values) is
 * passed through {@link sanitiseDisplayText} / {@link sanitiseDisplayValue}
 * before rendering. Bidi-override / zero-width / control characters are
 * stripped, NFKC normalisation collapses fullwidth and look-alike chars.
 *
 * On approve, the modal calls `useSigner().sign(header, body, opts?)` which
 * triggers the OS biometric prompt. There is no path through this component
 * that signs without showing the body — blind signing is structurally
 * prevented.
 *
 * Accessibility:
 *   • role="dialog" + aria-modal
 *   • Escape closes (when not signing)
 *   • backdrop click closes (when not signing)
 */

import type { KashEventSignature, SignEventOptions } from "@kashscript/identity-core";
import * as React from "react";
import { useSigner } from "../hooks";
import { CheckIcon, FingerprintIcon, GlobeIcon, ShieldCheckIcon, SpinnerIcon, XIcon } from "./icons";
import { ShadowFrame, useMountIntegrity, type IntegrityCheckTarget } from "./ShadowFrame";
import { MODAL_CSS } from "./modal.css";
import { sanitiseDisplayText, sanitiseDisplayValue } from "./sanitise";

export interface SignTransactionModalProps {
  readonly open: boolean;
  readonly onClose: () => void;
  /** App name or origin requesting the signature (e.g., `"duedale.app"`). */
  readonly requestedBy: string;
  /** Full Lexicon ID being signed. */
  readonly lexiconId: string;
  /** Human-readable action label (e.g., `"Create marketplace listing"`). */
  readonly action: string;
  /** Optional short paragraph elaborating the action's intent. */
  readonly description?: string;
  /** Kash-Event header that will be signed. */
  readonly header: Readonly<Record<string, unknown>>;
  /** Kash-Event body that will be signed. */
  readonly body: Readonly<Record<string, unknown>>;
  /** Pass-through to identity-core. */
  readonly signOptions?: SignEventOptions;
  /** Resolves with the signature once the user approves and signs. */
  readonly onSigned: (signature: KashEventSignature) => void;
  /** Surfaces sign errors (cancelled prompt, etc.). */
  readonly onError?: (err: Error) => void;
  /** Override the default approve / cancel label. */
  readonly approveLabel?: string;
  readonly cancelLabel?: string;
}

const INTEGRITY_TARGETS: readonly IntegrityCheckTarget[] = [
  { critical: "title",    label: "Signature-request title" },
  { critical: "approve",  label: "Approve & sign button" },
  { critical: "cancel",   label: "Cancel button" },
  { critical: "data",     label: "Data-being-signed panel" },
];

export function SignTransactionModal(props: SignTransactionModalProps): React.ReactElement | null {
  const {
    open,
    onClose,
    requestedBy,
    lexiconId,
    action,
    description,
    header,
    body,
    signOptions,
    onSigned,
    onError,
    approveLabel = "Approve & sign",
    cancelLabel = "Cancel",
  } = props;

  const { sign, identity, status } = useSigner();
  const [phase, setPhase] = React.useState<"review" | "signing" | "signed" | "error">("review");
  const [localError, setLocalError] = React.useState<Error | null>(null);
  const [shadowRoot, setShadowRoot] = React.useState<ShadowRoot | null>(null);
  const integrity = useMountIntegrity(shadowRoot, INTEGRITY_TARGETS);

  /* F5: sanitise every displayed string up front. Re-runs only when inputs change. */
  const safeRequestedBy = React.useMemo(() => sanitiseDisplayText(requestedBy, { maxLength: 128 }), [requestedBy]);
  const safeLexiconId   = React.useMemo(() => sanitiseDisplayText(lexiconId,   { maxLength: 128 }), [lexiconId]);
  const safeAction      = React.useMemo(() => sanitiseDisplayText(action,      { maxLength: 256 }), [action]);
  const safeDescription = React.useMemo(
    () => (description ? sanitiseDisplayText(description, { maxLength: 512 }) : ""),
    [description],
  );
  const safeBody        = React.useMemo(() => sanitiseDisplayValue(body) as Record<string, unknown>,   [body]);
  const safeHeader      = React.useMemo(() => sanitiseDisplayValue(header) as Record<string, unknown>, [header]);

  // reset internal state when re-opening
  React.useEffect(() => {
    if (open) { setPhase("review"); setLocalError(null); }
  }, [open]);

  // escape key — listens on the host document; KeyboardEvents bubble from
  // the shadow root via composedPath() by default, so this still catches
  // escape presses while focus is inside the shadow tree.
  React.useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent): void => {
      if (e.key === "Escape" && phase !== "signing") onClose();
    };
    document.addEventListener("keydown", handler);
    return (): void => document.removeEventListener("keydown", handler);
  }, [open, phase, onClose]);

  if (!open) return null;

  const expectedOrigin = typeof window !== "undefined" ? window.location.origin : "";
  const originMatches  = !!expectedOrigin && safeRequestedBy.includes(stripScheme(expectedOrigin));

  const approve = async (): Promise<void> => {
    // F1: integrity gate — refuse to sign if any critical element was
    // tampered out of visibility. Defence-in-depth above the shadow boundary.
    if (!integrity.ok) {
      const wrapped = new Error(
        `Refusing to sign: modal integrity check failed (${integrity.failures.map((f) => f.label).join(", ")}). Reload the page or report to the app operator.`,
      );
      setLocalError(wrapped);
      setPhase("error");
      onError?.(wrapped);
      return;
    }

    setPhase("signing");
    setLocalError(null);
    try {
      const sig = await sign(header, body, signOptions);
      setPhase("signed");
      onSigned(sig);
      window.setTimeout(onClose, 600);
    } catch (err) {
      const wrapped = err instanceof Error ? err : new Error(String(err));
      setLocalError(wrapped);
      setPhase("error");
      onError?.(wrapped);
    }
  };

  return (
    <ShadowFrame styles={MODAL_CSS} onReady={setShadowRoot}>
      {!integrity.ok ? (
        <IntegrityFailCard failures={integrity.failures} onClose={onClose} />
      ) : (
        <div className="kash-overlay" role="dialog" aria-modal="true" aria-labelledby="kash-sign-title">
          {/* backdrop */}
          <button
            type="button"
            aria-label="Close signature request"
            disabled={phase === "signing"}
            onClick={() => phase !== "signing" && onClose()}
            className="kash-backdrop"
          />

          {/* container */}
          <div className="kash-container">
            <header className="kash-header">
              <div className="kash-header__title-wrap">
                <FingerprintIcon className="kash-icon kash-icon--lg kash-icon--accent" />
                <h2 id="kash-sign-title" className="kash-header__title" data-kash-critical="title">
                  Signature request
                </h2>
              </div>
              <button
                type="button"
                onClick={() => phase !== "signing" && onClose()}
                disabled={phase === "signing"}
                className="kash-header__close"
                aria-label="Close"
              >
                <XIcon className="kash-icon" />
              </button>
            </header>

            <div className="kash-body">
              {/* ZONE 1: Requested by */}
              <section className="kash-section">
                <p className="kash-label">Requested by</p>
                <div className="kash-requested">
                  <span aria-hidden className="kash-requested__icon">
                    <GlobeIcon className="kash-icon--lg kash-icon--white" />
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <div className="kash-requested__name">{safeRequestedBy}</div>
                    <div className="kash-requested__origin">
                      {originMatches ? (
                        <>
                          <ShieldCheckIcon className="kash-icon kash-icon--sm" />
                          <span className="kash-origin--ok">origin verified · {expectedOrigin}</span>
                        </>
                      ) : (
                        <span className="kash-origin--warn">
                          origin does not match · {expectedOrigin || "unknown"}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </section>

              {/* ZONE 2: Action */}
              <section className="kash-section">
                <p className="kash-label">Action</p>
                <p className="kash-action__line">{safeAction}</p>
                {safeDescription ? <p className="kash-action__desc">{safeDescription}</p> : null}
                <p className="kash-action__lex">{safeLexiconId}</p>
              </section>

              {/* ZONE 3: Data being signed */}
              <section className="kash-section kash-section--data kash-data" data-kash-critical="data">
                <p className="kash-label">Data being signed</p>
                <dl>
                  {Object.entries(safeBody).map(([k, v]) => (
                    <DataField key={k} k={k} v={v} />
                  ))}
                </dl>
                <details>
                  <summary>Show envelope header</summary>
                  <dl>
                    {Object.entries(safeHeader).map(([k, v]) => (
                      <DataField key={k} k={k} v={v} muted />
                    ))}
                  </dl>
                </details>
              </section>

              {/* signing-as line */}
              {identity ? (
                <p className="kash-signing-as">
                  Signing as <code>{truncateDid(identity.did)}</code>
                  {identity.handle ? <span>· {sanitiseDisplayText(identity.handle, { maxLength: 64 })}</span> : null}
                </p>
              ) : null}

              {phase === "error" && localError ? (
                <p role="alert" className="kash-error-card">
                  {sanitiseDisplayText(localError.message, { maxLength: 512 })}
                </p>
              ) : null}
            </div>

            <footer className="kash-footer">
              <button
                type="button"
                onClick={onClose}
                disabled={phase === "signing"}
                className="kash-btn kash-btn--cancel"
                data-kash-critical="cancel"
              >
                {cancelLabel}
              </button>
              <button
                type="button"
                onClick={approve}
                disabled={status === "loading" || phase === "signing" || phase === "signed"}
                className="kash-btn kash-btn--approve"
                data-kash-critical="approve"
              >
                {phase === "signing" ? (
                  <><span className="kash-spinner" /> Awaiting biometric…</>
                ) : phase === "signed" ? (
                  <><CheckIcon className="kash-icon" /> Signed</>
                ) : (
                  <><FingerprintIcon className="kash-icon" /> {approveLabel}</>
                )}
              </button>
            </footer>
          </div>
        </div>
      )}
    </ShadowFrame>
  );
}

/* ── integrity-fail card ───────────────────────────────────────── */

function IntegrityFailCard({
  failures,
  onClose,
}: {
  readonly failures: ReadonlyArray<{ readonly label: string; readonly reason: string }>;
  readonly onClose: () => void;
}): React.ReactElement {
  return (
    <div className="kash-overlay" role="alertdialog" aria-modal="true">
      <button type="button" className="kash-backdrop" onClick={onClose} aria-label="Close" />
      <div className="kash-integrity-fail">
        <h3>Modal integrity check failed</h3>
        <p>
          The signature dialog could not verify its own interactive controls. Signing has been refused
          for your safety. This usually means a browser extension or the host page is interfering with
          the dialog's rendering.
        </p>
        <ul>
          {failures.map((f, i) => (
            <li key={i}><strong>{f.label}</strong>: {f.reason}</li>
          ))}
        </ul>
        <p>Disable extensions that modify pages, then reload and try again.</p>
        <button type="button" className="kash-btn kash-btn--cancel" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}

/* ── recursive key/value field renderer ─────────────────────── */

function DataField({
  k, v, depth = 0, muted = false,
}: {
  readonly k: string | number;
  readonly v: unknown;
  readonly depth?: number;
  readonly muted?: boolean;
}): React.ReactElement {
  return (
    <div className="kash-field">
      <dt style={{ paddingLeft: depth * 8 }}>{String(k)}</dt>
      <dd className={muted ? "muted" : undefined}>
        <ValueDisplay v={v} depth={depth} />
      </dd>
    </div>
  );
}

function ValueDisplay({ v, depth = 0 }: { readonly v: unknown; readonly depth: number }): React.ReactElement {
  if (v === null || v === undefined) return <span className="muted">—</span>;
  if (typeof v === "boolean") return <span>{v ? "yes" : "no"}</span>;
  if (typeof v === "number")  return <span style={{ fontVariantNumeric: "tabular-nums" }}>{v}</span>;
  if (typeof v === "string") {
    if (v.length > 64) return <span>{v.slice(0, 60)}…</span>;
    return <span>{v}</span>;
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="muted">[]</span>;
    return <span className="muted">{v.length} item{v.length === 1 ? "" : "s"}</span>;
  }
  if (typeof v === "object" && v !== null) {
    if (depth >= 1) {
      return <code style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: "0.6875rem" }}>{compactJson(v)}</code>;
    }
    return (
      <dl style={{ marginRight: "-0.5rem", display: "inline-block", textAlign: "left" }}>
        {Object.entries(v).map(([kk, vv]) => (
          <DataField key={kk} k={kk} v={vv} depth={depth + 1} />
        ))}
      </dl>
    );
  }
  return <span>{String(v)}</span>;
}

function compactJson(value: unknown): string {
  try { return JSON.stringify(value); } catch { return String(value); }
}

function truncateDid(did: string): string {
  if (did.length <= 28) return did;
  return `${did.slice(0, 16)}…${did.slice(-8)}`;
}

function stripScheme(origin: string): string {
  return origin.replace(/^https?:\/\//, "");
}
