/**
 * Self-contained CSS for `<SignTransactionModal>` — bundled as a string
 * and injected inside the shadow root by {@link ShadowFrame}. The shadow
 * boundary prevents host CSS from reaching in, so this stylesheet is the
 * ONLY source of styling for the modal. Keep it small, opinionated, and
 * mostly fixed: tokenisation via CSS custom properties allows light/dark
 * but does not expose theming knobs to the host.
 */

export const MODAL_CSS = /* css */ `
:host, * { box-sizing: border-box; }

:host {
  /* Tokens — kept private to the shadow tree. */
  --kash-bg:        rgb(255 255 255 / 1);
  --kash-bg-soft:   rgb(245 245 245 / 0.6);
  --kash-bg-card:   rgb(255 255 255 / 1);
  --kash-fg:        rgb(23 23 23);
  --kash-fg-muted:  rgb(115 115 115);
  --kash-fg-faint:  rgb(163 163 163);
  --kash-border:    rgb(229 229 229 / 0.7);
  --kash-divider:   rgb(229 229 229 / 0.6);
  --kash-accent:    rgb(16 185 129);          /* emerald-500 */
  --kash-accent-fg: rgb(6 78 59);             /* emerald-950 */
  --kash-accent-hi: rgb(52 211 153);          /* emerald-400 */
  --kash-warn:      rgb(245 158 11);          /* amber-500 */
  --kash-error:     rgb(244 63 94);           /* rose-500 */
  --kash-error-bg:  rgb(244 63 94 / 0.1);

  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.4;
  color: var(--kash-fg);
}

@media (prefers-color-scheme: dark) {
  :host {
    --kash-bg:        rgb(23 23 23);
    --kash-bg-soft:   rgb(10 10 10 / 0.4);
    --kash-bg-card:   rgb(10 10 10);
    --kash-fg:        rgb(245 245 245);
    --kash-fg-muted:  rgb(163 163 163);
    --kash-fg-faint:  rgb(115 115 115);
    --kash-border:    rgb(38 38 38);
    --kash-divider:   rgb(38 38 38 / 0.7);
    --kash-accent-fg: rgb(6 78 59);
  }
}

@keyframes kashfade {
  from { opacity: 0; transform: translateY(8px) scale(0.98); }
  to   { opacity: 1; transform: translateY(0)  scale(1);    }
}

.kash-overlay {
  position: fixed;
  inset: 0;
  z-index: 2147483647;            /* one less than MAX — defensive */
  display: flex;
  align-items: flex-end;
  justify-content: center;
}
@media (min-width: 640px) {
  .kash-overlay { align-items: center; }
}

.kash-backdrop {
  position: absolute;
  inset: 0;
  background: rgb(0 0 0 / 0.6);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  border: 0;
  padding: 0;
  cursor: pointer;
  transition: opacity 150ms ease;
}
.kash-backdrop[disabled] { cursor: progress; }

.kash-container {
  position: relative;
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
  border-radius: 1.5rem 1.5rem 0 0;
  background: var(--kash-bg);
  border: 1px solid var(--kash-border);
  box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.5);
  color: var(--kash-fg);
  animation: kashfade 180ms ease-out;
}
@media (min-width: 640px) {
  .kash-container { border-radius: 1.5rem; }
}

.kash-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 1.25rem 1.5rem 0.75rem;
}
.kash-header__title-wrap {
  display: inline-flex;
  align-items: center;
  gap: 0.625rem;
}
.kash-header__title {
  margin: 0;
  font-size: 0.875rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.kash-header__close {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 2rem;
  width: 2rem;
  margin-right: -0.25rem;
  border: 0;
  background: transparent;
  border-radius: 9999px;
  color: var(--kash-fg-muted);
  cursor: pointer;
  transition: background 120ms, color 120ms;
}
.kash-header__close:hover:not(:disabled) {
  color: var(--kash-fg);
  background: var(--kash-bg-soft);
}
.kash-header__close:disabled { opacity: 0.4; cursor: not-allowed; }

.kash-body {
  padding: 0 1.5rem 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.kash-section {
  border: 1px solid var(--kash-border);
  background: var(--kash-bg-soft);
  border-radius: 1rem;
  padding: 1rem;
}
.kash-section--data { background: var(--kash-bg-card); }

.kash-label {
  font-size: 0.625rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--kash-fg-muted);
  margin: 0 0 0.5rem;
}

.kash-requested {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.kash-requested__icon {
  height: 2.5rem;
  width: 2.5rem;
  border-radius: 0.75rem;
  background: linear-gradient(135deg, rgb(56 189 248), rgb(16 185 129));
  display: grid;
  place-items: center;
  color: white;
  box-shadow: inset 0 0 0 1px rgb(0 0 0 / 0.1);
}
.kash-requested__name {
  font-size: 0.875rem;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.kash-requested__origin {
  margin-top: 0.125rem;
  font-size: 0.6875rem;
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}
.kash-origin--ok    { color: var(--kash-accent); }
.kash-origin--warn  { color: var(--kash-warn); }

.kash-action__line { margin: 0.375rem 0 0; font-size: 0.875rem; font-weight: 500; }
.kash-action__desc { margin: 0.25rem 0 0; font-size: 0.75rem; color: var(--kash-fg-muted); }
.kash-action__lex  { margin: 0.5rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.6875rem; color: var(--kash-fg-muted); }

.kash-data dl { margin: 0; }
.kash-data .kash-field {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.5rem 0;
  border-top: 1px solid var(--kash-divider);
}
.kash-data .kash-field:first-child { border-top: 0; }
.kash-data dt {
  flex-shrink: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.6875rem;
  font-weight: 400;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--kash-fg-muted);
}
.kash-data dd {
  margin: 0;
  text-align: right;
  font-size: 0.78125rem;
  max-width: 65%;
  word-break: break-all;
  color: var(--kash-fg);
}
.kash-data dd .muted { color: var(--kash-fg-muted); }
.kash-data details { margin-top: 0.75rem; font-size: 0.6875rem; }
.kash-data details summary {
  cursor: pointer;
  user-select: none;
  color: var(--kash-fg-muted);
}
.kash-data details summary:hover { color: var(--kash-fg); }

.kash-signing-as {
  padding: 0 0.25rem;
  font-size: 0.6875rem;
  color: var(--kash-fg-muted);
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}
.kash-signing-as code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

.kash-error-card {
  border: 1px solid rgb(244 63 94 / 0.4);
  background: var(--kash-error-bg);
  border-radius: 0.75rem;
  padding: 0.5rem 0.75rem;
  font-size: 0.75rem;
  color: var(--kash-error);
}

.kash-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem 1.25rem;
  border-top: 1px solid var(--kash-border);
}

.kash-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border: 0;
  border-radius: 9999px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: background 120ms, color 120ms, opacity 120ms;
}
.kash-btn--cancel {
  background: transparent;
  color: var(--kash-fg);
}
.kash-btn--cancel:hover:not(:disabled) { background: var(--kash-bg-soft); }
.kash-btn--approve {
  background: var(--kash-accent);
  color: var(--kash-accent-fg);
  font-weight: 600;
}
.kash-btn--approve:hover:not(:disabled) { background: var(--kash-accent-hi); }
.kash-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.kash-btn:focus-visible {
  outline: 2px solid var(--kash-accent);
  outline-offset: 2px;
}

.kash-icon { width: 1rem; height: 1rem; flex-shrink: 0; }
.kash-icon--lg { width: 1.25rem; height: 1.25rem; }
.kash-icon--sm { width: 0.75rem; height: 0.75rem; }
.kash-icon--accent { color: var(--kash-accent); }
.kash-icon--white  { color: white; }

.kash-spinner {
  width: 1rem; height: 1rem;
  border-radius: 9999px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  animation: kashspin 600ms linear infinite;
}
@keyframes kashspin { to { transform: rotate(360deg); } }

/* ── Integrity-fail surface ─────────────────────────────────── */
.kash-integrity-fail {
  position: relative;
  width: 100%;
  max-width: 28rem;
  margin: 0 auto;
  border-radius: 1rem;
  background: var(--kash-bg);
  border: 2px solid var(--kash-error);
  padding: 1.25rem 1.5rem;
  color: var(--kash-fg);
}
.kash-integrity-fail h3 {
  margin: 0 0 0.5rem;
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--kash-error);
}
.kash-integrity-fail p { margin: 0 0 0.5rem; font-size: 0.8125rem; }
.kash-integrity-fail ul { margin: 0.5rem 0; padding-left: 1.25rem; font-size: 0.75rem; color: var(--kash-fg-muted); }
.kash-integrity-fail .kash-btn { margin-top: 0.75rem; }
`;
