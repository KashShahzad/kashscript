"use client";

/**
 * Trust-UX isolation primitive.
 *
 * `<ShadowFrame>` mounts its children inside a CLOSED shadow root attached
 * to an internal host element. Host-page CSS cannot reach into the shadow
 * tree — `display: none`, `opacity: 0`, off-screen translation, and other
 * CSS-injection attacks against the modal are foreclosed by the shadow
 * boundary itself.
 *
 * Why **closed** mode: `element.shadowRoot` returns `null` on closed roots,
 * preventing host scripts from snatching the root and querying its tree.
 * Our own integrity check reaches the root via the {@link onReady}
 * callback, which fires exactly once after attachment.
 *
 * The optional `styles` string is injected as a `<style>` element INSIDE
 * the shadow root so the modal can use class names without inheriting host
 * stylesheets. This is the standard adopted-stylesheet pattern but
 * implemented with `<style>` for older-browser compatibility.
 */

import * as React from "react";
import { createPortal } from "react-dom";

export interface ShadowFrameProps {
  readonly children: React.ReactNode;
  /** CSS injected inside the shadow root as a `<style>` element. */
  readonly styles?: string;
  /** className applied to the OUTER host element (lives in the host's DOM). */
  readonly className?: string;
  /** Fires once after the shadow root + styles are attached. */
  readonly onReady?: (root: ShadowRoot) => void;
  /** Sentinel attribute on the host for browser-devtools attribution. */
  readonly dataAttr?: string;
}

export function ShadowFrame({
  children,
  styles,
  className,
  onReady,
  dataAttr = "kash-shadow-frame",
}: ShadowFrameProps): React.ReactElement {
  const hostRef = React.useRef<HTMLDivElement | null>(null);
  const [root, setRoot] = React.useState<ShadowRoot | null>(null);

  React.useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    // attachShadow is idempotent-resistant: re-attaching throws. So we guard
    // by checking the closed-root captured in state.
    if (root) return;

    let shadow: ShadowRoot;
    try {
      shadow = host.attachShadow({ mode: "closed" });
    } catch (e) {
      // If host already has a shadow root (open mode, attached by another
      // component) attachShadow throws. Surface a clear console error and
      // bail; the modal will fall back to host-DOM rendering with reduced
      // isolation.
      console.error("[kash:identity-sdk] attachShadow failed; the host element already carries a shadow root.", e);
      return;
    }

    if (styles) {
      const styleEl = shadow.ownerDocument.createElement("style");
      styleEl.setAttribute("data-kash-styles", "modal");
      styleEl.textContent = styles;
      shadow.appendChild(styleEl);
    }

    setRoot(shadow);
    onReady?.(shadow);
    // We intentionally do not re-attach on re-renders. Cleanup is a no-op
    // because the shadow root dies with the host element on unmount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={hostRef}
      className={className}
      // eslint-disable-next-line @typescript-eslint/naming-convention
      {...{ [`data-${dataAttr}`]: "" }}
    >
      {root ? createPortal(children, root as unknown as Element) : null}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Mount-integrity hook.
 * ────────────────────────────────────────────────────────────────
 *
 * Even with a shadow boundary, paranoid defence is cheap and worth running:
 * after mount, query the critical elements (Approve button, Cancel button,
 * the title) and assert via `getComputedStyle` that they are visible,
 * opaque, and inside the viewport. If anyone (a bug, a future contributor,
 * or — unlikely but possible — a same-origin script with shadow-root access
 * via a leaked reference) hides them, the modal's caller is told.
 *
 * The hook returns `{ ok, failures }`. The modal renders a hard-fail card
 * instead of the dialog when `ok === false`, refusing to proceed.
 */

export interface IntegrityCheckTarget {
  /** `data-kash-critical` attribute value to find inside the shadow root. */
  readonly critical: string;
  /** Human-readable name for the failure message. */
  readonly label: string;
}

export interface IntegrityCheckResult {
  readonly ok: boolean;
  readonly failures: ReadonlyArray<{ readonly label: string; readonly reason: string }>;
}

export function useMountIntegrity(
  root: ShadowRoot | null,
  targets: readonly IntegrityCheckTarget[],
): IntegrityCheckResult {
  const [result, setResult] = React.useState<IntegrityCheckResult>({ ok: true, failures: [] });

  React.useEffect(() => {
    if (!root) return;
    // Defer one frame so the children have finished their first layout.
    const raf = requestAnimationFrame(() => {
      const failures: Array<{ label: string; reason: string }> = [];
      for (const t of targets) {
        const el = root.querySelector<HTMLElement>(`[data-kash-critical="${t.critical}"]`);
        if (!el) {
          failures.push({ label: t.label, reason: "element not found in shadow tree" });
          continue;
        }
        const cs = root.ownerDocument.defaultView!.getComputedStyle(el);
        if (cs.display === "none")        failures.push({ label: t.label, reason: `display: none` });
        if (cs.visibility === "hidden")   failures.push({ label: t.label, reason: `visibility: hidden` });
        const opacity = Number(cs.opacity);
        if (Number.isFinite(opacity) && opacity < 0.5) {
          failures.push({ label: t.label, reason: `opacity ${opacity.toFixed(2)} < 0.5` });
        }
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) {
          failures.push({ label: t.label, reason: `zero-sized (${rect.width.toFixed(1)} × ${rect.height.toFixed(1)})` });
        }
        // Viewport check — at least PART of the element must be onscreen.
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        if (rect.right < 0 || rect.bottom < 0 || rect.left > vw || rect.top > vh) {
          failures.push({ label: t.label, reason: `rendered offscreen (${rect.left.toFixed(0)},${rect.top.toFixed(0)})` });
        }
        if (cs.pointerEvents === "none") {
          failures.push({ label: t.label, reason: `pointer-events: none (uninteractive)` });
        }
      }
      setResult({ ok: failures.length === 0, failures });
    });
    return (): void => cancelAnimationFrame(raf);
  }, [root, targets]);

  return result;
}
