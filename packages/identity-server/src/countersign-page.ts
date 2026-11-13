// ============================================================================
// @kashscript/identity-server — the ceremony page
// ----------------------------------------------------------------------------
// One screen, framework-free, returned as a string so any host can serve it
// from anywhere. It is the minimum the mechanic needs and deliberately not a
// product surface: driver-specific presentation belongs to whoever composes it.
//
// ── The rule this page inherits ─────────────────────────────────────────────
// ECOSYSTEM decision 44: a person must be able to use this without ever
// learning the parent entity's name, the phrase *proof economy*, the word
// *standing*, or the name of any member. So the page names nobody, and it has
// no vocabulary of its own to name them with: every word it renders is either
// fixed chrome or something the REQUESTER wrote. The denylist that enforces
// this lives in `test/countersign.test.ts` — deliberately not here, because a
// package a stranger installs should not ship a list of the ecosystem's names.
//
// ── What the page does and does not do ──────────────────────────────────────
// The key is generated HERE, in the reader's browser, and never leaves it. The
// page posts back the finished signatures, not the key. There is no account, no
// password, no session and no cookie — possession of the link is the whole of
// the authorisation, which is what makes a one-click countersignature possible
// at all (decision 26: if a counterparty must create an account, the
// countersignature never happens).
//
// Declining is a real button and it is inert on purpose: it clears the page's
// own copy of the material and posts nothing. See `declineCountersignRequest`.
// ============================================================================

import type { SignedCountersignRequest } from "@kashscript/attest";

export interface CountersignPageOptions {
  /** The requester's own label for itself — a shop, a clinic, a co-op. Shown
   *  verbatim, attributed to them, and trusted for nothing. */
  readonly requesterLabel: string;
  /** Where the finished signatures are posted. The requester's own endpoint. */
  readonly submitUrl: string;
  /**
   * URL of an ES module the host serves, exporting
   * `signCeremony(request, subject)` — a browser bundle of
   * `generateOneTimeSigningKey` + `acceptCountersignRequest` from this package.
   * It is a parameter rather than an inlined script because the host owns its
   * own bundling and its own Content-Security-Policy; the page ships no
   * cryptography of its own.
   */
  readonly ceremonyModuleUrl: string;
  /** The envelope being countersigned, embedded so the page needs no second
   *  fetch — which is also what lets it be saved and signed offline. */
  readonly subject: unknown;
  /** BCP-47 tag for the `lang` attribute. */
  readonly localeCode?: string;
  /** Text-direction hint for right-to-left scripts. */
  readonly dir?: "ltr" | "rtl";
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Render the one-click ceremony page for `request`.
 *
 * The request is embedded as JSON so the page works with no second fetch —
 * which is also what lets the same page be saved, printed or handed over on a
 * device that is offline at the moment of signing.
 */
export function renderCountersignPage(
  request: SignedCountersignRequest,
  options: CountersignPageOptions,
): string {
  const body = request.body;
  const expiresIso = new Date(body.expiresAtUnix * 1000).toISOString().slice(0, 16).replace("T", " ");
  const disclosures = body.disclosures
    .map(
      (d) =>
        `<div class="row"><dt>${escapeHtml(d.label)}</dt><dd>${escapeHtml(d.value)}</dd></div>`,
    )
    .join("");

  return `<!doctype html>
<html lang="${escapeHtml(options.localeCode ?? "en")}" dir="${options.dir === "rtl" ? "rtl" : "ltr"}">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign or decline</title>
<style>
  :root { color-scheme: light dark; --fg: #111; --bg: #fff; --muted: #555; --line: #d7d7d7; }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #f2f2f2; --bg: #141414; --muted: #a8a8a8; --line: #3a3a3a; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg);
         font: 17px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 34rem; margin: 0 auto; }
  h1 { font-size: 1.35rem; line-height: 1.3; margin: 0 0 4px; }
  .from { color: var(--muted); font-size: .95rem; margin: 0 0 20px; }
  dl { margin: 20px 0; border-top: 1px solid var(--line); }
  .row { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--line); }
  dt { flex: 0 0 40%; color: var(--muted); margin: 0; }
  dd { flex: 1; margin: 0; overflow-wrap: anywhere; }
  .note { color: var(--muted); font-size: .9rem; margin: 18px 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 24px; }
  button { font: inherit; padding: 13px 22px; border-radius: 8px; cursor: pointer; border: 1px solid var(--fg); }
  #sign { background: var(--fg); color: var(--bg); }
  #no { background: transparent; color: var(--fg); }
  #done { margin-top: 20px; }
  [hidden] { display: none !important; }
</style>
<main>
  <h1>${escapeHtml(body.statement)}</h1>
  <p class="from">Asked by ${escapeHtml(options.requesterLabel)} · expires ${escapeHtml(expiresIso)} UTC</p>
  <dl>${disclosures}</dl>
  <p class="note">Signing creates a key on this device. It is never sent anywhere,
     and there is nothing to install or sign up for. Saying no costs you nothing:
     it records nothing at all, and nobody is told.</p>
  <div class="actions">
    <button id="sign" type="button">Sign</button>
    <button id="no" type="button">No thanks</button>
  </div>
  <p id="done" hidden></p>
</main>
<script type="application/json" id="request">${JSON.stringify(request).replace(/</g, "\\u003c")}</script>
<script type="application/json" id="subject">${JSON.stringify(options.subject).replace(/</g, "\\u003c")}</script>
<script type="module">
  const submitUrl = ${JSON.stringify(options.submitUrl)};
  const ceremonyModuleUrl = ${JSON.stringify(options.ceremonyModuleUrl)};
  const done = document.getElementById("done");
  const actions = document.querySelector(".actions");
  const say = (msg) => { done.textContent = msg; done.hidden = false; actions.hidden = true; };
  const read = (id) => JSON.parse(document.getElementById(id).textContent);

  document.getElementById("no").addEventListener("click", () => {
    // Nothing is posted and nothing is stored. A decline is indistinguishable
    // from never having opened this page.
    say("Nothing was recorded. You can close this page.");
  });

  document.getElementById("sign").addEventListener("click", async () => {
    try {
      const { signCeremony } = await import(ceremonyModuleUrl);
      // The key is made inside signCeremony, on this device, and only the
      // signatures come back out.
      const result = await signCeremony(read("request"), read("subject"));
      await fetch(submitUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(result),
      });
      say("Signed. You can close this page.");
    } catch {
      say("That did not go through. Nothing was recorded — you can close this page.");
    }
  });
</script>
</html>`;
}
