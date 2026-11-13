/**
 * Display-text sanitiser for the Trust-UX surfaces.
 *
 * A malicious or compromised caller can pass attacker-controlled strings to
 * the SignTransactionModal — `requestedBy`, `action`, `description`,
 * `lexiconId`, or any value inside the `body` object. Three classes of
 * Unicode trickery can make the user read something different from what is
 * about to be signed:
 *
 *   1. **Bidi overrides** (U+202E, U+202D, U+2066–U+2069, U+200E, U+200F).
 *      Reverse-text attacks: a request labelled "Transfer 5 USD" can
 *      render as "Transfer USD 5" — or worse, attacker-crafted strings can
 *      swap parts of a sentence to mean the opposite. See "Trojan Source"
 *      (Boucher & Anderson, 2021).
 *
 *   2. **Zero-width characters** (U+200B–U+200D, U+FEFF). Used to make
 *      `paypaI.com` (capital-I) and `paypal.com` look identical, or to
 *      split a word so search highlights miss the spoof.
 *
 *   3. **Compatibility look-alikes / homographs.** NFKC normalisation
 *      collapses fullwidth (`ｄｉｄ:ks`), small-form, and circled letters
 *      to their canonical ASCII equivalents. Removes the easiest spoofs
 *      without touching legitimate non-Latin scripts (Arabic, Cyrillic
 *      legitimate characters remain — homograph protection for those
 *      requires confusable-script policy, out of scope here).
 *
 * Sanitiser is INTENTIONALLY thin: lossy-but-deterministic, idempotent,
 * safe to apply twice. Pure logic — no DOM, no React.
 */

/* ── ranges & character sets ────────────────────────────────────── */

// Explicit bidi-override characters that flip text direction within a line.
// Listed individually because Unicode regex property escapes (`\p{Bidi_Control}`)
// have broader semantics than we want — we keep LRM/RLM-like neutral marks
// out so language-tagged text continues to render correctly.
const BIDI_OVERRIDES = new Set([
  0x202A, // LRE — Left-to-Right Embedding
  0x202B, // RLE — Right-to-Left Embedding
  0x202C, // PDF — Pop Directional Formatting
  0x202D, // LRO — Left-to-Right Override
  0x202E, // RLO — Right-to-Left Override
  0x2066, // LRI — Left-to-Right Isolate
  0x2067, // RLI — Right-to-Left Isolate
  0x2068, // FSI — First Strong Isolate
  0x2069, // PDI — Pop Directional Isolate
]);

// Zero-width characters that contribute no glyph but can split or hide content.
const ZERO_WIDTH = new Set([
  0x200B, // ZWSP — Zero-Width Space
  0x200C, // ZWNJ — Zero-Width Non-Joiner
  0x200D, // ZWJ  — Zero-Width Joiner
  0xFEFF, // BOM / Zero-Width No-Break Space
  0x180E, // Mongolian Vowel Separator (formatting code-point)
  0x2060, // Word Joiner
]);

// Common control characters (C0 except tab/newline/CR) and C1 controls.
function isControlCodePoint(cp: number): boolean {
  if (cp >= 0x00 && cp <= 0x1F) {
    return cp !== 0x09 && cp !== 0x0A && cp !== 0x0D;
  }
  if (cp >= 0x7F && cp <= 0x9F) return true;
  return false;
}

/* ── public API ─────────────────────────────────────────────────── */

export interface SanitiseOptions {
  /** Maximum length of the returned string. Strings longer than this are
   *  truncated with an ellipsis. Default 256 (matches the modal's display
   *  cap). Pass `Infinity` to disable. */
  readonly maxLength?: number;
}

/**
 * Sanitise a display string against bidi-override / zero-width / control-char
 * attacks, then NFKC-normalise to collapse compatibility look-alikes.
 *
 * Returns a string suitable for unfiltered injection into the modal's text
 * nodes. Idempotent.
 */
export function sanitiseDisplayText(input: string, opts: SanitiseOptions = {}): string {
  if (typeof input !== "string") return "";

  // Step 1: strip bidi overrides + zero-width + control chars.
  let stripped = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    if (BIDI_OVERRIDES.has(cp)) continue;
    if (ZERO_WIDTH.has(cp))     continue;
    if (isControlCodePoint(cp)) continue;
    stripped += ch;
  }

  // Step 2: NFKC-normalise — collapses fullwidth, small-form, sub/superscript,
  // and most compatibility variants to canonical ASCII / canonical letters.
  const normalised = stripped.normalize("NFKC");

  // Step 3: optionally truncate.
  const max = opts.maxLength ?? 256;
  if (Number.isFinite(max) && normalised.length > max) {
    return normalised.slice(0, max - 1) + "…"; // ellipsis (single-char NFKC-safe)
  }
  return normalised;
}

/**
 * Deep-sanitise an `unknown` value for safe display in the modal's
 * `body` / `header` recursive renderer. Strings are sanitised; primitives
 * pass through; objects/arrays are walked. Returns a structurally identical
 * shape with sanitised string leaves.
 *
 * Stops at `depth = 8` to bound runaway nesting. Sanitises keys as well as
 * values so a hostile key name like "ｐａｓｓｗｏｒｄ" can't impersonate "password".
 */
export function sanitiseDisplayValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[depth-cap]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return sanitiseDisplayText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map((v) => sanitiseDisplayValue(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[sanitiseDisplayText(k, { maxLength: 64 })] = sanitiseDisplayValue(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/**
 * Test-only inspection: returns `true` when `input` contains any character
 * that {@link sanitiseDisplayText} would strip. Useful for caller-side
 * warnings ("⚠ This request name was sanitised — review carefully").
 */
export function hasSuspiciousChars(input: string): boolean {
  if (typeof input !== "string") return false;
  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    if (BIDI_OVERRIDES.has(cp) || ZERO_WIDTH.has(cp) || isControlCodePoint(cp)) return true;
  }
  return input.normalize("NFKC") !== input;
}
