/**
 * scripts/confirm-landing.ts — did the registry show what publish-to-npmjs.ts just published?
 *
 * Kept out of publish-to-npmjs.ts (which runs `main()` on import) so it can be tested against a
 * fake registry. Three rules, each learned from a real publish on 2026-10-06:
 *
 *   1. Read the EXACT version (`name@version`) and the dist-tag it was published under. Never read
 *      back the bare package: an alpha publish leaves `latest` where it was, so `npm view name version`
 *      keeps answering the OLD version, and the check could never succeed.
 *   2. The registry is eventually consistent. A version answered E404 for about two minutes after
 *      `npm publish` had succeeded, so the window is minutes, not seconds.
 *   3. Check after every publish has gone out, not between them, so a slow registry delays no later
 *      publish — and say plainly when a publish is not yet visible, rather than reporting a stale
 *      version as the result.
 */

export interface LandingTarget {
  /** Scoped name, e.g. `@kashscript/attest`. */
  readonly name: string;
  readonly version: string;
  /** The dist-tag the version was published under: `alpha` for a prerelease, else `latest`. */
  readonly tag: string;
}

export interface LandingOptions {
  /** `npm view <spec> <field>`, trimmed; empty when the registry has no such thing yet. */
  readonly view: (spec: string, field: string) => string;
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => number;
  readonly deadlineMs: number;
  readonly intervalMs: number;
}

export interface LandingResult {
  readonly target: LandingTarget;
  /** True only when the exact version is visible, the tag points at it, and `main` is under `./dist/`. */
  readonly landed: boolean;
  /** The version's `main` as the registry reports it; empty when not landed. */
  readonly main: string;
}

export async function confirmLanding(targets: readonly LandingTarget[], opts: LandingOptions): Promise<LandingResult[]> {
  const started = opts.now();
  const landedMain = new Map<LandingTarget, string>();
  for (;;) {
    for (const t of targets) {
      if (landedMain.has(t)) continue;
      const exact = `${t.name}@${t.version}`;
      const version = opts.view(exact, "version");
      const tagged = opts.view(t.name, `dist-tags.${t.tag}`);
      const main = opts.view(exact, "main");
      if (version === t.version && tagged === t.version && main.startsWith("./dist/")) landedMain.set(t, main);
    }
    if (landedMain.size === targets.length || opts.now() - started >= opts.deadlineMs) break;
    await opts.sleep(opts.intervalMs);
  }
  return targets.map((target) => ({ target, landed: landedMain.has(target), main: landedMain.get(target) ?? "" }));
}
