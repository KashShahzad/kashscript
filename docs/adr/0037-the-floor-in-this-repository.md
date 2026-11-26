# ADR-0037: This repository runs the floor as tests — every route labelled for what it is, every finding fixed or waived with the decision that allows it

- **Status:** Accepted
- **Date:** 2026-11-27
- **Decision drivers:**
  - the prompt RW-18 (REAL-WORLD-SESSIONS-2026-11-09), whose plan the founder approved on 2026-11-27;
  - [ADR-0033](0033-the-floor-as-tests.md), the package and its manifest;
  - RW-17's rulings, made at the founder's delegation (2026-11-24): a transcript's `grade` is waived, a peer
    review's `score` leaves the lexicon in a new version.

## Context

`@kashscript/floor` checks a repository against the `floor.manifest.json` it keeps. The check is only as honest as
the manifest: it reads syntax, so a route labelled as something it is not passes. A rule for the labels has to be
written down, or each new route is labelled by whatever makes the run green.

This repository serves two sites (the foundry's and Kashverse) and holds the open protocol's packages. The public
repository holds the packages alone.

## Decision

1. **Two manifests.** `floor.manifest.json` at the root of this repository covers the two sites, the lexicons and
   every source file. The public repository gets its own (`scripts/public-tree/overlay/floor.manifest.json`): it
   serves nothing. `packages/floor` keeps its own and checks itself in its suite.
2. **Routes are listed one by one.** The manifest uses no glob, pages included, so a new page or route fails the run
   until someone says what it is.
3. **A label is true, never chosen to pass.**
   - A route about a person is declared about a person.
   - An organisation's seats, keys and agents are `mandate`. The caller's own is `self`. What arrives by a link its
     holder was given is `presented`.
   - A route that takes a person's identifier, or returns people to someone they did not give themselves to, is a
     lookup. It is changed, not relabelled.
4. **A waiver cites the decision that allows the exception**, and its reason says so in plain words. Where the finding
   is the scanner reading a word wrongly, the reason begins *false positive*, the citation is the nearest true one
   (d62(b): what a check reports must be true), and the case is listed for the package's next version.
5. **What is not read is named, with why**, in `excluded` and as a `!` pattern in `sources`: the floor package (its
   own manifest), the retired registry and resolver, and the development-only reference host in `services/`.
6. **CI runs `bun run check:kash-floor`** after the install. The name is not `floor`: that is the sites' colour floor.

## What changed to pass

- `kash.education.peer-review@2.0.0` is `1.0.0` without `score` (lexicons `0.8.0-alpha.0`). `1.0.0` stays
  registered, so a record signed under it still validates (append-only, d59); its field is waived.
- The foundry site's unused route that returned any GitHub user's activity calendar, by the user's name, is removed.
  It was a lookup of a person (d41), nothing called it, and without a token it returned made-up numbers.

## Consequences

### Positive

- A new route, a score column or a price on a record fails the build with the decision it breaks.

### Negative / accepted trade-offs

- Every new page needs a line in the manifest.
- The floor reads syntax: runtime behaviour and a mislabelled subject stay a reviewer's job.
- A waiver on the scanner's mistake cites a decision that is only the nearest true one, until the scanner learns the
  case.

## Alternatives considered

- **Page globs** — fewer lines, but a person page added later would be declared by the glob and never read.
- **Dropping `peer-review@1.0.0`** — passes with no waiver, but records signed under it would stop validating.
- **Fixing the scanner first** — needs a publish by hand before any repository could be wired.

## Dated note, 2026-11-27 (later) — the two forms are gone

At the founder's delegation (*"do mine to do yourself"*): the foundry site's subscribe form and fellowship form said
they had succeeded and kept nothing (d11, d62(b)). The home tile now links to Kashverse's two feeds, and
`/portal/fellowship` says no cohort is open and opens a letter in the visitor's own mail. Both server actions and their
manifest lines are removed. The Kashverse post that records an old draft offer's per-shipment figures stays as a dated
post.
