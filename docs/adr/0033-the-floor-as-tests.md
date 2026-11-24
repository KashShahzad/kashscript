# ADR-0033: The floor is a test package — a scanner and a small runtime driven by a manifest each repository keeps, every failure naming the decision it enforces

- **Status:** Accepted
- **Date:** 2026-11-24
- **Decision drivers:**
  - the floor as the log writes it: ECOSYSTEM d41 (presentation, never lookup; never built), d43 (no personal counts or rankings; every predicate names its rule version), d49 (a decline leaves no trace), d50 as amended by d96 (one fixed price on an accepted outcome; never per record, never a percentage), d84 P3–P4 and (c), d85(b) (the twelve floor rules), d91(h) (the forbidden gateways, absent rather than unused) and d97(i) (*k* = 5);
  - the prompt RW-17 (REAL-WORLD-SESSIONS-2026-11-09) and its status note of 2026-11-12, whose plan the founder approved on 2026-11-24;
  - Indusland's `scripts/check-desk.ts`, the precedent: a syntax scan that runs its own self-test.

## Context

The floor is prose, and five repositories enforce fragments of it, each its own way:
- Indusland's desk check and its RLS audit;
- the desk's route guards;
- Indorania's constitution checkers.

Nothing checks the whole floor across the five. Nothing ties a route, a count or a price field to the decision it must keep. A new route, a score column or a per-check fee can arrive without anyone reading the decisions it touches. The forbidden gateways of d91(h) must be *absent*, and that can be shown only by an inventory of everything that is mounted.

## Decision

We publish `@kashscript/floor` (Apache-2.0) from the open protocol's repository. RW-18 runs it in the five CIs.

1. **A manifest each repository keeps** (`floor.manifest.json`) declares:
   - every mounted route with its subject (`person`, `organisation`, `mandate`, `record`, `rule`, `place`, `public`) and shape (`one`, `list`, `search`, `lookup`, `aggregate`, `action`, `self`, `presented`, `export`, `push`, `closed`);
   - every exported aggregate and every classified count;
   - every price field, by kind;
   - where the schemas and sources are;
   - its waivers.
2. **Oracles make the inventory complete.** They read what is mounted from the code or the boot log, and the manifest must answer for each route:
   - **boot-log**, the engine's `mountedRoutes().list` printed on its boot line in CI. A git-tracked log is refused.
   - **next-app**: route handlers, pages, metadata routes and server actions.
   - **supabase**: edge functions, and the tables, views and functions PostgREST serves, found closed when row-level security or a revoke shuts every client out.
   - **ts-table**: tool and route tables.
3. **Seven rules, each citing its decisions in every failure:**
   - `person-lookup`
   - `person-score`
   - `price-per-record`
   - `declined-state`
   - `unsuppressed-count`
   - `decision-without-rule`
   - `undeclared-route`

   A declared person lookup, a push, an export beyond the organisation's own book, a counterfeit `suppress` and an undeclared route cannot be waived. Other findings can be, by a waiver naming its reason and a decision of the log. A waiver that cites only its own rule's decisions is refused, as is one that matches nothing.
4. **Counts are checked by type.** `suppress` makes a branded `FloorCount`. A declared aggregate's return type, followed through relative imports, may carry no raw `number` unless the manifest says why. Casts to `FloorCount` are refused. The repository's own `tsc` then forces `suppress` wherever a count is built. SQL counts pass `floor_suppress`, shipped with the package.
5. **The scanner reads syntax only** (the TypeScript parser, small readers for Prisma and Postgres DDL, JSON Schema and the lexicons DSL). It never runs the type checker or the code, and it proves itself on every run with a self-test.
6. **The runtime is the display half of the founder's ruling of 2026-11-20** (noise first, then *k* = 5): `suppress` and `suppressSeries`, with a total `"withheld"` when subtraction would expose a part. The noise is KS-Q7's.

## Consequences

### Positive

- One check for the floor, the same in five repositories. Each finding says which decision it keeps, so a waiver is a reading of the log, made in the open and printed on every run.
- An undeclared route fails the build, so the forbidden gateways' absence is checked, not assumed.
- Counts become typed: a raw count cannot leave through a declared aggregate without the repository's own compiler objecting.
- The dist loads under plain Node, so the Node-based CIs run it; the root entry is safe to import in server code.

### Negative / accepted trade-offs

- A manifest can lie about a subject or a shape. The cross-checks narrow the room (path nouns, person identifiers in queries and paths, row policies, schemas, types) but cannot close it. The oracles and schemas are what the manifest cannot lie about.
- Syntax only: an `any` can reach a `FloorCount`, a price computed in a function is not read, and SQL default privileges are assumed. Each is listed in the README.
- Word lists are heuristics: false positives cost a waiver, and the self-test and fixtures pin their behaviour.
- The engine must print its route list on its boot line, and CI must write that log. Both are RW-18's.
- A brand-new package cannot take a trusted publisher before it exists on npm, so its first publish needs the founder's hand (docs/publishing.md §2a).

## Alternatives considered

- **Semgrep or ESLint rules:** they cannot read a boot log, a Prisma schema or a migration history, or compare code with a declared inventory.
- **A runtime middleware alone:** it sees only the routes that are called, and only in production; the floor must fail before a route ships.
- **Per-repository scripts like check-desk:** five dialects of one floor, drifting apart; check-desk stays the precedent for the self-test.
- **Checking counts by their names:** misses `receiptsSignedByOthers` and passes `suppress(n) ?? n`; the type check catches both.
