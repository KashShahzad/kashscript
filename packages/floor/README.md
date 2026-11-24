# @kashscript/floor

The floor as tests. A scanner and a small runtime that check a repository against the `floor.manifest.json` it keeps. The manifest lists every mounted route with its subject and shape, every exported aggregate, every price field, and where the schemas and sources are. The run fails when the code breaks one of seven rules. Each failure names the decisions of the ecosystem's log that it enforces.

Apache-2.0. It runs under Node 20 or later and under Bun, and its scanner needs `typescript` 5 or 6, an optional peer dependency. Design and trade-offs: [ADR-0033](../../docs/adr/0033-the-floor-as-tests.md).

## Run it

```bash
kash-floor check                      # reads ./floor.manifest.json; exit 0 holds, 1 findings, 2 usage
kash-floor check --boot-log boot.log  # the engine's boot line, written in CI (a git-tracked log is refused)
kash-floor check --json               # the report as JSON
kash-floor routes --draft             # every mounted route not yet in the manifest, as entries to fill in
```

In CI, add one step after the install, for example `npx kash-floor check --boot-log "$RUNNER_TEMP/boot.log"`. Every run first runs the detector's own self-test, so a TypeScript or parser change that silences a rule fails the run instead of passing it.

**The manifest does not choose what the floor sees.** The floor looks for itself:
- every Next `app/` and Pages `pages/` folder;
- every Supabase project;
- every Cloudflare Worker (`wrangler.toml`);
- every Prisma schema, migration and lexicon;
- every TypeScript and JavaScript file outside tests.

Each must be covered by the manifest, or listed in `excluded` with why. A repository with no oracle must say `"serves": "none"`.

## The rules

| Rule | Fails when | Decisions |
|---|---|---|
| `person-lookup` | a route about a `person` is shaped `one`, `list`, `search` or `lookup`; any `lookup`; any `push`; an `export` not to the organisation's own book; a person's identifier (an email, a phone, a `holderDid`…) in a query, or in the path of a `self` or `presented` route; a `self` table whose row policy does not key rows to `auth.uid()`. **None of these can be waived.** A path naming persons (`/members`) declared as another subject can be waived, with the reason | d41 (presentation, never lookup), d85(b)2, d91(h), d84 P4.3 |
| `person-score` | a field shaped as a score, rank, rating, stars, average, percentile, streak, badge, standing, risk, trust or grade, or as a count or total, on a person: a person's model, a row keyed to a person through its subject column (not the actor's, such as `created_by`), or a lexicon object about a person. Prisma, SQL and lexicons (JSON Schema and the lexicons DSL) are read. A signing grade is not a score (d91) | d27, d41, d42, d43, d85(b)3, the standard §7 |
| `price-per-record` | a price for issuing, holding, presenting, checking, asking or declining, or on a record, receipt, confirmation, session or voucher; any percentage, bps, commission, take rate, markup or margin; a field of a price file the manifest does not name; two outcome prices or two allowances in one object (siblings named for entrances or currencies are one price by band); an outcome price in a list; a price literal or a price figure in copy outside the price files | d50, d84(c) as read by d96(b), d96(a), d96(d) |
| `declined-state` | a person's decline (*declined*, *refused*, *rejected*, *opted out*) kept on, or returned for, an ask, approval, request, invite, consent, confirmation or acceptance; a refusal (*no*, *partial*) or a no-show in a `list`, `search` or `export`; a query that filters on an outcome. A desk's *no* on a decision that names its rule version is allowed (d84 P3), and an organisation declining is not in scope | d49(a), d91(h), d41, d85(b)3, the standard §2.7 |
| `unsuppressed-count` | a declared aggregate whose return type carries a raw `number` (or `any`, `unknown`, an unseen type) where a `FloorCount` belongs, unless the manifest's `raw` says why; a `suppress` that is not this package's (a copy, a renaming that leads elsewhere, a shadowing local); a *k* that is not a literal of at least 5 or `FLOOR_K`; a cast to `FloorCount`; an alias of this package; a SQL aggregate with a count outside `floor_suppress(…)`; a count computed (`.count()`, `_count`, `count(*)` in SQL…) that is neither in a declared aggregate nor classified in `counts` | d97(i), d85(b)11, d91(f) |
| `decision-without-rule` | a decision (by its name, by an outcome, verdict or classification field, or as declared) without a non-null rule version; a decision lexicon that does not require `rule.version` | d43, d84 node rule 11 and P3, d85(b)5, d85(b)7 |
| `undeclared-route` | a route an oracle sees that the manifest does not declare; a declared route no oracle sees, unless `outsideOracle` says why; an oracle that cannot be read; a boot log tracked by git, or whose list disagrees with its count | d91(h): the forbidden gateways are absent, which only a complete inventory shows |

Since the fresh-session review (2026-11-24), these also fail:
- **Person lookups:** a person's identifier in any route's path or an RPC's arguments; an RPC that returns rows of persons on a route not declared about a person; a row policy that checks only that someone is signed in; a per-person aggregate.
- **Refusals:** a *rejected* or *refused* kept on a person's row outside a decision that names its rule version.
- **Counts:** Supabase's `count:` option, a cast to `any` or `unknown` inside a declared aggregate, `avg` and `cardinality` in SQL, counter columns on a served table, and a copy of `floor_suppress` that is not the shipped one.

## The manifest

```jsonc
{
  "floor": 1,
  "repository": "my-engine",
  "oracles": [
    { "kind": "boot-log" },                                     // the log comes from --boot-log
    { "kind": "next-app", "app": "apps/web/app", "host": "web" },
    { "kind": "supabase", "dir": "supabase", "schemas": ["public"] },
    { "kind": "ts-table", "file": "src/mcp.ts", "export": "TOOLS", "key": "name" }
  ],
  "routes": {
    "GET /api/v1/me": { "subject": "person", "shape": "self" },
    "GET /api/v1/north-star": { "subject": "organisation", "shape": "aggregate", "aggregates": ["north-star"] },
    "PAGE web:/**": { "subject": "public", "shape": "one" },
    "GET /api/streams/events": { "subject": "record", "shape": "self", "outsideOracle": "a WebSocket upgrade, outside the route table" }
  },
  "aggregates": {
    "north-star": { "file": "src/north-star.ts", "export": "orgWeeks", "raw": { "[].receiptsSignedByOthers": "the organisation's own receipts" } },
    "region": { "sql": "region_proof_stats" }
  },
  "counts": { "src/billing/meter.ts#monthCount": { "kind": "own", "why": "an organisation's own outcomes, on its bill" } },
  "serves": "none",                                              // only when there is no oracle at all
  "excluded": { "scripts/**": "local tools, never deployed" },
  "schemas": { "prisma": ["prisma/schema.prisma"], "sql": ["supabase/migrations/*.sql"], "lexicons": ["specs/*.schema.json"],
               "persons": [], "decisions": { "ExceptionClassification": "sopVersion" } },
  "sources": ["src/**/*.ts", "!src/older/**"],
  "prices": { "files": ["src/prices.ts"], "entrances": ["link", "api"],
              "fields": { "**.price": "outcome", "**.freeEachMonth": "allowance", "**.plans.*": "flat", "**.kind": "structure" } },
  "waivers": [ { "rule": "price-per-record", "at": "price-source:src/commission.ts#COMMISSION_RATE_BPS",
                 "reason": "the marketplace's commission on the bookings it brings", "decision": "d63(a), d84(c), d96(b)" } ]
}
```

**Route keys** are written `METHOD [host:]/path`.
- METHOD is GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS or ANY.
- Further keys: `PAGE`, `ACTION file#name`, `TOOL name`, `REST /rest/v1/table`, `RPC /rest/v1/rpc/fn` and `WS`.
- Parameters compare equal whatever they are called: `:id`, `[id]` and `{id}` match.
- `*` matches one segment and `**` any number. The most specific key wins.
- A glob may cover pages, or API routes under a literal prefix of two segments (`GET /api/v1/*`). It may never cover every route, tool or action, because a catch-all key declares nothing.

**Subjects:**
- `person`
- `organisation`
- `mandate` (seats, keys, agents: an organisation's grants)
- `record`
- `rule`
- `place`
- `public`

**Shapes:**
- `one`
- `list`
- `search`
- `lookup`
- `aggregate` (with `aggregates`)
- `action`
- `self`
- `presented`
- `export` (with `to: "own-book"`)
- `push`
- `closed` (with `why`)

A draft's `?` is never an answer.

**An exported count** is one shown to someone who cannot see each record behind it, one by one. An organisation's counts of its own records are not exported counts, but they are classified in `counts` with their reason. Every raw number in an aggregate's type carries its reason in `raw`.

**Price kinds:**
- `flat`
- `band`
- `outcome` (the fixed price of an accepted outcome)
- `allowance` (the outcomes free each month)
- `structure` (a field that holds no price)

Paths use `.`, with `[]` for list items. Every export of a price file is walked, and every leaf must be named.

**Waivers** carry a `reason` and a `decision` citing the log (`d63(a)`). Each waiver names one finding exactly, with no glob, and count keys likewise name one site. Some findings require a particular decision: a percentage is waived only citing d63(a), and a refusal in a list only citing d84 P3. A waiver is refused when:
- it matches no finding;
- it cites only the decisions its own rule enforces;
- the finding cannot be waived.

Waived findings are always printed. Findings are keyed by what they are about, never by a line number.

## The runtime

```ts
import { suppress, suppressSeries, FLOOR_K, type FloorCount, type FloorTotal } from "@kashscript/floor";

suppress(12);                       // 12
suppress(3);                        // null — the display says "fewer than 5"
suppressSeries([7, 3, 9]).total;    // "withheld" — 19 less the shown 16 would give the 3 away
```

- `suppress(n, k = 5)` returns a `FloorCount`, a branded number or `null`. It throws on a *k* below 5.
- **Only `suppress` makes a `FloorCount`**, so an aggregate typed with it cannot carry a raw count past the repository's own type check.
- `suppressSeries(cells, { total? })` suppresses a whole and its parts together. Its total is `"withheld"` whenever a hidden part leaves a remainder above zero: several hidden cells, each known to be below *k*, can be solved from their sum. It never shows as *fewer than k*.
- It is for a host's own display. The audit publishes no series until its privacy bound is designed (d97(i), d95(d)).
- The root entry loads no compiler and touches no file. The scanner is `@kashscript/floor/check`.

**For a count computed in SQL,** copy [`sql/floor_suppress.sql`](sql/floor_suppress.sql) into a migration and wrap every count you serve: `floor_suppress(count(*))`.

**This is the display half of the founder's ruling of 2026-11-20:** noise first, then *k* = 5 as display. The noise and its ε belong to KS-Q7 and are not built. Suppressing raw counts still leaks by differencing across time and overlapping windows (`specs/attestation/README.md` §3.3).

## What it cannot see

- **Runtime behaviour, and the type checker's verdict.** It reads syntax: a value typed `any` can reach a `FloorCount`, and the repository's own `tsc` must run.
- **SQL privileges beyond what the migrations say.** Default privileges are not read, and Supabase's defaults are assumed.
- **Function bodies declared `self`.**
- **Values held only in the environment,** although their types are read.
- **Prices computed inside functions.**
- **States held only in TypeScript** and not declared in a route's `states`.
- **Routes no oracle sees.**
- **A manifest that lies about a subject or a shape,** beyond the path, query, policy, schema and type cross-checks.
