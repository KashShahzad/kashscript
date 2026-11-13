# FEEL, the subset a rule's conditions are written in

**`specs/feel-subset.md` — v1 · 2026-10-28 · KS-Q1 · `@kashscript/predicate/feel` (Apache-2.0).**
From OMG's *Decision Model and Notation* 1.5, chapter 10 (FEEL) · used by [rule.md](rule.md) · tested against the [DMN TCK](https://github.com/dmn-tck/tck) (Apache-2.0) · [ADR-0021](../docs/adr/0021-rule-and-decision.md).

## 0. What it is

A criterion's condition is **one FEEL literal expression** — DMN's smallest executable unit — whose answer is a yes or a no. There are no decision tables, no decision requirements graph and no DMN XML.

The subset holds what a door needs — **counts, dates, sums and thresholds** — and nothing that can loop without end, define a function, or read a clock.

**A subset, never a dialect.** An expression this parser accepts is FEEL that any DMN engine — Camunda, Drools, feelin — evaluates the same way. What the subset does not hold is **refused by name**, never guessed at. The TCK test proves it at the pinned commit: every case either passes or is refused, and none is answered wrongly (§5).

## 1. Values

| Type | In the subset |
|---|---|
| number | **exact decimals** (decimal128: 34 significant digits, rounding half to even) — so `0.1 + 0.2 = 0.3`, and sums of money never drift; division by zero is null |
| string | with FEEL's escapes |
| boolean, null | three-valued logic, as FEEL defines it |
| date | `date("2026-10-28")`, `@"2026-10-28"`, `date(y, m, d)`, `date(<date and time>)` |
| date and time | **with an offset or `Z` only** — `date and time("2026-10-28T09:00:00Z")`, `@"…"`. Local date-times and zone ids are refused: without them every platform agrees, with no time-zone database |
| days and time duration · years and months duration | `duration("P28D")`, `duration("P24M")`, `@"P1Y"`, `years and months duration(from, to)` |
| list, context | lists of values; contexts come only from the input (each receipt is a context of its claims) |

## 2. Expressions

| In the subset | |
|---|---|
| literals, names (identifiers), `asOf`, a rule's parameters | `count(receipts) >= minProjects` |
| paths, also over lists | `receipts.issuer`, `p.skills`, `d.year` |
| filters, and a numeric index | `receipts[acceptedAt >= asOf - window]`, `xs[1]`, `xs[-1]` |
| `+ - * /` | numbers; string `+` string; date ± duration (month arithmetic clamps to the month's end: 2026-03-31 − P1M = 2026-02-28); date − date; duration × number (a year-month duration is truncated toward zero) |
| `= != < <= > >=` | values of one type; FEEL's null for anything else |
| `and`, `or`, `not(…)` | three-valued |
| `between … and …`, `in` | `level in ("B2", "C1", "C2")`, `x in [1..5)`, `x in (< 5, > 10)` |
| `some … in … satisfies …`, `every … in … satisfies …` | also as an operand: `a and some p in l satisfies b` |
| builtins | `not`, `count`, `sum`, `min`, `max`, `list contains`, `distinct values`, `date`, `date and time`, `duration`, `years and months duration` — positional or named arguments |

**Refused, each by name:**
- `for` and `if`;
- function definitions and calls to anything not listed above (`mean`, `string length`, `abs`, …);
- `instance of`, context literals, ranges as values, `**`, number exponents, comments;
- the `time` type, zone ids and local date-times;
- names with spaces;
- **`now()` and `today()`** — they read a clock. A rule reads `asOf`, which every caller passes.

## 3. The static check — `checkFeel(src, names)`

Before a rule validates, each condition is checked for five things:
1. **It parses inside the subset.**
2. **Every name is bound** — the criterion's claim ids (inside a filter or a quantifier), `issuer`, the rule's parameters and `asOf`.
3. **Its answer is a yes or a no.** A number is refused, so a condition can never be a score.
4. **Obvious type errors are caught** — comparing a date with a date and time is always null, and the check says to write `date(asOf)`.
5. **Its size:** at most 2 KiB, nested at most 32 deep.

It reports the names and claim fields the condition reads; a rule uses them to require those claims in every disclosure option, and to know which thresholds are sealed.

## 4. Evaluation

**Pure.**
- No clock, network, randomness or global state.
- Every loop runs over a finite list the input supplied.
- A step budget (100,000 by default) ends a pathological condition. A stranger's rule therefore always finishes — with an answer, or with null.

**Only `true` is met**, as a DMN decision table fires a rule only when its conditions are true. A null — FEEL's `sum([])`, or a claim that did not read as its declared type — is not met. Only a condition the budget stopped is *unread*, and it goes to a person.

**Typed input.** A claim becomes a FEEL value only as the rule declares — DMN's itemDefinition:
- `fromJson("2026-10-28", "date")` is a date;
- `fromJson(0.1, "number")` is the decimal `0.1`, never its binary expansion;
- a value that does not read as its type is null, never coerced.

## 5. The TCK — what it claims

`scripts/tck-extract.ts` reads a checkout of `dmn-tck/tck` at commit **`1e349176e5ae689d924a2a2c7a8df25c220d8b07`** as data. It takes every literal-expression decision that reads only input data, in sixteen folders of `TestCases/compliance-level-3/`:
- `0001-filter`, `0012-list-functions`, `0016-some-every`;
- `0064`–`0066` (and, or, not), `0068-feel-equality`, `0071-feel-between`, `0072-feel-in`, `0090-feel-paths`;
- `0099-arithmetic-negation`, `0100-arithmetic`;
- `1115`, `1117`, `1120`, `1121` (date, date and time, duration, years and months duration).

The output is `test/tck/cases.json` — **1,873 cases**, with a NOTICE.

`test/tck/run.ts` sorts every case:

| | Cases |
|---|---|
| **pass** — accepted, and answered as the TCK expects | **867** |
| **refused** — FEEL the subset does not hold, refused by name | **1,006** |
| **wrong** — accepted and answered differently | **0** |

The refusals by reason:
- **252** a local or zoned date-time;
- **164** `time`;
- **162** `**`;
- **136** context literals;
- **96** ranges as values;
- **94** builtins outside the list;
- **81** function definitions;
- **8** unary-test ranges;
- the rest, builtin forms outside the subset.

The bun test fails if any case is wrong, or if the passing count falls below 867.

## 6. Size

Browser bundle, minified, measured by `test/browser.test.ts`:
- **`/feel` alone:** 36.2 KiB (11.9 KiB gzipped);
- **the whole `@kashscript/predicate`**, with attest's SD-JWT, DSSE and held-record verification inside: 163.4 KiB (54.6 KiB gzipped).

## 7. Changelog

| Version | Date | |
|---|---|---|
| **v1** | 2026-10-28 | KS-Q1. The subset, its static check and evaluator; 867 TCK cases claimed, 1,006 refused, none wrong. Beyond the KS-Q1 plan, and still FEEL: `@"…"` literals (dates, date-times, durations) and string concatenation, so a value FEEL gives is never answered null here. |
