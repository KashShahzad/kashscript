# ADR-0021: A door's rule is DCQL queries plus FEEL conditions, evaluated by our own FEEL subset; the decision comes back as an SD-JWT VC; routing can say yes or not yet, never no

- **Status:** Accepted (KS-Q1 plan approved by the founder, 2026-10-28)
- **Date:** 2026-10-28
- **Decision drivers:** ECOSYSTEM d84(a) (rule · receipt · decision · recourse · renewal; a criterion is an OpenID4VP 1.0 DCQL query plus a DMN condition, checked on the person's side first; node rules 10 and 11); d84(f) P3 (a rule may say yes or not yet; only a person says no) and P4 (a rule asks only for its purpose); d71 (no format of our own); d27, d43, d62(d)2–3; d59 (`predicate` is the wallet's rule engine)

## Context

Receipts existed: attest, the wallet, Oreoasis's approvals, Duedale's confirmations. What every door, desk and engine still needed was **one format for what a door decides and what counts**, and **one for the decision that comes back**. OA-Q3, OA-N2, IN-N1, IN-Q2, DD-Q1, KS-Q3 and KS-N1 all cite them. Six constraints shaped them:

1. **d71:** no format of our own where an open one fits.
2. **d84(a):** the criterion's query is OpenID4VP's DCQL, and its condition is DMN's.
3. The person's side checks first — in a browser now, on a phone later. The evaluator must be pure, deterministic and small, and evaluating a stranger's rule must always end.
4. **P3:** software applies only fixed rules people wrote; it may grant or say *not yet*; it never refuses, binds or touches sensitive data.
5. **P4's second rule and node rule 10** must be refused at validation, not left to review.
6. **d62(d)3:** two viewers never receive the same holder key.

## Decision

**The rule** is `kash.rule@1.0.0`, a closed lexicon:
- signed by its author as a **DSSE** envelope (`application/vnd.kash.rule+json`), the trust lists' shape;
- each criterion is a DCQL credential query, verbatim, plus one FEEL expression and a DMN type for each claim it reads;
- the rule's whole `dcql_query` is derived from it, one required credential set per criterion.

**Two extensions, each in a point the spec leaves open:**
- the `kash-artifact` format — the holder contract's existing OID4VCI profile — gains `meta.dst_values`, `attestation` and `holder_path`, and a binding JWS (`kash-artifact-kb+jwt`);
- `trusted_authorities` gains `kash_issuer` and `kash_trust_list`.

**The person's own word** is a self-issued SD-JWT VC (`https://kashscript.com/vct/own-word/1`) under a fresh key per viewer, so the packet is one standard `vp_token`.

**The condition language is a FEEL subset of our own, not a dependency.** It is zero-dependency, about 1,400 lines, with exact decimal arithmetic and no clock (`asOf` is passed in; `now()` and `today()` are refused). It has no `for`, no `if`, no user functions, and a step budget. It is a subset, not a dialect: what it does not hold it refuses by name. The TCK test proves subset-or-refuse at commit `1e34917` — 867 cases claimed, 1,006 refused, none wrong.

**Validation refuses the floor's breaches** by a token vocabulary and structural checks:
- an ask for a refusal, including a condition met by showing nothing;
- an art. 9 category, an ascribed identity, a score;
- a criterion without a purpose, a person's identity;
- an automatic yes that binds;
- a condition that is a number.

Known proxies raise warnings the author must answer in writing, signed with the rule.

**The decision** is `kash.decision@1.0.0`, issued by the deciding organisation as an **SD-JWT VC** (`https://kashscript.com/vct/decision/1`) to the person's key for that desk:
- visible: the rule, the outcome, `automatic`; disclosable: the rest;
- receipts appear as hashes only;
- a person's decision carries their seat's detached signature.

**Routing** returns `automatic-yes`, `not-yet` or `to-a-person` — no refusal in the type. Validation refuses an automatic `no` or `partial`, an automatic `yes` on a rule that binds or is sensitive, and a refusal that names no unmet criterion or no confirmation the receipts were read.

**The wallet** checks a door's rule first and sends only on the person's yes, in copies. Its receive now asks for per-viewer copies of every SD-JWT a door may read — not only predicates — and a thank-you stays bound to its place.

## Consequences

### Positive

- Every door, desk and engine reads one rule and one decision.
- A rule is auditable by anyone: its queries are public even when it is private, and only its thresholds are sealed by commitments the desk must open.
- A checklist on the person's side and the desk's routing can never disagree: they call one evaluator.
- The floor's breaches are refused before signing, with a code and plain words.
- The person keeps every decision, and can show only *yes, under rule X v3* at the next door.

### Negative / accepted trade-offs

- **Counting SD-JWT receipts requires each one's record id.** Unlinkable copies would otherwise count twice, so two viewers who see the same record ids can link them. An issuer's predicate avoids it.
- **A countersigned `kash-artifact` cannot be re-keyed**, so two viewers who see the same one can link its holder — said in the view, and sent only on the person's choice (d62(d)3, until tier two).
- **The vocabulary catches what is named and obvious.** A hidden proxy passes it; P5's look and P4.7 are the rest of the defence. A product's *country of origin* is refused today.
- **Our own evaluator is our own code to keep right.** The TCK cases and the subset-or-refuse test are the guard.
- **An automatic *not yet* on a binding rule** follows P3's text; flagged for the founder.

## Alternatives considered

- **feelin (MIT, bpmn-io) as the evaluator** — lost: it brings `@lezer/lr`, `lezer-feel` and `luxon` into a kernel package that runs on phones (P6's supply-chain line); it reads a clock; it allows user functions and `for`; it is larger; and its full FEEL is more than a rule needs.
- **DMN decision tables or full DMN XML** — lost: a criterion's outcome is one yes or no; a literal expression is the smallest DMN unit that does it.
- **A Kash-Event for the rule** — lost to DSSE: the trust lists already publish public organisation records as DSSE, and the lexicon's envelope header needs a CID the evaluator would have to compute.
- **A DSSE envelope for the decision** — lost to SD-JWT VC: the decision must be presentable at the next door through DCQL, in copies, with its details selectively disclosable.
- **Raising proxies as refusals** — lost to warnings answered in writing: whether a postcode stands in for an ascribed identity depends on the door, as KS-Q1 asked.

## Dated note — 2026-10-29 (KS-Q1b, ECOSYSTEM d85(l))

d85 accepted KS-Q1 and asked for four additions; KS-Q1b builds them, under the founder's approved plan. The decision above stands; what changes:

- **The rule's address — `kash.rule@1.1.0`** (d85(c)): sector (ISIC Revision 5, a section or division, the revision named), anchor family, authority, journey and the seven givens, each in plain words with optional machine fields; places as references, never coordinates (d60). An addressed rule missing a given publishes only as a draft, and a draft is never decided under (d85(b) rule 7). **1.0.0 rules still validate**, with a `NO_ADDRESS` warning — frozen vectors of KS-Q1's four rules prove it.
- **Bounds and adoption** (d85(b) rule 8): a public rule's parameter may state bounds; `kash.adoption@1.0.0` is an anchor's signed record that it runs a rule with its own values within them. The checklist, the routing and the decision read it; an automatic outcome under it is the anchor's standing decision, issued by the anchor (d85(d)). See [specs/adoption.md](../../specs/adoption.md).
- **A vocabulary that knows its subject:** each criterion names `person`, `organisation`, `product` or `place`. Rule 1 binds when the subject is a person or an organisation's people, so **a product's country of origin is allowed** (the *Negative* line above is resolved), and **a person's nationality moves from a warning to a refusal**.
- **The decision's schema moves** from `@kashscript/lexicons` to `@kashscript/predicate` as `kash.decision@1.1.0`, with an optional `adoption`: d59 makes lexicons the home of public, organisation-authored records, and a decision is the person's own. `PERSONAL_LEXICONS` is gone (lexicons `0.3.0-alpha.0`, breaking, in alpha).
- **An automatic *not yet* is allowed on every rule** (d85(e)): the flag in *Negative* above is settled as built; a test runs it on the income rule, which binds.

Flagged, unchanged: d85(b)'s *"sensitive categories may be read only where a rule's purpose needs them"* against P4.2's *never* — the refusal for persons is kept; and *"an obvious stand-in"* — proxies stay warnings answered in writing, now for persons (and an organisation's people) only.
