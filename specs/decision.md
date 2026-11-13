# The decision receipt, and the routing

**`specs/decision.md` — v2 · 2026-10-29 · KS-Q1b · `kash.decision@1.1.0` (`@kashscript/predicate/decision`, its home since KS-Q1b), built and checked by `@kashscript/predicate` (Apache-2.0).**
Decisions: ECOSYSTEM d27, d41, d43, d49, d59, d62(d)2–3, d84 (a; f: P3, P4), d85 (d, e, l) · companions: [rule.md](rule.md) · [adoption.md](adoption.md) · schema: [`schemas/decision.schema.json`](schemas/decision.schema.json), generated from predicate · [ADR-0021](../docs/adr/0021-rule-and-decision.md).

> **What exists, and what does not.** v1 was built with tests and **published under `alpha` on 2026-10-28** (`@kashscript/predicate` `0.1.0-alpha.0`) `[v 10-28, npm view]`. v2 (KS-Q1b) was **published under `alpha` on 2026-10-28 (21:19 UTC)** (`@kashscript/predicate` `0.2.0-alpha.0`) `[v 10-29, npm view]`. No desk has decided anything for a person. IN-Q2 builds the Decision Desk on this; OA-Q3 records the first decision.

## 1. The receipt

**Every decision is itself a receipt the person keeps, naming the rule's version and its reasons** (d84(a); node rule 11). One door's output is the next door's input.

| Field | Meaning |
|---|---|
| `rule` | `{id, version, hash}` — the exact rule it was made under |
| `adoption` | **1.1.0** — `{id, hash}`: the anchor's adoption the door decided under ([adoption.md](adoption.md)). Absent at the rule author's own door; a 1.0.0 decision is a 1.1.0 decision without one |
| `outcome` | `yes` · `not-yet` · `no` · `partial` |
| `reasons[]` | codes from the rule's own list, whose outcome matches. At least one |
| `rows` | `{fired, missing}` — the criteria met, and the criteria not |
| `reliedOn[]` | **SHA-256 hex of each receipt relied on — never its content.** An SD-JWT: its issuer-signed JWT. An artifact: its record id. Anything but 64 hex characters is refused |
| `decidedBy` | `{kind: "standing", standing: "standing:<decider>"}` for an automatic outcome — the decider is the rule's author, or **the anchor** under an adoption (d85(d)) — or `{kind: "person", role, seat, signature}`: the deciding seat's own key and its detached JWS (`typ: kash-decision-seat+jwt`) over the body's JCS, signature left out. The receipt names a role, never the person; the seat's key makes the decision accountable |
| `automatic` | `true` or `false` |
| `refusal` | for `no` and `partial` only: `{unmet: [criteria], receiptsRead: true}` |
| `decidedAt`, `contestUntil` | the contest window: at least the rule's |
| `practice` | — |

**The shape is closed.** It has no field for a score, a receipt's content or a person's identity, and any field it does not name is refused.

**It is never published.** It is the person's record. **Its home is `@kashscript/predicate` (KS-Q1b, d85(l)):** d59 makes `@kashscript/lexicons` the home of public, organisation-authored records, and a decision is a credential its person holds — so its shape lives with the package that issues and checks it, as attest owns the predicate credential's. It is built with the lexicons' schema DSL and never registered for publishing. lexicons `0.3.0-alpha.0` drops `KASH_DECISION_*` and `PERSONAL_LEXICONS`; muffler's guard (KS-N1) needs no exception for it, because no public lexicon names it. `specs/schemas/decision.schema.json` is generated from `KASH_DECISION_LEXICON`, and predicate's `test/schemas.test.ts` keeps it in step.

## 2. The routing — `route(rule, packetCheck, {asOf, openings?, askedForPerson?, adoption?})`

For desks to reuse (P3). **It never returns a refusal** — its type is exactly three outcomes, and a test proves it.

The `packetCheck` it reads is `checkPacket`'s ([rule.md](rule.md) §8). Since AU-3 (A7-03, A7-08) that check counts one record once whatever wraps it (`ReceiptView.contentId`), and refuses a key binding further than `freshness.maxKbAgeSec` — ten minutes by default — from `asOf`, or with no time at all. The window bounds how long a captured packet stays valid; it is not the replay defence, which is the desk's own: each nonce issued once and accepted once.

| Situation | Route |
|---|---|
| every criterion met · the rule's author signed a standing yes (`automaticYes`) · the outcome only grants · it touches no sensitive data | **automatic-yes**, citing the rows that fired and the rule's first `yes` reason — the author's standing yes, or the adopting anchor's |
| a criterion not met, every row read | **not-yet**, with what is missing and who the rule accepts to supply it, and the rule's first `not-yet` reason — **on every rule, binding or not** (d85(e)) |
| every criterion met, but the outcome binds, is sensitive, or the author kept the yes for a person | **to-a-person** |
| a row the step budget stopped; a private rule's openings missing or wrong; the person asked for a person | **to-a-person** |

**Every result carries the safeguards (P3):**
- `told` — `automatic` or `a person decides`;
- `mayAskForPerson: true`;
- the contest window;
- `reliedOn` — hashes only.

**Only fixed rules people wrote decide.** No model is anywhere in this path: a test reads every source file of the evaluator for a clock, randomness, a network or any import outside the kernel.

**An automatic *not yet* is allowed on every rule** (d85(e), settling KS-Q1's flag): a *not yet* refuses nothing. It always says what is missing and that the person may ask for a person. On the income rule, which binds, a month missing routes to an automatic not yet whose receipt validates, while an automatic yes on the same rule is still refused (`test/doors.test.ts`).

**Under an adoption** the thresholds are the rule's, with the anchor's adopted values over them. The adoption must be of this rule's exact version and hash, and in force at `asOf`. An issuer's predicate says a criterion is met under the rule's *own* values, so it does not answer a criterion whose threshold the anchor set; there the receipts are read.

## 3. Making the receipt

- **`decisionFromRoute(route, rule, {decidedAt})`** drafts the receipt for an automatic outcome — `standing:<author>`, or `standing:<anchor>` with `adoption` when the route ran under one — and throws for a route to a person.
- **`decidePerson({rule, adoption?, outcome, reasons, fired, missing, reliedOn, refusal?, seat, decidedAt})`** is a named person's decision, signed by their seat's key. **A refusal or a partial grant names the unmet criterion the decider chose and their confirmation that they read the receipts** (SCHUFA, CJEU 2023; P3: the desk never pre-fills a refusal).
- **`validateDecision(body, rule, adoption?)`** refuses:

| Code | When |
|---|---|
| `AUTOMATIC_REFUSAL` | an automatic `no` or `partial` — only a person refuses |
| `AUTOMATIC_YES_ON_BINDING` · `AUTOMATIC_YES_ON_SENSITIVE` · `AUTOMATIC_YES_NOT_STANDING` | an automatic yes the rule does not allow |
| `STANDING_MISMATCH` | automatic without `standing:<author>` (or `standing:<anchor>` under an adoption), or a standing that is not automatic |
| `ADOPTION_MISMATCH` | a decision naming an adoption it is not checked against, or one at an anchor's door that does not name that adoption exactly |
| `SEAT_SIGNATURE` | a person's decision whose seat signature does not check — any change to the body breaks it |
| `REFUSAL_UNEXPLAINED` | a refusal or partial grant naming no unmet criterion |
| `REASON_NOT_IN_RULE` | a reason the rule does not list, or one for another outcome |
| `RULE_MISMATCH` · `ROWS` · `NOT_YET_NAMES_NOTHING` · `CONTEST_WINDOW` | the wrong rule, version or hash; rows that are not the rule's; a not yet with nothing missing; a window shorter than the rule's |
| `SHAPE` | anything outside the closed shape — content in `reliedOn`, a score, `receiptsRead: false` |

- **`issueDecision({body, rule, adoption?, issuer, holderPublicKey, iatUnix, expUnix})`** validates, then issues an SD-JWT VC, `vct https://kashscript.com/vct/decision/1`:
  - signed by the deciding organisation (d62(d)2) — the rule's author, or the anchor whose adoption the door ran;
  - `cnf` = the person's key for this desk, one copy per call; the wallet receives decisions in copies, like any receipt a door may read (d62(d)3);
  - **visible:** `decision.rule`, `decision.adoption` (when there is one), `decision.outcome`, `decision.automatic`;
  - **selectively disclosable:** `reasons`, `rows`, `reliedOn`, `decidedBy`, `decidedAt`, `contestUntil`, `refusal`.

  So the next door can read *"yes, under rule X version 3"* and nothing more.
- **`readDecision(sdJwt, {nowSec, presentedTo?})`** reads one offline: held, or as presented to a viewer.

## 4. What it does not do

- **It does not deliver the receipt.** The desk hands it over the holder contract's OID4VCI handoff (the wallet's practice desk does exactly this). IN-Q2 builds the delivery and the contest inbox.
- **It does not keep packets.** Retention is the desk's (IN-Q2: packets and run state deleted at the rule's term). The receipt's hashes let a regulator's export hold decisions and no receipt content.
- **A decision is not a predicate.** It says what one door decided, under one version of its rule. A later door that reads it reads exactly that — and may ask for it only as a yes (node rule 10).

## 5. Changelog

| Version | Date | |
|---|---|---|
| **v1** | 2026-10-28 | KS-Q1. The receipt, its validation, the routing, the seat's signature, SD-JWT VC issuance. **Published under `alpha`, 2026-10-28.** |
| **v2** | 2026-10-29 | KS-Q1b. `kash.decision@1.1.0`: the optional `adoption`; an automatic outcome under an adoption is the anchor's standing decision, issued by the anchor (d85(d)); the shape moves from lexicons to predicate (d59); an automatic not yet on every rule (d85(e)). **Published under `alpha`, 2026-10-28 (21:19 UTC).** |
