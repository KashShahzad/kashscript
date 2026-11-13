# The adoption — an anchor runs a rule with its own values

**`specs/adoption.md` — v1 · 2026-10-29 · KS-Q1b · `kash.adoption@1.0.0` (`@kashscript/lexicons/extensions/door`), read and checked by `@kashscript/predicate` (Apache-2.0).**
Decisions: ECOSYSTEM d43, d59, d62(d)2, d85 (b: rule 8; c; d; l) · companions: [rule.md](rule.md) · [decision.md](decision.md) · schema: [`schemas/adoption.schema.json`](schemas/adoption.schema.json) · [ADR-0021](../docs/adr/0021-rule-and-decision.md).

> **What exists, and what does not.** Built with tests in `packages/predicate` and `packages/lexicons`, and in the wallet's practice desk. **Published under `alpha` on 2026-10-28 (21:19 UTC)** `[v 10-29, npm view]`: lexicons `0.3.0-alpha.0`, predicate `0.2.0-alpha.0` and attest `0.2.0-alpha.8` (its envelope's row). No anchor has adopted a rule. Every value in the fixtures is SAMPLE.

## 0. Why

d85(b) rule 8: **written openly, executed locally** — one open source per rulebook, with local parameters within stated bounds. The Eurocodes are the precedent: each country sets its own values for a defined list of parameters in its National Annex. Here a rule states which of its parameters an adopter may set, and between what bounds (rule.md §1); an **adoption** is an anchor's signed record that it runs that rule, at that version, with these values. An anchor's adoption is its pact (d85(d)): the door it runs decides under the rule with these values, and an automatic outcome is the anchor's own standing decision.

## 1. The record

```
{ id:         "did:kash:<anchor>/adoption/<slug>",
  anchor:     <the anchor's DID — an organisation, signing as itself (d62(d)2)>,
  rule:       { id, version, hash },             // the exact rule adopted
  parameters: { <name>: <string | number | boolean> },
  dates:      { adopted, renewBy, endsAt },       // d43: it renews and ends
  practice?:  true }
```

**It names an anchor and numbers — never a person.** The shape is closed, so it has no field for one; every value is typed and bounded by the rule; and a string value is read for an email, a phone number or a DID (`PERSON_IDENTITY`). It is a public, organisation-authored record, so its lexicon is in `@kashscript/lexicons` (d59).

## 2. Validation — `validateAdoption(body, rule)`

Pure; reads no clock. It refuses:

| Code | When |
|---|---|
| `SHAPE` | anything outside the closed shape |
| `ID_MISMATCH` | an id not under the anchor's DID |
| `RULE_MISMATCH` | another rule, version or hash |
| `DRAFT` · `PRIVATE` | a draft (never decided under, rule.md §1.2) or a private rule (its thresholds are sealed; an adoption's values are public) |
| `NOT_ADOPTABLE` | a parameter the rule does not have, or one with no bounds — **the rulebook fixes what it does not bound** |
| `OUT_OF_BOUNDS` | a value that does not read as the parameter's type, or sits outside its range or its allowed list |
| `PERSON_IDENTITY` | an email, phone number or DID in a value |
| `DATES` | not adopted, then renewed, then ended; reviewed later than 366 days after adoption; adopted before the rule was published, or ending after it |

`adoptableParameters(rule)` lists what an anchor may set: a public rule's bounded parameters.

## 3. Signed, read, carried

- **Signed** by the anchor's own key: DSSE, payloadType `application/vnd.kash.adoption+json` (attest's registry, owner `@kashscript/predicate`), payload = JCS of the body (`signAdoption`). **Its hash** is SHA-256 hex of the signed bytes.
- **Read** offline from the anchor's self-certifying DID, against the rule it adopts (`readAdoption`): the signature is the anchor's, the bytes are canonical, and it validates.
- **Carried** in the door's request: `ruleRequest(rule, {…, adoption})` sets `client_id` to the anchor, so every presentation binds the anchor's audience, and adds `kash_adoption` and `kash_adoption_sha256`. `openRuleRequest` — and the wallet's `doors.open` — verify it, check the digest, that the request comes from the anchor, and that the adoption is in force (`adopted ≤ now < endsAt`).

## 4. What the evaluator does with it

- **Thresholds** are the rule's own values with the adoption's over them, in `checklist` (the person's side first), `route` (the desk) and the wallet's door. A test shows it deciding: two accepted projects are a *not yet* under the hiring rule's three, and an automatic yes under an anchor's two.
- **An issuer's predicate does not answer a criterion the anchor set.** A predicate says *meets rule X version 1* under the rule's own values; where the adoption changes a value the criterion reads, the receipts are read instead, and the checklist says why. (A predicate issued for an adoption is not built.)
- **The decision** names `adoption: {id, hash}`; an automatic outcome is `standing:<anchor>`, and the receipt is issued by the anchor ([decision.md](decision.md)). `route` refuses an adoption of another rule, or one not in force at `asOf`.

## 5. Fixtures

`hiringAdoption`, `internshipAdoption`, `cpdAdoption` and `incomeAdoption` adopt the four rules with `ADOPTED_VALUES` — two projects; eight weeks (the page's six to twelve); 150 CPD hours; 750 a month. `plantedAdoptions` holds one adoption per refusal; `fixedParameterAdoption` sets the internship's course code, which the rulebook fixes. The wallet's `PracticeDesk.adopt` signs one in a practice run.

## 6. Changelog

| Version | Date | |
|---|---|---|
| **v1** | 2026-10-29 | KS-Q1b. The record, its validation, signing and reading; carried in the request; read by the checklist, the routing and the decision. **Published under `alpha`, 2026-10-28 (21:19 UTC).** |
