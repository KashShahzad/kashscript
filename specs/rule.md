# The rule — what a door decides, and what counts

**`specs/rule.md` — v3 · 2026-11-08 · KS-Q11 · `kash.rule@1.2.0` (1.1.0 and 1.0.0 still read) (`@kashscript/lexicons/extensions/door`), evaluated by `@kashscript/predicate` (Apache-2.0).**
Decisions: ECOSYSTEM d27, d41, d43, d59, d60, d62(d)2–3, d71, d83(b), d84 (a; f: P3, P4), d85 (b, c, e, l) · companions: [decision.md](decision.md) · [adoption.md](adoption.md) · the condition language: [feel-subset.md](feel-subset.md) · schema: [`schemas/rule.schema.json`](schemas/rule.schema.json) (1.1.0) · decision record: [ADR-0021](../docs/adr/0021-rule-and-decision.md).

> **What exists, and what does not.** The format, its validation, the person-side checklist, the packet, the desk's check and the routing are built in source with fixtures and tests (`packages/predicate`, `packages/lexicons`, `packages/wallet`'s `doors`). **v1 was published under `alpha` on 2026-10-28** `[v 10-28, npm view]`: predicate `0.1.0-alpha.0`, lexicons `0.2.0-alpha.0`, attest `0.2.0-alpha.7`, wallet `0.1.0-alpha.4`. **v2 (KS-Q1b) was published under `alpha` on 2026-10-28 (21:19 UTC)** `[v 10-29, npm view]`: predicate `0.2.0-alpha.0`, lexicons `0.3.0-alpha.0`, attest `0.2.0-alpha.8`, wallet `0.1.0-alpha.5`. **A reader on predicate `0.1.0-alpha.0` refuses a 1.1.0 rule**, because the 1.0.0 shape is closed. **v3 (KS-Q11) is built in source and not yet published:** predicate `0.3.0-alpha.0`, lexicons `0.4.0-alpha.0`, wallet `0.1.0-alpha.6` (attest unchanged) — the founder publishes them under `alpha`. A reader on predicate `0.2.0-alpha.0` refuses a rule whose query names `holder`, for the same reason: it never falls back to the requester. No door has run with a person. The evaluator ran in headless Chrome 156 and in the wallet's practice harness; never on a phone.

## 0. The equation, and this document's part in it

A door is anywhere someone decides on evidence (d84(a)). It publishes a **rule**; the person's side checks it first, **as a checklist and never a score**; the person sends a **packet** by choice, a copy per viewer; the desk checks it free and **routes** it; the **decision** comes back as a receipt ([decision.md](decision.md)).

Nothing here is invented where a standard speaks (d71):
- each criterion is an **OpenID for Verifiable Presentations 1.0 DCQL** query (§6) for the receipts that answer it, plus a **DMN FEEL** condition over what the query returns ([feel-subset.md](feel-subset.md));
- the rule is a **DSSE** envelope its author signs;
- receipts travel as **SD-JWT VC** presentations with key binding, or as the holder contract's `kash-artifact` with its own binding (§6).

## 1. The rule

| Field | Meaning | Checked |
|---|---|---|
| `id` | `did:kash:<author>/rule/<slug>` — the publisher's DID plus a path, as d60 names places | the DID is `author` |
| `version` | an integer ≥ 1. A predicate cites it as a string | — |
| `author` | the organisation that publishes it, answers for it and decides under it (d62(d)2) | a `did:kash`; never a person |
| `title`, `purpose` | plain words: what the door decides, and why it reads these receipts | — |
| `visibility` | `public`, or `private` (§5) | — |
| `parameters` | named thresholds the conditions read, each `{type, value}` (public) or `{type, sealed}` (private) | in clear on a public rule, sealed on a private one; a value reads as its type |
| `dates` | `published`, `renewBy`, `endsAt` | **every rule renews and ends (d43):** published < renewBy ≤ endsAt; renewal within 366 days; an end within three years |
| `decider` | `{role}` — who decides, as a role | never a name; no email, phone number or person's DID anywhere in the rule's text |
| `outcome` | `{grants, binds, sensitive, automaticYes}` | `automaticYes` — the author's signed standing yes — is refused with `binds` (credit, a contract, a debt) or `sensitive` (P3) |
| `reasons[]` | `{code, outcome, text}`: the reasons a decider may give, for `yes`, `not-yet`, `no` or `partial` | at least one `yes` and one `not-yet` reason; codes unique |
| `contest` | `{windowDays, answerDays, how}` | — |
| `anotherWay` | the other way to show the same thing — paper is the floor (P4's first rule) | required |
| `criteria[]` | 1–32 criteria (§2) | ids unique |
| `answers[]` | the author's written answers to the warnings validation raised (§4.2) | published with the rule |
| `address` | **1.1.0** — sector, anchor family, authority, journey and the seven givens (§1.1) | the sector is a real ISIC Rev 5 code; all seven givens answered, or `draft` |
| `draft` | **1.1.0** — published for reading and comment, never decided under (§1.2) | required on an incomplete rule |
| `practice` | `true` on everything built before its gate | — |

The shape is closed: a field not named here is refused, so a rule can carry no score and no person.

**Parameters may carry bounds (1.1.0, d85(b) rule 8).** A public rule's parameter may add `bounds` — `{min?, max?}` for a number, a date, a date and time or a duration of one kind, compared with FEEL's own ordering (`P18M` sits between `P12M` and `P36M`), or `{allowed: [...]}` for anything. The rule's own value sits inside its bounds (`BOUNDS`). **A bounded parameter is adoptable; an unbounded one is fixed by the rulebook** ([adoption.md](adoption.md)). A sealed parameter carries no bounds (`SEALING`): an adoption's values are public.

### 1.1 The address (1.1.0, d85(c))

**Every rule has an address**, so any two rules can be compared field by field:

| Field | Meaning |
|---|---|
| `sector` | `{classification: "ISIC", revision: "5", code}` — one of the UN's **22 sections** (A–V) or **87 divisions** (two digits; a division names its section). Source: UN Statistics Division, `ISIC_Rev_5_english_structure.csv`, read 2026-10-28; the table is `@kashscript/predicate`'s `ISIC_REV5` |
| `anchorFamily` | `movement` · `knowledge` · `work` · `community` — which kind of institution adopts it |
| `authority` | `{kind: floor · law · standard · institution · community, name?, url?}` — whose rule it is |
| `journey` | `move` · `learn` · `earn-and-spend` · `live` · `leisure` — which part of a person's life it touches |
| `givens` | the seven givens below |

**The seven givens** are VISION's pillars read as the context every service has in space and time. Each is written twice: `text` in plain words, which is required, and optional fields a machine can compare.

| Given | Means | Machine fields |
|---|---|---|
| `area` | where it applies | `anywhere: true`, **or** `countries` (ISO 3166-1 alpha-2) and/or `places` (`did:kash:<publisher>/place/<slug>` — **never a coordinate**, d60) |
| `spaces` | on what infrastructure | `kinds`: premises · workplace · campus · site · vehicle · home · public-space · online; `places` |
| `capitals` | which resources it needs | `needs`: `[{kind: people · systems · resources, what}]` |
| `culture` | which norms of conduct | `codes`: `[{title, url?}]`; `languages` (BCP 47) — the service's norms, never anyone's identity |
| `economy` | on what terms | `level`: primary · secondary · tertiary · quaternary · quinary · uncounted |
| `time` | how long, and when it renews | `lasts`, `renews` — ISO 8601 durations |
| `relations` | which rulebooks it recognises | `recognises`: `[{rule, version?}]`; `within`: `[{id}]` — the pacts or rulebooks it sits in |

The givens are context: the evaluator never reads them, and no one is decided about on them. Their text is read for contact details like the rest of the rule (`PERSON_IDENTITY`).

The internship fixture's address is the worked example on d85's page: Education (division 85) · knowledge · the law (the higher-education regulator) · learn · any campus in Pakistan · a host workplace · a qualified supervisor · the host's code of conduct · paid or unpaid, stated in advance · three credit hours, reviewed yearly · minimum weeks between six and twelve.

### 1.2 Complete, or a draft (d85(b) rule 7)

- **A rule without `address` is a 1.0.0 rule.** It validates, signs and is decided under as before, with one warning, `NO_ADDRESS`, which needs no written answer. `kash.rule@1.0.0` stays registered, unchanged.
- **A rule with `address` is held to completeness.** Missing a given, it is **incomplete**: validation warns `INCOMPLETE` with the givens it lacks, and refuses it (`INCOMPLETE_NOT_DRAFT`) unless it says `draft: true`.
- **A draft is readable and testable, never decided under.** `checklist` runs and says `draft: true` (never `ready`); `ruleRequest`, `openRuleRequest`, `route` and an adoption refuse it.

## 2. A criterion

| Field | Meaning |
|---|---|
| `id`, `label` | a slug, and plain words |
| `subject` | **1.1.0** — `person` · `organisation` · `product` · `place`: what the criterion is about. **Required on an addressed rule** (`SUBJECT`); a criterion without one is read as a person's, the strictest reading (§4.3) |
| `purpose` | **why the door needs it.** Required, at least 12 characters, and more than the label (P4's second rule: *a rule asks only for what its purpose needs*) |
| `answer` | **receipts** — `query`: DCQL credential queries, verbatim; `options`: which of them together answer it (DCQL `credential_sets.options`; default each alone); `names`: display names for the issuers and lists the queries name. **Or own-word** — `statement`, and `fields` (name → DMN type) |
| `predicate` | *a predicate suffices:* `{issuers, freshDays}`. An issuer's predicate credential — attest's `https://kashscript.com/vct/predicate/1`, `kind` = this criterion's id, `rule` = this rule's id, version **and hash** — answers the row instead of the receipts, if its window ended within `freshDays`. The issuer ran this same condition over its own book and signs that it did |
| `condition` | `{feel, types}` — one FEEL expression ([feel-subset.md](feel-subset.md)), and a DMN type for every claim it reads (the itemDefinition's role) |
| `basis` | optional `{title, url, clause, page, quote}` — the clause a criterion comes from (KS-Q3's *Policy to door*) |

### 2.1 The queries

- **Formats this version reads:** `dc+sd-jwt` (SD-JWT VC; `meta.vct_values` required) and `kash-artifact` (the holder contract's OID4VCI profile, §1.3 there; `meta.dst_values` required). Anything else — `mso_mdoc`, `jwt_vc_json` — is refused by name, as *not readable by this version*.
- **`kash-artifact`'s `meta`**, in the spec's own extension point for formats:
  - `dst_values` — the registered types it accepts;
  - `attestation: countersigned` — two independent signatures over the same bytes (d26);
  - `holder_path` — where the signed payload names the holder's key, for the binding (§6);
  - `holder: "countersigner"` — **1.2.0 (KS-Q11)** — the holder is the party who countersigned these bytes, not the one who asked: a guest who accepted a host's delivered-booking receipt, whose payload names only the host. **It is exact.** The key is taken only from attest's own verdict on the bundle (`verifyCountersignBundle`): an acceptance counts only when its report is `ok` — its signature checks under its `countersignerDid`, it binds this request and these bytes, it was signed inside the request's window, that same DID signed the subject, and no earlier withdrawal stands against it. The requester's own acceptance is never a countersigner. **Exactly one** distinct countersigner must remain; none, or more than one, is no holder, and the binding is refused. Nothing unsigned is read. Key claims are not followed: the holder is the DID that signed the acceptance, so a wallet that recovered to a successor key cannot present the old record under the new one. `holder` and `holder_path` are never both named, and `holder: "countersigner"` needs `attestation: countersigned`.
- **Issuers**, in `trusted_authorities` — which OpenID4VP calls an extension point (§6.1.1; it defines `aki`, `etsi_tl` and `openid_federation`):
  - `kash_issuer` — issuer DIDs;
  - `kash_trust_list` — `<publisher DID>#<list id>`: whichever issuers that publisher's **pinned** list admits for this type. *"English at B2 from listed assessors"* is written this way.

  With neither, any issuer of that type will do — any client who countersigns, for example.
- **Claim ids are the condition's names.** Every claim carries an `id`; inside the condition, each receipt is a context of its claims by id, plus `issuer`. Claims path pointers follow §7: a string selects a key, `null` every array element, an integer an index. `values` pins a claim to exact values (§6.4.1).
- **What the person may show.** Every claim the condition reads appears in every `claim_sets` option; the rest are what the person may choose to show. An SD-JWT presentation discloses only the claims of the option sent.
- **Counting SD-JWT receipts.** A query for several SD-JWT receipts (`multiple: true`) must read each one's record id, under the claim id `record`. An SD-JWT's copies are unlinkable by design, so without it one record shown in two copies would count twice; with it, equal record ids count once. **What this costs:** two viewers who each see a record's id can tell it is the same record. An issuer's predicate (`predicate` above) avoids showing it.
- **Holder binding is always on.** `require_cryptographic_holder_binding: false` is refused.

### 2.2 The person's own word

A criterion the rule takes on the person's word is still a DCQL query, so the whole packet is one standard `vp_token`. Its credential is an SD-JWT VC of type `https://kashscript.com/vct/own-word/1`, **issued by the person to themselves** under a fresh key made for that viewer alone. `iss` and `cnf` are the same key. It carries:

```
word: { rule: {id, version, hash}, criterion, fields: {…} }
```

Its claims pin the rule, the version and the criterion, so a statement made for one rule never answers another. The condition reads its fields by name, for example `availableFrom <= date(asOf + startWithin)`.

## 3. The rule's DCQL query

`ruleToDcql(rule, hash)`:
- **`credentials`** — every criterion's own queries, plus:
  - `<criterion>_predicate` — `PREDICATE_VCT`, with claims pinning `predicate.kind`, `answer`, `rule.id`, `rule.version` and `rule.hash`;
  - `<criterion>_word` — `OWN_WORD_VCT`, pinning `word.rule.id`, `word.rule.version` and `word.criterion`.
- **`credential_sets`** — one required set per criterion, whose options are its receipts' options plus `[<criterion>_predicate]`.

Query ids are `<criterion>` or `<criterion>_<suffix>`; the `_predicate` and `_word` suffixes are the evaluator's.

## 4. Validation — `validateRule(body)`

Pure; reads no clock. Returns `{ok, refusals, warnings}`. A rule that does not validate cannot be signed (`signRule` throws) or opened (`readRule`, `openRuleRequest` throw).

### 4.1 Refusals

| Code | The rule it enforces | Caught by |
|---|---|---|
| `ASKS_FOR_A_REFUSAL` | node rule 10 | a query for decision receipts whose `["decision","outcome"]` claim is not pinned to `["yes"]`; refusal words in what a criterion reads or names (refused, rejected, declined, denied, blacklist, banned, debarred…) |
| `PROVES_ABSENCE` | node rule 10; *absence cannot be proven offline* | the condition holds when **no receipt** is shown — `count(receipts) = 0`, `not(some …)`, an empty `every` |
| `SENSITIVE_CATEGORY` | P4.2 · GDPR art. 9 | racial origin; religion and religious or philosophical belief (and religions by name); political opinion; trade-union membership; genetic, biometric and health data (pregnancy and disability included); sex life and sexual orientation |
| `ASCRIBED_IDENTITY` | d85(b) rule 1 · P4.2 · d27 · d36 | caste (*zaat*, *biradari*, *qaum*); sect (and sects by name); ethnicity, tribe, clan; lineage, ancestry, descent; father's and mother's names; place, country or city of birth; gender and sex (women, men, female, male); **nationality, citizenship and origin** (refused for a person since KS-Q1b, when d85(b) rule 1 named them; KS-Q1 warned). A superset of attest's ask pattern, so an ask and a rule agree. Which of these bind depends on the criterion's subject (§4.3) |
| `READS_A_SCORE` | node rule 3 · d43 | score, rank, rating, percentile, percentage, credit score |
| `NO_PURPOSE` | P4.2 | a criterion with no stated purpose |
| `PERSON_IDENTITY` | *a rule carries no person's identity* | an email, phone number or DID (other than the author's and the issuers') in the title, purpose, role, grants, reasons, labels, statements or answers. Contact details belong in `contest.how`, as a role address |
| `AUTOMATIC_YES_ON_BINDING`, `AUTOMATIC_YES_ON_SENSITIVE` | P3 | `automaticYes` with `binds` or `sensitive` |
| `DATES`, `REASONS`, `NO_ANOTHER_WAY`, `SEALING`, `AUTHOR_MISMATCH`, `CRITERIA` | d43 · node rule 11 · P4.1 | §1's checks |
| `CONDITION`, `FEEL_OUTSIDE_SUBSET`, `FEEL_INVALID`, `DISCLOSURE_GAP`, `COUNTS_COPIES` | the language | a receipts criterion without a condition; a construct outside the subset; an unbound name; **a condition that is not a yes or a no — never a number, so never a score**; a read claim missing from a `claim_sets` option; §2.1's record id |
| `DCQL_MALFORMED`, `DCQL_FORMAT_UNREADABLE`, `DCQL_UNBOUND` | OpenID4VP §6 | duplicate ids; `meta` for the wrong format (`holder` included); `holder` beside `holder_path`; `holder: "countersigner"` without `attestation: countersigned`; an unknown authorities type; a format this version cannot read; holder binding switched off |
| `UNANSWERED_WARNING` | §4.2 | a warning with no written answer |
| `ADDRESS` | d85(c) · d60 | a sector that is not an ISIC Rev 5 section or division; an area both `anywhere` and named; a duration that does not read |
| `INCOMPLETE_NOT_DRAFT` | d85(b) rule 7 | an addressed rule missing a given, not marked `draft` |
| `SUBJECT` | d85(b) rule 1 | an addressed rule's criterion with no `subject` |
| `BOUNDS` | d85(b) rule 8 | bounds on a list type; a range on a type with no order; a minimum above the maximum; bounds that do not read as the type; the rule's own value outside them |

### 4.2 Warnings, answered in writing

A known proxy is not refused outright: whether it stands in for an ascribed identity depends on the door. Instead, validation fails until the author answers it in `answers[]` — `{criterion, code, text}`, at least 12 characters — and the answer is signed and published with the rule. Each warning says whether it is `answerable`: `NO_ADDRESS` and `INCOMPLETE` are not — they are answered by completing the rule.

| Code | Raised for |
|---|---|
| `SINGLE_ISSUER` | a criterion that accepts one issuer only — the one school, employer or neighbourhood body |
| `RESIDENCE_PROXY` | address, postcode, district, neighbourhood, street, hometown |
| `NAME_PROXY` | family name, surname, given name, first or full name |
| `LANGUAGE_ORIGIN_PROXY` | mother tongue, native, first or home language |
| `AGE_PROXY` | a birth date or year — ask for an age predicate if age is what the purpose needs |
| `FAMILY_STATUS_PROXY` | marital status, spouse, children, dependants |
| `APPEARANCE_PROXY` | a photo, portrait, face, height or weight |
| `GRADE` | a grade or GPA |
| `NO_ADDRESS` | a 1.0.0 rule, with no address (§1.2) — not answerable |
| `INCOMPLETE` | a draft missing givens (§1.2) — not answerable |

*KS-Q1's `NATIONALITY_PROXY` is gone:* a person's nationality is now refused (§4.1). A door that needs a right to work asks for a right-to-work predicate, which says nothing of where anyone is from.

### 4.3 How the vocabulary reads

By whole tokens, after splitting camelCase, snake_case and kebab-case: `placeOfBirth`, `place_of_birth` and `place-of-birth` all read *place of birth*, while *original*, *insect*, *sextant* and *orientation week* match nothing.
- **Refusals** read what a criterion asks for — its id, claim ids and paths, types, pinned values and own-word field names — and also its label, its own-word statement and the reasons' text: a *caste certificate* label asks for caste.
- **Proxy warnings** read only what a criterion actually reads, never its plain words, so *"a face-to-face review at your address"* asks nothing.
- Neither reads purposes, `anotherWay` or the address's givens, which explain.
- A reason's text is refused if its words would be refused **for any subject the rule's criteria name**: a product rule's reason may speak of the goods' origin, and the same words are refused once a criterion is about a person.
- A phone number is a run of at least ten digits written as one, never a date, a time or an amount.

**It knows its subject (KS-Q1b).** d85(b) rule 1 — *judged by what you can show, never by who you are* — binds when the subject is a person, **or an organisation's people**:

| Refused, or warned | person | organisation | product | place |
|---|---|---|---|---|
| ascribed identity — caste, sect, descent, birth, ethnicity, gender, and nationality | refused | refused, **except jurisdiction** — nationality, citizenship, origin, country of origin: where it is registered | allowed | refused — it would describe the people who live there — except origin |
| art. 9, identity kinds — race, religion, political opinion, trade-union membership, sex life or orientation | refused | refused | allowed — a halal or kosher mark is a product's | refused |
| art. 9, data kinds — health, medical, genetic, biometric, disability | refused | refused **only beside a people word** | allowed — a medical device | allowed — a health facility |
| scores, ranks, ratings | refused (rule 3) | allowed — institutions may be compared (rule 3) | allowed | allowed |
| proxy warnings | warned | **only beside a people word** | none | none — **a place's location is allowed** |

- **An organisation's people.** A jurisdiction word, a data kind or a proxy next to one of the organisation's people — staff, employees, workers, members, owners, founders, directors, board, workforce, personnel, partners, shareholders — is about people again: `ownerGender`, `ownersNationality`, `staffHealth` and `womenOwned` are refused. For a place, its residents, inhabitants, population and households are its people.
- **For every subject:** `ASKS_FOR_A_REFUSAL` and `PROVES_ABSENCE` (node rule 10; d85(b) rule 6), `PERSON_IDENTITY`, and the FEEL and DCQL checks.
- **Tested both ways** (`test/subject.test.ts`): a product's origin is allowed and a person's refused; a place's district is allowed and a person's warned; an organisation's nationality is allowed and its owners' gender refused.

**What this does not do.** A vocabulary catches the named and the obvious. A rule that hides an ascribed identity behind a neutral word, or behind a value no list names, passes it — and a rule that declares a person's criterion `product` passes the person's table. P5's one-page look before a new kind of door, and the trust lists' consequence for breaking the floor (P4.7), are the rest of the defence.

## 5. Private rules

A private rule publishes everything but its thresholds: its queries, conditions, reasons and dates are public, so anyone can see what it reads (d84(c)). Each threshold is published as a commitment:

```
sealed = SHA-256( JCS({name, value, salt}) )
```

The desk holds the openings, `{name: {value, salt}}`. `route` opens them against the commitments; **an opening that is missing or does not match sends the packet to a person**. The thresholds cannot be changed silently: the rule's hash covers the commitments. On the person's side, a row whose condition reads a sealed threshold shows as **sealed** (§7) — the rule reads these receipts, and the desk checks the threshold.

## 6. Signed form, request, packet

- **Signed:** a DSSE envelope, payloadType `application/vnd.kash.rule+json`, payload = JCS of the body, signed by the author's own key (`signRule`). `readRule` verifies it offline from the author's self-certifying DID — the trust lists' shape (d62(d)5), mirrorable by any host. **The rule's hash** is SHA-256 hex of the signed payload bytes; predicates and decisions cite it.
- **The request** (`ruleRequest`): an OpenID4VP `direct_post` request carrying:
  - `client_id` — the rule's author, or **the anchor whose adoption it carries** ([adoption.md](adoption.md)) — which is also the audience every presentation binds;
  - a fresh `nonce`, and `state`;
  - `dcql_query`;
  - `kash_rule` (the envelope, by value) and `kash_rule_sha256` — extension parameters, as `kash_ask` is;
  - at an anchor's door, `kash_adoption` (the adoption's envelope) and `kash_adoption_sha256`.

  The person's side (`openRuleRequest`, the wallet's `doors.open`) refuses a request whose rule does not verify or validate, whose digest differs, that does not come from the rule's author (or, with an adoption, from its anchor), whose adoption does not verify, validate or stand in force, whose query is not exactly `ruleToDcql(rule)`, whose rule is a draft, or whose rule is not in force.
- **The packet** (`buildPacket`): one `vp_token` keyed by query id (§8.1).
  - **SD-JWT** receipts and predicates: a copy shown to this viewer or to no one, disclosing only the claims of the option sent, with a KB-JWT over this viewer's `aud` and `nonce`.
  - **The own word:** §2.2.
  - **`kash-artifact`:** `{artifact, kb}`, where `kb` is a compact JWS (`typ: kash-artifact-kb+jwt`) over `{aud, nonce, iat, artifact_sha256}` — the record id, attest's `recordIdOf` — signed by the record's holder as the query names it: the one verified countersigner (`holder: "countersigner"`), the key at `holder_path`, or else, for a countersign bundle, its requester. **`artifactHolderOf(query, view, artifact)` is the one reading**: the desk checks the binding with it, the wallet finds its key with it, and a desk issues its decision receipt to it.
  - **A receipt is sent once**, even when several criteria read it; the desk matches every receipt against every criterion's queries.
  - **One copy is never shown twice in a packet** (`COPY_TWICE`).
- **What a `kash-artifact` entry does not protect:** a countersigned record cannot be re-keyed per viewer, so two viewers who see the same one can tell it is the same holder's (d62(d)3, until the tier-two circuit exists). An organisation signs as itself (d62(d)2), so for an agency nothing is lost. For a person, the wallet sends one only on their choice, and only with a key it holds; its guarded send refuses any other relationship's identifier. **With `holder: "countersigner"`,** the key the door sees is the person's key for that one host: the door learns it, can recognise the same host relationship if it is shown again, and issues its decision to it. The wallet lists the row under `links` before the person sends.

## 7. The checklist — the person's side first

`checklist(rule, held, {asOf, trustLists, statusLists, ownWord, adoption?})` returns one row per criterion — under an anchor's adoption, against the anchor's values. A row is:

| State | Meaning |
|---|---|
| **answered** | the condition holds over these receipts, or a fresh predicate answers it |
| **missing** | it does not, and the row names the issuers, lists, or *any issuer of that kind* the rule accepts |
| **own-word** | the person states it; `holds` says whether what they stated meets the rule (null until stated) |
| **sealed** | a private rule's row whose threshold only the desk can read; the row lists the receipts the rule reads |

**A row carries no number of any kind** — no count, no share, no progress — and a test walks every output to keep it so.

**What counts.** A receipt counts only if:
- it verifies offline;
- it is unexpired at `asOf` (d27.5);
- it is not revoked or suspended on a status list the caller carries;
- it matches its query: format, type, issuers and `values`.

**A stopped work record never counts** (d43 §4.6). Only `true` is met: FEEL's null (`sum([])`, a claim that did not read as its type) is not met. Only a condition the step budget stopped is unread.

**Minimal by default (d27.2).** The receipts a row rests on start as every counting receipt; each is dropped, in record-id order, while the condition still holds without it. The result is irreducible and deterministic, and the person may add the rest.

## 8. The desk's check

`checkPacket({rule, request, vp_token, ctx, asOf, freshness?})` verifies each presentation once:
- the signatures — an SD-JWT's under the key `iss` names, never one a header names (`KID_NOT_ISSUER`; AU-3, A7-01);
- the key binding, audience and nonce — and the binding's age: further than `freshness.maxKbAgeSec` (ten minutes by default) from `asOf`, or with no time, it does not count (AU-3, A7-08; the nonce stays single-use by the desk's own hand);
- the issuers, against the query and the pinned trust lists;
- expiry and status;
- for an own word, that it is self-issued;
- for an artifact, its binding.

It then matches each receipt against every criterion's queries. **What does not check is never counted, and never held against anyone:** it is listed in `problems`, and the criterion it would have answered is simply missing. **One record counts once, whatever wraps it** (`ReceiptView.contentId`, attest's `contentIdOf`; AU-3, A7-03): a copy re-wrapped with an extra field or a junk signature entry, or shown bare and countersigned, is the same record. **One item that does not read never stops the rest** (A7-04): it is a problem line, and every other presentation is judged. Then `route` ([decision.md](decision.md) §2).

## 9. Fixtures — `@kashscript/predicate/fixtures`

Practice rules every door, desk and engine may test against. All are `practice: true`; every threshold not drawn from a cited source is SAMPLE.

| Fixture | Criteria | Outcome |
|---|---|---|
| **Hiring** (`hiringRule`, `privateHiringRule`) | three client-countersigned projects in 24 months, or Oreoasis's predicate · React in one of them · English at B2 or above from a listed assessor · available within four weeks, on the applicant's word | a paid trial project; automatic yes |
| **Internship credit** (`internshipRule`) | the weeks approved by the site supervisor, the hours, and the final review, from the campus's record · the course code, on the student's word. HEC's notice of 2025-09-25 is cited in `basis`; SAMPLE thresholds; never attendance (d74(d)) | the course's credit hours (a SAMPLE code); automatic yes |
| **CPD cycle** (`cpdRule`) | hours over the cycle, from listed providers · structured hours · the member's declaration. **SAMPLE figures** — ICAP's are not in this repository; KS-Q3 writes the real rule | confirmation of the cycle; automatic yes |
| **Income** (`incomeRule`) | at least a SAMPLE amount each month for six months, or Duedale's predicate · from at least two payers | a loan offer — **it binds, so a person decides**; an automatic *not yet* is allowed (d85(e)) |
| **Product origin** (`productOriginRule`, KS-Q1b) | the goods' country of origin, from a listed chamber — subject `product` | the preferential rate; automatic yes. SAMPLE scheme |
| **Booking review** (`bookingReviewRule`, KS-Q11) | a delivered booking the guest accepted — OA-V1's `booking.delivered/1`, a work record any host's book signs — within a writing window; the query names `holder: "countersigner"` | the right to write one review; automatic yes. SAMPLE window; division 55 (I) · movement · institution · leisure |

**KS-Q1b's addresses and bounds** (every bound SAMPLE):

| Fixture | Sector | Family · authority · journey | Bounds |
|---|---|---|---|
| hiring | 62 (K) | work · institution · earn-and-spend | `minProjects` 2–5 · `window` P12M–P36M · `startWithin` P7D–P56D |
| internship | 85 (Q) | knowledge · law (HEC) · learn | `minWeeks` 6–12 (the page's) · `minHours` 80–240; `course` fixed |
| CPD | 69 (N) | work · institution · learn | `minHours` 100–150 · `minStructured` 40–80 · `cycle` allowed `P3Y` |
| income | 64 (L) | work · institution · earn-and-spend | `minMonthly` 500–5000 · `minPayers` 1–3 |
| product origin | 13 (C) | work · law · earn-and-spend | `origin` allowed PK, LK, PH |

Each of the four has one adoption, with local values (`hiringAdoption` and the rest; `ADOPTED_VALUES`), and a test shows the local value decides. **The 1.0.0 rules are kept:** `test/vectors/*-rule-1.0.0.json` are KS-Q1's bodies byte for byte, and a test proves each still validates and that each fixture, with what 1.1.0 added taken away, is exactly its vector.

`plantedViolations(parties)` holds one rule for each refusal in §4.1, each naming its code — KS-Q1b adds a person's nationality and country of origin, an incomplete rule that is not a draft, a criterion with no subject, a bad sector and a value outside its bounds. `plantedAdoptions` and `fixedParameterAdoption` hold the adoptions validation refuses ([adoption.md](adoption.md)). `answeredProxyRule` shows a proxy answered in writing. Practice types live under `practice.invalid`; `registerPracticeTypes()` registers them at runtime, so a practice trust list may name them, and never in attest's own registry.

## 10. Changelog

| Version | Date | |
|---|---|---|
| **v1** | 2026-10-28 | KS-Q1. The rule, its validation, the checklist, the packet and the desk's check. `@kashscript/lexicons` `0.2.0-alpha.0`, `@kashscript/predicate` `0.1.0-alpha.0`, attest `0.2.0-alpha.7` (three registry rows), wallet `0.1.0-alpha.4` (`doors`) — **published under `alpha`, 2026-10-28**. |
| **v2** | 2026-10-29 | KS-Q1b (d85(l)). `kash.rule@1.1.0`: the address (ISIC Rev 5, the anchor family, the authority, the journey, the seven givens), drafts, parameter bounds, each criterion's subject; a vocabulary that knows its subject — a person's nationality is now refused; adoption ([adoption.md](adoption.md)). 1.0.0 rules still validate. predicate `0.2.0-alpha.0`, lexicons `0.3.0-alpha.0`, attest `0.2.0-alpha.8` (one registry row), wallet `0.1.0-alpha.5` — **published under `alpha`, 2026-10-28 (21:19 UTC)**. |
| **v3** | 2026-11-08 | KS-Q11. `kash.rule@1.2.0`: `meta.holder: "countersigner"` on a `kash-artifact` query — the one key whose acceptance in the bundle verifies is the holder (§2.1); `ReceiptView.countersigners`; `artifactHolderOf` exported as the one reading for the desk, the wallet and the decision; three new `DCQL_MALFORMED` checks; the booking review fixture. 1.1.0 and 1.0.0 rules still validate and bind as before. predicate `0.3.0-alpha.0`, lexicons `0.4.0-alpha.0`, wallet `0.1.0-alpha.6`; attest unchanged — **built, not published** (the founder publishes under `alpha`). |
