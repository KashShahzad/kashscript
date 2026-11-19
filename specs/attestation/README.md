# The attestation — six types, one profile, and what it keeps private

**`specs/attestation/README.md` — v1 · 2026-11-19 · RW-14 · `kash.attestation@1.0.0` and `kash.mandate@1.0.0` (`@kashscript/attest/attestation`), `kash.decision@1.2.0` (`@kashscript/predicate/decision`) — Apache-2.0.**
Decisions: ECOSYSTEM d26, d27, d28, d41, d43, d49, d59, d62(d), d84 (P3, P4), d85(f), d88, d91(a)–(f), d93(e), d97(h)–(i) · companions: [holder contract](../holder-contract.md) · [presentation](../presentation.md) · [countersign](../countersign.md) · [rule](../rule.md) · [decision](../decision.md) · [adoption](../adoption.md) · [public records](../public-records.md) · [trust log](../trust-log.md) · schemas: [`attestation`](../schemas/attestation.schema.json) · [`mandate`](../schemas/mandate.schema.json) · [`attestation-vc`](../schemas/attestation-vc.schema.json) · [`decision`](../schemas/decision.schema.json) · decision record: [ADR-0031](../../docs/adr/0031-the-attestation-profile.md).

> **Reviewed on Opus 5.5; re-read when Fable is available.** RW-14 is tagged for the deeper model because it touches the record model. It ran on Opus 5.5, so, as its block requires, each part was followed by a fresh-session adversarial review against d41, d43, d62(d) and d91. Part one's review found two critical and six high problems; part two's, one critical (the copies' `_sd` length and dates joined them) and five high. Each is fixed below, or named as open in §4 (marked †).
>
> **What exists, and what does not.** The two new shapes, their rules, the stranger's check of a record of truth (`verifyAttestationRecord`), the copy's and the projection's mappings, the registry rows, `kash.decision@1.2.0`, node rule 10 for the new type, the worked examples and the conformance cases are built in source with tests (attest `0.3.0-alpha.1`, predicate `0.3.0-alpha.4`) and **not published** — the founder publishes under `alpha`. No engine issues this record yet: Oreoasis still issues its work record and countersign bundle, which §1.9 maps. No ceremony produces it (§2.3), no chain of mandates is checked, and no proof page shows it. Nothing here has run with a person.
>
> **Two places this reads a decision differently — ruled by the founder on 2026-11-20** (ECOSYSTEM d91's dated note, which also confirms the rulings marked so below):
> - **d93(e)1** names `whiffin` as the host's mandate to the app. **Ruled:** it is read as `kash.mandate`, and whiffin keeps value mandates (§1.4).
> - **d91(e)** calls attest's envelope *an internal convenience*. **Ruled:** the DSSE envelope stays the record of truth — the one form that carries the two signatures d41 requires (§2.3) — until a standard form carries two signatures. The standard forms are the copy and the projection.

## 0. What this is

ECOSYSTEM d91(a) made one record type of everything the ecosystem signs: **an attestation is a signed outcome against a content-addressed reference, by a party who answers for it.** Around it sit five more types — the **key** that signs, the **reference** it is made against, the **mandate** that lets a key sign for someone else, the **rule** a decision applies, the **decision** itself — and two that travel beside every record, the **witness** that gives it a time and the **status** that says whether it still stands.

This document does three things:
- **§1, the algebra:** each type defined once, mapped to where it already lives in the packages, and each gap filled by a new lexicon version or registry row — appended, never rewritten (d59).
- **§2, the profile:** one record in three forms — the DSSE record of truth, the SD-JWT presentation, the W3C VC 2.0 projection — with worked examples a test checks and conformance cases anyone can run.
- **§3, the privacy games** and **§4, the open problems:** what this keeps private, against whom, how far, and what checks it today. *(RW-14's second part.)*

It is written so that **a stranger can implement it**: Duedale must accept a receipt it has never seen from an engine it does not run (d91(e)). Every check here is offline and free (d28).

## 1. The algebra

| Type | One sentence | Lives today | Filled by |
|---|---|---|---|
| **key** | what signs; a self-certifying identifier, scoped to one relationship for a person | identity-core, attest's resolver, the wallet, the trust list | nothing new |
| **reference** | what an attestation is made against, by hash and version | six different hashes in five places | the typed `reference` in `kash.attestation@1.0.0` |
| **attestation** | a signed outcome against a reference, by a party who answers for it | an engine's work record, the countersign bundle, the predicate credential | **`kash.attestation@1.0.0`** |
| **mandate** | a principal's grant to one key to sign within a scope until a date | an access token, a hash on a ceremony ticket — nothing a stranger can check | **`kash.mandate@1.0.0`** |
| **rule** | what a door decides, with its criteria, reasons and renewal | `kash.rule@1.2.0` | node rule 10 extended to the new type |
| **decision** | an attestation against one version of a rule | `kash.decision@1.1.0` | **`kash.decision@1.2.0`** — the mandate a seat signed under |
| *witness* | a public time over a hash, never the signer's | attest's trust log and witnesses (KS-Q4) | nothing new; it travels beside |
| *status* | whether a record still stands: expired, superseded, withdrawn, revoked | `kash.status-list@1.1.0`, attest's verdicts | `supersedes` in the attestation; a status entry required on every mandate |

**How they compose.** A **key** signs. If the key is not the principal's own, it cites a **mandate** from the principal. The principal is the **issuer** of an **attestation**, whose outcome is made against a **reference**; for a receipt or a finding, the other side — the **counterparty** — signs the same bytes. When the reference is a **rule**, the attestation is a **decision**. A **witness** over the record's hash fixes when it existed; a **status** list says whether it still stands. Nothing in the chain names a person except as the holder of a key scoped to one relationship (d41).

### 1.1 Key

**Defined:** an identifier that carries or resolves to a public key, and signs. A person's key is made for one relationship and used for no other (d41, d47(g), d62(d)3); an organisation signs as itself (d62(d)2).

**Lives today:**
- `did:kash:<base58>` — self-certifying, Ed25519 or P-256 (`identity-core/src/did.ts`: `deriveDid`, `deriveDidP256`). A stranger checks a signature from the identifier alone (d28).
- Resolution in one order — self-certifying, a pinned trust list, a held key — with every report naming the step (`attest/src/holder/keys.ts`, [holder contract](../holder-contract.md) §0). The algorithm comes from the key, never from a header (`attest/src/signing.ts`, ADR-0020).
- Per-relationship keys in the wallet (`wallet/src/relationships.ts`); the countersign acceptance records the key's custody (`keyCustody`).
- The trust list's keys, each with the issuer's **class** and the **grade** at which the key was shown to be the organisation's (`kash.trust-list@1.0.0`, [public records](../public-records.md) §2.5), and their history as key events in the trust log ([trust log](../trust-log.md) §1).

**Gaps, and where they go:**
- **`did:web`** is what a stranger resolves for an organisation on its own domain (d91(e)); `did:kash` has no registered method (d97(h)). This profile accepts a `did:web` as an issuer, a principal, or — at grade 3 only — a counterparty. **attest does not fetch a `did:web` document**: checked offline, its key comes from a pinned trust list or a held key, handed to the check as a resolver; otherwise its signature is not checked and the report says so. A mandate's delegate, and a person's counterparty key, must be a self-certifying `did:kash`. What a self-certifying key is called is RW-19's, branch B.
- **Engines' opaque identifiers** — Oreoasis's `did:kash:org:<slug>`, `did:kash:agent:<slug>:<ulid>` — resolve only through a list or a held key. The profile does not accept them as parties.

### 1.2 Reference

**Defined (d91(a)):** what an attestation is made against — agreements and purposes (private, in books), rules and standards (public, in the library) — each by hash and version. *"Accepted against this version of this reference"* replaces *"approved"*.

**Lives today, six ways:**

| Reference | Hash | Where |
|---|---|---|
| a rule, an adoption | SHA-256 hex of the DSSE payload bytes | [rule.md](../rule.md) §6, [adoption.md](../adoption.md) §3 |
| a held record | SHA-256 of RFC 8785 JCS of the artefact (`recordIdOf`); counted by content (`contentIdOf`) | `attest/src/holder/record-id.ts` |
| the receipts a decision relied on | SHA-256 hex, never content (`reliedOn`) | [decision.md](../decision.md) §1 |
| the records a predicate rests on | selectively disclosable hashes (`restsOn`) | [presentation.md](../presentation.md) §2 |
| an attestation in the trust log | `SHA-256("kash-log-salt-v1\n" ‖ salt ‖ record hash)` | [trust-log.md](../trust-log.md) §3 |
| a booking's terms; a chain consent's scope | `kash-trade:0x` + keccak-256 of the terms' JCS; SHA-256 of the JCS of five fields | Oreoasis `packages/contracts/src/booking.ts`, `subcontract.ts` |

**Gap:** no typed reference. Nothing says which kind of thing a hash names, so a verifier cannot tell a rule's hash from a delivery's.

**Filled by** the `reference` object of `kash.attestation@1.0.0`: `{kind, sha256, id?, version?}`.
- `kind` is one of `agreement · purpose · artefact · attestation · rule · standard`.
- `sha256` is the SHA-256 of the bytes the reference's own signer signed, or, for something unsigned, of its RFC 8785 canonical form. One algorithm, named in the field (Oreoasis's keccak reference is mapped in §1.9; digest agility is §4).
- **Public kinds** (`rule`, `standard`) carry their library `id` and `version` and are visible in every form: everyone answering to the same rule shares them, so showing one links nobody. The `id` is read for a person's contact like a statement (§2.2).
- **Private kinds** carry their hash, and their version when they have one — **never a book's own id**, which would be a second string to join on and a key to look up by (d41) — and are **always selectively disclosable** in a copy. That disclosure is the per-copy salted commitment §3 needs: each copy commits to the reference under its own fresh salt, and only the holder can open it (§2.4).

### 1.3 Attestation

**Defined (d91(a)):** a signed outcome — *accepted · not yet · refused · finding* — against a content-addressed reference, by a party who answers for it. Five kinds: a **receipt** (the other side's acceptance), a **decision** (against a rule's version), a **finding** (a deviation against a standard, countersigned by the doer, d43), an **assurance** (an assessor's, carrying the assessor's liability), a **contest** (the subject's, against the rule's recourse clause).

**Lives today:**
- Oreoasis's **work record** — DSSE, `application/vnd.oreoasis.work-record+json`, its job named in `meta.profile` (`booking.delivered/1`, `engagement.subcontract-consent/2`, `oreoasis-milestone/2`) — and the **countersign bundle** that carries the other side's acceptance over the same bytes (`kashscript-countersign/1`, [countersign](../countersign.md)).
- The **predicate credential** (SD-JWT VC, `vct …/predicate/1`) and Oreoasis's DSSE predicate.
- The **decision** (`kash.decision@1.1.0`).
- Older shapes, each verified unchanged by attest: agent receipts, Tehzeeb marks, improvement statements, session events.

**Gap:** none of these carries d91's outcome, a typed reference, a mandate citation or a supersession. An engine's work record is that engine's shape.

**Filled by `kash.attestation@1.0.0`** (§2), for four kinds: receipt, finding, assurance, contest. **A decision keeps its own record** — `kash.decision`, already a credential the person holds — and is mapped here, never duplicated (§1.6). The outcomes are not free for every kind:

| Kind | Outcomes | Made against | Counterparty | Why |
|---|---|---|---|---|
| receipt | accepted · not yet | an agreement, purpose, artefact or attestation | required | the other side's acceptance (d91(a)); two signatures or it is not proof (d41). **Never refused:** a decline by either party means no record, and leaves no trace (d49) |
| finding | finding | a standard or a rule | required — the doer | a deviation against a standard, countersigned by the doer (d43) |
| assurance | accepted · not yet · finding | an artefact, attestation, standard or rule | optional | the assessor's own attestation, carrying its liability (d91(f)) |
| contest | refused | **the rule** whose recourse clause it invokes, naming the decision in `contests` | never | the subject's own word against a decision — **the one place a party writes *refused***, and it is the subject's word about a decision, never anyone's about the subject |

A contest names the decision it contests by the content id of the copy its subject holds — SHA-256 of that copy's issuer-signed JWT, as `reliedOn` names an SD-JWT — and is signed by the subject's key for that desk. **The desk checks the binding:** the contest's signer is the key in the decision copy's `cnf`. The format cannot, because the copy is the subject's; a contest from anyone else's key binds to nothing.

d91's *refused* therefore appears in exactly two places: a contest, and a decision's `no` or `partial`, which only a named person signs (d84 P3).

### 1.4 Mandate

**Defined (d91(a)):** accountable keys mean a key plus a chain of signed mandates to a principal — an employee for a company, an agent under d88, a representative for a person, the desk applying a rule author's standing yes. **Every signature that is not the principal's own cites its mandate, with scope and expiry.**

**Lives today:**
- identity-server's **agent token** — an RFC 9068 access token whose `act.sub` names the agent acting for the owner, RFC 8693's delegation (`identity-server/src/agent/token.ts`).
- Oreoasis's **booking mandate** — that token, minted for 366 days for four scopes. The Org's own key signs the booking. The book's chain logs an event naming the agent connection (`agent.booking.issued`), the guest's acceptance request carries the agent's DID as an Org-signed disclosure, and the ceremony ticket carries `SHA-256("oreoasis-mandate\n" ‖ agentDid)`. **No record a stranger checks carries the mandate itself, by hash or by id** (Oreoasis `agent-connections.ts`, `booking-issue.ts`, `contracts/src/ceremony.ts`).
- **whiffin's grant** — a purpose-bound *value* mandate: this value, for this purpose, within these limits, until this date (d59, d64(h)).
- The countersign acceptance's `delegated-mint` custody, and the decision's seat signature.

**Gap:** no signed, citable authority mandate. d91(a) left *whether whiffin carries it* to KashScript. **This spec rules that it does not:** whiffin dedicates value to a purpose; this delegates the authority to sign, and putting it in whiffin would make a money package a dependency of every signature check. **d93(e)1 later names whiffin for the host's mandate to the app;** the founder ruled on 2026-11-20 that it is read as `kash.mandate` (d91's dated note).

**Filled by `kash.mandate@1.0.0`** (§2.2): `{id, principal, delegate: {key, kind, role?}, scope, dates, credentialStatus, practice?}`, signed by the principal as DSSE `application/vnd.kash.mandate+json`. A record signed under it carries `mandate: {id, hash}` — or, on the counterparty's side, `counterpartyMandate` — inside its own signed bytes, `hash` being the SHA-256 of the mandate's signed payload bytes.

- **One link.** A principal grants one key. A chain — a seat's own agent — is not in this version (§4): with one link the principal is always the party the record names, so no scope can widen on the way down.
- **Revocable.** A mandate carries a status entry, required, so it can be withdrawn before it ends — a seat's holder leaves, an app is disconnected.
- **Its floor, in the format:** an **agent's**, a **desk's** or **another organisation's** mandate names its outcomes, and *refused* is never one (d91(f): *a refusal carries a person-role signature and never a machine mandate*); an agent's covers receipts only — it never decides, judges a deviation, assures or contests (d88, d84 F, d43); a desk's covers decisions only (d84 P3); every mandate is bounded in scope and renews within 366 days (d43).
- **What the format cannot see:** the delegate's `kind` is the principal's own word. A key labelled `seat` may be a machine's. Whether a seat's key is held by a person is conduct, attested by the operator and sanctioned through the trust list (d91(f)) — §4.

**Checking a signature under a mandate** — offline, with the mandate presented beside the record (`verifyAttestationRecord` does steps 1–4):
1. the mandate's envelope verifies under its `principal`, which is the party the record names — the issuer for `mandate`, the counterparty for `counterpartyMandate` — and `hash` is the SHA-256 of its payload bytes;
2. the record's signing key is the mandate's `delegate.key`;
3. the record's kind, outcome, tag, profile and reference fall inside every bound the scope names;
4. the record's **claimed** time falls inside `dates` — the check says so;
5. the record's **witnessed** time falls inside `dates`, and the mandate's status is not revoked — both need what the check is not given (the trust log, the status list) and are listed in its `notChecked`.

### 1.5 Rule

**Lives today:** `kash.rule@1.2.0` — criteria as OpenID4VP DCQL plus a DMN FEEL condition, reasons, renewal, the address ([rule.md](../rule.md)). A rule reads the new type through its query as it reads any other — `vct_values: ["https://kashscript.com/vct/attestation/1"]` for a copy, `dst_values: ["application/vnd.kash.attestation+json"]` with `attestation: countersigned` for a record of truth.

**Gap, filled in predicate's validation, not the lexicon:** node rule 10 — *no rule may ask for a refusal* — covered only decision receipts. **A query for an attestation must now pin its outcome to `accepted`**: `["attestation","outcome"]` on a copy, `["outcome"]` on a record of truth, or the rule is refused (`ASKS_FOR_A_REFUSAL`). A not yet, a finding or a contest is never something a door asks to see against someone (P4.2, d43). Recognition between rules exists only as unread context (`givens.relations.recognises`) — §4.

### 1.6 Decision

**Lives today:** `kash.decision@1.1.0` in predicate, issued as an SD-JWT VC (`vct …/decision/1`) to the person ([decision.md](../decision.md)). It maps onto the algebra without change:

| Algebra | Decision |
|---|---|
| issuer | the deciding organisation — the rule's author, or the anchor under an adoption |
| reference | the rule, `{id, version, hash}` (public), and the adoption |
| outcome | `yes` → accepted · `not-yet` → not yet · `no` and `partial` → refused, by a named person only |
| what it relied on | `reliedOn` — hashes, never content |

**Gap:** a person's decision carries two signatures — the organisation's on the copy and the seat's over the body — and the seat's is not the organisation's own. It cited no mandate.

**Filled by `kash.decision@1.2.0`:** a person's `decidedBy` may carry `mandate: {id, hash}`, and the seat signs the citation with the body. `validateDecision` refuses a citation not under the deciding organisation (`MANDATE_MISMATCH`). **With the mandate presented beside the decision, it checks it whole** — the organisation's, signed by it, to this seat, a seat's (never an agent's or a desk's, d91(f)), covering this outcome, in force at the decision's time — and **without it, reports the mandate as not checked**, never as passed. Every 1.1.0 body is a 1.2.0 body; 1.1.0 stays frozen and refuses the field. **A standing decision cites no mandate:** its copy is signed by the deciding organisation's own key (`issueDecision`), so nothing signs under a mandate there — a desk signing with a key of its own is §4.

### 1.7 Witness

**Lives today:** the trust log — an RFC 9162 Merkle log any host mirrors, attestations entered by salted hash, heads stamped by OpenTimestamps and RFC 3161 (`attest/src/log`, `attest/src/witness`, [trust-log.md](../trust-log.md)). **No gap in the kernel:** a record's `claimedAt` is the signer's claim; what stands is the time of the first witnessed head holding its salted hash (d91(a)). The witness travels *beside* a record — a `kashscript-log-inclusion/1` proof — because nothing can carry its own witness inside its signed bytes. Oreoasis today witnesses its chain tip, not each record; that is the engine's to change.

### 1.8 Status

**Lives today:** W3C Bitstring Status Lists aligned in `kash.status-list@1.1.0`, with d91's terminal states — expired by the clock, superseded, withdrawn — and revocation and suspension ([holder contract](../holder-contract.md) §4). **Filled here:** `supersedes` in the attestation names the content id of the record it corrects, so *superseded by a citing attestation* (d91(a)) has a citation to follow. **Only the same issuer, about the same kind, with the same counterparty, and with both signatures, supersedes a record** — `verifyAttestationRecord` checks it when the superseded record is presented, and says it did not otherwise. No hash is ever deleted; content may be.

### 1.9 The records already signed, in the algebra

Nothing already signed is re-signed or re-wrapped ([holder contract](../holder-contract.md) §0). Each keeps verifying under its own verifier; this is how each reads in the algebra:

| Record | Issuer | Kind · outcome | Reference | Signatures |
|---|---|---|---|---|
| Oreoasis work record + countersign bundle (Client Sign-off, a booking) | the Org (`actor.id`) | receipt · accepted | `meta.reference` (keccak or SHA-256, untyped) | the Org's, and the counterparty's acceptance binding the subject's digest |
| Oreoasis chain consent (`engagement.subcontract-consent/2`) | the prime | receipt · accepted, by the client | SHA-256 of the scope's five fields | the prime's, and the client's at grade 1 |
| predicate credential (`vct …/predicate/1`) | the establishment | assurance · accepted | the rule `{id, version, hash}` | the issuer's on each copy |
| decision (`vct …/decision/1`) | the deciding organisation | decision | the rule, the adoption | the organisation's on the copy; a seat's over the body |
| booking mandate (an RFC 9068 token) | the Org | — a mandate no record carries | scopes | the Org's |

## 2. The profile — one record, three forms

### 2.1 The body — `kash.attestation@1.0.0`

| Field | Meaning |
|---|---|
| `issuer` | the party who answers for it and whose book issues it — a `did:kash` or a `did:web` |
| `kind` | `receipt` · `finding` · `assurance` · `contest` |
| `outcome` | `accepted` · `not-yet` · `refused` · `finding`, as §1.3 allows for the kind |
| `reference` | `{kind, sha256, id?, version?}` (§1.2) |
| `statement` | plain words, at most 280 characters, about the work, the deviation or the grounds |
| `profile` | the job, as `name/version` — `client-signoff/1`, `booking.delivered/1` (d91(a): conformity and flow are profiles) |
| `counterparty` | the other side, whose own signature over the same bytes completes the record — a person's key for this one relationship, or an organisation signing as itself (a `did:web` only at grade 3). **Written when the counterparty answers, never before (§2.3); never in a copy** |
| `mandate` | `{id, hash}` — when a delegate's key signed for the issuer (§1.4) |
| `counterpartyMandate` | `{id, hash}` — when a delegate's key signed for the counterparty: a client company's employee, a person's agent. **Never in a copy** |
| `grade` | the counterparty's signing ceremony, as the issuer's flow ran it: 0 practice only · 1 a passkey on the issuer's approval domain · 2 device-bound · 3 the organisation itself (d91(d)). Required on a receipt or a finding outside practice |
| `claimedAt` | the signer's claim of when; the witness decides (§1.7) |
| `expiresAt` | required — every record can expire (d27.5) |
| `supersedes` | the content id of the record this one corrects (§1.8) |
| `contests` | a contest's: the content id of the decision copy it contests (§1.3) |
| `credentialStatus` | the record of truth's own `BitstringStatusListEntry` |
| `reasons` | codes: what is missing for a not yet, a contest's grounds, a finding's class |
| `practice` | `true` on everything before its gate |

**The shape is closed:** no field for a score, a rating, a name, a contact or a free payload, and any field it does not name is refused. **`statement` is still free text**, and §2.2 says exactly what is read out of it.

### 2.2 The rules a shape cannot write

`checkAttestation` and `checkMandate` (`@kashscript/attest/attestation`) run the shape, then these. Pure: no clock, no key, no network.

**The attestation:**

| Code | The rule | Decision |
|---|---|---|
| `OUTCOME_FOR_KIND` | the outcomes §1.3's table allows; a receipt is never refused | d91(a), d49, d84 P3 |
| `REFERENCE_FOR_KIND` | the references §1.3's table allows; a contest against a rule | d91(a), d43 |
| `PUBLIC_REFERENCE` · `PRIVATE_REFERENCE_ID` | a rule or standard by id, version and hash; a private reference never by a book's id | d91(a), d41 |
| `CONTESTS` | a contest names the decision it contests; nothing else does | d91(a) |
| `COUNTERPARTY_FOR_KIND` · `COUNTERPARTY_IS_ISSUER` | a receipt and a finding name the other side, who is not the issuer; a contest names none | d41, d43, d26 |
| `COUNTERPARTY_WEB` | a `did:web` counterparty is an organisation signing as itself, at grade 3; a person signs with a key for this relationship alone | d41, d62(d)2–3 |
| `COUNTERPARTY_MANDATE` | a counterparty's mandate is one the counterparty granted | d91(a) |
| `GRADE_REQUIRED` · `GRADE_WITHOUT_COUNTERPARTY` · `GRADE_ZERO_PRACTICE` | outside practice a receipt or finding states its grade; the grade is the counterparty's ceremony's; grade 0 only in practice | d91(d) |
| `REASONS` | a not yet says what is missing; a contest gives its grounds | d85(e) |
| `DATES` | it expires after it is made | d27.5 |
| `MANDATE_PRINCIPAL` | a cited mandate is the issuer's | d91(a) |
| `PERSON_IDENTITY` | the statement holds no link, no DID and no email or phone number; a public reference's id holds no email or phone number | d41; the floor |

**What is not read out of a statement:** a person's name, or a judgement written in words. The statement describes the work, the deviation or the grounds, and its issuer answers for it; a vocabulary would catch the obvious and miss the rest (rule.md §4.3 says the same of rules). §4.

**The mandate:**

| Code | The rule | Decision |
|---|---|---|
| `ID_PRINCIPAL` · `DELEGATE_IS_PRINCIPAL` | its id is under its principal; a principal signing as itself needs none | d91(a) |
| `SCOPE_EMPTY` | it names the kinds, outcomes, tags, profiles or references it covers | d91(a): with scope |
| `MACHINE_REFUSAL` | an agent's, a desk's or another organisation's mandate names its outcomes, never *refused* | d91(f), d84 P3 |
| `AGENT_SCOPE` | an agent's mandate names its kinds, and they are receipts | d88, d84 F, d43 |
| `DESK_DECIDES_ONLY` | a desk's mandate is for decisions only | d91(a), d84 P3 |
| `DATES` | it ends after it starts, within 366 days | d43 |
| `PERSON_IDENTITY` | the role holds no link, DID, email or phone number | d97: a seat is a sign-in with a mandate, never a file on a person |

The status entry is required by the shape, not by a rule.

### 2.3 Form 1 — the record of truth

A DSSE envelope ([countersign](../countersign.md), Sigstore-compatible): `payloadType` **`application/vnd.kash.attestation+json`**, payload the body in **RFC 8785 canonical form**, signatures over `PAE(payloadType, payload)`.

**How it is made — the counterparty answers first, the issuer signs last.**
1. The issuer's flow puts a request to the other side. **The request names no counterparty** — as countersign's request does not (countersign.md, *the request names no counterparty*) — and nothing is signed that names one.
2. The counterparty answers. Their key is made or chosen at that moment (grade 1's passkey on the issuer's approval domain is made then). If they accept, or say *not yet* with their own reasons, the body is written with their key, their grade and their outcome, and they sign its final bytes.
3. The issuer — or its delegate, citing the mandate — signs the same bytes. The record exists from that moment, with both signatures.
4. **A request that is declined, ignored or left to expire leaves nothing**: no record, no body, no counterparty key in the book. **A body signed by one party alone is not a record** — it is discarded, never logged, copied or counted (d49: a decline by either party means no record, and leaves no trace).

The order of entries in `signatures[]` carries no meaning. **attest's countersign ceremony, as built, does not make this record:** its request binds a subject the holder signed *before* the request, while here the body names the counterparty only after they answer. Adapting it — a request over the proposal's digest, the final body adding only the counterparty, the grade and the outcome — is the engine's, with RW-24; until then the ceremony keeps making the records §1.9 maps.

**Its content id** is the SHA-256 hex of the payload bytes (`payloadSha256`), as a rule's hash is: what `supersedes`, a mandate citation and a copy's `record` name.

**Who holds it:** its parties — the issuer's book and the holder. It names the counterparty's key, so it travels to a verifier only when its holder sends it, through a `kash-artifact` query ([rule.md](../rule.md) §2.1, §6).

**The stranger's check — `verifyAttestationRecord(record, {resolveKey?, mandate?, counterpartyMandate?, superseded?})`**, offline:
- the tag is registered (`WRONG_TYPE`); the payload is JSON (`MALFORMED`), is a body that passes `checkAttestation` (`ATTESTATION_INVALID`), and is that body's canonical form (`NOT_CANONICAL`);
- the issuer's signature checks, or the delegate's under the cited mandate presented beside it (`ISSUER_SIGNATURE`, `MANDATE_MISSING`, `MANDATE_INVALID` — §1.4 steps 1–4);
- the counterparty's signature checks, or its delegate's under its mandate (`COUNTERPARTY_SIGNATURE`; the same mandate codes) — **one signature is a request, not a record** (d41);
- a supersession has its authority when the superseded record is presented (`SUPERSESSION`, §1.8);
- **`notChecked` always names** the witnessed time, the status, and the counterparty's independence — and the supersession's authority when the old record is absent. A check that cannot decide says so; it never passes by silence.

**What two signatures do not show.** A signature shows a key, not who holds it. At grade 1 the counterparty's key is made on the issuer's own approval domain, so an issuer could make one itself and countersign its own record. d91(d) names the defence: a third signal — a payment through a connector, an assessor's assurance. A grade-3 counterparty, an organisation listed as itself, is the strong case. §4.

**Why a new tag, not a profile.** d59(e) prefers a profile over a registered type to a new tag. The only candidate is Oreoasis's work record, an engine's own shape; the open protocol does not pin its one record type to one engine (d91(e): *accept a receipt from an engine it does not run*). So three rows are appended to attest's registry: the record, the mandate, and the copy's `vct` (ADR-0031).

### 2.4 Form 2 — the presentation

An **SD-JWT VC** (`typ: dc+sd-jwt`), **`vct https://kashscript.com/vct/attestation/1`**, presented through OpenID4VP with a KB-JWT over the verifier's audience and nonce, exactly as [presentation.md](../presentation.md) §3 checks it.

- **Made only from a record of truth that checks.** `copyClaimsOf(record, copy, opts)` runs `verifyAttestationRecord` first and refuses a record that does not check — so an unanswered request can never be copied as *accepted*.
- **Issued by the issuer's own key**, never a delegate's: attest refuses a copy whose key is not `iss`'s (`KID_NOT_ISSUER`). **One copy per verifier**, each with the holder's key for that verifier alone in `cnf` (d62(d)3), its own salts, and its own dates. Its `_sd` is padded with decoys to eight digests (`COPY_SD_SLOTS`; `copyClaimsOf` returns the count for `issueSdJwt`), so the array's length does not tell a record with a supersession, a mandate or reasons from one without.
- **A copy is the issuer's word** that the record of truth exists with its signatures. It does not carry the counterparty's signature, because that names the counterparty's key, which would join every copy. **So a copy is evidence only where the issuer's word is what a door relies on:** a host's book saying a stay was delivered and accepted, an assessor's finding the doer shows. **Where the issuer is also the holder — an agency showing its own sign-offs — a copy is self-attestation (d26)**: a door that needs the other side's acceptance reads the record of truth through a `kash-artifact` query with `attestation: countersigned`, never a copy. The format cannot see who holds a copy — its key is fresh by design — so this rule is the issuer's to keep and the door's to know (§4).

| Claim | Visibility | Why |
|---|---|---|
| `iss`, `vct` | visible | the issuer and the type — every holder of the kind shares them |
| `iat` | visible — **the day the copy is issued** | so two copies issued apart share no second |
| `exp` | visible — **the copy's own**: `iat` plus its lifetime (90 days, `COPY_LIFETIME_DAYS`, the same for every copy of a kind) | so no copy carries anything of its record's dates, which for a small issuer would join every copy of one record. A record that ends before a copy's lifetime would gets no copy: a shorter one would carry the record's end |
| `_sd` | visible — **always eight digests**, real or decoy | so its length says nothing about which claims a record carries |
| `cnf.jwk` | visible | this copy's key, for this verifier only |
| `credentialStatus` | **none, by recommendation** | a bit on a copy can be set only by an issuer that keeps which index belongs to which record — copy material §3 asks it not to keep — and a verifier fetching the list tells the issuer who checked, and when. Never the record's own entry, which every copy would share |
| `attestation` | visible | `{kind, outcome, profile?, grade?, practice?}` |
| `reference` | visible if **public** | a rule or standard everyone answering to it shares |
| `reference` | **selectively disclosable** if **private** | the per-copy salted commitment: the disclosure's salt is fresh in every copy |
| `statement`, `claimedAt`, `record`, `mandate`, `supersedes`, `contests`, `reasons` | **selectively disclosable** | each could join two copies of one record: free text, an exact time, the record's content id, a mandate's hash |
| `counterparty`, `counterpartyMandate` | **never** | `cnf` stands in their place |

**What disclosing costs:** any value disclosed to two verifiers links the two presentations — the record id above all — which is the holder's choice ([presentation.md](../presentation.md) §4). Against the issuer's database, one disclosed value is enough to name the record. **What a copy without status costs:** a copy of a record that is later superseded or withdrawn stays readable until it ends — at most 90 days. A verifier that needs current status asks for the record of truth, and links (§3 G1, §4).

### 2.5 Form 3 — the W3C VC 2.0 projection

A deterministic, **unsecured** credential in the [VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) data model, for software that speaks it: `projectVc(view)`.

| VC 2.0 | From |
|---|---|
| `@context` | `["https://www.w3.org/ns/credentials/v2"]` only — its issuer-dependent `@vocab` names the rest, so nothing needs hosting |
| `type` | `["VerifiableCredential", "KashAttestation"]` |
| `issuer` | `issuer` |
| `validFrom` · `validUntil` | `claimedAt` (or a copy's day of issue) · the copy's `exp` |
| `credentialSubject` | `kind`, `outcome`, `profile`, `grade`, `reference`, `statement`, `reasons`, `mandate`, `supersedes`, `contests` — as far as the view holds them. **No `id`, and never the counterparty**: a receipt's claims are about the work, not the party who accepted it |
| `credentialStatus` | the native `BitstringStatusListEntry` |
| `relatedResource` | when the record id was disclosed: the record of truth's payload bytes, named by RFC 6920 `ni:///sha-256;…`, with `digestSRI` over those same bytes — not over the envelope around them |

- **It proves nothing by itself.** It carries no securing mechanism, so it is a credential in VC 2.0's data model and not a verifiable one; a verifier checks the copy, or the record of truth `relatedResource` names. Securing it — VC-JOSE-COSE, or Data Integrity proof sets, which could carry two parties' proofs over one credential — is §4.
- **Project from the copy a viewer was given.**

### 2.6 The decision's forms

The decision keeps its record and its copy (§1.6): the body, signed by a seat when a person decided, inside an SD-JWT VC issued by the deciding organisation. `kash.decision@1.2.0` adds the mandate citation inside a person's `decidedBy`, which the copy already makes selectively disclosable. No DSSE form and no projection are defined for it here (§4).

### 2.7 The worked examples — `examples/`

Generated once (`packages/attest/scripts/attestation-examples.ts`, `packages/predicate/scripts/decision-example.ts`) and **never regenerated** — with one recorded exception: the attestation examples were regenerated on 2026-11-19, inside RW-14 and before anything was exported, when part two's review found the first copies' `_sd` length and dates could join them (§3 G1). Keys were made fresh and thrown away: the files hold public identifiers and signed bytes, no key material. Every party is SAMPLE and every record `practice: true`. Each record's folder holds `body.json`, `record.dsse.json` and `context.json`; a record shown in all three forms adds `copy.sd-jwt.txt` (every disclosure), `presentation.sd-jwt.txt` (to a SAMPLE verifier, disclosing what `context.json` lists) and `projection.vc.json`.

| Example | Shows |
|---|---|
| [`receipt-client-signoff/`](examples/receipt-client-signoff/) | a client company accepts an agency's delivery through one employee's seat, citing its mandate (`counterparty-mandate.*`); grade 1. **No copy:** the agency holds its own sign-off, so a door reads this record of truth |
| [`receipt-not-yet/`](examples/receipt-not-yet/) | the same client's *not yet*, with what is missing — the client's words, written when the client answered |
| [`receipt-booking/`](examples/receipt-booking/) | a host's book issues a delivered stay, the guest accepts at grade 1 and keeps it, and shows a review door a copy that discloses nothing private |
| [`supersession/`](examples/supersession/) | the host corrects the dates: a new record, both signatures, citing the first; the copy discloses the citation |
| [`mandate-seat/`](examples/mandate-seat/) | an assessor's mandate to one seat: findings only, until 2027-10-31, revocable |
| [`finding-under-mandate/`](examples/finding-under-mandate/) | the seat signs a finding under that mandate; the doer countersigns, keeps it, and shows an employer a copy the assessor issued |
| [`decision-person-mandate/`](examples/decision-person-mandate/) | a credit officer's seat decides under the lender's mandate (`kash.decision@1.2.0`), with the rule, the mandate and the person's copy |

**What the tests check** (`attest/test/attestation.test.ts`, `predicate/test/decision-mandate.test.ts`, `predicate/test/attestation-rule.test.ts`):
- each body passes its checks and is the canonical payload under the registered tag;
- `verifyAttestationRecord` passes with the mandates and superseded record each needs, and names what it could not decide; without a presented mandate it reports `MANDATE_MISSING`; with the other side's signature removed, the record fails and gets no copy; a wrong tag, a changed payload, a payload that is not canonical, a supersession by another counterparty, and a mandate presented for the wrong record each fail with their code;
- the signers are exactly the issuer's side and the counterparty's side, each checking with no lookup;
- each copy verifies under the issuer's key, its claims are exactly `copyClaimsOf(record)`, its dates are its own, its `_sd` holds eight digests, it carries no status entry, and nothing in §2.4's *never* or *selectively disclosable* rows is visible;
- each presentation binds its verifier's audience and nonce, fails for another audience, and discloses only what was chosen;
- each projection equals `projectVc` of what the verifier saw, fits [`attestation-vc.schema.json`](../schemas/attestation-vc.schema.json), and never names the counterparty;
- two fresh copies of one record, presented to two verifiers disclosing nothing private, share no correlator under attest's `linkabilityBetween`, and disclosing the record id links them; copies of two records of one class — one plain, one with a supersession, one with reasons — differ only in their keys, digests and signatures; copies of one record issued on two days carry different `exp`, and copies of two records issued on one day the same; a record that ends before a copy's lifetime would gets no copy;
- the decision example validates with its mandate presented and checked whole; a presented mandate to another seat, of another kind, not covering the outcome, out of its dates, or signed by another key is refused; a standing decision citing a mandate is refused;
- a rule reading an attestation not pinned to `accepted` is refused;
- the mandates carry status entries and are signed by their principals alone; the published schemas equal the definitions; no example file carries key material.

### 2.8 The conformance cases — `tck/`

One file per new version — [`kash.attestation@1.0.0`](tck/kash.attestation@1.0.0/cases.json), [`kash.mandate@1.0.0`](tck/kash.mandate@1.0.0/cases.json), [`kash.decision@1.2.0`](tck/kash.decision@1.2.0/cases.json) — each a list of `{name, body, valid, faults}`. A conforming reader runs the shape (the JSON Schema, or the definition) and then the rules of §2.2, and reaches `valid` with exactly the listed fault codes. **Every attestation and mandate fault code is exercised at least once.** The decision's cases are shapes only, run against both 1.1.0 and 1.2.0; its checks against a signed rule — the seat's signature, `MANDATE_MISMATCH` — run in predicate's tests. These sit beside predicate's DMN TCK, the upstream suite for the condition language, extracted unchanged, which cannot take cases of ours.

### 2.9 What this does not do

Make the record in a ceremony, issue copies at scale, serve proof pages, check a chain of mandates, or re-sign anything already signed · move an engine onto the record (RW-24) · salt the references of the record kinds already in use (RW-15) · publish anything · invent a format where a standard speaks (d71).

## 3. The privacy games

Four games, as RW-14 asks and due diligence named them (DD C6, C7; DDA C-3). Each says:
- the setting;
- what the adversary holds;
- the game, as a test could run it;
- the property claimed;
- the bound, said plainly, including where today's code fails it;
- what checks it today, or the words **not yet checked**.

A game is the claim's acceptance test. A design that loses one says so here, not in a footnote. Part two's adversarial review found the first copies losing G1 — their `_sd` length and their dates gave records away — and the fix is in §2.4.

**Terms.**
- A **relationship** is a person's key with one counterparty (d41).
- A **class** is the set of copies that look alike to anyone without a disclosure. They share the issuer and its `kid`; the `vct`; the `attestation` head (kind, outcome, profile, grade, practice); a public reference; the copy's `iat` and `exp` days; the `_sd` count, fixed at eight (§2.4); a status list's URL, if a copy carries one; and the type of the holder's key in `cnf` (Ed25519 or P-256).
- **The issuer's database** is everything an issuer keeps at rest:
  - every record of truth it signed;
  - the keys its counterparties used with it;
  - what it knows of each counterparty outside the record, such as the channel it sent a one-time code to;
  - its status lists and log entries;
  - its servers' logs: copies issued again, proof pages viewed, status lists fetched, approval pages opened.

  Where an engine holds organisations' keys and books (hosted custody, d97(g)), it is the operator's database, across every organisation the operator hosts.

### 3.1 G1 — a person's relationships cannot be linked across verifiers who do not collude

- **Setting.** A person holds attestations — a stay a host's book issued, a finding they countersigned — and shows them to verifiers, each through a relationship of its own. Each copy is made for one verifier (§2.4); copies are often issued in a batch when the record is handed over ([presentation.md](../presentation.md) §4). The verifiers do not pool what they receive.
- **The adversary holds:**
  - the issuer's database, as defined above;
  - every proof page ever served, as if every link had leaked;
  - everything public: trust lists, status lists, the trust log.

  It does not hold what any verifier received through OpenID4VP.
- **The game.**
  1. The challenger picks a class, and the days on which copies are issued and shown.
  2. It shows the adversary two presentations from that class, each disclosing nothing beyond the class. Either one counterparty is behind both, or two different ones are.
  3. The adversary wins by saying which.

  **The property:** the adversary does no better than the class's make-up allows. With *n* records of the class from *n* different counterparties, that means guessing. With a class of one, it always wins.
- **What the property rests on:**
  1. **Nothing visible differs within a class.** By construction, a copy shows its class and nothing else. Its dates are its own and not its record's; its `_sd` is padded to eight digests; and everything else is behind a disclosure under a fresh salt (§2.4).
  2. **A page shows nothing behind a disclosure to anyone but its holder.** That is the per-copy salted commitment. RW-15 builds it for the record kinds already in use; this record has it from the start.
  3. **The issuer keeps nothing that ties a copy, a view or a person to a record:**
     - no copy's salts, digests, key or status index;
     - no map from link to page;
     - no log of views or copies issued again, keyed to records;
     - no counterparty contact detail in clear.

     With any one of these, its database names the record and the person behind a page.
- **The bound, said plainly.**
  - **Within a class only.** The adversary learns each class's size from the issuer's database, and anyone can learn it from the trust log (below). Copies issued in a batch at handover make a class small: *records of this kind handed over that day*. Coarser dates widen it, at a cost in staleness (§4).
  - **Rule 3 rests on the issuer's conduct, not on cryptography.** The issuer mints every SD-JWT copy, and sees every salt and key as it signs. Only a presentation the holder derives — the ZK tier — removes that trust (G2).
  - **A proof page made for each viewer and served from the issuer's origin cannot pass G1 at all.** The server needs a stored map from each link to its page, and it sees every view. Only a page that carries the copy in the link's fragment, and checks it in the viewer's browser, keeps no state. Oreoasis's approval page (`openApproval`) already works that way for approvals.
  - **The printed receipt** (d91(c)) is one artefact shown to every viewer, so it links by construction.
  - **The trust log publishes a series.** It holds one entry per attestation logged — the issuer, a salted hash, and the claimed time to the second (trust-log.md §1). d91(a) asks for every attestation's hash there, so each issuer's event series, and every class's size, would be public. **The founder ruled on 2026-11-20 that attestations are entered per period, behind a padded root** (d91's dated note); KS-Q7 designs it, and until then none is entered one by one. §4.
  - **Contact channels in clear.** Oreoasis keeps a grade-1 reviewer's channel address in its tables. Under hosted custody, one address links a person's relationships across every organisation the operator hosts, whatever their keys. That is the strongest attack on d41, and G1 does not hold against an operator's database while it stands. §4.
  - **The holder's key type** — Ed25519, or P-256 in a phone's secure chip — is visible in every copy and the same across one person's copies. It splits every class by device. §4.
  - **Revocable copies break rule 3.** To revoke one copy, its issuer must keep which index belongs to which record. So a copy here carries no status entry and lives 90 days (§2.4). A verifier that needs current status asks for the record of truth, which links.
  - **A copy's witness.** A copy cannot carry its record's log inclusion proof, which would show the salted entry. So a verifier relying on d91(a)'s witnessed time asks for the record, and links. §4.
- **Holds today.** Two copies of one record, disclosing nothing private, share no correlator, and copies of two records of one class differ only in their keys, digests and signatures. Checked by:
  - `attest/test/attestation.test.ts`:
    - *two copies of one attestation, shown to two verifiers, share nothing to join on*;
    - *copies of two records of one class differ only in their keys, digests and signatures*;
    - *no copy carries its record's dates*;
  - `attest/test/sd-jwt.test.ts`;
  - `attest/test/exchange.test.ts` (*A and B — two copies to two verifiers — share nothing that links them*);
  - `predicate/test/hiring.test.ts`, where the one value two viewers share is the level every holder of that level discloses alike.

  These tests check conditions the game needs, not the game itself.
- **Fails today:**
  - **Proof pages as built.** Oreoasis's proof page carries `recordIdOf` of each countersign bundle, the same for every viewer, and the bundle names the counterparty's key (DD C6; d62(d)3's honest line). Pages served per viewer cannot pass in any case (above).
  - **The trust log's series** and **the operator's contact channels**, above.
  - **A `kash-artifact` packet** carries the raw record, which links by its own bytes, and the record's id in its binding (`predicate/src/packet.ts`). That is d62(d)3's honest line until the ZK tier. Both kinds of binding also carry the presentation's time to the second. Freshness needs it, and it belongs to that one presentation; timing at the network is G2's.
- **Not yet checked:**
  - the game itself, run end to end;
  - the issuer's retention, which is conduct;
  - class sizes in practice.
- **RW-15's test** says *two presentations of one receipt to two verifiers share no common string beyond the issuer's key and the profile name*. This spec reads it with the class: what every copy of a class shows — kind, outcome, grade, the copy's dates, the key type — is the class, not strings to remove. **The founder confirmed that reading on 2026-11-20** (d91's dated note); the prompt's words are unchanged.

### 3.2 G2 — what verifiers who collude can and cannot learn, without the ZK tier

- **Setting.** Verifiers pool everything they received: presentations, packets, attached records. There are two cases: (a) the verifiers among themselves, without the issuer's database; (b) the issuer with one or more of them.
- **(a) Verifiers alone.**
  - **They cannot learn,** within a class of more than one, that two copies are the same person's. Pooling adds copies, and each copy's key, salts and dates are its own. In a class of one, every copy is the same record, and they learn it.
  - **They can learn:**
    - whatever the holder disclosed identically: a private reference; the record id, which a rule counting several SD-JWT receipts requires (rule.md §2.1, `COUNTS_COPIES`); a decision's `reliedOn`; a seat's `decidedBy` and its mandate; a distinctive statement or reason;
    - any record of truth or countersigned bundle shown raw, which names the counterparty's key (d62(d)3);
    - the holder's key type, the same across one person's copies;
    - a relationship key used twice, which the wallet refuses to send and the holder's log flags;
    - the network's metadata — address, timing, the key binding's time — which the protocol does not hide.
- **(b) The issuer with a verifier.** An issuer that keeps its copies — their signatures, digests or keys — links every presentation of them to its record, and so to the counterparty. One that keeps nothing learns from a presentation only its class and what was disclosed. That it keeps nothing is conduct: SD-JWT cannot enforce it, and no test can show it.
- **What the ZK tier would add:**
  1. **Presentations the issuer cannot link.** The holder derives each one from a credential whose signature can be re-randomised (BBS, CL), so even an issuer that kept everything cannot recognise its own copy.
  2. **A countersigned record without the counterparty's key:** a proof of two valid signatures over the record that does not show who signed second. This is d62(d)3's *tier-two circuit*.
  3. **Predicates without disclosure:** *accepted within 24 months*, without the date.

  identity-zkp's circuit today proves membership in a list (d59). It does none of these.
- **Checked today:**
  - `linkabilityBetween` reports the correlators it knows: the same issued copy, the same holder key, the same digests or salts, the same status index, a second-precise `iat`, a `jti`, a disclosed value (`attest/test/sd-jwt.test.ts`). It does not look at `exp`, the `_sd` count, the header, the key type or the key binding; this profile fixes the first three by construction (`attest/test/attestation.test.ts`), and §4 lists the key type;
  - the holder's log flags a copy or a key shown to a second verifier (`validatePresentationLog`, `attest/test/exchange.test.ts`);
  - the wallet refuses to send another relationship's identifier (`wallet/test/transport.test.ts`: *another relationship's key — or the root — stops it before sending*).
- **Not yet checked:**
  - what an issuer keeps. It turns on conduct, not format;
  - network metadata.

### 3.3 G3 — the audit's published series cannot re-identify anyone

- **Setting.** The audit (d85(f), d91(f), d95) publishes issuers' totals — by rule or profile, by outcome, by period — committed to a public log, so anyone can recompute them. d93's third note already sets one series: a host's signed visits for the last 90 days and the last 12 months by month, a count below *k* = 5 shown as *fewer than 5* (d97(i)).
  - **The audit has no code.** d97(i) says it publishes no series until its bound is designed, and d95(d) puts that before IN-Q4 publishes anything.
  - **The trust log is already a series.** It holds one entry per attestation logged, with its issuer and its claimed time to the second, and no noise (G1).
- **The adversary holds:**
  - every series anyone published — the hosts' counters, the audit, the trust log;
  - every public record, and public reviews with their dates;
  - every other contribution to the series — the strong adversary differential privacy assumes.

  It wants to learn whether one relationship contributed, or what its outcome was.
- **Why suppression alone fails.** Suppressing each cell below *k* hides the cell, not its arithmetic:
  - **Subtraction across a total.** Take twelve months and their total, each suppressed below 5 on its own. If one month is under 5, and the other months and the total are shown, the total minus the shown months is the hidden month. **Indusland's counter does exactly this in code today:** `packages/doors/src/server/review-door.ts` suppresses `last12Months` and each month independently (`shown(…)`, *k* = 5) `[v 11-19, read]`. d95(d) and DD C7 recorded the leak on 2026-11-09; what is new is that it is now built.
  - **Differencing across time.** That counter computes `last90Days` again on every read, over a window that rolls by the millisecond. Anyone who polls it sees each acceptance as it happens. A daily rolling total does the same over a season.
  - **What else is public.** Reviews are public one by one, with their dates, so they put a floor under any suppressed month.
  - **Differencing with what is known.** An adversary who knows every other contributor learns the last one from any exact count, suppressed or not.
- **The claim differential privacy would give.** A mechanism M publishes noisy counts such that, for any two histories H and H′ that differ in **one unit's** contributions, and every set S of outputs: Pr[M(H) ∈ S] ≤ e^ε · Pr[M(H′) ∈ S] + δ.
  - **It covers every series a contribution enters** — a stay counted in the host's visits, the audit's totals and the trust log is counted three times — and all of them over a stated horizon. Budgets add across all three.
  - **A unit's contributions are bounded over the horizon:** at most *c* records in total, and sums clipped to a range. A bound per period does not bound the loss over many periods. d89's sums need the clip.
  - **Overlapping windows compose.** The simple correct design is to add noise once to each disjoint month and publish longer totals — 90 days, 12 months — as sums of the noisy months. That is post-processing, and costs no extra budget. A continual-release mechanism — the binary-tree counter of Dwork, Naor, Pitassi and Rothblum (2010) and of Chan, Shi and Song (2011) — does the same for a running count, with error growing about as log^1.5 of the horizon.
  - **Noise is drawn once per cell and served again.** A counter that draws fresh noise on every read lets a patient reader average the noise away.
- ***k* as display.** *k* is then a display rule applied to the **noisy** count: a noised value under 5 shows as *fewer than 5*. That is post-processing, which keeps the guarantee. Suppressing on the raw count does not, because which cells are hidden is itself a function of the raw data. **It changes what a shown number means:** under noise, a shown 7 can be a true 2. d91(f) says *small counts suppressed*; **the founder ruled on 2026-11-20: noise first, then *k* = 5 as display, and the page says its numbers are noisy** (d91's dated note).
- **The bound, said plainly.**
  - **The unit is a relationship, not a person.** An issuer sees a person only as a key for that relationship. A person with *r* relationships across issuers contributes to *r* units, and group privacy then gives *r*ε, with δ growing too. *r* cannot be capped, because relationships are unlinkable by design. The person-level guarantee is per relationship, and says so.
  - **Recomputing and adding noise pull against each other.**
    - d85(f) and d91(f) ask that anyone can recompute the totals, and KS-Q7's plan commits *each period's totals by outcome* beside a Merkle root of salted receipt hashes. **Exact totals in a public commitment are not differentially private.**
    - **A Merkle root gives away its own count:** every RFC 9162 inclusion proof carries the tree's size. So *exact totals only for holders and auditors, under inclusion proofs* holds only if the tree is padded with dummy leaves. The trust log's tree is the same.
    - The ways through are §4: a padded tree; noise from a committed seed revealed to auditors; or verifiable differential privacy, where the noise is proved correct (Narayan and others, 2015).
  - **The numbers are the founder's:** ε, δ, the horizon, the unit's bound, and the windows (d97(i): *k* = 5 for display; the bound stays open with KS-Q7). d93's third note set the windows, so changing them is his.
- **Not yet checked:**
  - Nothing is published by an audit, and no audit code exists.
  - Indusland's counter and the trust log publish today, and the attacks above apply to both.

  **KS-Q7 takes this game as its acceptance test** (REAL-WORLD part 2, decision 3): a subtraction attack that must recover nothing, and a privacy accountant that sums ε across every series a contribution enters.

### 3.4 G4 — a decline leaves no trace

- **Setting.** A request reaches a person — an approval link for a receipt, a door's request for a packet, an ask, an offer — and they decline.
- **The adversary holds:**
  - what the asker holds;
  - the operator's every database and log, the trust log and the status lists;
  - the network at the operator.

  It is not someone standing beside the person.
- **The game.** There are two worlds until the request expires: in one the person reads it and declines; in the other they never open it. **The property:** the adversary's views in the two worlds are identically distributed. Declining sends nothing, writes nothing that leaves the person's device, flags nothing and counts nothing (d49(a)).
- **What the property rests on:**
  - **A decline has no format:** no `access_denied`, no log entry (presentation.md §6).
  - **The wallet fetches nothing when the person decides a request.** Requests arrive by value, and the wallet refuses one by reference; the ask library is cached; status lists are prefetched on the wallet's own schedule (holder contract §4). An unused nonce and a declined one look the same to the asker.
  - **Nothing in the record can express a decline:**
    - a receipt is never *refused* (`OUTCOME_FOR_KIND`);
    - no body naming a counterparty exists before they answer, and a body one party signed alone is discarded (§2.3);
    - no rule may ask for a refusal (node rule 10, now for the attestation too, §1.5);
    - the floor allows no refusal query (d91(h)).
- **The bound, said plainly.**
  - **It does not hide that a request went unanswered.** The asker knows it asked. Declining and staying silent look the same, and both differ from accepting.
  - **On the device.** The person's own proof switch (d49(a)) is a setting stored on their device, and never sent.
  - **Offers by reference.** With the switch on, the wallet fetches an offer by reference when the person opens it, before they decide (`wallet/src/receive.ts`). For offers, *opened, then declined* can be told from *never opened*.
  - **A web approval link is weaker.** Opening it loads a page from the issuer's approval origin, which is per organisation, so the operator sees which organisation's link was opened, and when. Grade 1 then sends a one-time code, so it also sees *asked for a code*. A decline after opening looks the same as abandoning after opening — not the same as never opening. The approval page's access log is the operator's, and nothing here governs it.
  - **What today's ceremonies record:**
    - Oreoasis's flow signs its own side before the counterparty answers, and shows an unaccepted record as *issued*, never *awaiting* (Oreoasis `subcontract.ts`). That records the asking, not the decline, and it is the same whether the counterparty declined or never answered.
    - The session receipt is the same: a café's single-signed line names the person's session key, and stays *pending* when they switch off (`wallet/src/headless/scenarios.ts`).
    - Under this profile's order (§2.3), nothing is signed until the counterparty answers. **The discard rule is the spec's: no ceremony implements it yet** (§4).
  - **Timing.** A request expires on the asker's clock in both worlds. The protocol sends nothing on a decline, so there is nothing to time.
  - **What a person is seen doing** — face to face, at a counter — is outside the protocol.
- **Checked today:**
  - `attest/test/exchange.test.ts` (*has no entry for a decline*; the holder export refuses a `declined` log entry);
  - `wallet/test/doors.test.ts` (*no does nothing: no byte stored, no request sent (d49)*);
  - `wallet/test/headless.test.ts`, whose decline scenario checks that a *no* stores, sends and logs nothing, and that the café's line stays single-signed;
  - the receipt that is never refused (`specs/attestation/tck`);
  - node rule 10 for the attestation (`predicate/test/attestation-rule.test.ts`);
  - in Oreoasis's own repository, its acceptance tests (`acceptance-holder.test.ts`, `subcontract-chain.test.ts` and others).
- **Not yet checked:**
  - the approval page's open event and the operator's access logs;
  - offers fetched by reference;
  - timing.

## 4. Open problems

Each problem says where it would be settled. † marks the items a review raised (part one's or part two's) that this run did not fix.

**The record and its ceremony**
1. † **The ceremony that makes the record.** attest's countersign binds a subject signed before the request, while this record names its counterparty only after they answer (§2.3). The fix is a request over the proposal's digest, with the final body adding only the counterparty, the grade and the outcome, and a one-party body discarded. That is the engine's, with RW-24.
2. † **The grade's evidence.** `grade` is the issuer's statement of the ceremony it ran. Its evidence (a passkey assertion, the ceremony ticket) stays in the ceremony record. Binding the grade to that evidence, so a stranger can check it, is open.
3. † **The counterparty's independence.** At grade 1 the counterparty's key is made on the issuer's own domain, and a signature cannot show that the issuer did not make it (§2.3). d91(d)'s third signal — a payment connector, an assessor's assurance — has no field here yet.
4. **The counterparty's privacy in a record of truth shown whole.** The record names the counterparty's key. A host or an agency that shows the record to prove the other side's acceptance shows that key too (d62(d)3).
5. **Digest agility.** References are SHA-256 only. Oreoasis's `kash-trade:0x` keccak reference must be re-hashed or mapped when the engine moves (RW-24). A future algorithm joins as a new field, never a reinterpretation.
6. **The decision's own forms.** No DSSE form and no projection are defined for `kash.decision` (§2.6).

**Mandates**

7. † **Chains.** This version has one link (§1.4). A chain needs each link's scope and dates within its parent's, and each link signed by the parent's delegate; its depth and its revocation timing come with it.
8. † **The label is the principal's word.** The format cannot tell a machine's key from a person's: a key labelled `seat` may be a bot's (§1.4). This is conduct, attested by the operator and sanctioned through the trust list (d91(f)).
9. † **A person's mandates, one per relationship.** Under d88, a person's agent appears only under the person's identifier for that relationship. One agent key reused under several of a person's principals links them, and the format cannot see it.
10. † **A desk with a key of its own.** A standing decision is signed by the deciding organisation's own key (`issueDecision`). For a desk to sign it, the copy would need a delegate's key, which `KID_NOT_ISSUER` refuses (§1.6).
11. ~~**The conflict with d93(e)1**, which names whiffin for the host's mandate.~~ **Ruled 2026-11-20:** read as `kash.mandate`; whiffin keeps value mandates (d91's dated note).

**Copies and presentation**

12. † **Who holds a copy.** A copy's key is fresh by design, so the format cannot refuse a copy to its own issuer. An issuer copying its own sign-off is self-attestation (§2.4).
13. † **Small classes.** A copy dated to the day hides only in its class, and copies issued in a batch at handover make it small (G1). Coarser dates widen it, at a cost in staleness.
14. † **The holder's key type** splits every class by device (G1). A wallet could use one key type for all its copies of a kind.
15. † **Free text that every copy shows.** A `profile` and a public reference's `id` are the issuer's choice, and visible in every copy. A profile or a rule minted for one person makes a class of one, or puts a name in clear. A door or a trust list that accepts only registered profiles and library rules would close it (KS-Q8's library).
16. † **Copies and their status.** A status bit on a copy can be set only by an issuer that keeps which index belongs to which record, so this profile gives copies none, and short lives instead (§2.4) — **confirmed by the founder on 2026-11-20**. [presentation.md](../presentation.md) §2 gives the predicate credential's copies a status entry each; reconciling the two is open, as is a status scheme that hides which record an index belongs to.
17. † **A copy cannot carry its witness.** A log inclusion proof would show the salted entry, so a verifier relying on d91(a)'s witnessed time asks for the record of truth, and links (G1).
18. † **Copies need their issuer.** A copy is issued again from the issuer's book, and none is made in a record's last 90 days. When the issuer is gone, only the record of truth remains, which still checks (d28) and links. A copy lifetime per kind, or copies the holder derives (the ZK tier), would ease it.
19. **The issuer's retention of copy material** (G1's rule 3) is conduct, not format, and collusion with an issuer that keeps it links (G2).
20. **The ZK tier:** presentations the issuer cannot link, a countersigned record without the counterparty's key, and predicates without disclosure (G2). identity-zkp's circuit proves membership only.
21. **Correlators the holder chooses:** the record id that counting requires, `reliedOn`, a seat's `decidedBy` and mandate, a distinctive statement. The wallet's warning (presentation.md §4) is the only guard.
22. † **One use per record without the record id.** A door counting receipts needs each one's record id (rule.md §2.1), which links. A pseudonym per door, derived from the record, would let a door count each record once without seeing its id.
23. † **The `kash-artifact` packet's raw record**, and the record id in its binding (`predicate/src/packet.ts`; G1). The raw record links by its own bytes, and its binding is signed by the key the record names, so RW-15's salting cannot fix it. It is d62(d)3's honest line until the ZK tier.
24. † **Proof pages and the printed receipt.** A page made per viewer and served from the issuer's origin cannot pass G1. Only a page that carries the copy in the link's fragment and checks it in the browser can (G1). The printed receipt (d91(c)) is one artefact shown to everyone, so it links by construction. This is Oreoasis's, with RW-15.
25. † **Securing the projection** — with VC-JOSE-COSE, or with Data Integrity proof sets. Proof sets could carry both parties' proofs over one credential, and so carry d41's two signatures in a standard form, which would let a standard form be the record of truth — the condition the founder's 2026-11-20 ruling on d91(e) names.
26. † **What a statement can still carry:** a name, or a judgement in words (§2.2).

**What the operator keeps**

27. † **Contact channels in clear.** Oreoasis keeps a grade-1 reviewer's channel address in its tables. Under hosted custody, one address links a person's relationships across every organisation the operator hosts (G1). The fix is to keep the channel only as a salted hash per relationship, and to delete it once the ceremony ends. That is Oreoasis's.
28. † **Servers' logs.** Copies issued again, proof pages viewed, status lists fetched and approval pages opened each tie a person to a record in a log (G1, G4). What an issuer's or an operator's servers log, and for how long, is unwritten.

**Published series (G3)**

29. † **The trust log publishes each issuer's event series:** one entry per attestation, with its issuer and its claimed time to the second, and no noise. Every class's size is public with it (G1). The fixes are to batch entries per period behind a root padded with dummy leaves, the padding drawn from non-negative noise, or to drop or coarsen the issuer and the time. **Ruled 2026-11-20: per period, behind a root padded with dummy leaves** (d91's dated note); KS-Q7 designs the period and the padding, and until then no attestation is entered one by one.
30. **The mechanism and its numbers** — ε, δ, the horizon, the unit's bound and the windows. These are KS-Q7's and the founder's (d97(i)). Noise is drawn once per cell, never on each read.
31. **Recomputing against noise.** Exact totals in public commitments are not differentially private, and a Merkle root gives away its count. The options are a padded tree, noise from a committed seed, or verifiable differential privacy.
32. **The person-level bound:** *r*ε across *r* unlinkable relationships, with *r* unbounded.
33. ~~**What a shown number means.**~~ **Ruled 2026-11-20:** noise first, then *k* = 5 as display, and the page says its numbers are noisy (d91's dated note). KS-Q7 sets ε.
34. † **Indusland's visits counter** reveals a suppressed month by subtraction, and its 90-day total, recomputed on every read, reveals each acceptance to anyone who polls it (G3). Fixing it is Indusland's: suppress the total whenever any month is suppressed, compute the series once a day, or adopt the mechanism once it is chosen. The windows themselves are d93's third note, and the founder's.

**Declines (G4)**

35. † **What an opened request shows.** An approval page's load and its one-time code, and an offer fetched by reference, tell the operator a request was opened. What an approval origin logs, and for how long, is unwritten.
36. † **The session receipt's pending line** names the person's session key in the café's book before they answer (G4). This profile's order removes that for attestations; the session receipt keeps it.

**Rules and the scheme**

37. **Recognition between rules**, and **adoption over recognitions** (d91(c), (f)). `givens.relations.recognises` is context the evaluator never reads.
38. **The withdrawal window's number** (d84 P4.4) is the founder's. Verifiers pass it as `withdrawalWindowSec`.
39. **Naming:** what a self-certifying key is called (RW-19, branch B), and when a `did:web` organisation's key enters a trust list, so a stranger can check it offline.
40. ~~**The reading of RW-15's test** (G1).~~ **Confirmed by the founder on 2026-11-20.**

## Changelog

| Version | Date | |
|---|---|---|
| **v1.1** | 2026-11-20 | The founder's rulings on the open points, recorded (ECOSYSTEM d91's dated note): `kash.mandate` for the authority to sign; DSSE as the record of truth; the four rulings confirmed; small counts noised first with *k* = 5 as display; the trust log by period behind a padded root. No format change. |
| **v1 (§3–§4)** | 2026-11-19 | RW-14, part two. The four privacy games — unlinkability across verifiers who do not collude, what colluding verifiers learn without the ZK tier, non-re-identification from published series, a decline that leaves no trace — each with its adversary, its game, its bound and what checks it today; forty open problems. Part two's review found the first copies losing G1: `copyClaimsOf` now pads `_sd` to eight digests and gives a copy `iat` plus 90 days, refusing a record that ends sooner; copies carry no status entry; the attestation examples were regenerated before any export. Found: Indusland's visits counter reveals a suppressed month by subtraction and each acceptance to a poller; the trust log publishes each issuer's event series; Oreoasis keeps contact channels in clear (G1, G3). attest `0.3.0-alpha.1`, **not published.** |
| **v1 (§1–§2)** | 2026-11-19 | RW-14, part one. The algebra; `kash.attestation@1.0.0` and `kash.mandate@1.0.0` with `verifyAttestationRecord` (`@kashscript/attest/attestation`, attest `0.3.0-alpha.1`), three registry rows; `kash.decision@1.2.0` and node rule 10 for the attestation (predicate `0.3.0-alpha.4`); the three forms; seven worked examples; three conformance files. The adversarial review's fixes: the ceremony order, copies only from a record that checks, the copy's own dates, the contest against the rule, mandates of one link with a status entry, the counterparty's mandate, the machine floor widened to organisations and agents limited to receipts. **Not published.** |
