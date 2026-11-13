# Signed down the chain — rule, version 1

> **Before KashScript signs this rule:** `id` and `author` in [`rule.json`](rule.json) carry a placeholder, `did:kash:KashScriptDidGoesHereSwapBeforeSigning`. Replace it with the KashScript Org's own identifier in both places. That changes the rule's hash, so the hash under *Provenance* below must be updated too; the repository's test fails until it is. Nothing has been decided under this rule yet.

**What it decides, in one sentence.** When the company a client hired passes a bounded piece of the client's work to another organisation (a subcontractor), this rule says which signed records must exist before that step is shown to the client as done properly.

## The words it uses

- **The client** — the organisation the work is for.
- **The prime** — the company the client hired, and the one that answers to the client for all of the work. Under this version the prime is KashScript.
- **The house** — another organisation that does one piece of the work for the prime: a subcontractor.
- **A piece** — a bounded part of the work, with a title and a written statement of what *done* means.
- **A hop** — one step from the prime to one house, for one piece.
- **The client's scope** — the version of the work the client agreed with the prime, identified by its hash.
- **The proof page** — the page the client gets, which shows the signed records of its work and what each one does not prove.

**The name.** *Signed down the chain* means only this: each organisation that does a piece signs for it, all the way down from the client, and the client can see who did what.

## Who decides

- **Yes, by machine:** every check below is met. The hop is well-formed and may be shown on the client's proof page, under the engagement it belongs to. A yes binds no one; it only allows the hop to be shown.
- **Not yet, by machine:** a check is not met. The result names which one (C1 to C5) and what record would answer it.
- **No:** only a named person at the prime, with the reasons in writing. A machine never says no under this rule.
- **To contest a decision:** reply to the decision receipt within 30 days. A named person at the prime who did not make the first decision answers in writing within 14 days. The client may also raise it under its engagement terms.
- **Another way:** the client's consent in writing and the house's signed delivery note, on paper or by email, read by a named person at the prime.

## The five checks

Every check is about an organisation and the records it signed.

| | What must be true | The record it reads | Why |
|---|---|---|---|
| **C1** | The client accepted a consent, before the piece was passed, naming the house and the piece. | The consent: signed by the prime, accepted by the client with a second signature. It names the client's scope (by hash), the house, the piece's title, what done means, and what the house receives. The house must be a different organisation from the prime. | A client's reviewer needs to know the client agreed in advance to this house doing this piece. GDPR Art. 28(2): no sub-processor without the controller's prior written authorisation. |
| **C2** | The house signs its own work as an organisation. | The house's delivery record: it names an organisation as the one who did the work, it is signed with that organisation's own key, and that key is the one the client consented to in C1. | Each organisation answers for its own piece. Nobody signs for the house on its behalf. |
| **C3** | Each delivery cites the client's scope and the scope version it answers to. | The delivery names the client's scope (the same hash the consent names), the consent it rests on, and the version of the piece's own scope. | The piece was done inside what the client agreed. Anyone can follow the references offline. |
| **C4** | *Built with* is declared on the delivery. | The delivery's list of what the piece was built with. The list may be empty, but it must be there. | A client's reviewer asks what a piece was built with, AI tools among them where the contract asks. An empty list is an answer; a missing one is not. |
| **C5** | What the house receives is declared, and nobody's activity is monitored. | The consent lists what the house receives and states that no one's activity is monitored. | The house receives only what its piece needs. The work is proven by accepted deliveries, never by watching anyone. |

C2 and C3 read the consent and the delivery together. So anyone holding the records can recompute the yes, and check that the delivery came from the house the client consented to, within the scope it consented to.

## What this rule never asks

- **About a person.** It reads organisations and their signed records. No check names, counts, ranks or scores anyone.
- **For a refusal.** No check asks whether anyone was ever turned down.
- **About a time or a count.** No check reads a clock or a date, or counts anything.
- **About anyone's activity.** No screenshots, keystrokes, screen time, location or tracking.

## What a yes does not prove

- **That data stayed safe.** A receipt shows who was authorised, who did the work and who accepted it — never that data stayed safe.
- **The signing grade.** Each acceptance on the proof page shows how it was signed, from its own bytes: grade 1 is a passkey after a one-time code; grade 3 is the organisation signing as itself. This version of the rule does not read the grade, because it lives in the acceptance, outside the record the rule reads. A practice grade never counts, and the prime's desk reads the grade before a hop is shown.
- **That the client who accepted the consent is the client of the engagement above.** The rule checks that a second, independent party accepted the consent. The prime's book checks that it was this engagement's client when it adds the hop.
- **That the work is good.** A yes says the records are complete and agree with each other. Whether the work is right is what the client's acceptance of each delivery says.

## Why a client's reviewer asks for this

- **GDPR Art. 28(2) and (4):** a processor may not engage another processor without the controller's prior written authorisation, and stays fully liable to the controller for that processor's obligations.
- **DORA, Commission Delegated Regulation (EU) 2025/532:** an EU financial entity's contract identifies the chain of subcontractors behind an ICT service that supports a critical or important function.
- **AI use disclosed down the line:** where a client's contract asks that a subcontractor's use of AI tools be disclosed, C4's *Built with* carries it.

## Dates

- Published 2026-11-07.
- Renew by 2027-10-07.
- Ends 2027-11-07.

The rule is renewed by a new version, never extended.

## The records it reads (for implementers)

Every record is Oreoasis's registered work record (`application/vnd.oreoasis.work-record+json`), carrying two signatures. These are profiles on an existing type, never a new type.

- **The consent** — profile `engagement.subcontract-consent/1`, signed by the prime, accepted by the client. It holds five fields, and nothing else of the client's:
  - `meta.upstreamScopeHash`;
  - `meta.houseDid`;
  - `meta.pieceTitle`;
  - `meta.doneMeans`;
  - `meta.dataScope = { receives: [...], monitoring: "none" }`.

  The consent's reference is the SHA-256 of these five fields in canonical JSON (JCS), so anyone can recompute it.
- **A delivery** — the house's work record, accepted by the prime:
  - `actor = { class: "organisation", id: <the house's identifier> }`, signed by that identifier;
  - `rule = { id, version, hash }` — the piece's own scope version;
  - `meta.upstream = { ref: <the client's scope hash>, consentReceiptNo }`;
  - `meta.stack` — *Built with*.

The criteria in [`rule.json`](rule.json) are OpenID4VP 1.0 DCQL queries plus FEEL conditions, the DMN expression language: `kash.rule@1.1.0`, checked by `@kashscript/predicate`.

## Provenance

- **Decision:** ECOSYSTEM d94(c), 2026-11-06.
- **Author:** KashScript (the studio), as the prime. Written 2026-11-07 (KS-Q9).
- **Version:** 1.
- **The clause it is drawn from:** KashScript's engagement terms, the subcontracting clause, version 1, at https://www.kashscript.com/services once the site is deployed. When a second prime adopts it, the rule enters the professional guild pact.
- **Hash of rule.json:** SHA-256 of its canonical JSON (JCS), `011a3b3e4d8b495cee4441d6ad0ae610d12088002cd3bb70e6ee4d8545aa156c`. This hash is provisional until the placeholder identifier is replaced.
- **Licence:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It covers this text and [`rule.json`](rule.json); attribute it to KashScript.
