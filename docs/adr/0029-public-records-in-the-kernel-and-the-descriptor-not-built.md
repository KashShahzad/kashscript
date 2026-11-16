# ADR-0029: The public records live in the kernel as closed lexicons behind muffler's guard, and the node descriptor is not built until the one engine asks for one

- **Status:** Accepted
- **Date:** 2026-11-16
- **Decision drivers:** ECOSYSTEM d59(a) (muffler and lexicons hold public, organisation-authored records, never a person's) · d60 (a place is a DID and a path, no coordinate) · d62(d)5 (trust and status lists are signed muffler records any host may mirror) · d91 (the pact is an adoption record; the trust list is three assertions with issuer classes; a descriptor is built only if the desk needs it) · d94(b) (a workshop lists the engine's signed node descriptor) · d97(a) (one engine, two roles; RW-24 writes the plan before anything moves) · STRATEGY rule 8 (no format of our own where an open one fits) · the prompt KS-N1, as narrowed on 2026-11-02 and ordered on 2026-11-12.

## Context

KS-N1 was written on 2026-10-27 as three things: the pact record, the node descriptor, and KS-R5's public records. By the time it ran, two of the three had moved:

- **The pact** became an adoption record over rules and recognitions (d91): `kash.adoption@1.0.0`, built by KS-Q1b (ADR-0021). The eight parts VISION §3 names are carried by the rule it adopts (its address, its givens, its relations) and the recognition IN-Q5's commons will hold. A station's charter and a guild's house rule, which KS-R5 listed as lexicons, are adoptions of rules too.
- **The descriptor** was narrowed to *only if the desk needs it* (d91). The desk was then built (SPR-2) with a descriptor of its own — `application/vnd.duedale.desk-descriptor+json`, format `duedale-desk/1`, served at `/.well-known/duedale-desk.json`, signed by the organisation: its templates, its listed doors, its routes, its `response_uri` — and Oreoasis's door binding already reads that file to tie a door's answers address to the rule's author. Then d94(b) gave a kernel descriptor a reason (a workshop lists it), and d97(a) made Oreoasis the one engine with two roles, with RW-24 to write the plan before anything moves. The prompt sequence of 2026-11-12 (row 16) left the question to this prompt's own text and let PY-8 leave the slot empty and labelled.
- **The public records** were still unbuilt: `@kashscript/lexicons` held the door's rule and adoption and seven old vocabularies (`trade` among them, retired by d59); `@kashscript/muffler` had a refiner seam and no record kinds and no guard. Meanwhile their consumers had arrived: Indusland's geography holds 81 place records *unpublished because no `place` lexicon is published* (IL-V7); its listings table carries an empty `record_uri` for the signed public record d93(e)2 names; attest's trust list has the format and no publisher; KS-Q4, next in the sequence, needs the trust list and the status list as records to anchor.

## Decision

1. **The public records are the kernel's, as closed lexicons.** `@kashscript/lexicons` gains `kash.place@1.0.0`, `kash.place.pointer@1.0.0`, `kash.listing@1.0.0` and `kash.guide@1.0.0` (`./extensions/place`), and `kash.trust-list@1.0.0` and `kash.status-list@1.0.0` (`./extensions/lists`), each a closed shape with a JSON Schema in `specs/schemas/`, identified by its publisher's DID plus a path (d60), and each with the cross-field checks the schema DSL cannot write. With the door's two they are `PUBLIC_RECORD_LEXICONS` (`./extensions/public`), beside the person-identity scan `findPersonIdentity`. The specification is `specs/public-records.md`.
2. **The lists are attest's payloads in clear, not a redesign.** The trust list keeps `kashscript-trust-list/1` and writes d91's three assertions on it — identity (`class`, `grade`), standing (`listed · suspended · removed`), scope (`dsts`, `references`) — and the floor version; attest and the wallet read it unchanged today, and a suspended or removed entry must end its window so a checker that reads windows only agrees. The status list is `kashscript-status-list/1` as it is. The record's CID is the hash of the bytes attest signs. Teaching the checker standing, class, scope and the status list's three terminal states is KS-Q4's.
3. **muffler guards by kind and by content.** `createPublicRecordGuard()` admits only the public record lexicons, refuses any other collection under the protocol's namespace with a report (`PERSON_RECORD`), refuses a record that carries a person's identity in words (`PERSON_IDENTITY`) or breaks a cross-field rule (`INVALID_ATTRIBUTES`), and verifies no signature. It cannot tell a person's key from an organisation's, and says so: a key is an organisation's when a trust list says so (KS-Q4). An index rebuilt from the records alone equals the original (d28), proven by test.
4. **The node descriptor is not built now.** The desk does not need it — it publishes `duedale-desk/1` and Oreoasis binds against it. Each part a kernel descriptor would carry already has an open, published form: the records an issuer makes are its OpenID4VCI issuer metadata at `/.well-known/openid-credential-issuer`; the decision it serves, who decides, the dates and the reasons are the published `kash.rule`; its settings are the adoption's bounded parameters. What is left — a catalogue number, a consequence list, event names — has no consumer today but the internal catalogue's column. And what *the one engine* publishes about a template is RW-24's to cut (d97(a)); a format fixed before that plan is rewritten by it. The catalogue's descriptor column says what serves today; PY-8 leaves the slot empty and labelled. **If the one engine wants a kernel form,** RW-24 specifies it and a later prompt builds it with d83(b)'s validation (an automatic outcome on a decision about a person, a consequence that moves money, an output that lists people, a missing version or renewal date, an engine DID that is not the id's — refused as far as a descriptor can show).
5. **The pact is not a record of its own**, and `charter` and `house.rule` are not lexicons: all three are adoptions of rules (d91, d83(a), VISION §3). The `trade` extension is removed.

## Consequences

### Positive

- Indusland can publish its places and its hosts' listings as signed public records, and index places and listings, never people (d93(e)2); IL-V7's records map field for field.
- KS-Q4 anchors trust-list versions and issuer events in a format publishers already write, and the first trust list (d62(d)5) can be written today, citing the floor by its draft name.
- The guard makes d59's *never a person's* a tested refusal rather than a convention, and the d28 test makes mirroring a stated property.
- No third descriptor format sits beside the desk's and the issuer's metadata; RW-24 decides once.

### Negative / accepted trade-offs

- A d91-shaped trust list is accepted by a checker that does not yet read standing; the `STANDING_WINDOW` rule and the spec make that gap explicit, and KS-Q4 closes it.
- The guard refuses a phone number or an email anywhere in a public record, a host's included; a host's contact details live in its own app profile, outside the protocol. The founder may loosen this.
- The catalogue's descriptor column stays empty for now, and the practice-ready definition's fifth item (*the service's signed node descriptors in KS-N1's format*) is unmet until RW-24 says what, if anything, replaces it.
- lexicons `0.5.0-alpha.0` and muffler `0.2.0-alpha.0` are breaking in alpha (the `trade` subpath is gone; muffler's `RefineErrorCode` has two new members); Indusland's `^0.1.0` pin on muffler needs a re-pin.

## Alternatives considered

- **Build `kash.node@1.0.0` now** (engine DID, catalogue number, the decision served, settings as JSON Schema, records made, human steps, consequences in hudhud's allowlist style, events) — lost: no consumer today, three published forms already carry its parts, and d97(a) re-cuts it. Kept as the design a later prompt starts from.
- **Carry the DSSE envelope inside the list record** instead of the clear payload — lost: it duplicates index fields and base64 decoding into a zero-dependency package, while the clear payload's CID already names the signed bytes and the envelope is served beside it.
- **Bump attest's trust-list format to `/2` with the three assertions** — lost: the checker's reading of standing, class and scope is KS-Q4's whole subject; changing attest here would split that work.
- **A door enum on the listing** — lost: a corridor or sector owns no machinery (d46); ISIC Revision 5 is the open classification a rule's address already uses.
- **Register the retired words of d69(f) in the kernel's place check** — lost: a business's premises may carry any name; the register is Indusland's template guard.
