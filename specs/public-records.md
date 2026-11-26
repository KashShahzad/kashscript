# The public records — places, listings, guides, and the two lists

**`specs/public-records.md` — v1 · 2026-11-16 · KS-N1 (folding in KS-R5) · `@kashscript/lexicons/extensions/{place,lists,public}` (Apache-2.0), published by `@kashscript/muffler` behind its guard.**
Decisions: ECOSYSTEM d28, d41, d43, d46, d47(e), d51, d55(a), d59(a), d60, d62(c)7, d62(d)4–5, d69(c), d82, d83(c), d85(c), d91(d), d91(f), d93(e)2 · companions: [rule.md](rule.md) · [adoption.md](adoption.md) · [holder-contract.md](holder-contract.md) §3–§4 · [muffler.md](muffler.md) · schemas: [`schemas/place.schema.json`](schemas/place.schema.json), [`place-pointer`](schemas/place-pointer.schema.json), [`listing`](schemas/listing.schema.json), [`guide`](schemas/guide.schema.json), [`trust-list`](schemas/trust-list.schema.json), [`status-list`](schemas/status-list.schema.json) · decision record: [ADR-0029](../docs/adr/0029-public-records-in-the-kernel-and-the-descriptor-not-built.md).

> **What exists, and what does not.** Built in source with fixtures and tests in `packages/lexicons` (the shapes, the cross-field checks, the person-identity scan) and `packages/muffler` (the guard, the rebuilt index): lexicons `0.5.0-alpha.0`, muffler `0.2.0-alpha.0`, **not published** — the founder publishes from the public repository. No place, listing, guide or list has been published through muffler by anyone; Indusland's geography holds 81 place records waiting for this lexicon and for Indusland's own key, and its listings table has an empty `record_uri` column for the same reason. Every value in the fixtures is SAMPLE. attest's trust list has no publisher yet (d62(d)5: the founder holds the publisher's key).

## 0. What these records are, and are not

d59(a) gives muffler one job — *publishing for public, organisation-authored records* — and lexicons the schemas for them. **Never a person's.** A public record is written by an organisation about a place, an offering, a text or a list of issuers; it is identified by its publisher's DID plus a path (d60), so it says who answers for it; it is a closed shape, so it can carry no score, no count of people, no coordinate and no person's identity; and anyone may mirror it and check it without a server of ours (d28, d62(d)5).

Five kinds and a pointer, in two extensions:

| Kind | Lexicon | Who publishes | What it never carries |
|---|---|---|---|
| a place | `kash.place@1.0.0` | Indusland (landmarks, landscapes, islands, kasbahs, meeting places); a business (its own premises) | a coordinate, a point, a polygon, any number — positions live in the template that draws them (d69(c)) |
| a place's new publisher | `kash.place.pointer@1.0.0` | the old publisher | the place itself: the old record is never rewritten (d60(a)) |
| a listing | `kash.listing@1.0.0` | the host, an organisation with its own key (d93(e)1) | a rating, a star, an average, a review, a count; a phone or an email; a door's name |
| a guide | `kash.guide@1.0.0` | the publisher of the text (Maktub's guides and ebooks, a tourism office, a business) | a person's identifier, bylines included |
| a trust list | `kash.trust-list@1.0.0` | a list's publisher — the founder's key for the ecosystem's (d62(d)5), an organisation for a door's | a person; a score for an issuer |
| a status list | `kash.status-list@1.0.0` | an issuer, for its own records | a record, a person: it is a bitstring |

With the door's `kash.rule` and `kash.adoption` ([rule.md](rule.md), [adoption.md](adoption.md)) these eight NSIDs are **`PUBLIC_RECORD_LEXICONS`** (`@kashscript/lexicons/extensions/public`) — the one list muffler's guard admits (§4).

**Not here, by design.** The pact is not a record of its own: it is an adoption record over rules and recognitions (d91; `kash.adoption`). `charter` and `house.rule`, which KS-R5 named, are therefore not lexicons either: a station's charter is its pact with Indorania and a house's rule is a guild's — each an adoption of a rule — and KS-R5's note lands where it belongs: a rule cites places (`address.givens.area.places`, `spaces.places`), record kinds (each criterion's `dst_values` and `vct_values`) and the pacts it sits in (`givens.relations.within`), all in `kash.rule@1.1.0`. The node descriptor is not built (ADR-0029 §3). The `trade` extension is removed (d59: trade-core is retired; nothing in the repository imported it).

## 1. The identifiers

Every public record's id is a **DID URL**: `<publisher DID>/<kind>/<slug>`, with `<kind>` one of `place · listing · guide · rule · adoption` and the slug lowercase, digits and hyphens, at most 63 characters (`@kashscript/lexicons/extensions/refs`). **Since RW-19 B (2026-11-26; ECOSYSTEM d97(h)), the publisher's DID is a standard method** — `did:web:<domain>` for an organisation on its own domain (d91(e)), `did:key` for a publisher signing with a self-certifying key — and `did:kash`, the house spelling, stays in the grammar so every id already written remains a valid citation for ever. Each kind's 1.1.0 (the rule's 1.3.0, the adoption's 1.1.0) carries the widened grammar; the retirement and the mapping are [`did-kash.md`](did-kash.md). The DID is the publisher's own, so the id and the `publisher` (or `host`, or `author`) field agree — a cross-field rule the shape cannot write, checked by the `*Faults` functions (§3). **A place's id carries no coordinate** (d60(a)): `…/place/35.30,75.63` is refused by the pattern. A record cites another by its id, and by its hash when it pins a version (`cites[].hash`, `references[].hash`: SHA-256 hex of the cited record's canonical bytes). The trust list's `publisher` alone stays self-certifying in either spelling — never `did:web` — so the list's own signature checks from the identifier (its 1.1.0; [holder-contract.md](holder-contract.md) §3).

## 2. The records

### 2.1 `kash.place@1.0.0`

| Field | Meaning |
|---|---|
| `id`, `publisher` | the DID URL and the organisation that publishes it and answers for it |
| `name`, `names?` | the name, and other names by BCP 47 tag — Urdu and Roman Urdu beside English, the launch languages |
| `kind` | `island · kasbah · landmark · landscape · premises · meeting-place` — d66(e)'s island (a city or town) and kasbah (a neighbourhood, quarter or village); d60(a)'s landmarks and landscapes (Indusland's) and premises (a business's own); d82's meeting places |
| `hub?`, `cluster?` | a hub is the island a cluster of islands is named for — a place, never an office or a power (d69(c)); `cluster` is the hub's id, and a hub names its own |
| `within?` | the places it sits in — a kasbah's island, a premises' kasbah — at most eight |
| `region?` | the region it is listed in, by name: **a label over a list of places, never a boundary** (d55(a), d69). A meeting place has none (d82) |
| `status?` | `proposed · confirmed` — every row is proposed until the publisher confirms it |
| `source` | the public feature the name is pinned to (a GeoNames id, a gazetteer), or why there is none — never a position |
| `dates.published`, `practice?` | when; and *practice* inside what is signed, for everything built before its gate |

Cross-field (`placeFaults`): `ID_PUBLISHER` · `HUB_CLUSTER` (a hub names another cluster) · `MEETING_PLACE_REGION` · `WITHIN_SELF`.

**From Indusland's geography (IL-V7)**, one record per row: `address` → `id` under Indusland's DID once it holds one; `publisherDid` → `publisher`; `kind` as it is; `hub`; `cluster` → the hub's id; `region` (a name) → `region`; `status`; `source` → `source`. Nothing else moves: the positions stay in the template, for drawing. Indusland's 1,267 landmarks are `landmark` records when Indusland publishes them, their `lat`/`lng` left behind.

### 2.2 `kash.place.pointer@1.0.0`

`{ from, publisher, to, movedAt, note? }` — d60(a): a place that changes publisher gets a new identifier and a signed pointer from the old one. `from` is the old id, under `publisher` (the old publisher, who signs); `to` is the new id, under another publisher. The old record is never rewritten: the pointer is a new record in the old publisher's repository, keyed by the place's slug. Cross-field (`placePointerFaults`): `FROM_PUBLISHER` · `SAME_PUBLISHER` (under one publisher, a place simply stands).

### 2.3 `kash.listing@1.0.0`

| Field | Meaning |
|---|---|
| `id`, `host`, `hostName?` | the DID URL; the host — an organisation with its own key and book (d93(e)1); its public name, as a trust list's label |
| `title` (3–120), `summary` (10–1200) | plain words |
| `places` | where it is offered — one to eight d60 ids. **A listing names no door and no sector of its own** (d46): Indusland's doors are Indusland's words |
| `sector?` | `{classification: "ISIC", revision: "5", code}` — the same open classification as a rule's address (d85(c)) |
| `price` | `{amount, currency, unit}` — the published price: a decimal string (never a float), an ISO 4217 code, per `night · person · seat · vehicle · item · day · hour · fixed` |
| `terms?` | `{manifestId, hash}` — the `@kashscript/terms` agreement it is booked under |
| `deposit?`, `leadDays?` | the deposit in words (money moves on the parties' own rails, never here); how far ahead to book |
| `languages?`, `media?` | BCP 47 tags; pictures, sounds or films by CID with a mime type and alt text |
| `link?` | the host's own channel, https only — a booking through it is the host's own customer and carries no commission (d63(a)) |
| `version`, `dates.published`, `dates.validUntil?`, `practice?` | — |

**It has no rating field** (KS-R5), nor a star, an average, a review, a count of bookings or visits (d62(c)7, d41, d43): quality is shown as receipts and track record, never marked. It has no field for a phone number or an email: a host's contact details live in the host's own app profile, outside the protocol. Cross-field (`listingFaults`): `ID_HOST` · `DATES`.

**From Indusland's listings (IL-V2)**, when a host publishes: `slug` → the id's slug under the host's DID; `host_name` → `hostName`; `title`, `summary`; `place_id` (Indusland's encyclopedia district) → `places` as d60 ids, which Indusland maps; `unit`, `price_minor`, `currency` → `price` (`price_minor` 450000 PKR → `amount: "4500"`); `deposit_rule` → `deposit`; `lead_days` → `leadDays`; `contact_link` → `link`; `record_uri` ← the published record's address. `primary_door`, `second_door`, `agreement_kind`, `booking_mode`, `host_kind` and `details` stay Indusland's.

### 2.4 `kash.guide@1.0.0`

| Field | Meaning |
|---|---|
| `id`, `publisher`, `title`, `summary?` | — |
| `languages` | at least one BCP 47 tag |
| `places` | the places it is about — one to sixty-four d60 ids |
| `cites?` | the public records it cites — places, listings, guides, rules, adoptions — by id, and by hash when pinned |
| `sections` | one to sixty-four `{heading, text (markdown, ≤ 20,000), media?, places?}` |
| `credits?` | chosen bylines — `{role, name}` — because art is commissioned and credited (d51). **A byline is words:** the shape refuses a DID or anything with an `@` in it, and the scan (§3) refuses a phone number |
| `version`, `dates.published`, `dates.updated?`, `practice?` | — |

Cross-field (`guideFaults`): `ID_PUBLISHER` · `DATES`.

### 2.5 `kash.trust-list@1.0.0` — attest's list, with the three assertions

The body **is** attest's `kashscript-trust-list/1` payload ([holder-contract.md](holder-contract.md) §3), in clear: `format`, `listId`, monotonic `version`, `publisher` (a self-certifying `did:kash`), `issuedAtUnix`, the list's window, and `issuers[]` — each with `issuerId`, `label`, `keys[]` (`{keyid, alg: Ed25519 | ES256, publicKeyHex}`, for signers whose identifiers are not self-certifying), `dsts[]` (the exact registered tags it may issue, never a family) and its own window. **On it, d91(f)'s three assertions, which the EU's trusted lists also keep apart:**

| Assertion | Fields | Meaning |
|---|---|---|
| **identity** | `issuerId`, `keys`, `class`, `grade?` | this key is this organisation — of which class (`self-issuer · counterparty · assessor · accredited-body · insurer`), shown at which grade (0–3, d91(d); 3 is the organisation signing as itself) |
| **standing** | `standing` | `listed · suspended · removed`. Only `listed` lists |
| **scope** | `dsts`, `references?` | the exact tags it may issue (attest's rule), and the references — rules, standards' clauses — it may attest against, by id and hash |
| the floor | `floor` on the list, `floor?` on an entry | the floor version every entry conforms to (d91(f): every trust entry cites it). Until IN-N2 publishes the floor as a record, `version` names the draft — *VISION §4 draft, 2026-10-18* — and `hash` is absent |

**The format literal is unchanged**, and attest's verifier checks the fields it names and tolerates the rest, so **attest `0.2.0-alpha.10` and the wallet read a list of this shape today** — muffler's test signs one with `signTrustList`, verifies it with `verifyTrustList` and finds the listed issuer with `findListing`. What they do not read yet is the standing: a checker on attest today reads windows only. So the one cross-field rule with teeth is **`STANDING_WINDOW`: a `suspended` or `removed` entry ends its window no later than the list's `issuedAtUnix`** — then a checker that reads windows agrees with the standing, and nothing a publisher writes down says one thing to a new checker and another to an old one. Teaching the checker standing, class and scope, and the trust log that anchors each version, is **KS-Q4's**. Also `WINDOW` (a window ends after it starts).

### 2.6 `kash.status-list@1.0.0` — attest's list, as it is

The body is attest's `kashscript-status-list/1` payload ([holder-contract.md](holder-contract.md) §4), aligned to W3C Bitstring Status List v1.0: `type: BitstringStatusList`, `id` (the https URL the list is served at — shared by many records, never one per record), `issuer`, `statusPurpose` (`revocation · suspension`), `encodedList` (`u` + base64url of the GZIP'd bitstring; attest enforces the 131,072-entry floor when it signs), `issuedAtUnix`, `validUntilUnix | null`, `ttl?`. Cross-field (`statusListFaults`): `VALID_UNTIL`. **d91's three terminal states** — expired · superseded by a citing attestation · withdrawn within the window — are KS-Q4's, because the verifier must learn them too.

**2026-11-18 (KS-Q4):** `kash.status-list@1.1.0` sits beside `1.0.0` and adds the purposes `supersession` and `withdrawal`, so a list can carry d91's terminal states. A new enum value is a minor version, and the version is part of the id ([`docs/lexicon-versioning.md`](../docs/lexicon-versioning.md)). The checker now reads the three terminal states, a stated cache time and the withdrawal window ([holder-contract.md](holder-contract.md) §4). Each version of either list can be anchored in the trust log by the hash of its signed bytes ([trust-log.md](trust-log.md)).

### 2.7 One document, two forms

The muffler record is the clear payload. attest signs **the same document** as a DSSE envelope — `signTrustList` / `signStatusList` with `{ canonical: true }`, as `kash trust sign` does. Both canonicalise with RFC 8785, so **the record's CID (sha2-256 over its JCS bytes) is the hash of the very bytes the envelope signs**: a mirror serves the envelope beside the record, and anyone can tell they are one document. The same relation holds for `kash.rule` and `kash.adoption` as KS-Q1 shaped them. Nothing in lexicons or muffler verifies a signature — lexicons has no dependency and muffler stays off attest at runtime; attest verifies, offline (d28).

## 3. The checks the shape cannot write, and the person-identity scan

Every kind has a pure `*Faults(body)` function beside its schema, returning `[]` or `[{code, path, message}]` — the rules above (§2). `publicRecordFaults(nsid, body)` dispatches by NSID; for `kash.rule` and `kash.adoption` it returns nothing, because their meaning is `@kashscript/predicate`'s.

**`findPersonIdentity(body)`** walks every string in a record — values and keys, at any depth — and reports the first of three in words: an email address, a phone number (a run of ten or more digits written as a phone number is, never a date, a time or an amount), or a DID. The three patterns are predicate's `CONTACT_PATTERNS`, copied and not imported (lexicons stays zero-dependency). A string that *is* an identifier or an encoding is left alone — a whole `did:kash` or DID URL with or without a key fragment, a hex digest or key, a CID, a base64url bitstring — and a URL is read for an email only, because its digits are not a phone number. So `publisher: did:kash:…` passes and `summary: "Ask for Amina, amina.k@tours.example"` is refused.

## 4. The guard, in muffler

`createPublicRecordGuard()` (`@kashscript/muffler/guard`) is a `Refiner` (the seam [muffler.md](muffler.md) describes) built on `createLexiconRefiner`:

- **by kind:** it handles every collection under the protocol's namespace (`kash.*`) and every admitted NSID. A collection it does not admit — `kash.id.profile` (a person's own profile), `kash.social.post`, `kash.decision` (the person's receipt), anything else — is **refused with `PERSON_RECORD`**, so the indexer reports it and goes on; it is never skipped in silence, which the indexer's rule for an unhandled collection would otherwise do. A venture's own `app.*` collections are not its business: `composeRefiners(guard, ventureRefiner)` indexes both through one indexer;
- **by shape:** a body without its lexicon's shape is `INVALID_RECORD` — so a coordinate on a place, a rating on a listing, a contact field anywhere, is refused;
- **by content:** `publicRecordFaults` → `INVALID_ATTRIBUTES` with the faults; `findPersonIdentity` → `PERSON_IDENTITY` with the finding.

**What the guard cannot do, said plainly:** tell a person's key from an organisation's. No directory of people exists, by design (d41); the indexer learns a repository's DID and the record's `publisher`, and neither says what kind of party holds the key. The guard refuses by kind and by content. A key is an organisation's when a trust list says so (d91(f)), and that reading is KS-Q4's.

**d28 — an index rebuilt from the records alone equals the original.** muffler's `rebuild.test.ts` indexes a set of public records with the guard, publishes what the index holds again as records and nothing else — no CID, no time, another order — into a fresh index, and the two agree on every `(did, collection, rkey, cid, value)`; every CID recomputes from its record's canonical bytes; the planted person's record is in neither and was reported once each run; a record changed in transit fails its advertised CID and is not indexed.

## 5. Publishing, and what each consumer takes

- **A publisher** writes the clear record into its own repository through `MufflerClient.put(collection, rkey, record)` with the guard as its refiner, so nothing leaves the process that a mirror would refuse. The `rkey` is the record's slug (a trust list's `listId`); a new version replaces the record at that key. Lists are signed beside the record with `kash trust sign`, from the same clear payload.
- **Indusland** publishes its places (§2.1) and, through each host's own key under a mandate, the host's listings (§2.3), and indexes places and listings — never people (d93(e)2). `@indus/muffler` pins `@kashscript/muffler ^0.1.0`, which `0.2.0` does not satisfy: a re-pin.
- **The desk** (Duedale) signs a trust list per door with attest today; a list of this shape is what it signs, with `class`, `standing` and the floor written on it.
- **KS-Q4** takes the trust list's three assertions into the checker and the log, and the status list's three terminal states (§2.5–§2.6).
- **IN-Q5's reference library** (what remains of IN-N1 for Indorania) validates and indexes the six kinds and the door's two; **IN-Q1's key service** lists an organisation at a grade with `class` and `grade`.
- **The founder's first trust list** (d62(d)5) is this shape, signed by the publisher key only he holds, citing the floor by its draft name.

## 6. What was weighed, so no format of our own is made unsaid (STRATEGY rule 8)

JSON Schema 2020-12 (the published shape of every lexicon) · DSSE (the lists' signature) · W3C Bitstring Status List v1.0 (the status list) · the structure of the EU's trusted lists (identity · standing · scope) · W3C DID URLs (the identifiers) · ISIC Revision 5 (a listing's sector) — **adopted as they stand.** OpenID4VCI issuer metadata and RFC 8615 well-known URIs — what an engine already publishes about the records it makes, and where; the reason no descriptor of our own is added (ADR-0029). CNCF Serverless Workflow DSL 1.0 — for a run graph, which is the desk's and not in these records; W3C ODRL 2.2 — for rules, which are DCQL plus a DMN condition (d84(a)) and not here. Neither fits what this specification describes.

## 7. Changelog

| Version | Date | |
|---|---|---|
| **v1.1** | 2026-11-18 | KS-Q4. `kash.status-list@1.1.0` with `supersession` and `withdrawal` beside `1.0.0`; the schema regenerated; muffler's guard admits the withdrawal list. lexicons `0.6.0-alpha.0`, muffler `0.2.0-alpha.1`, **not published.** |
| **v1** | 2026-11-16 | KS-N1, folding in KS-R5. `kash.place`, `kash.place.pointer`, `kash.listing`, `kash.guide` (`extensions/place`); `kash.trust-list` with d91's three assertions and `kash.status-list` (`extensions/lists`); `PUBLIC_RECORD_LEXICONS`, `publicRecordFaults`, `findPersonIdentity` (`extensions/public`); muffler's guard and `composeRefiners`; the d28 test; the `trade` extension removed; the six JSON Schemas. lexicons `0.5.0-alpha.0`, muffler `0.2.0-alpha.0`, **not published.** |
