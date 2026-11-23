# Presentation and the ask — a yes, never the data

**`specs/presentation.md` — v1 · 2026-09-25 · PL-3 · verification in `@kashscript/attest/exchange` and `@kashscript/attest/sd-jwt` (Apache-2.0).**
Decisions: ECOSYSTEM d27.2, d36, d41, d42 §5, d43, d47(d), d49 · builds on [the holder contract](holder-contract.md) · schema: [`schemas/ask.schema.json`](schemas/ask.schema.json).

> **What exists, and what does not.** The formats and every verification step are built in attest source (`0.2.0-alpha.1`), with conformance vectors, and **unpublished** — a prerelease publish is founder-terminal. No wallet (PL-6), ask library (PL-8) or verifier endpoint exists. Nothing here has run with a person.

## 0. The rule

**An ask is answered with a yes, never with the data** (d27.2). Nothing here is invented where a standard exists: a predicate reaches the holder as an **SD-JWT VC** (IETF SD-JWT with SD-JWT VC's `dc+sd-jwt` issuer JWT), and reaches a verifier through **OpenID for Verifiable Presentations 1.0 (OID4VP)** with a DCQL query — *built on* it, not conformant: the Foundation's suites were run on 2026-10-10 and 2026-11-23 and the wallet does not pass them (`docs/conformance/2026-10-10`, `docs/conformance/2026-11-23`). An ask is the verifier's presentation request.

## 1. The ask

The shape of d42 §5, published as a JSON Schema with a reference validator (`validateAsk`). The two share one set of constants, and a test keeps them in step.

| Field | Meaning |
|---|---|
| `format` | `kashscript-ask/1` |
| `key`, `version` | a stable identity, e.g. `ask:workshop-safety-check` v1 |
| `title` | plain words |
| `who` | `{name, id}` — the verifier; `id` is the OID4VP `client_id` and the KB-JWT audience |
| `needs[]` | `{id, predicate, withinDays, issuers?}` — predicate kinds only |
| `why` | plain words, on the request |
| `answer` | `{form: "yes", restsOn: "issuers"}` — a yes and the issuers it rests on, never the records |
| `goodFor` | what a yes gets the holder |
| `declining` | `costs-only-goodFor` |
| `linking` | `separate` |
| `published` | `{library, atUnix}` — an https public library |
| `expiresAtUnix`, `state` | when it ends; `published` / `withdrawn` / `expired` |

**The eight rules, as validation:**

| Rule | How it is checked |
|---|---|
| 1 · predicates only | `needs` name predicate kinds and nothing else; no record, field, attachment or upload key anywhere in the ask; `answer.restsOn` is `issuers` |
| 2 · it says why | `why` is at least 12 characters and says more than the title |
| 3 · a no is answerable | `goodFor` is required, and `declining` is `costs-only-goodFor` |
| 4 · it expires | `expiresAtUnix` is after publication and at most 366 days after it |
| 5 · it is public | `published` names an https library and a date |
| 6 · no joining by default | `linking` is `separate`, and no predicate kind is asked twice |
| 7 · an excessive ask is recordable | a stable `key` and `version`, so the holder's own note can name it (§4) |
| 8 · never the improvement item | no need mentions *improv* in any form (d43) |

**Forbidden needs (d36).** No need may refer to origin, ethnicity, sect, caste or ancestry. The check is word-bounded, so *original* and *insect* pass.

**The request.** An ask becomes an OID4VP authorization request: `response_type=vp_token`, `response_mode=direct_post`, `client_id` = `who.id`, a fresh `nonce`, and a `dcql_query` with one credential query per need (`format: dc+sd-jwt`, `vct_values: [predicate]`, claims `predicate.kind` = the need's kind and `predicate.answer` = true). The request also carries the ask by value as `kash_ask`, with `kash_ask_sha256`, an extension parameter. Before showing the request, the wallet validates the ask and checks the digest against its cached copy of the public library. It then shows the `why`.

**2026-11-23 (RW-16): requests by reference, signed.** The wallet also reads a request by reference (`request_uri`, GET or POST), signed with ES256 under the `x509_hash` or `x509_san_dns` client identifier prefix (the leaf in `x5c`; **no chain is validated**, because the wallet keeps no X.509 trust list), or unsigned under `redirect_uri`, and answers by `direct_post` or by `direct_post.jwt`, encrypted with ECDH-ES to the verifier's key. Reading ends one of four ways: **the ask**, as above · **untrusted** — not tied to the verifier it names, so nothing is sent, not even an error · **invalid** — tied to its verifier but broken, which the person *may* report (`invalid_request` or `invalid_transaction_data`, about the request only, never about the person or what they hold; the wallet never sends it by itself, OpenID4VP §15.9.2) · **no ask** — refused, nothing sent. A query the wallet cannot answer sends nothing, since "I don't hold that" would be a refusal.

## 2. The predicate credential

An SD-JWT VC issued to the holder through the handoff ([holder contract §1](holder-contract.md)), `typ: dc+sd-jwt`, `alg: EdDSA` — or, since PL-2, `ES256`: **the issuer's key decides**, and a header naming the other algorithm fails. The holder's `cnf.jwk` may be an EC P-256 key (a phone's secure chip), and then the KB-JWT is ES256 (ADR-0020).

| Claim | Visibility | Meaning |
|---|---|---|
| `iss` | visible | the issuing establishment's `did:kash` (or a trust-listed key id) |
| `iat` | visible | **rounded to the day**, so copies carry no unique time |
| `exp`, `vct` | visible | `vct` = `https://kashscript.com/vct/predicate/1` |
| `cnf.jwk` | visible | the holder's **relationship key for this verifier** |
| `credentialStatus` | visible | this copy's own W3C `BitstringStatusListEntry` ([holder contract §4](holder-contract.md)) |
| `predicate` | visible | `{kind, answer, rule {id, version, hash}, window {from, to}}` — **the rule version is required** (d43) |
| `restsOn[]` | **selectively disclosable** | the record hashes the answer rests on, padded with decoy digests so their count does not show |

**One status format.** SD-JWT VC's own `status` claim points at the IETF Token Status List. This ecosystem keeps PL-1's single W3C-aligned format and carries it as `credentialStatus`. A verifier that reads only the Token Status List sees no status, and must say *not checked*.

Oreoasis's existing DSSE predicate (`application/vnd.oreoasis.predicate+json`) is unchanged. The credential carries the same answer to the holder, without the DSSE form's visible `justificationHash`, which would correlate.

**2026-11-23 (RW-15):** `restsOn` is padded to the next multiple of eight entries (`RESTS_ON_SLOTS`, at least one decoy; `restsOnDecoys`), and the credential's `_sd` carries no decoys (`issueSdJwt`'s `sdDecoys`), so two copies of one yes have one length and a yes over three records looks like a yes over seven ([attestation](attestation/README.md) §3 G1: the count was a split in the class). Verification is unchanged, and the frozen vectors are unchanged. `sharedValues(a, b)` joins `linkabilityBetween` as the diagnostic that knows nothing: every string two SD-JWTs share, with its path, for a caller to subtract the class from.

## 3. The presentation

The holder answers with an OID4VP `vp_token` holding one SD-JWT presentation per need: the issuer JWT, the disclosures the holder chose, and a **KB-JWT** (`typ: kb+jwt`) signed by the key in `cnf.jwk` over `aud` (= `client_id`), `nonce`, `iat` and `sd_hash` (the digest of everything before it).

**A verifier checks, offline:** the issuer signature — **the key is `iss`'s**: a self-certifying `iss`, a pinned trust list's key under that id, or a held key, and a `kid`, if present, must name `iss` (a `#fragment` apart) or the credential is refused as `KID_NOT_ISSUER` (AU-3, A7-01: a key resolved from the header and reported as `iss` would let any key sign in any organisation's name; **SD-JWT VC's issuer-metadata and type-metadata lookups are never fetched**) — every disclosure against a signed digest, no disclosure twice, the KB-JWT's signature, audience, nonce and `sd_hash` — and, at a desk, its age: predicate's `checkPacket` refuses a binding further than ten minutes from `asOf` unless the desk widens the window (`freshness.maxKbAgeSec`; AU-3, A7-08; the nonce stays single-use by the desk's own hand) — the vct, and the predicate's rule version. **Status is the one networked check**, and its verdict names its time: *valid unless revoked, as of \<list time\>*.

**2026-11-18 (KS-Q4, d84 P6):** a presentation verifies only against the verifier's own audience and nonce. Missing either is `AUDIENCE_NOT_SUPPLIED` or `NONCE_NOT_SUPPLIED`, by type and at run time, never the old note *audience or nonce not checked*. The binding's age is bounded by default: at most 600 seconds from now (`DEFAULT_PRESENTATION_MAX_AGE_SEC`), or from `--at`, the time a file checked later was received. The header's `alg` must be one that a live row of attest's profile registry names (`ALLOWED_JOSE_ALGS`: `EdDSA`, `ES256`). That is checked before any key is touched, so `none`, `HS256`, `RS256` and a header naming the other algorithm are refused, and any `crit` header is refused (`CRIT_UNSUPPORTED`). A nonce is single-use by the verifier's hand: `createNonceRegistry` issues each once and accepts each once (`acceptPresentationOnce`), in memory and bounded. A door that runs on several machines needs a shared one.

**Raw records travel only because the holder attached them.** An attached record is bound only if its record id equals a record hash the holder disclosed.

## 4. Unlinkable unless the holder links (rule 6)

- **One copy per verifier.** At handoff the wallet asks for a batch — one key proof per relationship key — and gets one copy per key. A copy is never shown to a second verifier.
- **No stable salt across presentations.** Each copy has its own disclosure salts, digests, status index (random), and relationship key.
- **Record hashes correlate.** They stay hidden unless the holder discloses them. Disclosed to two verifiers, they link the two presentations — the holder's choice, which the wallet warns about.
- `linkabilityBetween(a, b)` lists every correlator two presentations share. The test vectors show two presentations sharing none.

## 5. The presentation log

Holder-side, exported with the wallet (holder contract v1.1), **never sent anywhere**, and part of no presentation. Two kinds:

- **`presentation`** — when, to which verifier, under which relationship identifier, answering which ask (key, version, digest), which copies (by the digest of their issuer JWT), which disclosures, which attached record ids, and whether the holder deliberately linked it to an earlier one.
- **`excessive-ask`** — the holder's own note that an ask asked too much, naming it and the rules it breaks (rule 7). It is made only if the holder chooses to.

`validatePresentationLog` flags a copy or a relationship key shown to a second verifier unless the holder marked the link as theirs.

## 6. A decline has no format

**Declining emits nothing, to anyone.** There is no message to the verifier, no log entry, no flag and no count (d49(a); ADR-0018). OID4VP allows a wallet to return an `access_denied` error. This profile forbids it for a decline: the wallet sends nothing and the request expires. A verifier who asked a person face to face would otherwise learn who said no.

## 7. What this does not do

Invent a presentation protocol · carry a raw record the holder did not attach · give Indorania any signature · host the ask library (PL-8) · derive standing (PL-8) · add ES256 (PL-2).

## Changelog

| Version | Date | Change |
|---|---|---|
| **v1.3.1** | 2026-11-23 | RW-16, no format change: the wallet reads requests by reference (`request_uri`, GET or POST), signed under `x509_hash` or `x509_san_dns` (ES256, no chain validated: there is no X.509 trust list) or unsigned under `redirect_uri`, and answers by `direct_post` or `direct_post.jwt` (ECDH-ES, A128GCM or A256GCM). A request with no ask is refused and nothing is sent; an untrusted one sends nothing; one tied to its verifier but broken may be reported (`invalid_request`, `invalid_transaction_data`) only when the person chooses to. `@kashscript/wallet`, **not published.** |
| **v1.3** | 2026-11-23 | RW-15: `restsOn` padded to a multiple of eight and `_sd` without decoys, so a copy's counts say nothing; `sharedValues` beside `linkabilityBetween`. Issued bytes change, verified ones do not. attest `0.3.0-alpha.2`, **not published.** |
| **v1.2** | 2026-11-18 | KS-Q4: audience and nonce required on every presentation (`AUDIENCE_NOT_SUPPLIED`, `NONCE_NOT_SUPPLIED`); a 600-second default for the binding's age; the algorithm allow-list checked before any key, and `crit` refused; the nonce registry. Breaking at alpha. attest `0.3.0-alpha.0`, **not published.** |
| **v1.1** | 2026-10-01 | Additive (PL-2): the credential and its KB-JWT may be ES256 — the issuer's key and the holder's `cnf.jwk` decide, never the header; an EC P-256 holder key is a relationship key in a phone's secure chip. Verification in attest `0.2.0-alpha.2`, with vectors (`test/vectors/es256`). |
| **v1** | 2026-09-25 | The ask (schema, the eight rules, the forbidden needs, the OID4VP mapping), the predicate credential and its holder-bound presentation, unlinkability, the presentation log, and no format for a decline. Verification in attest `0.2.0-alpha.1`, with vectors — **unpublished**. |
