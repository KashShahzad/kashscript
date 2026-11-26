# did:kash — retired for standard identifiers

**`specs/did-kash.md` — v1 · 2026-11-26 · RW-19, branch B · ECOSYSTEM d97(h), d91(e), d71, d60 · Apache-2.0.**
Code: `@kashscript/identity-core` (`src/did.ts`, `src/did-key.ts`, `src/did-web.ts`) · attest `src/signing.ts`, `src/holder/keys.ts`, `src/holder/trust-list.ts` · lexicons `src/extensions/refs.ts` and the re-issued versions · predicate `src/rule.ts`, `src/dcql.ts`. Companion: [the attestation profile](attestation/README.md) §1.1. Decision record: [ADR-0035](../docs/adr/0035-did-kash-retired-for-standard-identifiers.md).

**The decision (d97(h), 2026-11-12):** *no DID method is registered. Where a stranger must resolve an identifier, a standard method is used — `did:web` for an organisation on its own domain (d91(e); d71's "no format of our own") — and RW-19's plan, branch B, says what a self-certifying key is called. Every record already signed stays checkable for ever.*

This file is branch B: what `did:kash` was, what each identifier in use is called now, the mechanical mapping, what never changes, and what each consumer does when it re-pins. A stranger who meets `did:kash` anywhere in this ecosystem's records should need nothing beyond this page.

## 1. What `did:kash` was

A self-certifying identifier: the method-specific body **is** the public key, base58btc, so a signature checks from the identifier alone — no registry, no resolver, no network (d28: never build anything whose verification requires us). Two key types, told apart by the bytes (ADR-0020):

| Type | Body | Example |
|---|---|---|
| Ed25519 | the raw 32-byte key, no prefix | `did:kash:4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw` |
| P-256 | the `p256-pub` multicodec (`0x80 0x24`) and the 33-byte compressed point | `did:kash:DnaevFAeTBp7Ht8bShhjcHBZmnZfubu9x4YJJHqB881YpeiX` |

It was never registered in the W3C DID method registry, and under d97(h) it never will be: an unregistered `did:` name is a format of our own (d71), and a stranger's standard tooling cannot read it.

## 2. The names now

1. **An organisation a stranger resolves is `did:web` on its own domain** (d91(e)). Its public records are DID URLs under it — `did:web:indusland.xyz/place/skardu` keeps d60(a)'s shape, *the publisher's DID plus a path*, under a method any library resolves. The resolution URL is derived, deterministic and never fetched by the kernel (`identity-core`'s `didWebUrl`); offline, a `did:web` signer's key comes from a pinned trust list or a held key, handed to the check as a resolver (the profile's §1.1).
2. **A self-certifying key is called `did:key`** — the W3C-registered method over exactly these bytes. Wherever a self-certifying identifier is written anew for a stranger — the public records' new versions, examples, documentation — it is written `did:key`. A publisher with no domain of its own (a small host) roots its records under its `did:key`.
3. **`did:kash` is the same key's house spelling.** It stays: (a) **for ever in everything already signed** — verification paths read it permanently (d97(h)); (b) as the kernel's **internal canonical comparison form** (attest's `canonicalSignerOf`; d91(e) calls the envelope an internal convenience); (c) in the engines' **opaque internal identifiers** (§4), which were never parties and never resolve. It is written no more where a stranger reads.
4. **Two spellings of one key are one party** on every path that compares signers (A7-02's rule): attest's keyid resolution and signer counting, the holder's resolution order step 1, trust-list publisher pinning and self-listed issuers, a rule's author match and its DCQL `kash_issuer` values, the wallet's restore check.

## 3. The mapping, mechanical and lossless

Implemented once, in `@kashscript/identity-core` (`toDidKey`, `fromDidKey`, `parseAnyKeyDid`, `deriveDidKey`, `parseDidKeyMethod`); attest, predicate and the wallet call it.

| From | To | How |
|---|---|---|
| `did:kash:<32-byte Ed25519 body>` | `did:key:z…` (begins `z6Mk`) | prepend the `ed25519-pub` multicodec (`0xed 0x01`), re-encode base58btc, prefix `z` |
| `did:kash:<p256-pub body>` (begins `Dn`) | `did:key:z<the same body>` (begins `zDn`) | **prepend `z`** — the bytes already agree (ADR-0020) |
| an organisation's identity | `did:web:<its-domain>` | not derivable from a key: the organisation's own domain names it, and a trust list binds its keys at listing, with class and grade |

Worked examples, checked by tests (`identity-core/src/did-key.test.ts`):

```
did:kash:DnaevFAeTBp7Ht8bShhjcHBZmnZfubu9x4YJJHqB881YpeiX     ← the live grade-1 ceremony key (founder-steps §12)
did:key:zDnaevFAeTBp7Ht8bShhjcHBZmnZfubu9x4YJJHqB881YpeiX     ← the same key, the standard spelling

did:kash:4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw           ← an Ed25519 key (bytes 0x01…0x20)
did:key:z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK       ← the same key
```

## 4. Every class of `did:kash` in use, and its disposition

Surveyed 2026-11-26 across `Kashscript 2.0`, `Duedale 2.0` (the engine), `Duedale-desk` and `Indusland 2.0`.

| In use | Where | Now called | Already signed |
|---|---|---|---|
| **Self-certifying keys** — issuer keys, ceremony keys, per-relationship counterparty keys, session keys, checkpoint origins | everywhere records are signed | `did:key` where written anew for a stranger; `did:kash` read for ever, and still what signers emit inside envelopes until the engines re-pin (§6) | reads for ever |
| **Public-record publishers and ids** — `<publisher>/rule·adoption·place·listing·guide/<slug>` (d60) | lexicons, muffler records, Indusland's places | `did:web:<domain>/<kind>/<slug>` for an organisation on its own domain; `did:key:…/<kind>/<slug>` for a keyless publisher; re-issue is d60(a)'s pointer — new identifier, old record never rewritten | old ids stay valid citations in the new versions' grammar |
| **Trust- and status-list publishers** | attest's holder, the engine's list | a self-certifying key, either spelling — never `did:web`, so the list's own signature checks from the identifier alone; pins match across spellings | reads for ever |
| **Engine-opaque identifiers** — `did:kash:org:<slug>`, `did:kash:agent:<slug>:<ulid>`, `did:kash:oreoasis:kernel:*`, the July legacy forms (`operator:`, `indus-logistics:…`) | the engine's database, tokens, derivation labels, signing contexts | unchanged — **internal, never parties** (the profile §1.1), never resolvable, kept by d99 (renaming identifiers inside signed records is a kernel format revision) | kept, by decision |
| **The PDS envelope and AT URIs** — `KashHeader.did`, `at://did:kash:…/…` | muffler | unchanged — internal transport addressing, key-bound, not a stranger-facing identifier | kept |
| **Fixtures, examples, documentation** | kernel tests, specs | re-issued under `did:web` / `did:key` where they model stranger-facing records (`lexicons/test/did-web.test.ts` holds the canonical set); old-form fixtures kept as the superset proof | n/a |

## 5. The resolver, honestly

Branch B's text asked for *"the resolver kept as a redirecting alias for one year."* **There is nothing to alias.** `services/kash-resolver` was never built — its README was always a placeholder explaining why a self-certifying DID needs no lookup — and `services/kash-registry` was retired by d59, never published, never deployed. No request for a `did:kash` has ever been served anywhere, so no address needs a redirect and no alias period is needed. d97(h) makes the retirement permanent; both READMEs now say so and point here.

## 6. What the consumers do when they re-pin

The kernel release carrying this change: **identity-core `0.5.0-alpha.0` · attest `0.3.0-alpha.4` · lexicons `0.7.0-alpha.0` · predicate `0.3.0-alpha.6` · wallet `0.1.0-alpha.8`** — published under `alpha` only by the founder. Reading both spellings is in this release; **what signers write inside envelopes flips only after both engines re-pin**, so nothing in flight breaks — the reversible order for an identifier change.

- **`Duedale 2.0` (the engine):** re-pin; nothing else changes behaviour. Then, in its own run: the trust list it publishes lists organisations by `did:web` `issuerId` with key material in `keys[]` (its own publisher key spelled `did:key` at the next signing, where d99's label note already waits); proof pages and the checker lines may show a self-certifying signer under its `did:key` spelling; serving `/.well-known/did.json` for duedale.com — and for an organisation's own domain only where that organisation asks — is the engine's choice, gated by its own plan. Opaque `org:`/`agent:` identifiers stay internal.
- **`Duedale-desk`:** re-pin only; `holderOfPacket` and every comparison inherit two-spellings-one-key through attest. The desk's archive role (OE-8) needs nothing.
- **`Indusland 2.0`:** re-pin; then, in its own run, re-issue its live places under `did:web:indusland.xyz/place/<slug>` with a `kash.place.pointer` from each old id (d60(a)), and its listings' hosts under each host's `did:web` or `did:key`. Its review-door rule and desk read both spellings through the kernel.
- **muffler (this repository):** carrying a `did:web`-published record end to end — the envelope's author stays a key; binding that key to the publisher is the trust list's job — is its own later work; the body-level records validate today.
- **`kash.attestation` / `kash.mandate` / `kash.decision` party grammars:** widen to the `did:key` spelling in the emission-flip release (`PARTY_DID_PATTERN`, `KEY_DID_PATTERN`; predicate's decision schema), with new versions and TCK cases, after the engines re-pin.

## 7. What never changes

- **Anything already signed verifies for ever** (d97(h)): `did:kash` stays in every verification path permanently, not for a transition window.
- **Identifiers inside signed records and hash inputs** — format ids, signing contexts, derivation labels, `did:kash:oreoasis:*` — are kept (d99); renaming them is a kernel format revision nobody has asked for.
- **No lookup appears anywhere** (d91(h)): neither spelling of a self-certifying key resolves over a network, `did:web` is fetched by no kernel path, and nothing here adds a directory of anyone.
