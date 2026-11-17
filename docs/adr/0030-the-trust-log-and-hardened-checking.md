# ADR-0030: The trust log is files any host mirrors, time comes from a public witness over its heads, and checking refuses what it cannot bind

- **Status:** Accepted
- **Date:** 2026-11-18
- **Decision drivers:** ECOSYSTEM d84 P6 (*before gear 3*: a trust log in Certificate Transparency's manner; an explicit algorithm allow-list; nonce and audience on every presentation; maximum ages; status with a stated cache time; scoped, short-lived tokens) · d91(a) (time comes from the log and a public witness, never the signer) · d91(f) (the trust list is three assertions with issuer classes, each citing the floor; status lists carry three terminal states) · d91(i) (a receipt issued before the log began carries a witness dated when anchored, never backdated; the log is pulled forward) · d28 (never build anything whose verification requires us) · d27 (hashes, never content) · d5 (OpenTimestamps) · Indorania ADR-0003's first finding (signers accept a `sign(bytes)` callback) · the prompt KS-Q4 (PROMPT-PATH §9), whose plan the founder approved on 2026-11-18.

## Context

The kernel had the pieces of a log and none of the log. attest held RFC 6962's tree with inclusion proofs (GP-6, for session anchors), an old `WitnessClient` that stores calendar bytes and verifies nothing, a trust list read by its windows alone, and a status list with two purposes and no cache time. A presentation verified without an audience or a nonce, with the note *audience or nonce not checked*. The algorithm came from the key, but no list said which algorithms exist. Kash-Event signers, the countersign ceremony and the ledger took a seed and nothing else.

KS-N1 (ADR-0029) wrote d91's three assertions onto the trust list and left the checker's reading of them, and the status list's terminal states, to this prompt. d91(i) pulled the log forward, because every receipt issued before it exists can only be backfilled.

## Decision

1. **The log is a folder, not a server.** `log.json`, `entries/NNNNNN.jsonl`, `checkpoints/<size>.json` and `witness/<size>.ots|.tsr`, in RFC 9162's tree. Any static host serves it and any host mirrors it by copying. The writer (`openTrustLog`) is pure over a `LogStore`: files in `kash log`, a database in an engine, memory in a test. `attest log verify` audits a folder offline and compares a mirror. The specification is [`specs/trust-log.md`](../../specs/trust-log.md).
2. **Four closed entries, and a guard.** A trust list's version and a status list's version, each by the hash of the signed bytes; an issuer key added, rotated or revoked; an attestation by its salted hash. The guard refuses an unknown kind, an extra field, free text and any field named for a person, a record or a presentation, before a leaf is made. Every checker runs it on every entry it reads.
3. **The log's key is the publisher key**, the role that signs trust lists (d62(d)5). It signs DSSE checkpoints carrying RFC 9162's tree-head fields and the previous head. The log's id is `<did:kash>/log/<slug>`, so the id names the only key that may sign.
4. **Time is witnessed, never claimed.** A public witness stamps each checkpoint's payload hash: OpenTimestamps (d5), or RFC 3161 at DigiCert as GOV-5 does. The attested time of an entry is the earliest final witness over the first head that held it. An entry claiming a time earlier than that by more than the log's declared `maxBatchDelaySec` (default 86,400, the founder's to change) is **`CLAIMED_BEFORE_WITNESS`**: this is the planted backdated attestation, caught. A claim after the witness is impossible and always reported. **A backfilled mark holds only for a claim from before the log began.** The audit reads the start from `log.json` and bounds it by the first head's witness, so the mark cannot shelter a backdated claim the log could have witnessed.
5. **The witnesses are read in TypeScript and checked where they must be.** attest reads and writes `.ots` byte for byte, recomputes every operation and checks a supplied Bitcoin header's proof of work. It reads an RFC 3161 token's DER itself. **The token's CMS signature and chain are verified by `openssl ts -verify`** against a root the caller names (`--tsa-root`), exported as `@kashscript/attest/openssl` for Node. Without the check, a token's time is read and never relied on.
6. **No gossip in this version, and every report says so.** Two heads of one size with different roots are `SPLIT_VIEW` when both are held. A checker shown one view cannot see another.
7. **Checking refuses what it cannot bind.** This is a breaking change at alpha, taken now.
   - `SIGNATURE_PROFILES` is the algorithm registry, and `ALLOWED_JOSE_ALGS` derives from its live rows. A header naming anything else, `none`, `HS256` and `RS256` included, is refused before a key is touched. Any `crit` header is refused.
   - A presentation verifies only against the verifier's audience and nonce (`AUDIENCE_NOT_SUPPLIED`, `NONCE_NOT_SUPPLIED`), required by type and at run time. Its binding may be at most 600 seconds old unless the verifier says otherwise. The CLI requires `--audience` and `--nonce`, and takes `--at` for a file checked later.
   - `createNonceRegistry` issues each nonce once and accepts it once, in memory and bounded. It is the contract a door implements.
   - An approval request open for more than 90 days is `REQUEST_WINDOW_TOO_LONG` (`COUNTERSIGN_MAX_TTL_SECONDS` moves into attest; identity-server imports it).
8. **The checker reads d91's trust list and status list.** Only `listed` lists. A suspended or removed entry is a refusal with its reason, and a sanction in any pinned list stands over a listing elsewhere. Class, grade, scope (the exact tag, and the reference when the caller names it) and the floor are reported. Status lists gain `supersession` and `withdrawal` beside `revocation` and `suspension` (lexicons `kash.status-list@1.1.0` beside `1.0.0`). Verdicts gain `expired` (the record's own clock), `superseded` and `withdrawn`, and every verdict names its cache time.
9. **Every kernel signer takes a key service.** identity-core's `EventSigner` gains an Ed25519 `sign(bytes)` variant, and so do identity-server's countersign request, acceptance, withdrawal and key claim, and attest's `signLedgerBlock`. Each checks the callback's answer under the public key before using it, and the bytes equal the seed path's. Seeds keep working unchanged. The platform keeps its copied recipes until IN-Q1 switches to the kernel.
10. **Crypto agility is designed, not built.** `ML-DSA-65` (FIPS 204) is a reserved row: named, verifying nothing. How it joins is in the spec's §12.
11. **Versions move in source only:** attest `0.3.0-alpha.0`, identity-core `0.4.0-alpha.3`, identity-server `0.3.0-alpha.0`, lexicons `0.6.0-alpha.0`, muffler `0.2.0-alpha.1`, predicate `0.3.0-alpha.3`, wallet `0.1.0-alpha.7`, kash `0.6.0-alpha.0`. Nothing is published.

## Where the build departs from the approved plan, and why

- **The agent token's ceiling is the verifier's option, not a hard 3,600 seconds.** Oreoasis mints one-hour, eight-hour and one-day tokens, and a 366-day booking mandate. A hard ceiling would break them, and choosing their lifetimes is the engine's call. `maxLifetimeSeconds` on mint and verify enforces a ceiling where one is stated (`LIFETIME_TOO_LONG`), and `RECOMMENDED_AGENT_TOKEN_LIFETIME_SECONDS` is 3,600.
- **The withdrawal window lives in the status check** (`withdrawalWindowSec`), not in the countersign verifier, because a withdrawal list's bit is read there as well as a presented withdrawal. It is unset by default, since the number is the founder's (d84 P4.4). Unset, a withdrawal reads as withdrawn and the verdict says the window was not checked.
- **A status list past its cache time keeps its reading and is flagged stale.** W3C Bitstring Status List says `ttl` does not override validity. A verifier that wants a bound sets `maxAgeSec`, and an older list then decides nothing (`unknown`).
- **`kash.status-list@1.1.0` was added beside `1.0.0`** rather than changing it: a new enum value is a minor version, and the version is part of the id.
- **The backfilled mark's limit (decision 4) was added during the build.** The plan exempted every backfilled entry from the early-claim rule, which would have let a backdated attestation carry the mark and pass. `kash log add` also refuses an attestation whose mark does not fit its claim.

## Consequences

### Positive

- A stranger checks a list's version, a key change or an attestation, and its witnessed time, with attest alone. A mirror rebuilt from the entries alone reaches every signed root, and every tamper in the vectors is named.
- d91(a)'s rule has a test with teeth: the planted backdated attestation fails as `CLAIMED_BEFORE_WITNESS` in the library, through openssl against the SAMPLE root, and in the CLI.
- Replay, algorithm confusion, a wrong audience, a wrong nonce, a stale binding, an expired or out-of-date status list and a 91-day approval window are each refused by a test.
- The trust list's standing, class, grade and scope reach the wallet's words, the holder export and predicate's receipts.

### Negative / accepted trade-offs

- **Breaking at alpha.** Every caller that verified a presentation without an audience and a nonce must now pass both. Oreoasis's two door handlers already do. Duedale's desk and Indusland re-pin when release 2 is published.
- No gossip: a split view is caught only by someone who holds both views.
- RFC 3161 rests on openssl, and OpenTimestamps on a header the checker holds. Without them, a time is read and never relied on.
- `log.json` is unsigned. Its start is bounded by the first head's witness, and its allowance is the operator's word.
- The nonce registry is in memory. A door that runs on several machines needs a shared one.

## Alternatives considered

- **A hosted log API (Trillian, or a service of ours)** — lost: checking would need our server (d28), and a static folder mirrors by copying. An engine embeds the writer instead (OA-Q5).
- **Sigstore's Rekor as the log** — lost: it is a public log of software signatures run by others, and logging our entries there would publish them under its policy. The old `WitnessClient` stays for Oreoasis's audit anchor and is not relied on.
- **RFC 3161's CMS verified in TypeScript** — lost for now: an X.509 chain validator in a zero-dependency package is a large, risky surface. openssl does it, as GOV-5 already does.
- **Witness co-signing between mirrors (CT's gossip, or the witness network's cosigned checkpoints)** — deferred: it needs mirrors run by other people. The checkpoint already names its previous head, so a co-signature can be added beside it later.
- **ML-DSA now** — lost: no runtime in the ecosystem's path verifies it, and no buyer asks. The reserved row keeps the name.
